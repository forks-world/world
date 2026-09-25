use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use world_runtime::{
    policy::Policy,
    run::{self, RunOptions},
    silo,
};

#[derive(Parser)]
#[command(name = "world", version, about = "World local runtime")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Network {
        #[command(subcommand)]
        command: Network,
    },
    /// Manage local workspaces with an isolated localhost.
    Workspace {
        #[arg(long, global = true)]
        state_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: Workspace,
    },
    /// Run a command inside a workspace's isolated localhost.
    Exec {
        workspace: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long,default_value="5m",value_parser=humantime::parse_duration)]
        timeout: Duration,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}
#[derive(Subcommand)]
enum Network {
    Exec {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long,default_value="5m",value_parser=humantime::parse_duration)]
        timeout: Duration,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}
#[derive(Subcommand)]
enum Workspace {
    Create {
        workspace: String,
        #[arg(long)]
        workdir: PathBuf,
    },
    Show {
        workspace: String,
    },
    /// macOS: add the workspace loopback alias (requires sudo). Linux: start
    /// the process holding the workspace network namespace (no privilege).
    Setup {
        workspace: String,
    },
    /// Linux: stop the workspace namespace holder started by setup.
    Teardown {
        workspace: String,
    },
}

fn main() {
    // World must collect workload exit statuses; an ignored SIGCHLD
    // inherited from the launcher (e.g. `trap '' CHLD`) would discard them.
    #[cfg(unix)]
    // SAFETY: resets one signal disposition before any thread exists.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        // A blocked mask survives exec too; Tokio's worker threads inherit it.
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() { 125 } else { 0 };
            let _ = err.print();
            std::process::exit(code);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("world: start runtime: {err}");
            std::process::exit(125);
        }
    };
    std::process::exit(runtime.block_on(run(cli)));
}

async fn run(cli: Cli) -> i32 {
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal.cancel();
    });
    match execute(cli, cancel).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("world: {err:#}");
            125
        }
    }
}

async fn execute(cli: Cli, cancel: CancellationToken) -> Result<i32> {
    match cli.command {
        Commands::Network {
            command:
                Network::Exec {
                    policy,
                    workdir,
                    timeout,
                    command,
                },
        } => {
            let policy = Policy::read(std::fs::File::open(policy)?)?;
            run::run(
                RunOptions {
                    policy,
                    workdir,
                    timeout,
                    command,
                },
                cancel,
            )
            .await
        }
        Commands::Workspace { state_dir, command } => {
            let state = state_dir.map(Ok).unwrap_or_else(silo::default_state_dir)?;
            match command {
                Workspace::Create { workspace, workdir } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&silo::create(&state, &workspace, &workdir)?)?
                    );
                    Ok(0)
                }
                Workspace::Show { workspace } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&silo::get(&state, &workspace)?)?
                    );
                    Ok(0)
                }
                Workspace::Setup { workspace } => {
                    silo::setup(&state, &silo::get(&state, &workspace)?)?;
                    Ok(0)
                }
                Workspace::Teardown { workspace } => {
                    silo::teardown(&state, &silo::get(&state, &workspace)?)?;
                    Ok(0)
                }
            }
        }
        Commands::Exec {
            workspace,
            state_dir,
            timeout,
            command,
        } => {
            let state = state_dir.map(Ok).unwrap_or_else(silo::default_state_dir)?;
            let world = silo::get(&state, &workspace)?;
            silo::exec(&state, world, command, timeout, cancel).await
        }
    }
}
