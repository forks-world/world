use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use world_runtime::{
    apple_vm,
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
    /// List local workspace registrations, including unavailable VM runtimes.
    List,
    /// Remove a stopped VM workspace. Does not delete a forkfs branch.
    Delete {
        workspace: String,
        /// Permanently delete data in the VM writable layer.
        #[arg(long)]
        discard_runtime_data: bool,
    },
    Create {
        workspace: String,
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Execution OS. Omitted means native; macOS + linux uses an experimental VM.
        #[arg(long, value_parser = ["linux", "macos"])]
        os: Option<String>,
        #[arg(long)]
        cpus: Option<u32>,
        /// VM workload memory limit, e.g. 256M, 512M or 1G.
        #[arg(long, value_parser = parse_memory)]
        memory: Option<u32>,
    },
    Show {
        workspace: String,
    },
    /// Copy a host directory into an empty Linux VM /workspace.
    Import {
        workspace: String,
        #[arg(long)]
        source: PathBuf,
    },
    /// macOS: add the workspace loopback alias (requires sudo). Linux: start
    /// the process holding the workspace network namespace (no privilege).
    Setup {
        workspace: String,
        /// Explicitly recreate an absent VM with an empty writable layer.
        #[arg(long)]
        recreate_missing: bool,
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
                Workspace::List => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&apple_vm::list(&state).await?)?
                    );
                    Ok(0)
                }
                Workspace::Delete {
                    workspace,
                    discard_runtime_data,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("delete currently supports Linux VM workspaces only; native workspaces are unchanged")?;
                    apple_vm::delete(&state, &vm, discard_runtime_data).await?;
                    Ok(0)
                }
                Workspace::Create {
                    workspace,
                    workdir,
                    os,
                    cpus,
                    memory,
                } => {
                    let requested = os.as_deref().unwrap_or(std::env::consts::OS);
                    let vm = requested == "linux" && std::env::consts::OS == "macos";
                    if vm {
                        anyhow::ensure!(
                            workdir.is_none(),
                            "Linux VM uses /workspace; --workdir is only for native workspaces (use workspace import after setup)"
                        );
                        let record = apple_vm::create(
                            &state,
                            &workspace,
                            cpus.unwrap_or(1),
                            memory.unwrap_or(512),
                        )?;
                        println!("{}", serde_json::to_string_pretty(&record)?);
                    } else {
                        anyhow::ensure!(
                            requested == std::env::consts::OS,
                            "unsupported host/execution OS combination"
                        );
                        anyhow::ensure!(
                            cpus.is_none() && memory.is_none(),
                            "resource flags currently require the Linux VM backend"
                        );
                        let workdir = workdir.context("native workspace requires --workdir")?;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&silo::create(
                                &state, &workspace, &workdir
                            )?)?
                        );
                    }
                    Ok(0)
                }
                Workspace::Import { workspace, source } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("import requires a Linux VM workspace")?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &apple_vm::import(&state, &vm, &source, cancel).await?
                        )?
                    );
                    Ok(0)
                }
                Workspace::Show { workspace } => {
                    if let Some(vm) = apple_vm::get(&state, &workspace)? {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&apple_vm::show(&state, &vm).await?)?
                        );
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&silo::get(&state, &workspace)?)?
                        );
                    }
                    Ok(0)
                }
                Workspace::Setup {
                    workspace,
                    recreate_missing,
                } => {
                    if let Some(vm) = apple_vm::get(&state, &workspace)? {
                        apple_vm::setup(&state, &vm, recreate_missing).await?;
                    } else {
                        anyhow::ensure!(
                            !recreate_missing,
                            "--recreate-missing requires a Linux VM workspace"
                        );
                        silo::setup(&state, &silo::get(&state, &workspace)?)?;
                    }
                    Ok(0)
                }
                Workspace::Teardown { workspace } => {
                    if let Some(vm) = apple_vm::get(&state, &workspace)? {
                        apple_vm::teardown(&state, &vm).await?;
                    } else {
                        silo::teardown(&state, &silo::get(&state, &workspace)?)?;
                    }
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
            if let Some(vm) = apple_vm::get(&state, &workspace)? {
                apple_vm::exec(&state, &vm, command, timeout, cancel).await
            } else {
                let world = silo::get(&state, &workspace)?;
                silo::exec(&state, world, command, timeout, cancel).await
            }
        }
    }
}

fn parse_memory(input: &str) -> Result<u32, String> {
    let (number, multiplier) = if let Some(value) = input.strip_suffix('M') {
        (value, 1)
    } else if let Some(value) = input.strip_suffix('G') {
        (value, 1024)
    } else {
        return Err("memory requires M or G suffix, e.g. 256M".into());
    };
    number
        .parse::<u32>()
        .ok()
        .and_then(|v| v.checked_mul(multiplier))
        .filter(|v| (256..=4096).contains(v))
        .ok_or_else(|| "memory must be between 256M and 4G".into())
}
