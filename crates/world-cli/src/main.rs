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
    Silo {
        #[arg(long, global = true)]
        state_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: Silo,
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
enum Silo {
    Create {
        #[arg(long)]
        world: String,
        #[arg(long)]
        workdir: PathBuf,
    },
    Inspect {
        #[arg(long)]
        world: String,
    },
    Setup {
        #[arg(long)]
        world: String,
    },
    /// Linux: stop the World namespace holder started by setup.
    Teardown {
        #[arg(long)]
        world: String,
    },
    /// Internal: keeps a Linux World namespace alive.
    #[command(hide = true)]
    Hold,
    Exec {
        #[arg(long)]
        world: String,
        #[arg(long,default_value="5m",value_parser=humantime::parse_duration)]
        timeout: Duration,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() { 125 } else { 0 };
            let _ = err.print();
            std::process::exit(code);
        }
    };
    // The namespace holder keeps default signal dispositions: plain kill stops it.
    #[cfg(target_os = "linux")]
    if let Commands::Silo {
        command: Silo::Hold,
        ..
    } = cli.command
    {
        // Before any runtime exists: the holder stays a single thread.
        world_runtime::linux::hold();
    }
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
    let code = match execute(cli, cancel).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("world: {err:#}");
            125
        }
    };
    code
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
        Commands::Silo { state_dir, command } => {
            let state = state_dir.map(Ok).unwrap_or_else(silo::default_state_dir)?;
            match command {
                Silo::Create { world, workdir } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&silo::create(&state, &world, &workdir)?)?
                    );
                    Ok(0)
                }
                Silo::Inspect { world } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&silo::inspect(&state, &world)?)?
                    );
                    Ok(0)
                }
                Silo::Setup { world } => {
                    silo::setup(&state, &silo::inspect(&state, &world)?)?;
                    Ok(0)
                }
                Silo::Teardown { world } => {
                    silo::teardown(&state, &silo::inspect(&state, &world)?)?;
                    Ok(0)
                }
                Silo::Hold => anyhow::bail!("hold is internal to Linux silo setup"),
                Silo::Exec {
                    world,
                    timeout,
                    command,
                } => {
                    let world = silo::inspect(&state, &world)?;
                    silo::exec(&state, world, command, timeout, cancel).await
                }
            }
        }
    }
}
