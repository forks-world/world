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
    #[command(name = "__port-worker", hide = true)]
    PortWorker {
        state: PathBuf,
        workspace: String,
        spec: String,
    },
    #[command(name = "__forkfs-worker", hide = true)]
    ForkfsWorker {
        state: PathBuf,
        workspace: String,
        boot_id: String,
    },
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
    /// Manage persistent services inside a Linux VM workspace.
    Service {
        #[arg(long, global = true)]
        state_dir: Option<PathBuf>,
        /// Retry a write using the operation ID printed by the first attempt.
        #[arg(long, global = true)]
        request_id: Option<String>,
        #[command(subcommand)]
        command: Service,
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
enum Service {
    Publish {
        workspace: String,
        service: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        host_port: u16,
        #[arg(long)]
        target_port: u16,
    },
    Unpublish {
        workspace: String,
        service: String,
        #[arg(long)]
        name: String,
    },
    Ports {
        workspace: String,
        service: String,
    },
    Operation {
        workspace: String,
        id: String,
    },
    Start {
        workspace: String,
        name: String,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    List {
        workspace: String,
    },
    Show {
        workspace: String,
        name: String,
    },
    Stop {
        workspace: String,
        name: String,
    },
    Restart {
        workspace: String,
        name: String,
    },
    Remove {
        workspace: String,
        name: String,
    },
    /// Return the last 64 KiB of a log stream in JSON as base64.
    Logs {
        workspace: String,
        name: String,
        #[arg(long, default_value = "stdout", value_parser = ["stdout", "stderr"])]
        stream: String,
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
        /// Host Unix socket of a running forkfsd daemon.
        #[arg(long, requires_all = ["forkfs_repository", "forkfs_branch"])]
        forkfs_socket: Option<PathBuf>,
        /// Expected repository ID reported by forkfsd.
        #[arg(long, requires = "forkfs_socket")]
        forkfs_repository: Option<String>,
        /// Existing mutable branch to lease for /workspace.
        #[arg(long, requires = "forkfs_socket")]
        forkfs_branch: Option<String>,
    },
    Show {
        workspace: String,
    },
    /// Save a named checkpoint of a stopped forkfs-backed workspace.
    Checkpoint {
        workspace: String,
        name: String,
    },
    /// Compare two named checkpoints in the forkfs repository.
    Diff {
        workspace: String,
        before: String,
        after: String,
        /// Resume after the path in the previous page's next_after field.
        #[arg(long, default_value = "")]
        after_path: String,
        #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u8).range(1..=64))]
        limit: u8,
    },
    /// Create a storage branch from a checkpoint in the same repository.
    Fork {
        workspace: String,
        revision: String,
        branch: String,
    },
    /// Preview a three-way merge, or apply it to a stopped forkfs workspace.
    Merge {
        workspace: String,
        base: String,
        source: String,
        /// Apply the exact target and checkpoints identified by this token.
        #[arg(long)]
        expect_token: Option<String>,
    },
    /// Preview a forkfs branch discard, or confirm it with the preview token.
    Discard {
        workspace: String,
        /// Confirm removal of the exact branch state named by this token.
        #[arg(long)]
        expect_token: Option<String>,
    },
    /// Copy a host directory into an empty Linux VM /workspace.
    Import {
        workspace: String,
        #[arg(long)]
        source: PathBuf,
    },
    /// Copy a Linux VM workspace into a new host directory.
    Export {
        workspace: String,
        #[arg(long)]
        destination: PathBuf,
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
        Commands::ForkfsWorker {
            state,
            workspace,
            boot_id,
        } => {
            if let Err(error) = apple_vm::forkfs_worker(&state, &workspace, &boot_id, cancel).await
            {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stdout(),
                    "{}",
                    serde_json::json!({"error":format!("{error:#}")})
                );
                return Ok(125);
            }
            Ok(0)
        }
        Commands::PortWorker {
            state,
            workspace,
            spec,
        } => {
            if let Err(error) = apple_vm::port_worker(&state, &workspace, &spec, cancel).await {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stdout(),
                    "{}",
                    serde_json::json!({"error":format!("{error:#}")})
                );
                return Ok(125);
            }
            Ok(0)
        }
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
                    forkfs_socket,
                    forkfs_repository,
                    forkfs_branch,
                } => {
                    let forkfs = match (forkfs_socket, forkfs_repository, forkfs_branch) {
                        (Some(socket), Some(repository), Some(branch)) => {
                            Some(apple_vm::ForkfsBinding {
                                socket: std::path::absolute(socket)?,
                                repository,
                                branch,
                            })
                        }
                        (None, None, None) => None,
                        _ => anyhow::bail!("forkfs requires socket, repository ID, and branch"),
                    };
                    let requested = os.as_deref().unwrap_or(std::env::consts::OS);
                    let vm = requested == "linux" && std::env::consts::OS == "macos";
                    if vm {
                        anyhow::ensure!(
                            workdir.is_none(),
                            "Linux VM uses /workspace; --workdir is only for native workspaces (use workspace import after setup)"
                        );
                        let record = apple_vm::create_with_storage(
                            &state,
                            &workspace,
                            cpus.unwrap_or(1),
                            memory.unwrap_or(512),
                            forkfs,
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
                        anyhow::ensure!(
                            forkfs.is_none(),
                            "forkfs requires the macOS Linux VM backend"
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
                Workspace::Checkpoint { workspace, name } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("checkpoint requires a forkfs-backed workspace")?;
                    let result = apple_vm::checkpoint(&state, &vm, &name).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(0)
                }
                Workspace::Diff {
                    workspace,
                    before,
                    after,
                    after_path,
                    limit,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("diff requires a forkfs-backed workspace")?;
                    let result =
                        apple_vm::diff(&state, &vm, &before, &after, &after_path, limit).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(0)
                }
                Workspace::Fork {
                    workspace,
                    revision,
                    branch,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("fork requires a forkfs-backed workspace")?;
                    let result = apple_vm::fork(&state, &vm, &revision, &branch).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(0)
                }
                Workspace::Merge {
                    workspace,
                    base,
                    source,
                    expect_token,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("merge requires a forkfs-backed workspace")?;
                    let result =
                        apple_vm::merge(&state, &vm, &base, &source, expect_token.as_deref())
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(i32::from(
                        expect_token.is_some() && result["state"] == "conflict",
                    ))
                }
                Workspace::Discard {
                    workspace,
                    expect_token,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("discard requires a forkfs-backed workspace")?;
                    let result = apple_vm::discard(&state, &vm, expect_token.as_deref()).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
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
                Workspace::Export {
                    workspace,
                    destination,
                } => {
                    let vm = apple_vm::get(&state, &workspace)?
                        .context("export requires a Linux VM workspace")?;
                    let result = apple_vm::export(&state, &vm, &destination, cancel).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
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
        Commands::Service {
            state_dir,
            request_id,
            command,
        } => {
            use serde_json::json;

            let state = state_dir.map(Ok).unwrap_or_else(silo::default_state_dir)?;
            let vm_for = |workspace: &str| {
                apple_vm::get(&state, workspace)?.context("service requires a Linux VM workspace")
            };
            let command = match command {
                Service::Publish {
                    workspace,
                    service,
                    name,
                    host_port,
                    target_port,
                } => {
                    anyhow::ensure!(
                        request_id.is_none(),
                        "--request-id is not supported for ports"
                    );
                    let vm = vm_for(&workspace)?;
                    let result =
                        apple_vm::publish(&state, &vm, service, name, host_port, target_port)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    return Ok(0);
                }
                Service::Unpublish {
                    workspace,
                    service,
                    name,
                } => {
                    anyhow::ensure!(
                        request_id.is_none(),
                        "--request-id is not supported for ports"
                    );
                    apple_vm::unpublish(&state, &vm_for(&workspace)?, &service, &name).await?;
                    return Ok(0);
                }
                Service::Ports { workspace, service } => {
                    anyhow::ensure!(
                        request_id.is_none(),
                        "--request-id is not supported for ports"
                    );
                    let result =
                        apple_vm::service_ports(&state, &vm_for(&workspace)?, &service).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    return Ok(0);
                }
                other => other,
            };
            let (workspace, request) = match command {
                Service::Start {
                    workspace,
                    name,
                    argv,
                } => (
                    workspace,
                    json!({"action": "start", "name": name, "argv": argv}),
                ),
                Service::Operation { workspace, id } => (
                    workspace,
                    json!({"action": "operation", "operation_id": id}),
                ),
                Service::List { workspace } => (workspace, json!({"action": "list"})),
                Service::Show { workspace, name } => {
                    (workspace, json!({"action": "show", "name": name}))
                }
                Service::Stop { workspace, name } => {
                    (workspace, json!({"action": "stop", "name": name}))
                }
                Service::Restart { workspace, name } => {
                    (workspace, json!({"action": "restart", "name": name}))
                }
                Service::Remove { workspace, name } => {
                    (workspace, json!({"action": "remove", "name": name}))
                }
                Service::Logs {
                    workspace,
                    name,
                    stream,
                } => (
                    workspace,
                    json!({"action": "logs", "name": name, "stream": stream}),
                ),
                Service::Publish { .. } | Service::Unpublish { .. } | Service::Ports { .. } => {
                    unreachable!()
                }
            };
            let vm = vm_for(&workspace)?;
            let response = apple_vm::service(&state, &vm, request, request_id).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(0)
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
