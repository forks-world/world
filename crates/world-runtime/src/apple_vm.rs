//! Experimental macOS-host / Linux-world backend. A VM is not an egress policy.
//! Provider metadata is structured JSON; user argv never passes through a shell.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const IMAGE: &str = "docker.io/library/python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741";
const GUEST: &str = include_str!("../guest/supervisor.py");
const HELPER: &str = "/opt/world/supervisor.py";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vm {
    pub schema_version: u32,
    pub id: String,
    pub backend: String,
    pub execution_os: String,
    pub arch: String,
    pub instance_id: String,
    pub owner: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Record {
    Native(crate::silo::World),
    Vm(Vm),
}

pub(crate) fn records(state: &Path) -> Result<BTreeMap<String, Record>> {
    let file = match File::open(state.join("registry.json")) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    let records: BTreeMap<String, Record> =
        serde_json::from_reader(file).context("unsupported or corrupt workspace registry")?;
    for (id, value) in &records {
        if let Record::Vm(vm) = value {
            vm.validate(id)?;
        }
    }
    Ok(records)
}

pub fn get(state: &Path, id: &str) -> Result<Option<Vm>> {
    Ok(match records(state)?.remove(id) {
        Some(Record::Vm(vm)) => Some(vm),
        _ => None,
    })
}

fn random_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}
fn hex_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Vm {
    fn validate(&self, id: &str) -> Result<()> {
        ensure!(
            self.schema_version == 2
                && self.id == id
                && self.backend == "apple-container"
                && self.execution_os == "linux"
                && self.arch == "arm64",
            "invalid VM registry record"
        );
        ensure!(
            hex_id(&self.owner) && self.instance_id == format!("world-{}", self.owner),
            "invalid VM ownership"
        );
        ensure!(
            self.image == IMAGE
                && (1..=8).contains(&self.cpus)
                && (256..=4096).contains(&self.memory_mib),
            "unsupported VM configuration"
        );
        Ok(())
    }
}

pub fn supported() -> Result<()> {
    ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "Linux VM backend requires an Apple Silicon macOS host"
    );
    Ok(())
}

pub fn create(state: &Path, id: &str, cpus: u32, memory_mib: u32) -> Result<Vm> {
    supported()?;
    ensure!(
        !id.is_empty() && id.len() <= 128 && !id.contains(['\0', '\r', '\n']),
        "invalid workspace ID"
    );
    let _lock = crate::silo::lock(state)?;
    let mut records = records(state)?;
    if let Some(record) = records.get(id) {
        if let Record::Vm(vm) = record {
            ensure!(
                vm.cpus == cpus && vm.memory_mib == memory_mib,
                "workspace exists with different resources"
            );
            return Ok(vm.clone());
        }
        bail!("workspace already uses a native backend; create a new workspace to change OS");
    }
    let owner = random_id();
    let vm = Vm {
        schema_version: 2,
        id: id.into(),
        backend: "apple-container".into(),
        execution_os: "linux".into(),
        arch: "arm64".into(),
        instance_id: format!("world-{owner}"),
        owner,
        image: IMAGE.into(),
        cpus,
        memory_mib,
    };
    vm.validate(id)?;
    // Preserve a pre-VM registry for inspection; never restore it automatically.
    let backup = state.join("registry.before-vm.json");
    if state.join("registry.json").exists() && !backup.exists() {
        std::fs::copy(state.join("registry.json"), &backup)?;
        File::open(&backup)?.sync_all()?;
    }
    records.insert(id.into(), Record::Vm(vm.clone()));
    crate::silo::persist(state, "registry.json", &records)?;
    Ok(vm)
}

// Fail rather than block the async executor or race teardown against exec.
fn operation_lock(state: &Path, vm: &Vm, shared: bool) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join(format!("{}.lock", vm.instance_id)))?;
    if shared {
        FileExt::try_lock_shared(&file)
    } else {
        file.try_lock_exclusive()
    }.context("workspace busy with another lifecycle operation or execution; cancel active executions before teardown")?;
    Ok(file)
}

fn provider() -> Command {
    let mut cmd = Command::new("container");
    cmd.kill_on_drop(true);
    cmd
}

async fn output(args: &[&str], limit: Duration) -> Result<String> {
    let output = timeout(limit, provider().args(args).stdin(Stdio::null()).output())
        .await
        .context("container operation timed out; state must be inspected before retry")??;
    ensure!(
        output.status.success(),
        "container {} failed: {}{}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stdout).context("provider returned non-UTF8 metadata")
}

async fn check_provider() -> Result<()> {
    supported()?;
    let version = output(&["--version"], Duration::from_secs(10))
        .await
        .context("Apple container is missing; install container 1.6.1")?;
    ensure!(
        version.split_whitespace().any(|s| s == "1.6.1"),
        "unsupported container version; this experimental backend requires 1.6.1"
    );
    output(&["system", "status"], Duration::from_secs(10))
        .await
        .context("start Apple container with: container system start")?;
    Ok(())
}

async fn inspect(vm: &Vm) -> Result<Option<serde_json::Value>> {
    // A failed provider query is never interpreted as an absent VM.
    let all: Vec<serde_json::Value> = serde_json::from_str(
        &output(
            &["list", "--all", "--format", "json"],
            Duration::from_secs(15),
        )
        .await?,
    )?;
    let found = all
        .iter()
        .any(|v| v["id"].as_str() == Some(&vm.instance_id));
    if !found {
        return Ok(None);
    }
    let entries: Vec<serde_json::Value> = serde_json::from_str(
        &output(&["inspect", &vm.instance_id], Duration::from_secs(15)).await?,
    )?;
    let entry = entries.into_iter().next().context("empty inspect result")?;
    ensure!(
        entry["configuration"]["labels"]["world.owner"].as_str() == Some(&vm.owner),
        "VM ownership mismatch; refusing to use or stop instance"
    );
    ensure!(
        entry["configuration"]["image"]["reference"].as_str() == Some(&vm.image),
        "VM image mismatch"
    );
    Ok(Some(entry))
}

async fn guest(vm: &Vm, args: &[&str]) -> Result<String> {
    let mut argv = vec!["exec", &vm.instance_id, "python3", "-I", HELPER];
    argv.extend_from_slice(args);
    output(&argv, Duration::from_secs(15)).await
}

pub async fn show(vm: &Vm) -> Result<serde_json::Value> {
    let observation = async {
        check_provider().await?;
        inspect(vm).await
    }
    .await;
    let (observed, error) = match observation {
        Ok(value) => (value, None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(
        serde_json::json!({"configuration":vm,"observed":observed,"observation_error":error,"experimental":true,
        "capabilities":{"host_directory_mounts":false,"file_import":true,"egress_filtering":false,"host_lan_blocking":false,"worldfs":false,"pty":false,"parallel_exec":true},
        "network_policy":"provider NAT, unrestricted egress; not a hostile-workload sandbox"}),
    )
}

pub async fn setup(state: &Path, vm: &Vm) -> Result<()> {
    let _lock = operation_lock(state, vm, false)?;
    // Serialize VM admission across registries created by this user. A per-state
    // lock alone would allow two independent --state-dir values to race.
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required")?)
        .join(".local/share/world");
    std::fs::create_dir_all(&home)?;
    let admission = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(home.join("vm-admission.lock"))?;
    admission
        .try_lock_exclusive()
        .context("another VM setup is in progress")?;
    check_provider().await?;
    let current = inspect(vm).await?;
    let running = current
        .as_ref()
        .is_some_and(|v| v["status"]["state"] == "running");
    if !running {
        let all: Vec<serde_json::Value> = serde_json::from_str(
            &output(&["list", "--format", "json"], Duration::from_secs(15)).await?,
        )?;
        ensure!(
            all.is_empty(),
            "another container is running; experimental low-memory mode permits only one VM at a time"
        );
        if current.is_none() {
            let cpus = vm.cpus.to_string();
            let memory = format!("{}M", vm.memory_mib);
            let label = format!("world.owner={}", vm.owner);
            // Fixed bootstrap, never interpolated user data. Installed through
            // argv, not stdin (stdin belongs to future workloads).
            let bootstrap = "import os,pathlib,time; p=pathlib.Path('/opt/world'); p.mkdir(exist_ok=True); (p/'supervisor.py').write_text(__import__('sys').argv[1]); [(pathlib.Path(x).mkdir(parents=True,exist_ok=True),os.chown(x,1000,1000)) for x in ['/workspace','/home/world']]; time.sleep(2147483647)";
            output(
                &[
                    "create",
                    "--name",
                    &vm.instance_id,
                    "--cpus",
                    &cpus,
                    "--memory",
                    &memory,
                    "--label",
                    &label,
                    &vm.image,
                    "python3",
                    "-I",
                    "-c",
                    bootstrap,
                    GUEST,
                ],
                Duration::from_secs(180),
            )
            .await?;
        }
        output(&["start", &vm.instance_id], Duration::from_secs(60)).await?;
    }
    let install = "import os,pathlib,sys; p=pathlib.Path('/opt/world'); p.mkdir(exist_ok=True); t=p/'supervisor.py.update'; t.write_text(sys.argv[1]); os.chmod(t,0o644); os.replace(t,p/'supervisor.py')";
    output(
        &[
            "exec",
            &vm.instance_id,
            "python3",
            "-I",
            "-c",
            install,
            GUEST,
        ],
        Duration::from_secs(15),
    )
    .await?;
    let mut last = None;
    for _ in 0..20 {
        match guest(vm, &["probe"]).await {
            Ok(data) => {
                let probe: serde_json::Value = serde_json::from_str(&data)?;
                ensure!(
                    probe["protocol"] == 1 && probe["uid"] == 0 && probe["cgroup_kill"] == true,
                    "guest protocol/capability mismatch"
                );
                eprintln!(
                    "world: experimental Linux VM ready; no host mounts; NAT egress is unrestricted"
                );
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "guest readiness failed (VM preserved for inspection): {}",
        last.unwrap()
    );
}

pub async fn teardown(state: &Path, vm: &Vm) -> Result<()> {
    let _lock = operation_lock(state, vm, false)?;
    check_provider().await?;
    if inspect(vm)
        .await?
        .is_some_and(|v| v["status"]["state"] == "running")
    {
        output(
            &["stop", "--time", "2", &vm.instance_id],
            Duration::from_secs(20),
        )
        .await?;
    }
    Ok(())
}

pub async fn exec(
    state: &Path,
    vm: &Vm,
    command: Vec<OsString>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<i32> {
    crate::run::validate_command(&command, duration)?;
    ensure!(
        duration.as_secs_f64() <= 86400.0,
        "VM execution timeout cannot exceed 24 hours"
    );
    let _lock = operation_lock(state, vm, true)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running; run world workspace setup first"
    );
    let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
    ensure!(probe["protocol"] == 1, "guest protocol mismatch");
    if cancel.is_cancelled() {
        return Ok(124);
    }
    let token = random_id();
    let seconds = duration.as_secs_f64().to_string();
    eprintln!("world: execution {token} (Linux VM; unrestricted NAT egress)");
    let mut child = provider()
        .args([
            "exec",
            "-i",
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "run",
            &token,
            &seconds,
        ])
        .args(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = tokio::select! {
        result = child.wait() => Some(result?),
        _ = cancel.cancelled() => None,
        _ = sleep(duration + Duration::from_secs(10)) => None,
    };
    if status.is_none() {
        guest(vm, &["cancel", &token]).await.context("guest cancellation not confirmed; execution may still be running until its guest deadline")?;
        match timeout(Duration::from_secs(10), child.wait()).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                child.kill().await?;
                bail!("execution status unknown after cancellation; VM preserved");
            }
        }
    }
    let result: serde_json::Value = serde_json::from_str(&guest(vm, &["status", &token]).await?)?;
    match result["state"].as_str() {
        Some("exited" | "timed_out" | "cancelled") => Ok(result["exit_code"]
            .as_i64()
            .context("missing guest exit code")?
            as i32),
        _ => bail!("execution {token} did not complete successfully: {result}"),
    }
}

/// Copy a completed host snapshot into an empty guest workspace. The exclusive
/// lifecycle lock prevents commands from racing extraction/publication.
pub async fn import(
    state: &Path,
    vm: &Vm,
    source: &Path,
    cancel: CancellationToken,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, false)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running; run world workspace setup first"
    );
    let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
    ensure!(
        probe["import_protocol"] == 1,
        "guest lacks import support; run workspace setup to update helper"
    );
    let source = source.to_path_buf();
    let snapshot =
        tokio::task::spawn_blocking(move || crate::import_stream::snapshot(&source)).await??;
    ensure!(
        !cancel.is_cancelled(),
        "import cancelled before transfer; workspace unchanged"
    );
    let input = File::open(snapshot.path())?;
    let child = provider()
        .args([
            "exec",
            "-i",
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "import",
        ])
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Once streaming starts, allow it to reach a definite result. Dropping an
    // exec client cannot prove that the guest has not already committed.
    let output = timeout(Duration::from_secs(600), child.wait_with_output())
        .await
        .context(
            "import result unknown after transfer timeout; inspect /workspace before retrying",
        )??;
    ensure!(
        output.status.success(),
        "import failed (inspect workspace if connection was interrupted): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        result["state"] == "imported",
        "unexpected guest import result"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_future_schema_instead_of_falling_back() {
        let state = tempfile::tempdir().unwrap();
        let owner = "a".repeat(32);
        let vm = Vm {
            schema_version: 99,
            id: "vm".into(),
            backend: "apple-container".into(),
            execution_os: "linux".into(),
            arch: "arm64".into(),
            instance_id: format!("world-{owner}"),
            owner,
            image: IMAGE.into(),
            cpus: 1,
            memory_mib: 256,
        };
        crate::silo::persist(
            state.path(),
            "registry.json",
            &BTreeMap::from([("vm", Record::Vm(vm))]),
        )
        .unwrap();
        assert!(get(state.path(), "vm").is_err());
        assert!(crate::silo::get(state.path(), "native").is_err());
    }
}
