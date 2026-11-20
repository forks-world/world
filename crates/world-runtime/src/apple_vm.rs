//! Experimental macOS-host / Linux-world backend. A VM is not an egress policy.
//! Provider metadata is structured JSON; user argv never passes through a shell.
use crate::forkfs_mount;
pub use crate::forkfs_mount::Binding as ForkfsBinding;
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
    io::AsyncReadExt,
    process::Command,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const IMAGE: &str = "docker.io/library/python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741";
const PROVIDER_VERSIONS: &[&str] = &["1.6.1", "1.7.1"];
const GUEST: &str = concat!(
    include_str!("../guest/supervisor.py"),
    "\n",
    include_str!("../guest/export.py"),
    "\n",
    include_str!("../guest/port_bridge.py"),
    "\n",
    include_str!("../guest/services.py")
);
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forkfs: Option<ForkfsBinding>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Created,
    Provisioning,
    Starting,
    Ready,
    Stopping,
    Stopped,
    Deleting,
    Discarding,
    Discarded,
    Legacy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifecycle {
    owner: String,
    phase: Phase,
    generation: u64,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discard_token: Option<String>,
}

fn lifecycle(state: &Path, vm: &Vm) -> Result<Lifecycle> {
    match File::open(state.join(format!("{}.runtime.json", vm.instance_id))) {
        Ok(file) => {
            let value: Lifecycle =
                serde_json::from_reader(file).context("invalid VM lifecycle journal")?;
            ensure!(value.owner == vm.owner, "lifecycle owner mismatch");
            Ok(value)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Lifecycle {
            owner: vm.owner.clone(),
            phase: Phase::Legacy,
            generation: 0,
            boot_id: None,
            discard_token: None,
        }),
        Err(error) => Err(error.into()),
    }
}

fn save_lifecycle(state: &Path, vm: &Vm, lifecycle: &Lifecycle) -> Result<()> {
    crate::silo::persist(
        state,
        &format!("{}.runtime.json", vm.instance_id),
        lifecycle,
    )
}

fn check_registered(state: &Path, vm: &Vm) -> Result<()> {
    ensure!(
        get(state, &vm.id)?.is_some_and(|current| current.owner == vm.owner),
        "workspace was deleted or replaced; reload its configuration"
    );
    Ok(())
}

fn require_storage_retained(journal: &Lifecycle) -> Result<()> {
    ensure!(
        !matches!(journal.phase, Phase::Discarding | Phase::Discarded),
        "workspace discard is pending or complete; use workspace show to inspect its status"
    );
    Ok(())
}

fn require_ready(state: &Path, vm: &Vm) -> Result<String> {
    let journal = lifecycle(state, vm)?;
    ensure!(
        journal.phase == Phase::Ready,
        "workspace is not ready; run workspace show and workspace setup first"
    );
    journal
        .boot_id
        .context("VM boot is unverified; run workspace setup first")
}

/// Local records are returned even when the provider cannot be contacted.
pub async fn list(state: &Path) -> Result<Vec<serde_json::Value>> {
    let mut result = Vec::new();
    for (id, record) in records(state)? {
        match record {
            Record::Vm(vm) => result.push(show(state, &vm).await?),
            Record::Native(world) => result.push(serde_json::json!({
                "id":id, "configuration":world, "backend":"native",
                "status":"unobserved", "note":"native runtime state is not probed by list"
            })),
        }
    }
    Ok(result)
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
        if let Some(binding) = &self.forkfs {
            binding.validate()?;
        }
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
    create_with_storage(state, id, cpus, memory_mib, None)
}

pub fn create_with_storage(
    state: &Path,
    id: &str,
    cpus: u32,
    memory_mib: u32,
    forkfs: Option<ForkfsBinding>,
) -> Result<Vm> {
    supported()?;
    ensure!(
        !id.is_empty() && id.len() <= 128 && !id.contains(['\0', '\r', '\n']),
        "invalid workspace ID"
    );
    let _lock = crate::silo::lock(state)?;
    let mut records = records(state)?;
    if let Some(record) = records.get(id) {
        if let Record::Vm(vm) = record {
            let journal = lifecycle(state, vm)?;
            require_storage_retained(&journal)?;
            ensure!(
                journal.phase != Phase::Deleting,
                "workspace deletion is pending; retry workspace delete before reusing the name"
            );
            ensure!(
                vm.cpus == cpus && vm.memory_mib == memory_mib,
                "workspace exists with different resources"
            );
            ensure!(
                vm.forkfs == forkfs,
                "workspace exists with a different storage binding"
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
        forkfs,
    };
    vm.validate(id)?;
    // Preserve a pre-VM registry for inspection; never restore it automatically.
    let backup = state.join("registry.before-vm.json");
    if state.join("registry.json").exists() && !backup.exists() {
        std::fs::copy(state.join("registry.json"), &backup)?;
        File::open(&backup)?.sync_all()?;
    }
    save_lifecycle(
        state,
        &vm,
        &Lifecycle {
            owner: vm.owner.clone(),
            phase: Phase::Created,
            generation: 0,
            boot_id: None,
            discard_token: None,
        },
    )?;
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
        .context(
            "cannot query Apple container version; check that container is installed and on PATH",
        )?;
    ensure!(
        version
            .split_whitespace()
            .any(|s| PROVIDER_VERSIONS.contains(&s)),
        "unsupported Apple container version: {}; supported versions: {}",
        version.trim(),
        PROVIDER_VERSIONS.join(", ")
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

async fn forkfs_guest(vm: &Vm, boot_id: &str, mode: &str) -> Result<String> {
    output(
        &[
            "exec",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            mode,
        ],
        Duration::from_secs(10),
    )
    .await
}

async fn require_storage(vm: &Vm, boot_id: &str) -> Result<()> {
    if vm.forkfs.is_some() {
        let result = forkfs_guest(vm, boot_id, "forkfs-check")
            .await
            .context("storage_unavailable: cannot verify forkfs /workspace; run workspace show")?;
        ensure!(
            result.trim() == "mounted",
            "storage_unavailable: invalid forkfs mount response"
        );
    }
    Ok(())
}

#[doc(hidden)]
pub async fn forkfs_worker(
    state: &Path,
    workspace: &str,
    boot_id: &str,
    cancel: CancellationToken,
) -> Result<()> {
    let vm = get(state, workspace)?.context("workspace missing for forkfs worker")?;
    let binding = vm
        .forkfs
        .as_ref()
        .context("workspace has no forkfs binding")?;
    let mut guest = provider();
    guest
        .args([
            "exec",
            "-i",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            "-e",
            &format!("WORLD_FORKFS_SOURCE=world-forkfs-{}", vm.owner),
            &vm.instance_id,
            "python3",
            "-I",
            "-u",
            "-c",
            forkfs_mount::GUEST,
        ])
        .stderr(Stdio::inherit());
    forkfs_mount::worker(state, &vm.instance_id, binding, guest, cancel).await
}

async fn guest_service(
    vm: &Vm,
    boot_id: &str,
    request: serde_json::Value,
) -> Result<serde_json::Value> {
    let request = serde_json::to_string(&request)?;
    ensure!(
        request.len() <= 64 * 1024,
        "service request exceeds size limit"
    );
    let response = output(
        &[
            "exec",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "service",
            &request,
        ],
        Duration::from_secs(15),
    )
    .await?;
    Ok(serde_json::from_str(&response)?)
}

fn publication_operation_lock(state: &Path, vm: &Vm) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join(format!("{}.publication.lock", vm.instance_id)))?;
    lock.try_lock_exclusive()
        .context("another service or publication operation is in progress")?;
    Ok(lock)
}

fn publication_json(publication: crate::port_publish::Publication) -> serde_json::Value {
    serde_json::json!({
        "state": "active",
        "name": publication.name,
        "service": publication.service,
        "run_id": publication.run_id,
        "host_address": "127.0.0.1",
        "host_port": publication.host_port,
        "target_address": "127.0.0.1",
        "target_port": publication.target_port,
    })
}

pub async fn service_ports(state: &Path, vm: &Vm, service: &str) -> Result<Vec<serde_json::Value>> {
    let _workspace = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    Ok(crate::port_publish::control(&vm.owner, b"?")
        .await?
        .filter(|publication| publication.service == service)
        .map(publication_json)
        .into_iter()
        .collect())
}

pub async fn unpublish(state: &Path, vm: &Vm, service: &str, name: &str) -> Result<()> {
    let _workspace = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    let _operation = publication_operation_lock(state, vm)?;
    if crate::port_publish::control(&vm.owner, b"?")
        .await?
        .is_some_and(|publication| publication.service == service && publication.name == name)
    {
        crate::port_publish::control(&vm.owner, b"q").await?;
    }
    Ok(())
}

pub async fn publish(
    state: &Path,
    vm: &Vm,
    service: String,
    name: String,
    host_port: u16,
    target_port: u16,
) -> Result<serde_json::Value> {
    ensure!(
        (1024..).contains(&host_port) && target_port != 0,
        "invalid publication port"
    );
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
        "invalid publication name"
    );
    let _workspace = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    let _operation = publication_operation_lock(state, vm)?;
    let boot_id = require_ready(state, vm)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running"
    );
    require_storage(vm, &boot_id).await?;
    let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
    ensure!(
        probe["port_protocol"] == 1,
        "guest lacks TCP publishing support; run workspace setup first"
    );
    let capabilities = guest_service(vm, &boot_id, serde_json::json!({
        "action": "publication-capabilities",
    })).await.context("cannot verify TCP publishing support in the running service supervisor; stop the VM with workspace teardown and run workspace setup")?;
    ensure!(
        capabilities["port_protocol"] == 1,
        "running service supervisor lacks TCP publishing support; stop the VM with workspace teardown and run workspace setup"
    );
    let status = guest_service(
        vm,
        &boot_id,
        serde_json::json!({"action":"show","name":service}),
    )
    .await?;
    ensure!(status["state"] == "running", "service is not running");
    let run_id = status["run_id"]
        .as_str()
        .filter(|id| hex_id(id))
        .context("invalid service run ID")?;
    let publication = crate::port_publish::Publication {
        service,
        name,
        run_id: run_id.into(),
        host_port,
        target_port,
    };
    if let Some(active) = crate::port_publish::control(&vm.owner, b"?").await? {
        ensure!(
            active == publication,
            "a different publication is active; unpublish it first"
        );
    } else {
        crate::port_publish::launch(&std::env::current_exe()?, state, &vm.id, &publication).await?;
    }
    Ok(publication_json(publication))
}

#[doc(hidden)]
pub async fn port_worker(
    state: &Path,
    workspace: &str,
    spec: &str,
    cancel: CancellationToken,
) -> Result<()> {
    let vm = get(state, workspace)?.context("publication requires a Linux VM workspace")?;
    let boot_id = require_ready(state, &vm)?;
    let publication: crate::port_publish::Publication = serde_json::from_str(spec)?;
    check_provider().await?;
    ensure!(
        inspect(&vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running"
    );
    ensure!(
        publication.host_port >= 1024 && publication.target_port != 0,
        "invalid publication port"
    );
    require_storage(&vm, &boot_id).await?;
    let bridge = provider()
        .args([
            "exec",
            "-i",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "port-bridge",
            &publication.service,
            &publication.run_id,
            &publication.target_port.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    crate::port_publish::broker(&vm.owner, publication, bridge, cancel).await
}

pub async fn service(
    state: &Path,
    vm: &Vm,
    mut request: serde_json::Value,
    request_id: Option<String>,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    let boot_id = require_ready(state, vm)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running; run workspace setup first"
    );
    let action = request["action"]
        .as_str()
        .context("missing service action")?
        .to_owned();
    if matches!(action.as_str(), "start" | "restart") {
        require_storage(vm, &boot_id).await?;
    }
    let writes = matches!(action.as_str(), "start" | "stop" | "restart" | "remove");
    let _publication = writes
        .then(|| publication_operation_lock(state, vm))
        .transpose()?;
    let service = request["name"].as_str().map(str::to_owned);
    if writes {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let id = request_id.unwrap_or_else(|| format!("{now}-{}", random_id()));
        ensure!(
            id.split_once('-').is_some_and(|(issued, token)| {
                !issued.is_empty()
                    && issued.len() <= 12
                    && issued.bytes().all(|c| c.is_ascii_digit())
                    && hex_id(token)
                    && token.bytes().all(|c| !c.is_ascii_uppercase())
            }),
            "invalid service operation ID"
        );
        eprintln!("world: service operation {id}");
        request["operation_id"] = id.into();
    } else {
        ensure!(
            request_id.is_none(),
            "--request-id requires a service write operation"
        );
    }
    if matches!(action.as_str(), "start" | "stop" | "restart")
        && let Some(active) = crate::port_publish::control(&vm.owner, b"?").await?
        && service.as_deref() == Some(active.service.as_str())
    {
        // A retry returns its historical result. It must leave any publication
        // created since that result untouched.
        let cache = guest_service(
            vm,
            &boot_id,
            serde_json::json!({
                "action": "operation-known", "operation_id": request["operation_id"],
            }),
        )
        .await?;
        let known = cache["known"]
            .as_bool()
            .context("invalid operation cache response")?;
        if !known {
            let retains_run = if action == "start" {
                let current = guest_service(
                    vm,
                    &boot_id,
                    serde_json::json!({
                        "action": "show", "name": active.service,
                    }),
                )
                .await?;
                current["state"] == "running" && current["run_id"] == active.run_id
            } else {
                false
            };
            if retains_run {
                request["retain_run_id"] = active.run_id.into();
            } else {
                crate::port_publish::control(&vm.owner, b"q").await?;
            }
        }
    }
    let mut result = guest_service(vm, &boot_id, request).await?;
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "observed_generation".into(),
            lifecycle(state, vm)?.generation.into(),
        );
    }
    Ok(result)
}

async fn start_service_supervisor(vm: &Vm, boot_id: &str) -> Result<()> {
    if guest_service(vm, boot_id, serde_json::json!({"action": "list"}))
        .await
        .is_ok()
    {
        return Ok(());
    }
    output(
        &[
            "exec",
            "--detach",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "service-daemon",
        ],
        Duration::from_secs(15),
    )
    .await?;
    let mut last = None;
    for _ in 0..20 {
        match guest_service(vm, boot_id, serde_json::json!({"action": "list"})).await {
            Ok(_) => return Ok(()),
            Err(error) => last = Some(error),
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(last.unwrap()).context("guest service supervisor did not become ready")
}

pub async fn show(state: &Path, vm: &Vm) -> Result<serde_json::Value> {
    let journal = lifecycle(state, vm)?;
    let observation = async {
        check_provider().await?;
        inspect(vm).await
    }
    .await;
    let (observed, error) = match observation {
        Ok(value) => (value, None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    let mut error = error;
    let status = if journal.phase == Phase::Discarded {
        "discarded"
    } else if journal.phase == Phase::Discarding {
        "discarding"
    } else if error.is_some() {
        "unknown"
    } else if journal.phase == Phase::Deleting {
        "deleting"
    } else if let Some(value) = &observed {
        match value["status"]["state"].as_str() {
            Some("running") if journal.phase == Phase::Ready && journal.boot_id.is_some() => {
                match guest(vm, &["boot-id"]).await {
                    Ok(boot_id) if journal.boot_id.as_deref() == Some(boot_id.trim()) => {
                        match require_storage(vm, boot_id.trim()).await {
                            Ok(()) => "ready",
                            Err(cause) => {
                                error = Some(format!("{cause:#}"));
                                "storage_unavailable"
                            }
                        }
                    }
                    Ok(_) => "unverified",
                    Err(cause) => {
                        error = Some(format!("cannot verify guest boot: {cause:#}"));
                        "unknown"
                    }
                }
            }
            Some("running") => "unverified",
            Some("stopped") => "stopped",
            _ => "unverified",
        }
    } else if journal.phase == Phase::Created {
        "created"
    } else {
        "missing"
    };
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(
        serde_json::json!({"id":vm.id,"status":status,"lifecycle":journal,"observed_at_unix":observed_at,"configuration":vm,"observed":observed,"observation_error":error,"experimental":true,
        "capabilities":{"host_directory_mounts":false,"file_import":vm.forkfs.is_none(),"file_export":true,"egress_filtering":false,"host_lan_blocking":false,"worldfs":vm.forkfs.is_some() && status == "ready","pty":false,"parallel_exec":true,"guest_services":true,"host_tcp_publish":true},
        "network_policy":"provider NAT, unrestricted egress; not a hostile-workload sandbox"}),
    )
}

pub async fn setup(state: &Path, vm: &Vm, recreate_missing: bool) -> Result<()> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    let mut journal = lifecycle(state, vm)?;
    require_storage_retained(&journal)?;
    ensure!(
        journal.phase != Phase::Deleting,
        "workspace deletion is pending; retry workspace delete"
    );
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
            ensure!(
                journal.phase == Phase::Created || recreate_missing,
                "previous VM is missing or provisioning was interrupted; refusing to replace it with an empty VM. Inspect data recovery options, then use setup --recreate-missing to explicitly create an empty runtime"
            );
            journal.phase = Phase::Provisioning;
            save_lifecycle(state, vm, &journal)?;
            let cpus = vm.cpus.to_string();
            let memory = format!("{}M", vm.memory_mib);
            let label = format!("world.owner={}", vm.owner);
            // Fixed bootstrap, never interpolated user data. Installed through
            // argv, not stdin (stdin belongs to future workloads).
            let bootstrap = "import os,pathlib,sys,time; p=pathlib.Path('/opt/world'); p.mkdir(exist_ok=True); (p/'supervisor.py').write_text(sys.argv[1]); pathlib.Path('/workspace').mkdir(exist_ok=True); pathlib.Path('/home/world').mkdir(exist_ok=True); os.chown('/home/world',1000,1000); os.chown('/workspace',1000,1000) if not sys.argv[2] else (p/'forkfs-source').write_text(sys.argv[2]); time.sleep(2147483647)";
            let source = vm
                .forkfs
                .as_ref()
                .map(|_| format!("world-forkfs-{}", vm.owner))
                .unwrap_or_default();
            let mut create = vec![
                "create",
                "--name",
                &vm.instance_id,
                "--cpus",
                &cpus,
                "--memory",
                &memory,
                "--label",
                &label,
            ];
            if vm.forkfs.is_some() {
                create.extend(["--cap-add", "SYS_ADMIN"]);
            }
            create.extend([
                vm.image.as_str(),
                "python3",
                "-I",
                "-c",
                bootstrap,
                GUEST,
                &source,
            ]);
            output(&create, Duration::from_secs(180)).await?;
        }
        journal.generation = journal
            .generation
            .checked_add(1)
            .context("VM generation overflow")?;
        journal.phase = Phase::Starting;
        save_lifecycle(state, vm, &journal)?;
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
                let boot_id = probe["boot_id"].as_str().context("guest boot ID missing")?;
                if running
                    && journal.phase != Phase::Starting
                    && journal.boot_id.as_deref() != Some(boot_id)
                {
                    journal.generation = journal
                        .generation
                        .checked_add(1)
                        .context("VM generation overflow")?;
                }
                if vm.forkfs.is_some() {
                    let mounted = forkfs_guest(vm, boot_id, "forkfs-mounted").await?;
                    match mounted.trim() {
                        "mounted" => (),
                        "unmounted" => {
                            ensure!(
                                journal.phase != Phase::Ready
                                    || journal.boot_id.as_deref() != Some(boot_id),
                                "storage_unavailable: forkfs detached during this boot; run workspace teardown before setup"
                            );
                            forkfs_mount::wait_worker(state, &vm.instance_id).await?;
                            forkfs_mount::launch(state, &vm.id, boot_id)
                                .await
                                .context("storage_unavailable: forkfs mount setup failed")?;
                        }
                        _ => bail!("storage_unavailable: invalid forkfs mount state"),
                    }
                    require_storage(vm, boot_id).await.context(
                        "run workspace teardown before retrying an unhealthy forkfs mount",
                    )?;
                }
                start_service_supervisor(vm, boot_id).await?;
                guest_service(vm, boot_id, serde_json::json!({"action": "activate"})).await?;
                journal.boot_id = Some(boot_id.to_owned());
                journal.phase = Phase::Ready;
                save_lifecycle(state, vm, &journal)?;
                eprintln!("world: experimental Linux VM ready; NAT egress is unrestricted");
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
    check_registered(state, vm)?;
    let mut journal = lifecycle(state, vm)?;
    require_storage_retained(&journal)?;
    ensure!(
        journal.phase != Phase::Deleting,
        "workspace deletion is pending; retry workspace delete"
    );
    crate::port_publish::control(&vm.owner, b"q").await?;
    check_provider().await?;
    if inspect(vm)
        .await?
        .is_some_and(|v| v["status"]["state"] == "running")
    {
        journal.phase = Phase::Stopping;
        save_lifecycle(state, vm, &journal)?;
        let drain = async {
            let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
            if probe["service_protocol"] == 1 {
                let boot_id = probe["boot_id"].as_str().context("guest boot ID missing")?;
                start_service_supervisor(vm, boot_id).await?;
                guest_service(vm, boot_id, serde_json::json!({"action": "drain"})).await?;
                return Ok(Some(boot_id.to_owned()));
            } else {
                ensure!(
                    vm.forkfs.is_none(),
                    "cannot drain forkfs workspace without its supervisor"
                );
            }
            Ok::<_, anyhow::Error>(None)
        };
        match timeout(Duration::from_secs(15), drain).await {
            Ok(Ok(Some(boot_id))) if vm.forkfs.is_some() => {
                forkfs_guest(vm, &boot_id, "forkfs-unmount")
                    .await
                    .context("forkfs teardown could not confirm unmount")?;
                forkfs_mount::wait_worker(state, &vm.instance_id).await?;
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) if vm.forkfs.is_some() => {
                return Err(error).context("forkfs teardown could not confirm drain and unmount");
            }
            Err(_) if vm.forkfs.is_some() => bail!("forkfs teardown timed out before VM stop"),
            Ok(Err(error)) => {
                eprintln!("world: guest service drain failed; stopping VM: {error:#}")
            }
            Err(_) => eprintln!("world: guest service drain timed out; stopping VM"),
        }
        output(
            &["stop", "--time", "2", &vm.instance_id],
            Duration::from_secs(20),
        )
        .await?;
        ensure!(
            !inspect(vm)
                .await?
                .is_some_and(|v| v["status"]["state"] == "running"),
            "VM still running after stop"
        );
    }
    if vm.forkfs.is_some() {
        forkfs_mount::wait_worker(state, &vm.instance_id).await?;
    }
    // Missing is observed by show, not hidden by a successful teardown.
    journal.phase = if journal.phase == Phase::Created {
        Phase::Created
    } else {
        Phase::Stopped
    };
    save_lifecycle(state, vm, &journal)?;
    Ok(())
}

/// Removes the owned provider instance and its record. Guest writable-layer
/// data needs explicit consent. A bound forkfs branch is left in its repository.
pub async fn delete(state: &Path, vm: &Vm, discard_runtime_data: bool) -> Result<()> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    check_provider().await?;
    let current = inspect(vm).await?;
    if let Some(value) = &current {
        ensure!(
            matches!(
                value["status"]["state"].as_str(),
                Some("stopped" | "created")
            ),
            "VM is running or its state is not safely stopped; use workspace teardown before delete"
        );
        ensure!(
            value["configuration"]["mounts"]
                .as_array()
                .is_some_and(|v| v.is_empty()),
            "VM has mounts; detach managed storage before deleting runtime"
        );
        ensure!(
            discard_runtime_data,
            "VM writable layer may contain project files; pass --discard-runtime-data to delete it permanently"
        );
    }
    crate::port_publish::control(&vm.owner, b"q").await?;
    if vm.forkfs.is_some() {
        forkfs_mount::wait_worker(state, &vm.instance_id).await?;
    }
    let mut journal = lifecycle(state, vm)?;
    journal.phase = Phase::Deleting;
    save_lifecycle(state, vm, &journal)?;
    if current.is_some() {
        output(&["delete", &vm.instance_id], Duration::from_secs(30)).await?;
    }
    ensure!(
        inspect(vm).await?.is_none(),
        "VM still exists after delete; registration retained"
    );
    let _registry_lock = crate::silo::lock(state)?;
    let mut registered = records(state)?;
    ensure!(
        matches!(registered.get(&vm.id), Some(Record::Vm(current)) if current.owner == vm.owner),
        "workspace registration changed during delete"
    );
    registered.remove(&vm.id);
    crate::silo::persist(state, "registry.json", &registered)?;
    // Keep the tiny deletion journal and lock as tombstones. Waiting clients
    // must not acquire a new inode or resurrect a stale Vm value.
    Ok(())
}

async fn require_stopped(vm: &Vm, operation: &str) -> Result<()> {
    check_provider().await?;
    if let Some(instance) = inspect(vm).await? {
        ensure!(
            matches!(
                instance["status"]["state"].as_str(),
                Some("stopped" | "created")
            ),
            "{operation} requires a stopped workspace; run workspace teardown first"
        );
    }
    Ok(())
}

pub async fn checkpoint(state: &Path, vm: &Vm, name: &str) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    let binding = vm
        .forkfs
        .as_ref()
        .context("checkpoint requires a forkfs-backed workspace")?;
    require_storage_retained(&lifecycle(state, vm)?)?;
    require_stopped(vm, "checkpoint").await?;
    forkfs_mount::checkpoint(binding, name).await
}

pub async fn discard(state: &Path, vm: &Vm, expected: Option<&str>) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    let binding = vm
        .forkfs
        .as_ref()
        .context("discard requires a forkfs-backed workspace")?;
    let mut journal = lifecycle(state, vm)?;
    ensure!(
        journal.phase != Phase::Deleting,
        "workspace deletion is pending"
    );
    let Some(token) = expected else {
        require_storage_retained(&journal)?;
        return forkfs_mount::discard_plan(binding).await;
    };
    if let Some(recorded) = &journal.discard_token {
        ensure!(
            recorded == token,
            "discard token differs from the recorded operation"
        );
    }
    let discarded = || serde_json::json!({"state": "discarded", "world": binding.branch});
    if journal.phase == Phase::Discarded {
        return Ok(discarded());
    }
    let retry = journal.phase == Phase::Discarding;
    require_stopped(vm, "discard").await?;
    let request = forkfs_mount::DiscardRequest::prepare(binding, token, retry).await?;
    let previous = journal.phase;
    if !retry {
        journal.phase = Phase::Discarding;
        journal.discard_token = Some(token.to_owned());
        save_lifecycle(state, vm, &journal)?;
    }
    let outcome = request.commit().await.context(
        "discard outcome unknown; retry with the same token after checking the workspace",
    )?;
    let result = match outcome {
        forkfs_mount::DiscardOutcome::Removed(mut result) => {
            result["state"] = "discarded".into();
            Ok(result)
        }
        forkfs_mount::DiscardOutcome::Absent => Ok(discarded()),
        forkfs_mount::DiscardOutcome::Rejected(error) => Err(error),
    };
    if result.is_err() && !retry {
        journal.phase = previous;
        journal.discard_token = None;
        save_lifecycle(state, vm, &journal)?;
    }
    let result = result?;
    journal.phase = Phase::Discarded;
    save_lifecycle(state, vm, &journal)
        .context("forkfs branch is absent; retry to record discard")?;
    Ok(result)
}

pub async fn diff(
    state: &Path,
    vm: &Vm,
    before: &str,
    after: &str,
    cursor: &str,
    limit: u8,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    let binding = vm
        .forkfs
        .as_ref()
        .context("diff requires a forkfs-backed workspace")?;
    forkfs_mount::diff(binding, before, after, cursor, limit).await
}

pub async fn fork(
    state: &Path,
    vm: &Vm,
    revision: &str,
    branch: &str,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, true)?;
    check_registered(state, vm)?;
    let binding = vm
        .forkfs
        .as_ref()
        .context("fork requires a forkfs-backed workspace")?;
    forkfs_mount::fork(binding, revision, branch).await
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
    check_registered(state, vm)?;
    let boot_id = require_ready(state, vm)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running; run world workspace setup first"
    );
    let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
    ensure!(probe["protocol"] == 1, "guest protocol mismatch");
    ensure!(
        probe["boot_id"].as_str() == Some(&boot_id),
        "VM restarted outside World; run workspace setup first"
    );
    require_storage(vm, &boot_id).await?;
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
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
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
    let result: serde_json::Value =
        serde_json::from_str(&guest(vm, &["status", &token]).await.with_context(|| {
            format!(
                "execution {token} status unknown; guest result unavailable, command may have run"
            )
        })?)?;
    match result["state"].as_str() {
        Some("exited" | "timed_out" | "cancelled") => Ok(result["exit_code"]
            .as_i64()
            .context("missing guest exit code")?
            as i32),
        Some("failed")
            if result["error"]
                .as_str()
                .is_some_and(|error| error.starts_with("storage_unavailable:")) =>
        {
            bail!("{}", result["error"].as_str().unwrap())
        }
        _ => bail!("execution {token} status unknown; command may have run: {result}"),
    }
}

/// Copy a completed host snapshot into an empty guest workspace. The exclusive
/// lifecycle lock prevents commands from racing extraction/publication.
async fn require_no_active_services(vm: &Vm, boot_id: &str) -> Result<()> {
    let services = guest_service(vm, boot_id, serde_json::json!({"action": "list"}))
        .await
        .context("cannot verify service state; run workspace setup first")?;
    ensure!(
        services
            .as_array()
            .context("invalid service state")?
            .iter()
            .all(|service| {
                matches!(
                    service["state"].as_str(),
                    Some("stopped" | "exited" | "failed" | "interrupted")
                )
            }),
        "workspace has active services; stop them before transferring files"
    );
    Ok(())
}

pub async fn import(
    state: &Path,
    vm: &Vm,
    source: &Path,
    cancel: CancellationToken,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    ensure!(
        vm.forkfs.is_none(),
        "workspace import requires VM-local storage; seed the forkfs branch with forkfsd before mounting"
    );
    let boot_id = require_ready(state, vm)?;
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
    ensure!(
        probe["boot_id"].as_str() == Some(&boot_id),
        "VM restarted outside World; run workspace setup first"
    );
    if probe["service_protocol"] == 1 {
        require_no_active_services(vm, &boot_id).await?;
    }
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
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
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

/// Export a quiescent workspace into a new host directory.
pub async fn export(
    state: &Path,
    vm: &Vm,
    destination: &Path,
    cancel: CancellationToken,
) -> Result<serde_json::Value> {
    let _lock = operation_lock(state, vm, false)?;
    check_registered(state, vm)?;
    let boot_id = require_ready(state, vm)?;
    check_provider().await?;
    ensure!(
        inspect(vm)
            .await?
            .is_some_and(|v| v["status"]["state"] == "running"),
        "workspace is not running; run workspace setup first"
    );
    let probe: serde_json::Value = serde_json::from_str(&guest(vm, &["probe"]).await?)?;
    ensure!(
        probe["export_protocol"] == 1,
        "guest lacks export support; run workspace setup first"
    );
    ensure!(
        probe["boot_id"].as_str() == Some(&boot_id),
        "VM restarted outside World; run workspace setup first"
    );
    require_storage(vm, &boot_id).await?;
    require_no_active_services(vm, &boot_id).await?;
    ensure!(!cancel.is_cancelled(), "export cancelled");
    let mut staging = crate::export_stream::Staging::new(destination)?;
    let mut child = provider()
        .args([
            "exec",
            "-e",
            &format!("WORLD_EXPECTED_BOOT_ID={boot_id}"),
            &vm.instance_id,
            "python3",
            "-I",
            HELPER,
            "export",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().context("export stdout missing")?;
    let mut stderr = child.stderr.take().context("export stderr missing")?;
    let collect_stderr = async {
        let mut diagnostic = Vec::new();
        (&mut stderr)
            .take(16384)
            .read_to_end(&mut diagnostic)
            .await?;
        tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await?;
        Ok::<_, std::io::Error>(diagnostic)
    };
    let transferred = tokio::select! {
        result = timeout(Duration::from_secs(600), async {
            tokio::join!(staging.receive(stdout), child.wait(), collect_stderr)
        }) => result.context("export timed out"),
        _ = cancel.cancelled() => Err(anyhow::anyhow!("export cancelled")),
    };
    let (entries, status, diagnostic) = match transferred {
        Ok(transfer) => transfer,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error);
        }
    };
    let diagnostic = diagnostic?;
    ensure!(
        status?.success(),
        "guest export failed: {}",
        String::from_utf8_lossy(&diagnostic).trim()
    );
    let entries = entries?;
    ensure!(!cancel.is_cancelled(), "export cancelled");
    tokio::task::spawn_blocking(move || staging.publish(&cancel)).await??;
    Ok(
        serde_json::json!({"state":"exported", "entries":entries, "destination":destination.to_string_lossy()}),
    )
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
            forkfs: None,
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[tokio::test]
    async fn pending_delete_blocks_setup_create_and_stale_handles() {
        let root = tempfile::tempdir().unwrap();
        let vm = create(root.path(), "vm", 1, 256).unwrap();
        let mut journal = lifecycle(root.path(), &vm).unwrap();
        assert_eq!(journal.phase, Phase::Created);
        journal.phase = Phase::Deleting;
        save_lifecycle(root.path(), &vm, &journal).unwrap();
        assert!(
            setup(root.path(), &vm, false)
                .await
                .unwrap_err()
                .to_string()
                .contains("deletion")
        );
        assert!(
            create(root.path(), "vm", 1, 256)
                .unwrap_err()
                .to_string()
                .contains("deletion")
        );
        assert!(require_ready(root.path(), &vm).is_err());
        let records: BTreeMap<String, Record> = BTreeMap::new();
        crate::silo::persist(root.path(), "registry.json", &records).unwrap();
        let replacement = create(root.path(), "vm", 1, 256).unwrap();
        assert_ne!(replacement.owner, vm.owner);
        assert!(check_registered(root.path(), &vm).is_err());
        assert!(check_registered(root.path(), &replacement).is_ok());
    }
}
