//! Host-side branch binding and lease broker for the experimental Linux VM.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::{Child, Command},
    time::{interval, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

pub(crate) const GUEST: &str = include_str!("../guest/forkfs.py");
const MAX_RPC: usize = 1024 * 1024;
const MAX_LINE: usize = 128 * 1024;
const MAX_IO: usize = 4096;
const LEASE_MS: &str = "15000";
const RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub socket: PathBuf,
    pub repository: String,
    pub branch: String,
}

impl Binding {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.socket.is_absolute() && !self.socket.as_os_str().as_encoded_bytes().contains(&0),
            "forkfs socket must be an absolute Unix socket path"
        );
        ensure!(
            self.repository.len() == 32 && self.repository.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid forkfs repository ID"
        );
        validate_name(&self.branch, "branch")?;
        Ok(())
    }
}

fn validate_name(name: &str, kind: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && !matches!(name, "." | ".."),
        "invalid forkfs {kind} name"
    );
    Ok(())
}

struct Rpc<'a> {
    socket: &'a Path,
    identity: (u64, u64),
}

struct Rejection {
    code: u32,
    detail: Vec<u8>,
}

fn identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = path
        .symlink_metadata()
        .context("forkfs socket unavailable")?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
        "forkfs socket must be owned by the current user"
    );
    Ok((metadata.dev(), metadata.ino()))
}

impl<'a> Rpc<'a> {
    fn new(socket: &'a Path) -> Result<Self> {
        Ok(Self {
            socket,
            identity: identity(socket)?,
        })
    }

    async fn bound(binding: &'a Binding) -> Result<Self> {
        let rpc = Self::new(&binding.socket)?;
        let status: serde_json::Value = serde_json::from_slice(&rpc.required(&[b"status"]).await?)?;
        ensure!(
            status["repository_id"].as_str() == Some(&binding.repository),
            "forkfs repository identity mismatch"
        );
        Ok(rpc)
    }

    async fn open_session(&self) -> Result<String> {
        let response: serde_json::Value = serde_json::from_slice(
            &self
                .required(&[b"session-open", LEASE_MS.as_bytes()])
                .await?,
        )?;
        Ok(response["session"]
            .as_str()
            .context("forkfs session missing")?
            .to_owned())
    }

    async fn mount_root(&self, binding: &Binding, session: &str) -> Result<serde_json::Value> {
        let view: serde_json::Value = serde_json::from_slice(
            &self
                .required(&[
                    b"inode-root",
                    b"--world",
                    binding.branch.as_bytes(),
                    b"--session",
                    session.as_bytes(),
                ])
                .await?,
        )?;
        ensure!(
            view["repository"].as_str() == Some(&binding.repository),
            "forkfs repository identity mismatch"
        );
        ensure!(
            view["inode"]["directory"] == true,
            "forkfs mount root must be a directory"
        );
        Ok(view["inode"].clone())
    }

    async fn close_session(&self, session: &str) -> Result<()> {
        self.required(&[b"session-close", session.as_bytes()])
            .await?;
        Ok(())
    }

    async fn call(&self, fields: &[&[u8]]) -> Result<std::result::Result<Vec<u8>, Rejection>> {
        timeout(RPC_TIMEOUT, async {
            ensure!(
                identity(self.socket)? == self.identity,
                "forkfs socket replaced"
            );
            let mut payload = (fields.len() as u32).to_le_bytes().to_vec();
            for field in fields {
                payload.extend_from_slice(&(field.len() as u32).to_le_bytes());
                payload.extend_from_slice(field);
            }
            ensure!(payload.len() <= MAX_RPC, "forkfs request too large");
            let mut channel = UnixStream::connect(self.socket).await?;
            ensure!(
                identity(self.socket)? == self.identity,
                "forkfs socket replaced"
            );
            channel.write_all(b"FFRPC001").await?;
            channel
                .write_all(&(payload.len() as u32).to_le_bytes())
                .await?;
            channel.write_all(&payload).await?;
            let mut magic = [0u8; 8];
            channel.read_exact(&mut magic).await?;
            let len = channel.read_u32_le().await? as usize;
            ensure!(
                &magic == b"FFRSP001" && (4..=MAX_RPC).contains(&len),
                "invalid forkfs reply"
            );
            let code = channel.read_u32_le().await?;
            let mut data = vec![0; len - 4];
            channel.read_exact(&mut data).await?;
            Ok(if code == 0 {
                Ok(data)
            } else {
                Err(Rejection { code, detail: data })
            })
        })
        .await
        .context("forkfs RPC timed out")?
    }

    async fn required(&self, fields: &[&[u8]]) -> Result<Vec<u8>> {
        let operation = String::from_utf8_lossy(fields[0]);
        self.call(fields)
            .await
            .with_context(|| format!("could not confirm forkfs {operation}"))?
            .map_err(|error| {
                anyhow::anyhow!(
                    "forkfs {operation} failed: {}",
                    String::from_utf8_lossy(&error.detail),
                )
            })
    }
}

pub(crate) async fn checkpoint(binding: &Binding, name: &str) -> Result<serde_json::Value> {
    validate_name(name, "checkpoint")?;
    let rpc = Rpc::bound(binding).await?;
    let session = rpc.open_session().await?;
    let result = async {
        rpc.mount_root(binding, &session)
            .await
            .context("checkpoint requires an exclusive forkfs lease with no open file handles")?;
        let response = rpc
            .required(&[
                b"fs-snapshot",
                name.as_bytes(),
                b"--world",
                binding.branch.as_bytes(),
                b"--session",
                session.as_bytes(),
            ])
            .await?;
        let reply: serde_json::Value = serde_json::from_slice(&response)?;
        let revision_id = reply["revision_id"]
            .as_str()
            .context("forkfs checkpoint revision missing")?;
        Ok::<_, anyhow::Error>(serde_json::json!({
            "checkpoint": name, "revision_id": revision_id, "branch": binding.branch,
        }))
    }
    .await;
    let closed = rpc.close_session(&session).await;
    let result = result?;
    closed.with_context(|| {
        format!("checkpoint {name} committed, but forkfs lease release was not confirmed")
    })?;
    Ok(result)
}

pub(crate) async fn diff(
    binding: &Binding,
    before: &str,
    after: &str,
    cursor: &str,
    limit: u8,
) -> Result<serde_json::Value> {
    validate_name(before, "before revision")?;
    validate_name(after, "after revision")?;
    ensure!((1..=64).contains(&limit), "diff page size must be 1..64");
    ensure!(
        cursor.is_empty()
            || (cursor.starts_with('/') && cursor.len() <= 4096 && !cursor.contains('\0')),
        "diff cursor must be an absolute forkfs path"
    );
    let rpc = Rpc::bound(binding).await?;
    let reply = rpc
        .required(&[
            b"fs-diff",
            before.as_bytes(),
            after.as_bytes(),
            cursor.as_bytes(),
            limit.to_string().as_bytes(),
        ])
        .await?;
    Ok(serde_json::from_slice(&reply)?)
}

pub(crate) async fn fork(
    binding: &Binding,
    revision: &str,
    branch: &str,
) -> Result<serde_json::Value> {
    validate_name(revision, "revision")?;
    validate_name(branch, "branch")?;
    ensure!(branch != "main", "main is reserved");
    let rpc = Rpc::bound(binding).await?;
    rpc.required(&[b"fs-fork", revision.as_bytes(), branch.as_bytes()])
        .await?;
    Ok(serde_json::json!({
        "branch": branch, "from": revision, "repository": binding.repository,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    args: Vec<String>,
    data: Option<String>,
}

fn errno_name(code: u32) -> &'static str {
    // Translate Darwin errno values to symbolic names for the Linux frontend.
    match code.saturating_sub(1) as libc::c_int {
        libc::EACCES => "EACCES",
        libc::EBADF => "EBADF",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EFBIG => "EFBIG",
        libc::EILSEQ => "EILSEQ",
        libc::EINVAL => "EINVAL",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::EMFILE => "EMFILE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOENT => "ENOENT",
        libc::ENOSPC => "ENOSPC",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ENOTSUP => "EOPNOTSUPP",
        libc::EPERM if code > 1 => "EPERM",
        libc::EROFS => "EROFS",
        libc::ESTALE => "ESTALE",
        _ => "EIO",
    }
}

impl Request {
    fn binary(&self) -> Result<Option<Vec<u8>>> {
        let count = match self.op.as_str() {
            "root" | "inode-sync" => 0,
            "inode-stat" | "inode-readlink" | "fs-hstat" | "fs-close" | "inode-dir-open"
            | "fs-dir-close" => 1,
            "inode-lookup" | "inode-open" | "fs-dir-entries" | "fs-hwrite" => 2,
            "inode-create" | "inode-mkdir" | "inode-symlink" | "fs-hread" => 3,
            "inode-remove" => 4,
            "inode-rename" => 6,
            "inode-setattr-times" => 7,
            _ => bail!("unknown forkfs operation"),
        };
        ensure!(
            self.args.len() == count
                && self
                    .args
                    .iter()
                    .all(|s| s.len() <= MAX_IO && !s.contains('\0')),
            "invalid forkfs arguments"
        );
        if self.op == "fs-hread" {
            ensure!(
                self.args[2].parse::<usize>()? <= MAX_IO,
                "forkfs read too large"
            );
        }
        if self.op == "fs-dir-entries" {
            ensure!(
                (1..=64).contains(&self.args[1].parse::<usize>()?),
                "invalid directory page"
            );
        }
        ensure!(
            (self.op == "fs-hwrite") == self.data.is_some(),
            "invalid forkfs binary argument"
        );
        let data = self.data.as_ref().map(|s| STANDARD.decode(s)).transpose()?;
        ensure!(
            data.as_ref().is_none_or(|data| data.len() <= MAX_IO),
            "forkfs write too large"
        );
        Ok(data)
    }
}

struct Bridge<'a> {
    rpc: Rpc<'a>,
    binding: &'a Binding,
    session: String,
    healthy: bool,
}

impl Bridge<'_> {
    async fn keepalive(&mut self) {
        if self.healthy {
            self.healthy = self
                .rpc
                .required(&[b"session-keepalive", self.session.as_bytes()])
                .await
                .is_ok();
        }
    }

    async fn response(&mut self, line: &[u8], root: &[u8]) -> serde_json::Value {
        fn error(name: &str) -> serde_json::Value {
            serde_json::json!({"error": name})
        }

        let Ok(request) = serde_json::from_slice::<Request>(line) else {
            return error("EINVAL");
        };
        let Ok(data) = request.binary() else {
            return error("EINVAL");
        };
        if !self.healthy {
            return error("EIO");
        }
        if request.op == "root" {
            return serde_json::json!({"data": STANDARD.encode(root)});
        }
        let mut fields = vec![request.op.as_bytes()];
        fields.extend(request.args.iter().map(|s| s.as_bytes()));
        if let Some(bytes) = &data {
            fields.push(bytes);
        }
        fields.extend([
            b"--world",
            self.binding.branch.as_bytes(),
            b"--session",
            self.session.as_bytes(),
        ]);
        match self.rpc.call(&fields).await {
            Ok(Ok(data)) if data.len() <= MAX_LINE / 2 => {
                serde_json::json!({"data": STANDARD.encode(data)})
            }
            Ok(Ok(_)) => error("EOVERFLOW"),
            Ok(Err(rejection)) => error(errno_name(rejection.code)),
            Err(_) => {
                self.healthy = false;
                error("EIO")
            }
        }
    }

    async fn serve(
        &mut self,
        mut child: Child,
        root: &[u8],
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut input = child.stdin.take().context("missing forkfs guest stdin")?;
        let mut output =
            BufReader::new(child.stdout.take().context("missing forkfs guest stdout")?);
        let mut line = Vec::new();
        let mut renew = interval(Duration::from_secs(3));
        let mut ready = false;
        loop {
            line.clear();
            let count = {
                let mut bounded = (&mut output).take(MAX_LINE as u64);
                let mut pending = std::pin::pin!(bounded.read_until(b'\n', &mut line));
                loop {
                    tokio::select! {
                        res = &mut pending => break res?,
                        _ = renew.tick() => self.keepalive().await,
                        _ = cancel.cancelled() => bail!("forkfs mount worker cancelled"),
                    }
                }
            };
            if count == 0 {
                let status = timeout(RPC_TIMEOUT, child.wait()).await??;
                ensure!(ready && status.success(), "forkfs guest frontend exited");
                return Ok(());
            }
            ensure!(
                line.ends_with(b"\n"),
                "oversized or truncated forkfs request"
            );
            if line == b"ready\n" {
                ensure!(!ready && self.healthy, "unexpected forkfs mount readiness");
                println!("{{\"ready\":true}}");
                ready = true;
            } else {
                let mut response = serde_json::to_vec(&self.response(&line, root).await)?;
                response.push(b'\n');
                timeout(RPC_TIMEOUT, input.write_all(&response)).await??;
            }
        }
    }
}

fn worker_file(state: &Path, instance: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join(format!("{instance}.forkfs.lock")))?)
}

pub(crate) async fn wait_worker(state: &Path, instance: &str) -> Result<()> {
    let file = worker_file(state, instance)?;
    timeout(Duration::from_secs(8), async {
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(50)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .context("forkfs mount worker is still active")??;
    Ok(())
}

pub(crate) async fn worker(
    state: &Path,
    instance: &str,
    binding: &Binding,
    mut guest: Command,
    cancel: CancellationToken,
) -> Result<()> {
    let lock = worker_file(state, instance)?;
    lock.try_lock_exclusive()
        .context("a forkfs mount worker is already active")?;
    let rpc = Rpc::bound(binding).await?;
    let session = rpc.open_session().await?;
    let mut bridge = Bridge {
        rpc,
        binding,
        session,
        healthy: true,
    };
    let result = async {
        let root = bridge.rpc.mount_root(binding, &bridge.session).await?;
        let root = serde_json::to_vec(&root)?;
        let child = guest.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        bridge.serve(child, &root, cancel).await
    }
    .await;
    let closed = bridge.rpc.close_session(&bridge.session).await;
    result?;
    if bridge.healthy {
        closed?;
    }
    Ok(())
}

pub(crate) async fn launch(state: &Path, workspace: &str, boot: &str) -> Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["__forkfs-worker"])
        .arg(state)
        .args([workspace, boot])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The worker outlives setup and owns just this mount lease.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .context("missing forkfs worker stdout")?;
    let mut reply = Vec::new();
    let ready = timeout(
        Duration::from_secs(14),
        BufReader::new(stdout)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut reply),
    )
    .await;
    if !matches!(ready, Ok(Ok(_))) || !reply.ends_with(b"\n") {
        let _ = child.kill().await;
        bail!("forkfs mount worker did not become ready");
    }
    let value: serde_json::Value = serde_json::from_slice(&reply)?;
    ensure!(
        value["ready"] == true,
        "{}",
        value["error"].as_str().unwrap_or("forkfs mount failed")
    );
    Ok(())
}
