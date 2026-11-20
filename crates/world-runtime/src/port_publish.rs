//! One explicitly published loopback endpoint per experimental Linux VM.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    process::{Child, Command},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

use tokio_util::sync::CancellationToken;

const CHUNK: usize = 8192;
pub(crate) const STREAMS: usize = 8;
const LINE: u64 = 12_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Publication {
    pub service: String,
    pub name: String,
    pub run_id: String,
    pub host_port: u16,
    pub target_port: u16,
}

fn control_dir(owner: &str, create: bool) -> Result<Option<PathBuf>> {
    ensure!(
        owner.len() == 32 && owner.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid publication owner"
    );
    let uid = unsafe { libc::geteuid() };
    let path = Path::new("/tmp").join(format!("world-port-{uid}-{owner}"));
    if create {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(&path)
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(error.into());
        }
    }
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o777 == 0o700,
        "publication control directory must be private and owned by the current user"
    );
    Ok(Some(path))
}

pub(crate) async fn control(owner: &str, command: &[u8]) -> Result<Option<Publication>> {
    let Some(directory) = control_dir(owner, false)? else {
        return Ok(None);
    };
    let mut channel = match UnixStream::connect(directory.join("s")).await {
        Ok(channel) => channel,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    timeout(Duration::from_secs(3), async {
        channel.write_all(command).await?;
        let mut response = Vec::new();
        (&mut channel).take(LINE).read_to_end(&mut response).await?;
        if command == b"q" {
            ensure!(
                response == b"closed",
                "publication closure was not confirmed"
            );
            Ok(None)
        } else {
            Ok(Some(serde_json::from_slice(&response)?))
        }
    })
    .await
    .context("publication broker did not respond")?
}

pub(crate) async fn launch(
    executable: &Path,
    state: &Path,
    workspace: &str,
    publication: &Publication,
) -> Result<()> {
    let mut command = Command::new(executable);
    command
        .arg("__port-worker")
        .arg(state)
        .arg(workspace)
        .arg(serde_json::to_string(publication)?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The broker has no controlling terminal and outlives the publishing CLI.
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
        .context("publication broker output is missing")?;
    let mut response = Vec::new();
    let result = timeout(Duration::from_secs(12), async {
        BufReader::new(stdout)
            .take(LINE)
            .read_until(b'\n', &mut response)
            .await
    })
    .await;
    if !matches!(result, Ok(Ok(_))) || response.is_empty() {
        let _ = child.kill().await;
        bail!("publication broker did not become ready");
    }
    let result: serde_json::Value = serde_json::from_slice(&response)?;
    ensure!(
        result["ready"] == true,
        "{}",
        result["error"].as_str().unwrap_or("publication failed")
    );
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Frame {
    pub(crate) kind: String,
    pub(crate) id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<String>,
}

impl Frame {
    pub(crate) fn new(kind: &str, id: u64) -> Self {
        Self {
            kind: kind.into(),
            id,
            data: None,
        }
    }
}

pub(crate) async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Frame> {
    let mut line = Vec::new();
    let length = reader.take(LINE + 1).read_until(b'\n', &mut line).await?;
    ensure!(
        length > 0 && length as u64 <= LINE && line.ends_with(b"\n"),
        "publication bridge disconnected or frame exceeded limit"
    );
    Ok(serde_json::from_slice(&line)?)
}

pub(crate) async fn broker(
    owner: &str,
    publication: Publication,
    mut bridge: Child,
    cancel: CancellationToken,
) -> Result<()> {
    let directory = control_dir(owner, true)?.context("missing publication control directory")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(directory.join("lock"))?;
    lock.try_lock_exclusive()
        .context("a publication is already active for this World")?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, publication.host_port))
        .await
        .context("cannot bind host loopback port")?;
    let mut output = BufReader::new(bridge.stdout.take().context("bridge stdout missing")?);
    let mut input = bridge.stdin.take().context("bridge stdin missing")?;
    let hello = timeout(Duration::from_secs(8), read_frame(&mut output)).await??;
    ensure!(
        hello.kind == "hello" && hello.id == 0,
        "invalid guest bridge handshake"
    );
    let socket = directory.join("s");
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let control_socket = UnixListener::bind(&socket)?;
    println!("{{\"ready\":true}}");
    let (outbound, mut frames) = mpsc::channel::<Frame>(2 * STREAMS);
    let write_frames = async {
        while let Some(frame) = frames.recv().await {
            let mut wire = serde_json::to_vec(&frame)?;
            wire.push(b'\n');
            input.write_all(&wire).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let serve = relay(listener, control_socket, &publication, output, outbound);
    let outcome = tokio::select! {
        result = serve => result.map(Some),
        _ = cancel.cancelled() => Ok(None),
        result = write_frames => result.and(Err(anyhow::anyhow!("publication bridge writer closed"))),
        result = bridge.wait() => match result {
            Ok(status) => Err(anyhow::anyhow!("publication guest bridge exited: {status}")),
            Err(error) => Err(error.into()),
        },
    };
    let _ = std::fs::remove_file(socket);
    let _ = bridge.kill().await;
    drop(lock);
    if let Some(mut peer) = outcome? {
        peer.write_all(b"closed").await?;
    }
    Ok(())
}

struct Stream {
    inbox: mpsc::Sender<Frame>,
    credit: mpsc::Sender<()>,
}

async fn relay(
    listener: TcpListener,
    control: UnixListener,
    publication: &Publication,
    mut output: impl AsyncBufRead + Unpin,
    outbound: mpsc::Sender<Frame>,
) -> Result<UnixStream> {
    let mut sockets = JoinSet::new();
    let mut streams = HashMap::<u64, Stream>::new();
    let mut next_id = 1;
    let mut heartbeat = tokio::time::Instant::now();
    let mut check = tokio::time::interval(Duration::from_secs(1));
    // Keep the partially read frame alive while accepting more sockets.
    let (from_guest, mut incoming) = mpsc::channel(STREAMS);
    let read_frames = async {
        loop {
            let frame = match read_frame(&mut output).await {
                Ok(frame) => frame,
                Err(error) => break Err(error),
            };
            from_guest.send(frame).await?;
        }
    };
    let serve = async {
        loop {
            tokio::select! {
                connection = listener.accept(), if streams.len() < STREAMS => {
                    let (tcp, _) = connection?;
                    let (inbox, channel) = mpsc::channel(2);
                    let (credit, ack) = mpsc::channel(1);
                    let id = next_id;
                    next_id += 1;
                    streams.insert(id, Stream { inbox, credit });
                    let sender = outbound.clone();
                    sockets.spawn(async move {
                        let result = connection_task(tcp, id, channel, ack, &sender).await;
                        if result.is_err() {
                            let _ = sender.send(Frame::new("reset", id)).await;
                        }
                        id
                    });
                }
                Some(done) = sockets.join_next() => { streams.remove(&done?); }
                request = control.accept() => {
                    let (mut peer, _) = request?;
                    let request = timeout(Duration::from_millis(500), peer.read_u8()).await;
                    match request {
                        Ok(Ok(b'?')) => {
                            let data = serde_json::to_vec(publication)?;
                            let _ = timeout(Duration::from_millis(500), peer.write_all(&data)).await;
                        }
                        Ok(Ok(b'q')) => {
                            drop(listener);
                            sockets.shutdown().await;
                            timeout(Duration::from_secs(2), async {
                                outbound.send(Frame::new("shutdown", 0)).await?;
                                while let Some(frame) = incoming.recv().await {
                                    if frame.kind == "closed" && frame.id == 0 {
                                        return Ok(());
                                    }
                                }
                                bail!("guest publication shutdown was not confirmed")
                            }).await.context("guest publication shutdown timed out")??;
                            return Ok(peer);
                        }
                        _ => {}
                    }
                }
                frame = incoming.recv() => {
                    let frame = frame.context("publication bridge reader closed")?;
                    if frame.kind == "heartbeat" && frame.id == 0 {
                        heartbeat = tokio::time::Instant::now();
                    } else if let Some(stream) = streams.get(&frame.id) {
                        if frame.kind == "ack" {
                            if let Err(mpsc::error::TrySendError::Full(_)) = stream.credit.try_send(()) {
                                bail!("unexpected publication stream credit");
                            }
                        } else if let Err(mpsc::error::TrySendError::Full(_)) = stream.inbox.try_send(frame) {
                            bail!("publication stream exceeded receive credit");
                        }
                    }
                }
                _ = check.tick() => ensure!(heartbeat.elapsed() < Duration::from_secs(5), "publication heartbeat timed out"),
            }
        }
    };
    tokio::select! {
        result = read_frames => result,
        result = serve => result,
    }
}

async fn connection_task(
    tcp: TcpStream,
    id: u64,
    mut frames: mpsc::Receiver<Frame>,
    credit: mpsc::Receiver<()>,
    outbound: &mpsc::Sender<Frame>,
) -> Result<()> {
    outbound.send(Frame::new("open", id)).await?;
    let response = timeout(Duration::from_secs(6), frames.recv())
        .await?
        .context("open interrupted")?;
    ensure!(
        response.kind == "opened",
        "guest service refused connection"
    );
    relay_stream(tcp, id, frames, credit, outbound).await
}

pub(crate) async fn relay_stream(
    tcp: TcpStream,
    id: u64,
    mut frames: mpsc::Receiver<Frame>,
    mut credit: mpsc::Receiver<()>,
    outbound: &mpsc::Sender<Frame>,
) -> Result<()> {
    let (mut rx, mut tx) = tcp.into_split();
    let download = async {
        while let Some(frame) = frames.recv().await {
            match frame.kind.as_str() {
                "data" => {
                    let data = STANDARD.decode(frame.data.context("missing stream data")?)?;
                    ensure!(
                        !data.is_empty() && data.len() <= CHUNK,
                        "invalid bridge chunk"
                    );
                    tx.write_all(&data).await?;
                    outbound.send(Frame::new("ack", id)).await?;
                }
                "fin" => {
                    tx.shutdown().await?;
                    return Ok(());
                }
                _ => bail!("bridge peer closed stream"),
            }
        }
        bail!("bridge stream lost");
    };
    let upload = async {
        let mut buffer = [0; CHUNK];
        loop {
            let size = rx.read(&mut buffer).await?;
            if size == 0 {
                outbound.send(Frame::new("fin", id)).await?;
                return Ok(());
            }
            let mut frame = Frame::new("data", id);
            frame.data = Some(STANDARD.encode(&buffer[..size]));
            outbound.send(frame).await?;
            credit
                .recv()
                .await
                .context("bridge credit channel closed")?;
        }
    };
    tokio::try_join!(download, upload)?;
    Ok(())
}
