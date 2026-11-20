//! Bounded reverse TCP relay into one execution's authenticated host proxy.
use crate::{
    policy::Policy,
    port_publish::{Frame, STREAMS, read_frame, relay_stream},
    proxy::Proxy,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, TcpListener},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

pub(crate) struct Session {
    cancel: CancellationToken,
    task: JoinHandle<Result<()>>,
}

impl Session {
    pub(crate) async fn start(policy: &Policy, mut command: Command, boot: &str) -> Result<Self> {
        let prepared = timeout(Duration::from_secs(12), Proxy::prepare_vm_egress(policy))
            .await
            .context("resolving egress policy timed out")??;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let mut proxy = prepared.serve(port, vec![listener])?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut input = child.stdin.take().context("egress bridge stdin missing")?;
        let mut output = BufReader::new(
            child
                .stdout
                .take()
                .context("egress bridge stdout missing")?,
        );
        let mut config = Frame::new("config", 0);
        config.data = Some(proxy.url());
        timeout(Duration::from_secs(8), async {
            let mut bytes = serde_json::to_vec(&config)?;
            bytes.push(b'\n');
            input.write_all(&bytes).await?;
            let hello = read_frame(&mut output).await?;
            ensure!(
                hello.kind == "hello" && hello.id == 0 && hello.data.as_deref() == Some(boot),
                "invalid egress bridge boot handshake"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("egress bridge handshake timed out")??;

        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let task = tokio::spawn(async move {
            let (outbound, mut frames) = mpsc::channel::<Frame>(2 * STREAMS);
            let write_frames = async {
                while let Some(frame) = frames.recv().await {
                    let mut wire = serde_json::to_vec(&frame)?;
                    wire.push(b'\n');
                    input.write_all(&wire).await?;
                }
                bail!("egress bridge writer closed")
            };
            let outcome = tokio::select! {
                outcome = relay(output, outbound, port) => outcome,
                outcome = write_frames => outcome,
                _ = child.wait() => Err(anyhow::anyhow!("guest egress bridge exited")),
                _ = shutdown.cancelled() => Ok(()),
            };
            if outcome.is_ok() {
                let _ = timeout(
                    Duration::from_secs(1),
                    input.write_all(b"{\"kind\":\"shutdown\",\"id\":0}\n"),
                )
                .await;
            }
            drop(input);
            proxy.close().await;
            if timeout(Duration::from_secs(2), child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
            outcome
        });
        Ok(Self { cancel, task })
    }

    pub(crate) async fn finished(&mut self) -> Result<()> {
        (&mut self.task).await?
    }

    pub(crate) async fn close(mut self) {
        self.cancel.cancel();
        let _ = self.finished().await;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Stream {
    frames: mpsc::Sender<Frame>,
    credit: mpsc::Sender<()>,
}

async fn relay(
    mut output: impl AsyncBufRead + Unpin,
    outbound: mpsc::Sender<Frame>,
    port: u16,
) -> Result<()> {
    let mut streams = HashMap::<u64, Stream>::new();
    let mut sockets = JoinSet::new();
    let mut last = 0;
    let mut heartbeat = Instant::now();
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    let (from_guest, mut incoming) = mpsc::channel(STREAMS);
    let read_frames = async {
        loop {
            let frame = read_frame(&mut output).await?;
            from_guest.send(frame).await?;
        }
    };
    let serve = async {
        loop {
            tokio::select! {
                _ = ticks.tick() => {
                    ensure!(heartbeat.elapsed() < Duration::from_secs(5), "guest egress heartbeat expired");
                    timeout(Duration::from_secs(1), outbound.send(Frame::new("heartbeat", 0))).await??;
                }
                Some(done) = sockets.join_next() => { streams.remove(&done?); }
                frame = incoming.recv() => {
                    let frame = frame.context("egress bridge reader closed")?;
                    match frame.kind.as_str() {
                        "heartbeat" if frame.id == 0 => heartbeat = Instant::now(),
                        "open" => {
                            ensure!(frame.id > last && frame.data.is_none(), "invalid egress stream ID");
                            let id = frame.id;
                            last = id;
                            if streams.len() >= STREAMS {
                                outbound.send(Frame::new("reset", id)).await?;
                                continue;
                            }
                            let (inbox, frames) = mpsc::channel(2);
                            let (credit, ack) = mpsc::channel(1);
                            streams.insert(id, Stream { frames: inbox, credit });
                            let sender = outbound.clone();
                            sockets.spawn(async move {
                                let result = async {
                                    let socket = timeout(Duration::from_secs(3),
                                        TcpStream::connect((Ipv4Addr::LOCALHOST, port))).await??;
                                    sender.send(Frame::new("opened", id)).await?;
                                    relay_stream(socket, id, frames, ack, &sender).await
                                }.await;
                                if result.is_err() {
                                    let _ = sender.send(Frame::new("reset", id)).await;
                                }
                                id
                            });
                        }
                        "data" | "fin" | "ack" | "reset" if frame.id != 0 && frame.id <= last => {
                            if let Some(stream) = streams.get(&frame.id) {
                                if frame.kind == "ack" {
                                    ensure!(!matches!(stream.credit.try_send(()), Err(mpsc::error::TrySendError::Full(_))),
                                        "unexpected egress stream credit");
                                } else {
                                    ensure!(!matches!(stream.frames.try_send(frame), Err(mpsc::error::TrySendError::Full(_))),
                                        "egress stream exceeded receive credit");
                                }
                            }
                        }
                        _ => bail!("invalid egress bridge frame"),
                    }
                }
            }
        }
    };
    tokio::select! {
        result = read_frames => result,
        result = serve => result,
    }
}
