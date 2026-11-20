//! Host proxy for the real offline-VM transport probe.
use anyhow::{Context, Result};
use std::{fs::File, net::TcpListener};
use tokio::io::AsyncReadExt;
use world_runtime::{policy::Policy, proxy::Proxy};

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .context("expected a policy path")?;
    let policy = Policy::read(File::open(path)?)?;
    let prepared = Proxy::prepare_vm_egress(&policy).await?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let mut proxy = prepared.serve(port, vec![listener])?;
    // The orchestrator reads the credential through a private pipe.
    println!("{}", proxy.url());
    let _ = tokio::io::stdin().read_u8().await;
    proxy.close().await;
    Ok(())
}
