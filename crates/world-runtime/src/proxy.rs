use crate::policy::{Policy, authority, canonical_host};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{Request, Response, StatusCode, body::Incoming, header, service::service_fn};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;

pub struct Proxy {
    port: u16,
    credential: String,
    cancel: CancellationToken,
    accepts: Vec<JoinHandle<()>>,
    tasks: TaskTracker,
}

struct Service {
    routes: HashMap<String, Vec<SocketAddr>>,
    authorization: String,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl Proxy {
    pub async fn start(policy: &Policy) -> Result<Self> {
        policy.validate()?;
        let mut routes = HashMap::new();
        for endpoint in &policy.allow {
            let host = canonical_host(&endpoint.host)?;
            let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
                vec![SocketAddr::new(ip, endpoint.port)]
            } else {
                let addresses: Vec<_> = timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host((host.as_str(), endpoint.port)),
                )
                .await??
                .collect();
                if addresses.is_empty() || addresses.iter().any(|addr| !public_ip(addr.ip())) {
                    bail!(
                        "host {host} resolves to non-public address; authorize a literal IP explicitly"
                    );
                }
                addresses
            };
            routes.insert(authority(&host, endpoint.port), addresses);
        }
        let v4 = TcpListener::bind("127.0.0.1:0").await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await?;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let credential = secret
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let authorization = format!("Basic {}", STANDARD.encode(format!("world:{credential}")));
        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();
        let service = Arc::new(Service {
            routes,
            authorization,
            cancel: cancel.clone(),
            tasks: tasks.clone(),
        });
        let mut accepts = Vec::new();
        for listener in [v4, v6] {
            let service = service.clone();
            accepts.push(tokio::spawn(async move {
                loop {
                    let accepted=tokio::select! { biased; _=service.cancel.cancelled()=>break, accepted=listener.accept()=>accepted };
                    let Ok((stream,_))=accepted else {service.cancel.cancel();break};
                    let state=service.clone();
                    service.tasks.spawn(async move {
                        let handler=state.clone();
                        let connection=hyper::server::conn::http1::Builder::new()
                            .max_buf_size(32*1024)
                            .serve_connection(TokioIo::new(stream),service_fn(move |req|handler.clone().handle(req)))
                            .with_upgrades();
                        tokio::select! { _=state.cancel.cancelled()=>{}, _=connection=>{} }
                    });
                }
            }));
        }
        Ok(Self {
            port,
            credential,
            cancel,
            accepts,
            tasks,
        })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Contains an execution credential. Never log this value.
    pub fn url(&self) -> String {
        format!("http://world:{}@127.0.0.1:{}", self.credential, self.port)
    }
    pub async fn close(&mut self) {
        self.cancel.cancel();
        for task in self.accepts.drain(..) {
            let _ = task.await;
        }
        self.tasks.close();
        self.tasks.wait().await;
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_documentation()
        }
        IpAddr::V6(v) => {
            if let Some(v) = v.to_ipv4_mapped() {
                public_ip(v.into())
            } else {
                !v.is_loopback()
                    && !v.is_unspecified()
                    && !v.is_multicast()
                    && !v.is_unique_local()
                    && !v.is_unicast_link_local()
            }
        }
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(message.as_bytes()))
                .map_err(|never: Infallible| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

impl Service {
    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        let supplied = req
            .headers()
            .get(header::PROXY_AUTHORIZATION)
            .map(|v| v.as_bytes())
            .unwrap_or_default();
        if !bool::from(supplied.ct_eq(self.authorization.as_bytes())) {
            let mut res = response(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "execution proxy credential required",
            );
            res.headers_mut().insert(
                header::PROXY_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"world\""),
            );
            return Ok(res);
        }
        Ok(match self.forward(req).await {
            Ok(response) => response,
            Err(_) => response(StatusCode::BAD_GATEWAY, "upstream unavailable"),
        })
    }
    async fn forward(self: Arc<Self>, mut req: Request<Incoming>) -> Result<Response<Body>> {
        let connect = req.method() == hyper::Method::CONNECT;
        let Some(auth) = req.uri().authority() else {
            return Ok(response(StatusCode::BAD_REQUEST, "absolute URL required"));
        };
        if !connect && req.uri().scheme_str() != Some("http") {
            return Ok(response(StatusCode::BAD_REQUEST, "HTTP URL required"));
        }
        let host = canonical_host(auth.host().trim_matches(['[', ']']))?;
        let port = match auth.port_u16() {
            Some(port) => port,
            None if !connect => 80,
            None => return Ok(response(StatusCode::BAD_REQUEST, "CONNECT port required")),
        };
        let key = authority(&host, port);
        let Some(addresses) = self.routes.get(&key) else {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "destination denied by Network policy",
            ));
        };
        let mut stream = None;
        for address in addresses {
            if let Ok(Ok(connected)) =
                timeout(Duration::from_secs(5), TcpStream::connect(address)).await
            {
                stream = Some(connected);
                break;
            }
        }
        let Some(mut stream) = stream else {
            bail!("upstream unavailable")
        };
        if connect {
            let upgrade = hyper::upgrade::on(&mut req);
            let state = self.clone();
            self.tasks.spawn(async move {
                let transfer = async {
                    if let Ok(Ok(upgraded)) = timeout(Duration::from_secs(5), upgrade).await {
                        let _ =
                            tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut stream)
                                .await;
                    }
                };
                tokio::select! {_=state.cancel.cancelled()=>{},_=transfer=>{}}
            });
            return Ok(response(StatusCode::OK, ""));
        }
        let original_authority = req.uri().authority().unwrap().as_str().to_string();
        let target = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .parse()?;
        *req.uri_mut() = target;
        strip_hop_headers(req.headers_mut());
        req.headers_mut()
            .insert(header::HOST, original_authority.parse()?);
        req.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            tokio::select! {_=cancel.cancelled()=>{},_=connection=>{}}
        });
        let mut res = timeout(Duration::from_secs(30), sender.send_request(req)).await??;
        strip_hop_headers(res.headers_mut());
        Ok(res.map(|body| {
            body.map_err(|err| -> BoxError { Box::new(err) })
                .boxed_unsync()
        }))
    }
}

fn strip_hop_headers(headers: &mut header::HeaderMap) {
    let tokens: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|v| v.trim().to_string()))
        .collect();
    for token in tokens {
        headers.remove(token);
    }
    for key in [
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn proxy_auth_policy_and_revocation() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        });
        let p = Policy {
            network_id: "test".into(),
            allow: vec![crate::policy::Endpoint {
                host: "127.0.0.1".into(),
                port: target.port(),
            }],
        };
        let mut proxy = Proxy::start(&p).await.unwrap();
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("world:{}", proxy.credential))
        );
        for (ip, credential, destination, status) in [
            ("127.0.0.1", "bad", target.to_string(), 407),
            ("::1", auth.as_str(), "127.0.0.1:1".into(), 403),
        ] {
            let mut c = TcpStream::connect((ip, proxy.port())).await.unwrap();
            c.write_all(format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: {credential}\r\n\r\n").as_bytes()).await.unwrap();
            let mut buf = [0; 1024];
            let n = c.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains(&status.to_string()));
        }
        let mut c = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        c.write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {auth}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = [0; 1024];
        let n = c.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200"));
        c.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        c.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ping");
        proxy.close().await;
        assert_eq!(c.read(&mut buf).await.unwrap_or(0), 0);
        server.await.unwrap();
        assert!(TcpStream::connect(("::1", proxy.port())).await.is_err());
    }
}
