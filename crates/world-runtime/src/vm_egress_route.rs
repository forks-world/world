//! macOS routing validation for the offline VM's host-side proxy.
use anyhow::{Result, anyhow, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Debug, PartialEq, Eq)]
struct Route {
    interface: String,
    gateway: IpAddr,
}

#[cfg(any(target_os = "macos", test))]
fn parse_route(output: &str, ipv4: bool, target: Option<IpAddr>, scoped: bool) -> Result<Route> {
    fn field<'a>(output: &'a str, key: &str) -> Option<&'a str> {
        let mut found = output
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix(key))
            .map(str::trim);
        let value = found.next()?;
        found.next().is_none().then_some(value)
    }

    let reject = || anyhow!("VM egress requires the physical default route");
    let interface = field(output, "interface:").ok_or_else(reject)?;
    let ethernet = interface.strip_prefix("en").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    });
    let flags = field(output, "flags:")
        .and_then(|flags| flags.strip_prefix('<'))
        .and_then(|flags| flags.strip_suffix('>'))
        .ok_or_else(reject)?;
    let has_flag = |flag| flags.split(',').any(|item| item == flag);
    let destination = field(output, "destination:").ok_or_else(reject)?;
    let zero = if ipv4 { "0.0.0.0" } else { "::" };
    let default = (destination == "default" || destination == zero)
        && field(output, "mask:").is_some_and(|mask| mask == "default" || mask == zero)
        && !has_flag("HOST");
    let cloned = target.is_some()
        && destination.parse::<IpAddr>().ok() == target
        && has_flag("HOST")
        && has_flag("WASCLONED")
        && !has_flag("STATIC");
    if !ethernet
        || (!default && !cloned)
        || !["UP", "GATEWAY"].into_iter().all(has_flag)
        || ["REJECT", "BLACKHOLE", "LOCAL", "DYNAMIC", "MODIFIED"]
            .into_iter()
            .any(has_flag)
        || (has_flag("IFSCOPE") && !scoped && !cloned)
    {
        return Err(reject());
    }
    let raw = field(output, "gateway:").ok_or_else(reject)?;
    let gateway = match raw.split_once('%') {
        Some((ip, scope)) if !ipv4 && scope == interface => ip,
        Some(_) => return Err(reject()),
        None => raw,
    };
    let gateway = gateway.parse::<IpAddr>().map_err(|_| reject())?;
    if gateway.is_ipv4() != ipv4
        || gateway.is_unspecified()
        || gateway.is_loopback()
        || gateway.is_multicast()
    {
        return Err(reject());
    }
    Ok(Route {
        interface: interface.into(),
        gateway,
    })
}

#[cfg(target_os = "macos")]
async fn route(ipv4: bool, destination: &str, scope: Option<&str>) -> Result<Option<Route>> {
    let family = if ipv4 { "-inet" } else { "-inet6" };
    let mut command = tokio::process::Command::new("/sbin/route");
    command
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .args(["-n", "get", family]);
    if let Some(interface) = scope {
        command.args(["-ifscope", interface]);
    }
    let output =
        tokio::time::timeout(Duration::from_secs(1), command.arg(destination).output()).await??;
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    // route(8) can report a failed kernel lookup with a successful exit code.
    if stdout.trim().is_empty() && stderr.contains("not in table") {
        return Ok(None);
    }
    if !output.status.success() || !stderr.trim().is_empty() {
        bail!("VM egress could not query the host route");
    }
    Ok(Some(parse_route(
        stdout,
        ipv4,
        destination.parse().ok(),
        scope.is_some(),
    )?))
}

#[cfg(not(target_os = "macos"))]
async fn route(_ipv4: bool, _destination: &str, _scope: Option<&str>) -> Result<Option<Route>> {
    bail!("VM egress route validation requires macOS")
}

#[cfg(any(target_os = "macos", test))]
fn specific_route(table: &str, address: IpAddr) -> Result<bool> {
    let mut lines = table.lines().skip_while(|line| {
        !line
            .split_whitespace()
            .eq(["Destination", "Gateway", "Flags", "Netif", "Expire"])
    });
    if lines.next().is_none() {
        bail!("VM egress could not read the host routing table");
    }
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let (Some(destination), Some(_), Some(flags), Some(_)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            bail!("invalid macOS route table row");
        };
        if destination == "default" {
            continue;
        }
        // Ignore only generated gateway host routes. A more-specific parent
        // remains visible in the all-routes dump and is checked independently.
        if flags.contains('W')
            && flags.contains('H')
            && flags.contains('G')
            && !['S', 'D', 'M'].into_iter().any(|flag| flags.contains(flag))
        {
            continue;
        }
        let (network, width) = destination
            .split_once('/')
            .map_or((destination, None), |(ip, prefix)| (ip, Some(prefix)));
        let network = network.split('%').next().unwrap_or(network);
        let overlaps = match address {
            IpAddr::V4(address) => {
                // macOS abbreviates IPv4 routes with trailing zero octets.
                let mut octets = [0u8; 4];
                let mut count = 0;
                for (i, octet) in network.split('.').enumerate() {
                    *octets
                        .get_mut(i)
                        .ok_or_else(|| anyhow!("invalid IPv4 route"))? = octet.parse()?;
                    count += 1;
                }
                let bits: u32 = width.map(str::parse).transpose()?.unwrap_or(count * 8);
                if bits > 32 {
                    bail!("invalid IPv4 route width");
                }
                bits != 0 && (u32::from(address) ^ u32::from_be_bytes(octets)) >> (32 - bits) == 0
            }
            IpAddr::V6(address) => {
                let network: std::net::Ipv6Addr = network.parse()?;
                let bits: u32 = width.map(str::parse).transpose()?.unwrap_or(128);
                if bits > 128 {
                    bail!("invalid IPv6 route width");
                }
                bits != 0 && (u128::from(address) ^ u128::from(network)) >> (128 - bits) == 0
            }
        };
        if overlaps {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
async fn reject_specific_route(address: IpAddr) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::process::Command::new("/usr/sbin/netstat")
            .kill_on_drop(true)
            .env("LC_ALL", "C")
            .args([
                "-rnaW",
                "-f",
                if address.is_ipv4() { "inet" } else { "inet6" },
            ])
            .output(),
    )
    .await??;
    if !output.status.success() || specific_route(std::str::from_utf8(&output.stdout)?, address)? {
        bail!("VM egress rejects destinations with a more-specific host route");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn reject_specific_route(_address: IpAddr) -> Result<()> {
    bail!("VM egress route validation requires macOS")
}

#[cfg(target_os = "macos")]
async fn require_hardware_interface(interface: &str) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::process::Command::new("/usr/sbin/networksetup")
            .kill_on_drop(true)
            .env("LC_ALL", "C")
            .arg("-listallhardwareports")
            .output(),
    )
    .await??;
    if !output.status.success()
        || !std::str::from_utf8(&output.stdout)?.lines().any(|line| {
            line.strip_prefix("Device: ")
                .is_some_and(|name| name.trim() == interface)
        })
    {
        bail!("VM egress could not verify the default route's hardware interface");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn require_hardware_interface(_interface: &str) -> Result<()> {
    bail!("VM egress route validation requires macOS")
}

fn interface_index(route: &Route) -> Result<u32> {
    let interface = std::ffi::CString::new(route.interface.as_str())?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        bail!("VM egress interface disappeared");
    }
    Ok(index)
}

struct Pin {
    route: Route,
    index: u32,
}

impl Pin {
    fn confirm(
        &self,
        default: Option<&Route>,
        effective: Option<&Route>,
        scoped: Option<&Route>,
        index: u32,
    ) -> Result<()> {
        if default != Some(&self.route)
            || effective != default
            || scoped != default
            || index != self.index
        {
            bail!("VM egress route changed");
        }
        Ok(())
    }
}

pub(crate) struct PinnedRoutes {
    pins: HashMap<IpAddr, Pin>,
    revoked: CancellationToken,
    #[cfg(test)]
    fixture: Option<(SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
}

impl PinnedRoutes {
    pub(crate) async fn prepare(routes: &mut HashMap<String, Vec<SocketAddr>>) -> Result<Self> {
        use std::collections::HashSet;
        let families: HashSet<_> = routes
            .values_mut()
            .flat_map(|addresses| {
                for address in addresses.iter_mut() {
                    if let SocketAddr::V6(v6) = address
                        && let Some(ip) = v6.ip().to_ipv4_mapped()
                    {
                        *address = SocketAddr::new(ip.into(), address.port());
                    }
                }
                addresses.iter().map(|address| address.is_ipv4())
            })
            .collect();
        let mut defaults = HashMap::new();
        for ipv4 in families {
            let default = route(ipv4, "default", None).await?;
            if let Some(default) = &default {
                require_hardware_interface(&default.interface).await?;
            }
            defaults.insert(ipv4, default);
        }
        let mut pins = HashMap::new();
        for (authority, addresses) in routes {
            // A family with no default route is excluded for this session.
            addresses.retain(|address| {
                defaults
                    .get(&address.is_ipv4())
                    .is_some_and(Option::is_some)
            });
            if addresses.is_empty() {
                bail!("VM egress has no usable default route for {authority}");
            }
            for address in addresses {
                if let std::collections::hash_map::Entry::Vacant(entry) = pins.entry(address.ip()) {
                    let Some(default) = &defaults[&address.is_ipv4()] else {
                        bail!("VM egress lost its default route");
                    };
                    let destination = address.ip().to_string();
                    let (effective, scoped, ()) = tokio::try_join!(
                        route(address.is_ipv4(), &destination, None),
                        route(address.is_ipv4(), &destination, Some(&default.interface)),
                        reject_specific_route(address.ip()),
                    )?;
                    if effective.as_ref() != Some(default)
                        || scoped.as_ref() != Some(default)
                        || address.ip() == default.gateway
                    {
                        bail!("VM egress target does not use the verified default route");
                    }
                    entry.insert(Pin {
                        index: interface_index(default)?,
                        route: Route {
                            interface: default.interface.clone(),
                            gateway: default.gateway,
                        },
                    });
                }
            }
        }
        Ok(Self {
            pins,
            revoked: CancellationToken::new(),
            #[cfg(test)]
            fixture: None,
        })
    }

    pub(crate) fn revocation(&self) -> &CancellationToken {
        &self.revoked
    }

    async fn confirm_current(&self, address: SocketAddr) -> Result<u32> {
        #[cfg(test)]
        if let Some((affected, changed)) = &self.fixture {
            anyhow::ensure!(
                address != *affected || !changed.load(std::sync::atomic::Ordering::SeqCst),
                "VM egress route changed"
            );
            return Ok(0);
        }
        crate::vm_egress::require_public_destinations(&[address])?;
        let pin = self
            .pins
            .get(&address.ip())
            .ok_or_else(|| anyhow!("VM egress target has no pinned route"))?;
        let destination = address.ip().to_string();
        let (default, effective, scoped, ()) = tokio::try_join!(
            route(address.is_ipv4(), "default", None),
            route(address.is_ipv4(), &destination, None),
            route(address.is_ipv4(), &destination, Some(&pin.route.interface)),
            reject_specific_route(address.ip()),
        )?;
        pin.confirm(
            default.as_ref(),
            effective.as_ref(),
            scoped.as_ref(),
            interface_index(&pin.route)?,
        )?;
        Ok(pin.index)
    }

    async fn current(&self, address: SocketAddr) -> Result<u32> {
        let result = tokio::select! {
            biased;
            _ = self.revoked.cancelled() => bail!("VM egress route authorization was revoked"),
            result = self.confirm_current(address) => result,
        };
        if result.is_err() {
            self.revoked.cancel();
        }
        let index = result?;
        anyhow::ensure!(
            !self.revoked.is_cancelled(),
            "VM egress route authorization was revoked"
        );
        Ok(index)
    }

    fn bound_socket(&self, address: SocketAddr, index: u32) -> Result<tokio::net::TcpSocket> {
        #[cfg(test)]
        if self.fixture.is_some() {
            return Ok(tokio::net::TcpSocket::new_v4()?);
        }
        bind_interface(address, index)
    }

    pub(crate) async fn connect(&self, address: SocketAddr) -> Result<Option<TcpStream>> {
        let index = self.current(address).await?;
        let socket = self
            .bound_socket(address, index)
            .inspect_err(|_| self.revoked.cancel())?;
        let connected = tokio::select! {
            biased;
            _ = self.revoked.cancelled() => bail!("VM egress route authorization was revoked"),
            result = tokio::time::timeout(Duration::from_secs(5), socket.connect(address)) => result,
        };
        // Confirm the route again before the proxy transfers application data.
        self.current(address).await?;
        Ok(connected.ok().and_then(Result::ok))
    }

    pub(crate) async fn wait_for_change(&self, address: SocketAddr) {
        tokio::select! {
            biased;
            _ = self.revoked.cancelled() => {},
            _ = watch_route(Duration::from_secs(2), || async {
                self.current(address).await.is_ok()
            }) => {},
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        affected: SocketAddr,
    ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let changed = std::sync::Arc::default();
        (
            Self {
                pins: HashMap::new(),
                revoked: CancellationToken::new(),
                fixture: Some((affected, std::sync::Arc::clone(&changed))),
            },
            changed,
        )
    }
}

async fn watch_route<F: std::future::Future<Output = bool>>(
    period: Duration,
    mut still_valid: impl FnMut() -> F,
) {
    loop {
        tokio::time::sleep(period).await;
        if !still_valid().await {
            return;
        }
    }
}

#[cfg(target_os = "macos")]
fn bind_interface(address: SocketAddr, index: u32) -> Result<tokio::net::TcpSocket> {
    use std::os::fd::AsRawFd;
    let (socket, level, option) = if address.is_ipv4() {
        (
            tokio::net::TcpSocket::new_v4()?,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
        )
    } else {
        (
            tokio::net::TcpSocket::new_v6()?,
            libc::IPPROTO_IPV6,
            libc::IPV6_BOUND_IF,
        )
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(socket)
}

#[cfg(not(target_os = "macos"))]
fn bind_interface(_address: SocketAddr, _index: u32) -> Result<tokio::net::TcpSocket> {
    bail!("VM egress interface binding requires macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "route to: 1.1.1.1\ndestination: default\nmask: default\n gateway: 10.2.0.1\n interface: en0\n flags: <UP,GATEWAY,DONE,STATIC,GLOBAL>";

    fn default_route(output: &str, ipv4: bool) -> Result<Route> {
        parse_route(output, ipv4, None, false)
    }

    #[test]
    fn cloned_lookup_cannot_hide_a_more_specific_parent_route() {
        let address: IpAddr = "1.1.1.1".parse().unwrap();
        let clone = "route to: 1.1.1.1
 destination: 1.1.1.1
 gateway: 10.2.0.1
 interface: en0
 flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE>";
        assert!(parse_route(clone, true, Some(address), true).is_ok());
        assert!(
            parse_route(
                &clone.replace("WASCLONED", "STATIC"),
                true,
                Some(address),
                true
            )
            .is_err()
        );
        let prefix = "Destination Gateway Flags Netif Expire
default 10.2.0.1 UGScg en0
1.1.1.1 10.2.0.1 UGHWIi en0
127 link#1 UCS lo0
";
        assert!(!specific_route(prefix, address).unwrap());
        assert!(specific_route(&format!("{prefix}1.1.1/24 10.2.0.1 UGSc en0"), address).unwrap());
        assert!(specific_route(&format!("{prefix}1.1/16 link#18 UCS utun2"), address).unwrap());
        assert!(specific_route(&format!("{prefix}1.1.1.1 10.2.0.2 UGHS en0"), address).unwrap());
        let v6 = "Destination Gateway Flags Netif Expire
default fe80::1%en0 UG en0
2606:4700::%utun2/32 fe80::1%utun2 UGS utun2";
        assert!(specific_route(v6, "2606:4700:4700::1111".parse().unwrap()).unwrap());
    }

    #[test]
    fn checks_route_prefix_interface_and_flags_together() {
        let initial = default_route(DEFAULT, true).unwrap();
        for replaced in [
            DEFAULT.replace("destination: default", "destination: 1.1.1.0"),
            DEFAULT.replace("mask: default", "mask: 255.255.255.0"),
            DEFAULT.replace("interface: en0", "interface: utun4"),
            DEFAULT.replace("UP,GATEWAY", "UP,HOST"),
            DEFAULT.replace("UP,GATEWAY", "UP,GATEWAY,REJECT"),
            DEFAULT.replace("UP,GATEWAY", "UP,GATEWAY,BLACKHOLE"),
            DEFAULT.replace("UP,GATEWAY", "UP,GATEWAY,DYNAMIC"),
            DEFAULT.replace("UP,GATEWAY", "UP,GATEWAY,IFSCOPE"),
        ] {
            assert!(default_route(&replaced, true).is_err(), "{replaced}");
        }
        assert_ne!(
            initial,
            default_route(&DEFAULT.replace("10.2.0.1", "10.2.0.2"), true).unwrap()
        );
        assert_ne!(
            initial,
            default_route(&DEFAULT.replace("en0", "en1"), true).unwrap()
        );
    }

    #[test]
    fn rejects_changes_to_default_scoped_route_and_interface_identity() {
        let pin = Pin {
            route: default_route(DEFAULT, true).unwrap(),
            index: 6,
        };
        let other = default_route(&DEFAULT.replace("10.2.0.1", "10.2.0.2"), true).unwrap();
        let saved = Some(&pin.route);
        assert!(pin.confirm(saved, saved, saved, 6).is_ok());
        assert!(pin.confirm(Some(&other), saved, saved, 6).is_err());
        assert!(pin.confirm(saved, Some(&other), saved, 6).is_err());
        assert!(pin.confirm(saved, saved, Some(&other), 6).is_err());
        assert!(pin.confirm(saved, saved, None, 6).is_err());
        assert!(pin.confirm(saved, saved, saved, 7).is_err());
    }

    #[tokio::test]
    async fn watcher_stops_on_the_first_route_change() {
        use std::cell::Cell;
        let pin = Pin {
            route: default_route(DEFAULT, true).unwrap(),
            index: 6,
        };
        let changed = default_route(&DEFAULT.replace("10.2.0.1", "10.2.0.2"), true).unwrap();
        let polls = Cell::new(0);
        let query = || async {
            polls.set(polls.get() + 1);
            let previous = Some(&pin.route);
            let current = if polls.get() == 1 {
                previous
            } else {
                Some(&changed)
            };
            pin.confirm(current, current, current, 6).is_ok()
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            watch_route(Duration::from_millis(1), query),
        )
        .await
        .unwrap();
        assert_eq!(polls.get(), 2);
    }

    #[test]
    fn ipv6_gateway_must_belong_to_the_verified_interface() {
        let sample = DEFAULT.replace("10.2.0.1", "fe80::1%en0");
        assert!(default_route(&sample, false).is_ok());
        assert!(default_route(&sample, true).is_err());
        assert!(default_route(&sample.replace("%en0", "%utun3"), false).is_err());
    }
}
