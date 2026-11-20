//! Destination checks for a proxy attached to a VM without a network interface.
use anyhow::{Result, bail, ensure};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};

pub(crate) fn dns_name(host: &str) -> Result<String> {
    ensure!(
        host.contains('.')
            && !["local", "localhost", "internal", "home.arpa"]
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}"))),
        "VM egress requires a public DNS name: {host}"
    );
    // An absolute name avoids resolver search domains on the host.
    Ok(format!("{host}."))
}

#[derive(Debug)]
struct LocalNetwork {
    address: IpAddr,
    mask: Option<IpAddr>,
}

impl LocalNetwork {
    fn contains(&self, target: IpAddr) -> bool {
        let target = match target {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(target, IpAddr::V4),
            _ => target,
        };
        if self.address == target {
            return true;
        }
        match (self.address, self.mask, target) {
            (IpAddr::V4(local), Some(IpAddr::V4(mask)), IpAddr::V4(target)) => {
                (u32::from(local) ^ u32::from(target)) & u32::from(mask) == 0
            }
            (IpAddr::V6(local), Some(IpAddr::V6(mask)), IpAddr::V6(target)) => {
                (u128::from(local) ^ u128::from(target)) & u128::from(mask) == 0
            }
            _ => false,
        }
    }
}

struct InterfaceList(*mut libc::ifaddrs);

impl Drop for InterfaceList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

/// A non-null pointer from getifaddrs has the layout indicated by sa_family.
unsafe fn ip_address(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family } as libc::c_int {
        libc::AF_INET => {
            #[cfg(target_os = "macos")]
            if usize::from(unsafe { (*address).sa_len }) < std::mem::size_of::<libc::sockaddr_in>()
            {
                return None;
            }
            let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Some(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into())
        }
        libc::AF_INET6 => {
            #[cfg(target_os = "macos")]
            if usize::from(unsafe { (*address).sa_len }) < std::mem::size_of::<libc::sockaddr_in6>()
            {
                return None;
            }
            let address = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Some(Ipv6Addr::from(address.sin6_addr.s6_addr).into())
        }
        _ => None,
    }
}

fn local_networks() -> io::Result<Vec<LocalNetwork>> {
    let mut head = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = InterfaceList(head);
    let mut networks = Vec::new();
    let mut current = list.0;
    while let Some(interface) = unsafe { current.as_ref() } {
        if let Some(address) = unsafe { ip_address(interface.ifa_addr) } {
            let mask = unsafe { ip_address(interface.ifa_netmask) };
            if crate::proxy::public_ip(address)
                && !mask.is_some_and(|value| value.is_ipv4() == address.is_ipv4())
            {
                return Err(io::Error::other(
                    "missing host subnet mask for a public interface",
                ));
            }
            networks.push(LocalNetwork { address, mask });
        }
        current = interface.ifa_next;
    }
    Ok(networks)
}

fn validate_destinations(addresses: &[SocketAddr], local: &[LocalNetwork]) -> Result<()> {
    ensure!(
        !addresses.is_empty(),
        "VM egress found no destination addresses"
    );
    for address in addresses {
        if matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0)
            || !crate::proxy::public_ip(address.ip())
            || local.iter().any(|network| network.contains(address.ip()))
        {
            bail!("VM egress destination {address} is non-public or on a local host network");
        }
    }
    Ok(())
}

pub(crate) fn require_public_destinations(addresses: &[SocketAddr]) -> Result<()> {
    validate_destinations(addresses, &local_networks()?)
}

#[cfg(test)]
pub(crate) fn require_public_ip_only_for_test(addresses: &[SocketAddr]) -> Result<()> {
    validate_destinations(addresses, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_mixed_and_locally_routed_addresses() {
        let networks = [
            LocalNetwork {
                address: "8.8.8.5".parse().unwrap(),
                mask: Some("255.255.255.0".parse().unwrap()),
            },
            LocalNetwork {
                address: "2606:4700:42::9".parse().unwrap(),
                mask: Some("ffff:ffff:ffff:ffff::".parse().unwrap()),
            },
        ];
        let allowed = "1.1.1.1:443".parse().unwrap();
        assert!(validate_destinations(&[allowed], &networks).is_ok());
        for address in [
            "127.0.0.1:443",
            "192.168.64.1:443",
            "8.8.8.8:443",
            "[::ffff:8.8.8.8]:443",
            "[::1]:443",
            "[fd00::1]:443",
            "[2606:4700:42::1]:443",
        ] {
            let rejected = address.parse().unwrap();
            assert!(validate_destinations(&[allowed, rejected], &networks).is_err());
        }
    }

    #[test]
    fn dns_uses_absolute_public_names() {
        assert_eq!(dns_name("example.com").unwrap(), "example.com.");
        for name in [
            "printer",
            "printer.local",
            "foo.home.arpa",
            "a.localhost",
            "a.internal",
        ] {
            assert!(dns_name(name).is_err(), "{name}");
        }
    }
}
