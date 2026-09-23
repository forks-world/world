use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{io::Read, net::IpAddr};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub network_id: String,
    #[serde(default)]
    pub allow: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Policy {
    pub fn read(input: impl Read) -> Result<Self> {
        let mut data = Vec::new();
        input.take(65537).read_to_end(&mut data)?;
        if data.len() > 65536 {
            bail!("policy exceeds 64 KiB");
        }
        let value: Self = serde_json::from_slice(&data)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.network_id.is_empty()
            || self.network_id.len() > 128
            || self.network_id.contains(['\0', '\r', '\n'])
        {
            bail!("invalid network_id");
        }
        if self.allow.len() > 256 {
            bail!("at most 256 destinations allowed");
        }
        for endpoint in &self.allow {
            canonical_host(&endpoint.host)?;
            if endpoint.port == 0 {
                bail!("destination port must be positive");
            }
        }
        Ok(())
    }
}

pub fn canonical_host(input: &str) -> Result<String> {
    if let Ok(ip) = input.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            bail!("unsupported destination IP");
        }
        return Ok(match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(|v| v.to_string())
                .unwrap_or(ip.to_string()),
            _ => ip.to_string(),
        });
    }
    let host = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        bail!("invalid destination host");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("invalid destination host");
        }
    }
    Ok(host)
}

pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_policy() {
        for input in [
            "{}",
            "null",
            r#"{"network_id":"a","unknown":true}"#,
            r#"{"network_id":"a"} {}"#,
            r#"{"network_id":"a","allow":[{"host":"*","port":80}]}"#,
            r#"{"network_id":"a","allow":[{"host":"x","port":0}]}"#,
        ] {
            assert!(Policy::read(input.as_bytes()).is_err(), "{input}");
        }
        assert!(Policy::read(br#"{"network_id":"a","allow":[]}"#.as_slice()).is_ok());
    }
}
