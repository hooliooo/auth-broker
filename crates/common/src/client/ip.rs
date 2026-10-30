//! The client's IP address: the connection's, or the one a trusted proxy names in a header
//! (behind the ingress or a CDN, e.g. `cf-connecting-ip`), for rate limiting and the
//! `X-Forwarded-For` the API receives.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use axum::http::{HeaderMap, HeaderName};

use thiserror::Error;

/// Why the client IP settings were refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientIpError {
    /// The named setting is malformed.
    #[error("setting {0} is invalid")]
    InvalidSetting(&'static str),
    /// A client IP header without trusted proxies: anyone could set it.
    #[error("CLIENT_IP_HEADER needs TRUSTED_PROXIES, or anyone could set it")]
    UntrustedClientIpHeader,
}

/// A range of addresses, e.g. `10.42.0.0/16`; a single address is a range of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    /// First address of the range.
    network: IpAddr,
    /// Number of leading bits an address must share with `network`.
    prefix: u8,
}

impl IpRange {
    /// Whether `ip` lies in this range. IPv4 and IPv6 never match each other.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => matches_prefix(
                network.to_bits().into(),
                ip.to_bits().into(),
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                matches_prefix(network.to_bits(), ip.to_bits(), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// Whether `a` and `b` share their first `prefix` bits, both `width` bits wide.
fn matches_prefix(a: u128, b: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(width - prefix);
    (a >> shift) == (b >> shift)
}

impl FromStr for IpRange {
    type Err = ();

    /// Parses `s` as `address/prefix` or a bare `address`.
    fn from_str(s: &str) -> Result<Self, ()> {
        let (address, prefix) = s.trim().split_once('/').unwrap_or((s.trim(), ""));
        let network: IpAddr = address.parse().map_err(|_| ())?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix.is_empty() {
            width
        } else {
            prefix.parse().map_err(|_| ())?
        };
        if prefix > width {
            return Err(());
        }
        Ok(Self {
            network: network.to_canonical(),
            prefix,
        })
    }
}

/// Where the client's address comes from: the connection, or a header set by a trusted proxy.
#[derive(Clone, Debug, Default)]
pub struct ClientIpSource {
    /// Header holding the client's address, e.g. `cf-connecting-ip`; `None` uses the connection.
    header: Option<HeaderName>,
    /// Connections whose `header` is believed; from anywhere else it is ignored.
    trusted_proxies: Vec<IpRange>,
}

impl ClientIpSource {
    /// Builds the source from the `header` setting and the comma-separated `trusted_proxies`
    /// setting. A header without trusted proxies is refused: anyone could then set it.
    pub fn from_settings(
        header: Option<&str>,
        trusted_proxies: Option<&str>,
    ) -> Result<Self, ClientIpError> {
        let header = header
            .map(|name| {
                HeaderName::try_from(name)
                    .map_err(|_| ClientIpError::InvalidSetting("CLIENT_IP_HEADER"))
            })
            .transpose()?;
        let trusted_proxies = trusted_proxies
            .unwrap_or_default()
            .split(',')
            .filter(|range| !range.trim().is_empty())
            .map(|range| {
                range
                    .parse()
                    .map_err(|()| ClientIpError::InvalidSetting("TRUSTED_PROXIES"))
            })
            .collect::<Result<Vec<IpRange>, _>>()?;
        if header.is_some() && trusted_proxies.is_empty() {
            return Err(ClientIpError::UntrustedClientIpHeader);
        }
        Ok(Self {
            header,
            trusted_proxies,
        })
    }

    /// The client's address for a request with `headers` over a connection from `peer`: the
    /// header's address if `peer` is a trusted proxy and the header holds a valid IP, otherwise
    /// `peer`'s own address.
    pub fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        let peer_ip = peer.ip().to_canonical();
        let from_trusted_proxy = self
            .trusted_proxies
            .iter()
            .any(|range| range.contains(peer_ip));
        self.header
            .as_ref()
            .filter(|_| from_trusted_proxy)
            .and_then(|name| headers.get(name))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map_or(peer_ip, |ip| ip.to_canonical())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// `s` parsed as a range.
    fn range(s: &str) -> IpRange {
        s.parse().unwrap()
    }

    /// Request headers with `cf-connecting-ip` set to `value`.
    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_str(value).unwrap());
        headers
    }

    /// A connection from `ip`.
    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 40_000)
    }

    /// A source reading `cf-connecting-ip` from proxies in `trusted`.
    fn behind_proxy(trusted: &str) -> ClientIpSource {
        ClientIpSource::from_settings(Some("cf-connecting-ip"), Some(trusted)).unwrap()
    }

    #[test]
    fn given_ranges_then_membership_follows_the_prefix() {
        assert!(range("10.42.0.0/16").contains("10.42.200.1".parse().unwrap()));
        assert!(!range("10.42.0.0/16").contains("10.43.0.1".parse().unwrap()));
        assert!(range("172.30.0.1").contains("172.30.0.1".parse().unwrap()));
        assert!(!range("172.30.0.1").contains("172.30.0.2".parse().unwrap()));
        assert!(range("0.0.0.0/0").contains("203.0.113.9".parse().unwrap()));
        assert!(range("2400:cb00::/32").contains("2400:cb00:1::7".parse().unwrap()));
        assert!(!range("2400:cb00::/32").contains("10.0.0.1".parse().unwrap()));
        assert!(range("10.0.0.0/8").contains("::ffff:10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn given_malformed_ranges_then_they_are_refused() {
        for bad in ["10.0.0.0/33", "::/129", "not-an-ip", "10.0.0.0/x"] {
            assert!(bad.parse::<IpRange>().is_err(), "{bad}");
        }
    }

    #[test]
    fn given_a_trusted_proxy_then_the_header_is_used() {
        let source = behind_proxy("10.42.0.0/16");
        let ip = source.client_ip(&headers("203.0.113.7"), peer("10.42.0.9"));
        assert_eq!(ip, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_a_connection_from_elsewhere_then_the_header_is_ignored() {
        let source = behind_proxy("10.42.0.0/16");
        let ip = source.client_ip(&headers("203.0.113.7"), peer("198.51.100.4"));
        assert_eq!(ip, "198.51.100.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_no_header_setting_then_the_connection_is_used() {
        let source = ClientIpSource::from_settings(None, None).unwrap();
        let ip = source.client_ip(&headers("203.0.113.7"), peer("10.42.0.9"));
        assert_eq!(ip, "10.42.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_a_header_that_is_not_an_ip_then_the_connection_is_used() {
        let source = behind_proxy("10.42.0.0/16");
        let ip = source.client_ip(&headers("not-an-ip"), peer("10.42.0.9"));
        assert_eq!(ip, "10.42.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_a_header_without_trusted_proxies_then_startup_is_refused() {
        assert!(matches!(
            ClientIpSource::from_settings(Some("cf-connecting-ip"), None),
            Err(ClientIpError::UntrustedClientIpHeader)
        ));
        assert!(matches!(
            ClientIpSource::from_settings(Some("cf-connecting-ip"), Some("10.0.0.0/40")),
            Err(ClientIpError::InvalidSetting("TRUSTED_PROXIES"))
        ));
    }
}
