//! The gate every outbound request passes through.
//!
//! A service that fetches whatever URL it is handed is a weapon pointed at its
//! own network unless something stops it. The classic abuse is not the obvious
//! `http://127.0.0.1` — it is `http://169.254.169.254`, the cloud metadata
//! address, which on an unguarded host hands back the machine's own credentials.
//! Private ranges, loopback and link-local are all the same shape of attack:
//! make the server reach somewhere the caller could not reach themselves.
//!
//! So this classifies a resolved address and refuses the ones that point inward.
//! Two properties matter and are kept deliberately separate:
//!
//! [`forbidden`] is a pure function of an `IpAddr`. It touches no network and no
//! clock, so it can be tested exhaustively, which is the whole point: a guard
//! you cannot enumerate is a guard you cannot trust.
//!
//! [`resolve_and_check`] is where a hostname becomes addresses and each is run
//! through [`forbidden`]. It resolves once and reports every address it found,
//! so the caller can connect to a vetted IP rather than to the name — resolving
//! again at connect time is exactly the gap a rebinding attack drives through.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// Why an address was refused, in words fit to show a person.
///
/// A blocked scan should say which rule caught it, both so a legitimate target
/// on an odd network can be understood and so the guard's behaviour is legible
/// rather than a flat "no".
pub type Reason = &'static str;

/// The reason an address is refused, or `None` when it may be reached.
///
/// Every branch is explicit rather than leaning on the standard library's
/// `is_private` and friends. A security control should say exactly what it
/// blocks and why, and several of the ranges that matter here — carrier-grade
/// NAT, benchmarking, the metadata address — are not covered by the stable
/// helpers anyway.
pub fn forbidden(ip: IpAddr) -> Option<Reason> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<Reason> {
    match ip.octets() {
        // 0.0.0.0/8: "this network". Routes to the local host on many stacks.
        [0, ..] => Some("unspecified address (0.0.0.0/8)"),
        // 127.0.0.0/8: loopback, the server talking to itself.
        [127, ..] => Some("loopback (127.0.0.0/8)"),
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16: private networks.
        [10, ..] => Some("private network (10.0.0.0/8)"),
        [172, x, ..] if (16..=31).contains(&x) => Some("private network (172.16.0.0/12)"),
        [192, 168, ..] => Some("private network (192.168.0.0/16)"),
        // 169.254.0.0/16: link-local, and with it 169.254.169.254, the cloud
        // metadata endpoint. The single most important line here.
        [169, 254, ..] => Some("link-local, includes cloud metadata (169.254.0.0/16)"),
        // 100.64.0.0/10: carrier-grade NAT, a provider's internal space.
        [100, x, ..] if (64..=127).contains(&x) => Some("carrier-grade NAT (100.64.0.0/10)"),
        // 192.0.0.0/24 and 192.0.2.0/24: IETF protocol assignments and TEST-NET.
        [192, 0, 0, _] => Some("IETF protocol assignment (192.0.0.0/24)"),
        [192, 0, 2, _] => Some("documentation range (192.0.2.0/24)"),
        [198, 51, 100, _] => Some("documentation range (198.51.100.0/24)"),
        [203, 0, 113, _] => Some("documentation range (203.0.113.0/24)"),
        // 198.18.0.0/15: benchmarking.
        [198, x, ..] if (18..=19).contains(&x) => Some("benchmarking range (198.18.0.0/15)"),
        // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved, up to the broadcast
        // address. Nothing a scan should ever be aimed at.
        [224..=239, ..] => Some("multicast (224.0.0.0/4)"),
        [255, 255, 255, 255] => Some("broadcast address"),
        [240..=255, ..] => Some("reserved (240.0.0.0/4)"),
        _ => None,
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<Reason> {
    // An IPv4 address wearing an IPv6 coat. ::ffff:169.254.169.254 reaches the
    // metadata endpoint as surely as the bare v4 does, so it is unwrapped and
    // judged as what it is. `to_ipv4_mapped` is exactly this and nothing else,
    // so it does not misread a native v6 address as v4.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return forbidden_v4(v4);
    }

    if ip.is_unspecified() {
        return Some("unspecified address (::)");
    }
    if ip.is_loopback() {
        return Some("loopback (::1)");
    }

    let first = ip.segments()[0];

    // fe80::/10 link-local.
    if first & 0xffc0 == 0xfe80 {
        return Some("link-local (fe80::/10)");
    }
    // fc00::/7 unique local, the v6 equivalent of a private network.
    if first & 0xfe00 == 0xfc00 {
        return Some("unique local address (fc00::/7)");
    }
    // ff00::/8 multicast.
    if first & 0xff00 == 0xff00 {
        return Some("multicast (ff00::/8)");
    }
    // Deprecated IPv4-compatible addresses (::a.b.c.d) tunnel to a v4 host and
    // are another way to smuggle a private target past a v6-only check.
    let [.., c, d] = ip.segments();
    if ip.segments()[..6].iter().all(|&s| s == 0) && ip != Ipv6Addr::LOCALHOST {
        let v4 = Ipv4Addr::new(
            (c >> 8) as u8,
            (c & 0xff) as u8,
            (d >> 8) as u8,
            (d & 0xff) as u8,
        );
        return forbidden_v4(v4).or(Some("IPv4-compatible IPv6 address"));
    }

    None
}

/// What a hostname resolved to, and whether it may be scanned.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// Every address the name resolved to, paired with the reason it is blocked
    /// if it is. All of them are reported, not just the first, because a name
    /// that resolves to one public and one private address is a rebinding
    /// attempt and the whole set has to be seen to catch it.
    pub addresses: Vec<(IpAddr, Option<Reason>)>,
}

impl Resolved {
    /// The reason to refuse the whole name, or `None` when every address it
    /// resolved to is safe to reach.
    ///
    /// One forbidden address condemns the name. A host that answers with a
    /// public address now and a private one at connect time has defeated a
    /// check that only looked at the first, so any inward-pointing answer is
    /// enough to stop here.
    pub fn blocked(&self) -> Option<Reason> {
        self.addresses.iter().find_map(|(_, reason)| *reason)
    }

    /// The vetted addresses, for a caller that will connect to an IP rather than
    /// re-resolve the name. Empty when anything was blocked, since a partial
    /// answer is not something to act on.
    pub fn safe_addresses(&self) -> Vec<IpAddr> {
        if self.blocked().is_some() {
            return Vec::new();
        }
        self.addresses.iter().map(|(ip, _)| *ip).collect()
    }
}

/// Resolves a host and classifies every address behind it.
///
/// The port is required by the resolver and otherwise unused. Resolution is the
/// one blocking, network-touching step in this module and is kept apart from the
/// classification so the classification stays pure and testable.
pub fn resolve_and_check(host: &str, port: u16) -> std::io::Result<Resolved> {
    let addresses = (host, port)
        .to_socket_addrs()?
        .map(|socket| {
            let ip = socket.ip();
            (ip, forbidden(ip))
        })
        .collect::<Vec<_>>();

    Ok(Resolved { addresses })
}

#[cfg(test)]
mod tests;
