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

/// [`forbidden`], but with local targets allowed when the scanner was started
/// for them.
///
/// A capture-the-flag challenge is very often on the machine running the
/// scanner, in a container on `localhost`, or on another box on the same LAN.
/// The default guard refuses all of those, correctly, because a scanner that
/// reaches inward is the whole danger it exists to stop. So reaching them is not
/// the default: it is a thing the person starting the scanner turns on, having
/// decided the target is theirs.
///
/// Even then the relaxation is narrow. Only loopback, the RFC1918 private ranges
/// and IPv6 unique-local are let through, because those are where a local
/// challenge lives. The cloud metadata address and everything else stay refused,
/// because no challenge is ever there and the risk of reaching it does not go
/// away just because the target happens to be local.
pub fn forbidden_with(ip: IpAddr, allow_local: bool) -> Option<Reason> {
    // Metadata endpoints are refused first, so the local-mode allowance below can
    // never reach them. A unique-local address like fd00:ec2::254 is "local" by
    // shape, but it is AWS's metadata endpoint and stays shut in every mode.
    if let Some(reason) = cloud_metadata_reason(ip) {
        return Some(reason);
    }
    let reason = forbidden(ip)?;
    if allow_local && is_local(ip) {
        return None;
    }
    Some(reason)
}

/// Whether an address is somewhere a local challenge plausibly lives: this
/// machine, or a private network. Deliberately not link-local, so the metadata
/// address is never caught by it.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || matches!(v4.octets(), [10, ..] | [192, 168, ..])
                || matches!(v4.octets(), [172, b, ..] if (16..=31).contains(&b))
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_local(IpAddr::V4(mapped));
            }
            // Loopback (::1) and unique-local (fc00::/7), the v6 private space.
            v6.is_loopback() || v6.segments()[0] & 0xfe00 == 0xfc00
        }
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
        // 168.63.129.16: Azure's wire server, a metadata endpoint that lives on
        // an otherwise public-looking address, so it needs naming outright.
        [168, 63, 129, 16] => Some("link-local, includes cloud metadata (168.63.129.16)"),
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
    // An IPv4 address wearing an IPv6 coat, in any of the forms that tunnel to a
    // v4 host: mapped, compatible, NAT64, 6to4, Teredo. Each reaches the embedded
    // v4 as surely as the bare address does, so the v4 rules judge it. A private
    // or metadata target smuggled through one of these is caught exactly as the
    // bare v4 would be; a public one stays reachable, the same as `::ffff:8.8.8.8`.
    if let Some(v4) = embedded_v4(ip) {
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
    // fec0::/10 site-local, deprecated but still routed on some stacks.
    if first & 0xffc0 == 0xfec0 {
        return Some("site-local (fec0::/10)");
    }
    // fc00::/7 unique local, the v6 equivalent of a private network.
    if first & 0xfe00 == 0xfc00 {
        return Some("unique local address (fc00::/7)");
    }
    // ff00::/8 multicast.
    if first & 0xff00 == 0xff00 {
        return Some("multicast (ff00::/8)");
    }
    // Everything reachable on the public v6 internet is global unicast, 2000::/3.
    // Refusing all else is the opposite default from v4 and the safe one: the
    // special-purpose blocks above are specific, and nothing outside 2000::/3 is
    // an ordinary target, so the catch-all denies rather than allows.
    if first & 0xe000 != 0x2000 {
        return Some("not global unicast (outside 2000::/3)");
    }

    None
}

/// The IPv4 address an IPv6 address carries, when it is one of the forms that
/// tunnel to a v4 host. `None` for a native IPv6 address.
///
/// Returned so the v4 rules can judge the real destination: `64:ff9b::a9fe:a9fe`
/// reaches the metadata endpoint exactly as `169.254.169.254` does, and a guard
/// that only looked at the v6 bits would wave it through.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    // ::ffff:a.b.c.d, the mapped form a dual-stack socket hands back.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }

    let s = ip.segments();

    // ::a.b.c.d, the deprecated IPv4-compatible form, but not :: or ::1.
    if s[..6].iter().all(|&x| x == 0) && (s[6], s[7]) != (0, 0) && ip != Ipv6Addr::LOCALHOST {
        return Some(v4_from(s[6], s[7]));
    }
    // 64:ff9b::/96, the well-known NAT64 prefix: the v4 is the last 32 bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|&x| x == 0) {
        return Some(v4_from(s[6], s[7]));
    }
    // 2002::/16, 6to4: the v4 is the second and third segments.
    if s[0] == 0x2002 {
        return Some(v4_from(s[1], s[2]));
    }
    // 2001:0::/32, Teredo: the server v4 is segments 2 and 3, the client v4 is
    // the last two segments with every bit flipped. Either can point inward, so
    // the one that the v4 rules refuse is the one to report.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        let server = v4_from(s[2], s[3]);
        if forbidden_v4(server).is_some() {
            return Some(server);
        }
        return Some(v4_from(!s[6], !s[7]));
    }

    None
}

/// The IPv4 address packed into two IPv6 segments, high segment first.
fn v4_from(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
}

/// The reason an address is a cloud metadata endpoint, checked in every mode.
///
/// These are the addresses a scanner must never reach however it was started:
/// the link-local metadata range and the provider addresses outside it, in v4
/// and in the v6 forms that reach the same place. Kept apart from [`forbidden`]
/// so [`forbidden_with`] can refuse them before it ever considers the local-mode
/// allowance, since the promise that metadata stays blocked does not bend for a
/// local scan.
fn cloud_metadata_reason(ip: IpAddr) -> Option<Reason> {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [169, 254, ..] => Some("link-local, includes cloud metadata (169.254.0.0/16)"),
            [168, 63, 129, 16] => Some("link-local, includes cloud metadata (168.63.129.16)"),
            _ => None,
        },
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return cloud_metadata_reason(IpAddr::V4(v4));
            }
            // fd00:ec2::254, the unique-local address AWS answers IMDS on over v6.
            if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
                return Some("link-local, includes cloud metadata (fd00:ec2::254)");
            }
            None
        }
    }
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
pub fn resolve_and_check(host: &str, port: u16, allow_local: bool) -> std::io::Result<Resolved> {
    let addresses = (host, port)
        .to_socket_addrs()?
        .map(|socket| {
            let ip = socket.ip();
            (ip, forbidden_with(ip, allow_local))
        })
        .collect::<Vec<_>>();

    Ok(Resolved { addresses })
}

/// Whether every address a host resolved to is one local mode exists to reach:
/// blocked by default, allowed only when local mode is on. Empty or mixed with a
/// public or metadata address, the answer is no.
///
/// This is how the entry to a scan is classified. Local access is a property of
/// the target the person named, not a blanket setting: it is earned only when
/// that target itself is local, so a public page cannot inherit it and redirect
/// or resolve its way into the network behind the scanner.
fn addresses_are_local_entry(addresses: &[IpAddr]) -> bool {
    !addresses.is_empty()
        && addresses
            .iter()
            .all(|&ip| forbidden(ip).is_some() && forbidden_with(ip, true).is_none())
}

/// Whether a scan entered at this host may use local access: the scanner is in
/// local mode and the host resolves wholly to local or private addresses.
///
/// Resolution failure or any public or metadata address means no, so the strict
/// guard governs the whole scan. The later per-hop [`resolve_and_check`] still
/// runs with the answer, so this only ever narrows what a scan may reach.
pub fn host_allows_local(host: &str, port: u16, scanner_allow_local: bool) -> bool {
    if !scanner_allow_local {
        return false;
    }
    match (host, port).to_socket_addrs() {
        Ok(sockets) => {
            let addresses: Vec<IpAddr> = sockets.map(|socket| socket.ip()).collect();
            addresses_are_local_entry(&addresses)
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests;
