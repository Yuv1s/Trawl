use super::*;

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse().unwrap())
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse().unwrap())
}

#[test]
fn blocks_the_cloud_metadata_address() {
    // The one that matters most. An unguarded fetcher on a cloud host hands its
    // own credentials to anyone who asks it to reach this.
    assert!(forbidden(v4("169.254.169.254")).is_some());
    // And the same address smuggled through IPv6.
    assert!(forbidden(v6("::ffff:169.254.169.254")).is_some());
}

#[test]
fn blocks_loopback() {
    assert!(forbidden(v4("127.0.0.1")).is_some());
    assert!(forbidden(v4("127.1.2.3")).is_some());
    assert!(forbidden(v6("::1")).is_some());
    assert!(forbidden(v6("::ffff:127.0.0.1")).is_some());
}

#[test]
fn blocks_every_private_range() {
    for addr in [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ] {
        assert!(forbidden(v4(addr)).is_some(), "{addr} was allowed");
    }
}

#[test]
fn the_edges_of_the_private_ranges_are_public() {
    // 172.16/12 is 172.16 through 172.31. The neighbours are ordinary internet.
    assert!(forbidden(v4("172.15.255.255")).is_none());
    assert!(forbidden(v4("172.32.0.0")).is_none());
    // 100.64/10 is 100.64 through 100.127.
    assert!(forbidden(v4("100.63.255.255")).is_none());
    assert!(forbidden(v4("100.128.0.0")).is_none());
}

#[test]
fn blocks_link_local_and_carrier_nat() {
    assert!(forbidden(v4("169.254.0.1")).is_some());
    assert!(forbidden(v4("100.64.0.1")).is_some());
    assert!(forbidden(v4("100.127.255.255")).is_some());
}

#[test]
fn blocks_unspecified_multicast_and_reserved() {
    assert!(forbidden(v4("0.0.0.0")).is_some());
    assert!(forbidden(v4("224.0.0.1")).is_some());
    assert!(forbidden(v4("239.255.255.255")).is_some());
    assert!(forbidden(v4("240.0.0.1")).is_some());
    assert!(forbidden(v4("255.255.255.255")).is_some());
}

#[test]
fn blocks_documentation_and_benchmarking() {
    assert!(forbidden(v4("192.0.2.1")).is_some());
    assert!(forbidden(v4("198.51.100.1")).is_some());
    assert!(forbidden(v4("203.0.113.1")).is_some());
    assert!(forbidden(v4("198.18.0.1")).is_some());
    assert!(forbidden(v4("198.19.255.255")).is_some());
}

#[test]
fn blocks_ipv6_local_ranges() {
    assert!(forbidden(v6("fe80::1")).is_some()); // link-local
    assert!(forbidden(v6("fc00::1")).is_some()); // unique local
    assert!(forbidden(v6("fd12:3456::1")).is_some()); // unique local
    assert!(forbidden(v6("ff02::1")).is_some()); // multicast
    assert!(forbidden(v6("::")).is_some()); // unspecified
}

#[test]
fn blocks_ipv4_compatible_ipv6_pointing_inward() {
    // ::a.b.c.d is a deprecated form that still tunnels to a v4 host.
    assert!(forbidden(v6("::127.0.0.1")).is_some());
    assert!(forbidden(v6("::10.0.0.1")).is_some());
}

#[test]
fn allows_ordinary_public_addresses() {
    for addr in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.114.1"] {
        assert!(forbidden(v4(addr)).is_none(), "{addr} was blocked");
    }
    // A real public v6 (one of Google's).
    assert!(forbidden(v6("2001:4860:4860::8888")).is_none());
    // A public v4 wearing a v6 coat stays allowed.
    assert!(forbidden(v6("::ffff:8.8.8.8")).is_none());
}

#[test]
fn the_reason_names_the_rule() {
    // A blocked scan should be legible, not a flat refusal.
    let reason = forbidden(v4("169.254.169.254")).unwrap();
    assert!(reason.contains("metadata"), "unhelpful reason: {reason}");
}

#[test]
fn one_bad_address_condemns_the_whole_name() {
    // The rebinding shape: a name answering with a public and a private address.
    // The public one is not a reason to proceed.
    let resolved = Resolved {
        addresses: vec![
            (v4("93.184.216.34"), None),
            (v4("127.0.0.1"), forbidden(v4("127.0.0.1"))),
        ],
    };

    assert!(resolved.blocked().is_some());
    assert!(
        resolved.safe_addresses().is_empty(),
        "a mixed answer must not be acted on"
    );
}

#[test]
fn a_clean_name_yields_its_addresses() {
    let resolved = Resolved {
        addresses: vec![(v4("93.184.216.34"), None), (v4("8.8.8.8"), None)],
    };

    assert!(resolved.blocked().is_none());
    assert_eq!(resolved.safe_addresses().len(), 2);
}

#[test]
fn resolves_localhost_and_refuses_it() {
    // An end-to-end check that resolution and classification meet correctly:
    // localhost is reachable to resolve and must come back blocked.
    let resolved = resolve_and_check("localhost", 80, false).expect("localhost did not resolve");

    assert!(!resolved.addresses.is_empty());
    assert!(resolved.blocked().is_some(), "localhost was not blocked");
}

#[test]
fn local_mode_allows_loopback_and_private_targets() {
    // The opt-in for local challenges: this machine and private networks become
    // reachable, so a challenge on localhost or in a container can be scanned.
    for addr in ["127.0.0.1", "10.0.0.5", "192.168.1.20", "172.16.9.9"] {
        assert!(
            forbidden(v4(addr)).is_some(),
            "{addr} should be blocked by default"
        );
        assert!(
            forbidden_with(v4(addr), true).is_none(),
            "{addr} should be allowed locally"
        );
    }
    // IPv6 loopback and unique-local too, since localhost often resolves to ::1.
    assert!(forbidden_with(v6("::1"), true).is_none());
    assert!(forbidden_with(v6("fd00::1"), true).is_none());
    assert!(forbidden_with(v6("::ffff:127.0.0.1"), true).is_none());
}

#[test]
fn local_mode_still_refuses_the_metadata_address() {
    // The one thing local mode must never open. No challenge is at the cloud
    // metadata endpoint, and the reason to keep it shut does not depend on the
    // rest of the target being local.
    assert!(forbidden_with(v4("169.254.169.254"), true).is_some());
    assert!(forbidden_with(v6("::ffff:169.254.169.254"), true).is_some());
    // And the other never-a-target ranges stay shut in local mode as well.
    assert!(forbidden_with(v4("224.0.0.1"), true).is_some());
    assert!(forbidden_with(v4("100.64.0.1"), true).is_some());
    assert!(forbidden_with(v6("fe80::1"), true).is_some());
}

#[test]
fn local_mode_leaves_public_addresses_exactly_as_they_were() {
    // Turning it on must not change the answer for an ordinary public address.
    for addr in ["8.8.8.8", "93.184.216.34"] {
        assert_eq!(forbidden(v4(addr)), forbidden_with(v4(addr), true));
    }
}
