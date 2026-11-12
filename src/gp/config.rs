use super::{child_text, scalar_text, xml, GpError};
use ipnet::Ipv4Net;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime},
};
use tokio::time::Instant;

/// The deliberately supported subset of gateway domain split-tunnel rules.
/// A literal is exact; `*.example.test` excludes the apex `example.test`.
/// Search suffixes are separate metadata, not domain authorization rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GatewayDomainRule {
    Exact(String),
    Subdomains(String),
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Request-start anchor: network/setup delays consume gateway leases.
    pub received_at: Instant,
    pub received_wall: SystemTime,
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub dns_suffixes: Vec<String>,
    pub include_domains: Vec<GatewayDomainRule>,
    pub exclude_domains: Vec<GatewayDomainRule>,
    pub include_routes: Vec<Ipv4Net>,
    pub exclude_routes: Vec<Ipv4Net>,
    pub mtu: usize,
    /// None means the gateway supplied no tunnel rekey deadline.
    pub timeout: Option<Duration>,
    /// Remaining login lifetime at receipt, not permission to extend an old session.
    pub lifetime: Option<Duration>,
    pub ssl_tunnel_path: String,
}

const MAX_DOMAIN_RULES: usize = 4096;

fn parse_domain_rule(text: &str) -> Result<GatewayDomainRule, GpError> {
    let text = text.trim();
    // Longest supported input: "*." + 253-byte name + optional root dot.
    if text.is_empty() || text.len() > 256 || !text.is_ascii() {
        return Err(GpError::Protocol("invalid split-tunnel domain rule"));
    }
    let (subdomains, domain) = match text.strip_prefix("*.") {
        Some(domain) => (true, domain),
        None => (false, text),
    };
    let domain = domain
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    // PAN supports more glob/port forms than this implementation. Their wire
    // representation and semantics must be verified before accepting them.
    // Never strip a port or wildcard and silently broaden authorization.
    if domain.is_empty()
        || domain.len() > 253
        || domain.parse::<IpAddr>().is_ok()
        || domain
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(GpError::Protocol("unsupported split-tunnel domain rule"));
    }
    Ok(if subdomains {
        GatewayDomainRule::Subdomains(domain)
    } else {
        GatewayDomainRule::Exact(domain)
    })
}

fn domain_rules(
    root: roxmltree::Node<'_, '_>,
    name: &str,
) -> Result<Vec<GatewayDomainRule>, GpError> {
    let mut containers = root
        .children()
        .filter(|node| node.tag_name().name() == name);
    let Some(container) = containers.next() else {
        return Ok(Vec::new());
    };
    if containers.next().is_some()
        || container.tag_name().namespace().is_some()
        || container.attributes().len() != 0
        || container
            .children()
            .any(|node| node.is_text() && !node.text().unwrap_or("").trim().is_empty())
    {
        return Err(GpError::Protocol(
            "ambiguous split-tunnel domain collection",
        ));
    }
    let mut result = Vec::new();
    for member in container.children().filter(|node| node.is_element()) {
        if member.tag_name().name() != "member"
            || member.tag_name().namespace().is_some()
            || member.attributes().len() != 0
            || result.len() >= MAX_DOMAIN_RULES
        {
            return Err(GpError::Protocol(
                "unsupported split-tunnel domain collection",
            ));
        }
        result.push(parse_domain_rule(scalar_text(member)?)?);
    }
    Ok(result)
}

fn members<'a>(root: roxmltree::Node<'a, 'a>, name: &str) -> Result<Vec<&'a str>, GpError> {
    let containers: Vec<_> = root.children().filter(|n| n.has_tag_name(name)).collect();
    if containers.len() > 1 {
        return Err(GpError::Protocol("duplicate configuration collection"));
    }
    let mut result = Vec::new();
    if let Some(node) = containers.first() {
        for member in node.children().filter(|n| n.is_element()) {
            if !member.has_tag_name("member") {
                return Err(GpError::Protocol(
                    "unexpected configuration collection entry",
                ));
            }
            let text = scalar_text(member)?.trim();
            if text.is_empty() || result.len() >= 4096 {
                return Err(GpError::Protocol("invalid configuration collection"));
            }
            result.push(text);
        }
    }
    Ok(result)
}

pub(super) fn valid_tunnel_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= 2048
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
}

pub fn parse_config(body: &str) -> Result<TunnelConfig, GpError> {
    let received_at = Instant::now();
    let received_wall = SystemTime::now();
    if body.trim() == "errors getting SSL/VPN config" {
        return Err(GpError::ConfigurationRejected);
    }
    let doc = xml(body)?;
    let root = doc.root_element();
    if !root.has_tag_name("response") || root.attribute("status") != Some("success") {
        return Err(GpError::Authentication);
    }
    for name in [
        "need-tunnel",
        "ip-address",
        "ssl-tunnel-url",
        "mtu",
        "timeout",
        "lifetime",
    ] {
        if root.children().filter(|n| n.has_tag_name(name)).count() > 1 {
            return Err(GpError::Protocol("duplicate configuration field"));
        }
    }
    if child_text(root, "need-tunnel")? != Some("yes") {
        return Err(GpError::Protocol("gateway did not authorize a tunnel"));
    }
    let address: Ipv4Addr = child_text(root, "ip-address")?
        .ok_or(GpError::Protocol("gateway supplied no IPv4 address"))?
        .parse()
        .map_err(|_| GpError::Protocol("invalid tunnel IPv4 address"))?;
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
    {
        return Err(GpError::Protocol("unusable tunnel IPv4 address"));
    }
    let ssl_tunnel_path =
        child_text(root, "ssl-tunnel-url")?.ok_or(GpError::Protocol("missing SSL tunnel path"))?;
    if !valid_tunnel_path(ssl_tunnel_path) {
        return Err(GpError::Protocol("unsafe SSL tunnel path"));
    }
    let reported_mtu: usize = child_text(root, "mtu")?
        .unwrap_or("0")
        .parse()
        .map_err(|_| GpError::Protocol("invalid MTU"))?;
    let mtu = if reported_mtu == 0 {
        1400
    } else {
        reported_mtu
    };
    if !(576..=9000).contains(&mtu) {
        return Err(GpError::Protocol("MTU outside supported range"));
    }
    let duration = |name| -> Result<Option<Duration>, GpError> {
        root.children()
            .find(|node| node.has_tag_name(name))
            .map(|node| {
                let s = Some(scalar_text(node)?.trim())
                    .filter(|text| !text.is_empty())
                    .ok_or(GpError::Protocol("empty session deadline"))?;
                let secs: u64 = s
                    .parse()
                    .map_err(|_| GpError::Protocol("invalid session deadline"))?;
                if secs == 0 || secs > 366 * 86400 {
                    return Err(GpError::Protocol(
                        "session deadline outside supported range",
                    ));
                }
                Ok(Duration::from_secs(secs))
            })
            .transpose()
    };
    let dns = members(root, "dns")?
        .into_iter()
        .map(|s| {
            let ip: Ipv4Addr = s
                .parse()
                .map_err(|_| GpError::Protocol("invalid DNS server"))?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || ip.is_broadcast() {
                return Err(GpError::Protocol("unusable DNS server"));
            }
            Ok(ip)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let dns_suffixes = members(root, "dns-suffix")?
        .into_iter()
        .map(|s| {
            let s = s.trim_end_matches('.').to_ascii_lowercase();
            if s.is_empty()
                || s.len() > 253
                || !s.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(GpError::Protocol("invalid DNS suffix"));
            }
            Ok(s)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let routes = |name| -> Result<Vec<Ipv4Net>, GpError> {
        members(root, name)?
            .into_iter()
            .map(|s| {
                s.parse()
                    .map_err(|_| GpError::Protocol("invalid IPv4 access route"))
            })
            .collect()
    };
    let include_domains = domain_rules(root, "include-split-tunneling-domain")?;
    let exclude_domains = domain_rules(root, "exclude-split-tunneling-domain")?;
    if include_domains.len() + exclude_domains.len() > MAX_DOMAIN_RULES {
        return Err(GpError::Protocol("too many split-tunnel domain rules"));
    }
    Ok(TunnelConfig {
        received_at,
        received_wall,
        address,
        dns,
        dns_suffixes,
        include_domains,
        exclude_domains,
        include_routes: routes("access-routes")?,
        exclude_routes: routes("exclude-access-routes")?,
        mtu,
        timeout: duration("timeout")?,
        lifetime: duration("lifetime")?,
        ssl_tunnel_path: ssl_tunnel_path.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"<response status="success"><need-tunnel>yes</need-tunnel>
        <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><ip-address>10.2.3.4</ip-address>
        <mtu>0</mtu><timeout>3600</timeout><lifetime>86400</lifetime>
        <dns><member>10.2.0.53</member></dns><dns-suffix><member>Example.Internal.</member></dns-suffix>
        <access-routes><member>10.0.0.0/8</member></access-routes>
        <exclude-access-routes><member>10.5.0.0/16</member></exclude-access-routes></response>"#;

    #[test]
    fn parses_configuration_without_touching_host_network() {
        let config = parse_config(CONFIG).unwrap();
        assert_eq!(config.address, Ipv4Addr::new(10, 2, 3, 4));
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.dns_suffixes, ["example.internal"]);
        assert_eq!(config.timeout, Some(Duration::from_secs(3600)));
        assert_eq!(config.include_routes[0].prefix_len(), 8);
        assert!(config.include_domains.is_empty());
        assert!(config.exclude_domains.is_empty());
    }

    fn with_domain_xml(xml: &str) -> String {
        CONFIG.replace("</response>", &format!("{xml}</response>"))
    }

    #[test]
    fn gateway_domain_rules_preserve_exact_and_subdomain_semantics() {
        let config = parse_config(&with_domain_xml(
            "<include-split-tunneling-domain><member>API.Example.Internal.</member><member>*.Corp.Example.</member></include-split-tunneling-domain><exclude-split-tunneling-domain><member>public.corp.example</member></exclude-split-tunneling-domain>",
        )).unwrap();
        assert_eq!(
            config.include_domains,
            vec![
                GatewayDomainRule::Exact("api.example.internal".into()),
                GatewayDomainRule::Subdomains("corp.example".into()),
            ]
        );
        assert_eq!(
            config.exclude_domains,
            vec![GatewayDomainRule::Exact("public.corp.example".into())]
        );
        // The independently parsed search list is not converted to a rule.
        assert_eq!(config.dns_suffixes, ["example.internal"]);
        let empty = parse_config(&with_domain_xml(
            "<include-split-tunneling-domain/><exclude-split-tunneling-domain/>",
        ))
        .unwrap();
        assert!(empty.include_domains.is_empty() && empty.exclude_domains.is_empty());
    }

    #[test]
    fn unsupported_domain_rules_cannot_silently_drop_exclusions() {
        for name in [
            "include-split-tunneling-domain",
            "exclude-split-tunneling-domain",
        ] {
            for member in [
                "",
                "*corp.example",
                "corp.*.example",
                "*",
                "?.corp.example",
                "corp.example:443",
                "corp.example:0",
                "https://corp.example",
                "corp.example..",
                "127.0.0.1",
                "*.127.0.0.1",
                "127.1",
                "[::1]",
                "corp_foo.example",
                "cörp.example",
                "corp.example&lt;script&gt;",
                "corp<!--split-->.example",
                "corp<port>443</port>.example",
            ] {
                let body = with_domain_xml(&format!("<{name}><member>{member}</member></{name}>"));
                assert!(matches!(parse_config(&body), Err(GpError::Protocol(_))));
            }
            for body in [
                format!("<{name}><member port='443'>corp.example</member></{name}>"),
                format!("<{name}><entry>corp.example</entry></{name}>"),
                format!("<{name}>hidden.example<member>corp.example</member></{name}>"),
                format!("<{name} mode='exclude'><member>corp.example</member></{name}>"),
                format!("<{name}/><{name}/>"),
                format!("<x:{name} xmlns:x='urn:other'><member>corp.example</member></x:{name}>"),
            ] {
                assert!(matches!(
                    parse_config(&with_domain_xml(&body)),
                    Err(GpError::Protocol(_))
                ));
            }
        }
    }

    #[test]
    fn gateway_domain_rule_limits_are_bounded_without_truncating() {
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest.len(), 253);
        assert!(parse_domain_rule(&format!("*.{longest}.")).is_ok());
        assert!(parse_domain_rule(&format!("{longest}e")).is_err());
        assert!(parse_domain_rule(&format!("{}.example", "x".repeat(64))).is_err());
        let at_limit = "<member>corp.example</member>".repeat(MAX_DOMAIN_RULES);
        let body =
            format!("<include-split-tunneling-domain>{at_limit}</include-split-tunneling-domain>");
        assert_eq!(
            parse_config(&with_domain_xml(&body))
                .unwrap()
                .include_domains
                .len(),
            MAX_DOMAIN_RULES
        );
        assert!(parse_config(&with_domain_xml(&format!("{body}<exclude-split-tunneling-domain><member>public.example</member></exclude-split-tunneling-domain>"))).is_err());
    }

    #[test]
    fn rejects_injection_ambiguity_and_unusable_configuration() {
        assert!(matches!(
            parse_config("errors getting SSL/VPN config"),
            Err(GpError::ConfigurationRejected)
        ));
        for (old, new) in [
            ("/ssl-tunnel-connect.sslvpn", "//evil.test/steal"),
            ("/ssl-tunnel-connect.sslvpn", "/x?user=attacker"),
            ("<mtu>0</mtu>", "<mtu>0</mtu><mtu>1400</mtu>"),
            ("<timeout>3600</timeout>", "<timeout>-1</timeout>"),
            ("<timeout>3600</timeout>", "<timeout>0</timeout>"),
            ("<lifetime>86400</lifetime>", "<lifetime>0</lifetime>"),
            ("<lifetime>86400</lifetime>", "<lifetime/>"),
            (
                "<lifetime>86400</lifetime>",
                "<lifetime>8<hidden/>6400</lifetime>",
            ),
            (
                "<lifetime>86400</lifetime>",
                "<lifetime>8<!--split-->6400</lifetime>",
            ),
            (
                "<lifetime>86400</lifetime>",
                "<lifetime>86400</lifetime><lifetime>10</lifetime>",
            ),
            ("10.2.3.4", "127.0.0.1"),
            ("Example.Internal.", "internal\"; return 'DIRECT'; //"),
            ("10.0.0.0/8", "10.0.0.0/99"),
            ("<need-tunnel>yes", "<need-tunnel>no"),
        ] {
            assert!(parse_config(&CONFIG.replace(old, new)).is_err(), "{new}");
        }
        assert!(parse_config(
            "<!DOCTYPE response [<!ENTITY a 'b'>]><response status='success'>&a;</response>"
        )
        .is_err());
    }
}
