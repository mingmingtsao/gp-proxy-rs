//! Explicit destinations allowed to use the corporate tunnel; PAC never falls
//! back to DIRECT for these destinations and never resolves names locally.
use crate::gp::GatewayDomainRule;
use ipnet::{IpNet, Ipv4Net};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    domains: Vec<String>,
    networks: Vec<IpNet>,
    excludes: Vec<IpNet>,
    gateway_domains: Vec<GatewayDomainRule>,
    excluded_domains: Vec<GatewayDomainRule>,
}

impl Policy {
    pub fn new(domains: Vec<String>, mut networks: Vec<IpNet>) -> io::Result<Self> {
        let mut normalized = Vec::with_capacity(domains.len());
        for domain in domains {
            let domain = normalize_host(&domain)?;
            if domain.parse::<IpAddr>().is_ok() {
                return Err(invalid("domain rule must be a DNS name"));
            }
            normalized.push(domain);
        }
        normalized.sort_unstable();
        normalized.dedup();
        networks = networks.into_iter().map(normalize_network).collect();
        networks.sort_unstable();
        networks.dedup();
        Ok(Self {
            domains: normalized,
            networks,
            excludes: Vec::new(),
            gateway_domains: Vec::new(),
            excluded_domains: Vec::new(),
        })
    }

    pub fn with_excludes(mut self, excludes: Vec<IpNet>) -> Self {
        self.excludes = excludes.into_iter().map(normalize_network).collect();
        self
    }

    /// Gateway literals are exact, unlike the local `domains` suffix rules.
    /// Exclusions restrict egress even when a local rule also authorizes a name.
    pub fn with_gateway_domains(
        mut self,
        includes: Vec<GatewayDomainRule>,
        excludes: Vec<GatewayDomainRule>,
    ) -> io::Result<Self> {
        self.gateway_domains = normalize_rules(includes)?;
        self.excluded_domains = normalize_rules(excludes)?;
        Ok(self)
    }

    pub fn excludes_ip(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.excludes.iter().any(|network| network.contains(&ip))
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        !self.excludes_ip(ip) && self.networks.iter().any(|network| network.contains(&ip))
    }

    pub fn allows_host(&self, host: &str) -> bool {
        let Ok(host) = normalize_host(host) else {
            return false;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.allows_ip(ip);
        }
        if self
            .excluded_domains
            .iter()
            .any(|rule| matches_rule(rule, &host))
        {
            return false;
        }
        self.domains
            .iter()
            .any(|domain| host == *domain || is_subdomain(&host, domain))
            || self
                .gateway_domains
                .iter()
                .any(|rule| matches_rule(rule, &host))
    }

    pub fn allows(&self, target: &crate::proxy::Target) -> bool {
        target.port != 0 && self.allows_host(&target.host)
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    pub fn gateway_domains(&self) -> &[GatewayDomainRule] {
        &self.gateway_domains
    }

    /// Cumulative PAC classification, never permission to open a connection.
    /// Exclusions cannot turn a remembered destination into DIRECT.
    pub fn merge_classification(&self, current: &Self) -> io::Result<Self> {
        let mut domains = self.domains.clone();
        domains.extend_from_slice(&current.domains);
        let mut networks = self.networks.clone();
        networks.extend_from_slice(&current.networks);
        let mut gateway_domains = self.gateway_domains.clone();
        gateway_domains.extend_from_slice(&current.gateway_domains);
        let merged =
            Self::new(domains, networks)?.with_gateway_domains(gateway_domains, Vec::new())?;
        if merged.domains.len() + merged.networks.len() + merged.gateway_domains.len() > 16384 {
            return Err(invalid("cumulative PAC policy limit reached"));
        }
        Ok(merged)
    }

    /// Standard IPv4-mapped literals follow their IPv4 destination policy.
    /// Other IPv6 PAC parsing is deliberately conservative: when IPv6 routes
    /// exist, those literals use the proxy for exact CIDR authorization.
    pub fn pac(&self, proxy: SocketAddr) -> String {
        let mut script = String::new();
        if !self.networks.is_empty() {
            script.push_str(PAC_MAPPED_IPV4);
        }
        script.push_str(&format!("function FindProxyForURL(url, host) {{\n  host = host.toLowerCase();\n  if (host.charAt(host.length - 1) === '.') host = host.slice(0, -1);\n  var proxy = \"PROXY {proxy}\";\n"));
        if !self.networks.is_empty() {
            script.push_str(
                "  var mapped = gpMappedIPv4(host);\n  if (mapped !== null) host = mapped;\n",
            );
        }
        for domain in &self.domains {
            script.push_str(&format!(
                "  if (host === \"{domain}\" || dnsDomainIs(host, \".{domain}\")) return proxy;\n"
            ));
        }
        for rule in &self.gateway_domains {
            match rule {
                GatewayDomainRule::Exact(domain) => {
                    script.push_str(&format!("  if (host === \"{domain}\") return proxy;\n"))
                }
                GatewayDomainRule::Subdomains(domain) => script.push_str(&format!(
                    "  if (dnsDomainIs(host, \".{domain}\")) return proxy;\n"
                )),
            }
        }
        if self.networks.iter().any(|n| matches!(n, IpNet::V4(_))) {
            // Avoid isInNet entirely: some PAC implementations resolve inputs
            // that resemble numeric addresses but are not canonical literals.
            script.push_str("  var octets = host.match(/^(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})$/);\n  if (octets && octets[1] <= 255 && octets[2] <= 255 && octets[3] <= 255 && octets[4] <= 255) {\n    var v4 = ((+octets[1] << 24) | (+octets[2] << 16) | (+octets[3] << 8) | +octets[4]) >>> 0;\n");
            for network in &self.networks {
                if let IpNet::V4(network) = network {
                    script.push_str(&format!(
                        "    if (((v4 & {}) >>> 0) === {}) return proxy;\n",
                        u32::from(network.netmask()),
                        u32::from(network.network())
                    ));
                }
            }
            // Ambiguous numeric inputs must be rejected by the connector,
            // never delegated to a host resolver through a PAC DNS helper.
            script.push_str("  } else if (/^[0-9.]+$/.test(host)) return proxy;\n");
        }
        if self.networks.iter().any(|n| matches!(n, IpNet::V6(_))) {
            script.push_str("  if (host.indexOf(':') !== -1) return proxy;\n");
        }
        script.push_str("  return \"DIRECT\";\n}\n");
        script
    }
}

// PAC engines do not share an IPv6 parsing helper. This bounded, DNS-free
// parser recognizes only the standard IPv4-mapped prefix, including the hex
// form URL parsers produce. Other IPv6 literals retain their original policy.
const PAC_MAPPED_IPV4: &str = r#"function gpMappedIPv4(host) {
  if (host.charAt(0) === '[' && host.charAt(host.length - 1) === ']') host = host.slice(1, -1);
  if (host.length > 45 || host.indexOf(':') === -1 || /[^0-9a-f:.]/.test(host)) return null;
  var halves = host.split('::');
  if (halves.length > 2) return null;
  function words(part, allowDotted) {
    if (part === '') return [];
    var pieces = part.split(':'), result = [];
    for (var i = 0; i < pieces.length; i++) {
      var piece = pieces[i];
      if (piece.indexOf('.') !== -1) {
        if (!allowDotted || i !== pieces.length - 1) return null;
        var v4 = piece.match(/^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/);
        if (!v4 || v4[1] > 255 || v4[2] > 255 || v4[3] > 255 || v4[4] > 255) return null;
        result.push((+v4[1] << 8) | +v4[2], (+v4[3] << 8) | +v4[4]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
        result.push(parseInt(piece, 16));
      }
      if (result.length > 8) return null;
    }
    return result;
  }
  var left = words(halves[0], halves.length === 1);
  var right = halves.length === 2 ? words(halves[1], true) : [];
  if (left === null || right === null) return null;
  var missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  while (missing-- > 0) left.push(0);
  var address = left.concat(right);
  for (var j = 0; j < 5; j++) if (address[j] !== 0) return null;
  if (address[5] !== 65535) return null;
  return [address[6] >>> 8, address[6] & 255, address[7] >>> 8, address[7] & 255].join('.');
}
"#;

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn normalize_network(network: IpNet) -> IpNet {
    let network = network.trunc();
    if let IpNet::V6(v6) = network {
        // Only an explicitly mapped prefix is an IPv4 grant. A broad IPv6
        // rule such as ::/0 must not silently authorize IPv4 destinations.
        if v6.prefix_len() >= 96 {
            if let Some(v4) = v6.network().to_ipv4_mapped() {
                return IpNet::V4(
                    Ipv4Net::new(v4, v6.prefix_len() - 96)
                        .expect("mapped IPv4 prefix is at most 32 bits"),
                );
            }
        }
    }
    network
}

fn is_subdomain(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn matches_rule(rule: &GatewayDomainRule, host: &str) -> bool {
    match rule {
        GatewayDomainRule::Exact(domain) => host == domain,
        GatewayDomainRule::Subdomains(domain) => is_subdomain(host, domain),
    }
}

fn normalize_rules(rules: Vec<GatewayDomainRule>) -> io::Result<Vec<GatewayDomainRule>> {
    let mut result = Vec::with_capacity(rules.len());
    for rule in rules {
        let (subdomains, domain) = match rule {
            GatewayDomainRule::Exact(domain) => (false, domain),
            GatewayDomainRule::Subdomains(domain) => (true, domain),
        };
        let domain = normalize_host(&domain)?;
        if domain.parse::<IpAddr>().is_ok() {
            return Err(invalid("domain rule must be a DNS name"));
        }
        result.push(if subdomains {
            GatewayDomainRule::Subdomains(domain)
        } else {
            GatewayDomainRule::Exact(domain)
        });
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

pub(crate) fn normalize_host(host: &str) -> io::Result<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(normalize_ip(ip).to_string());
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(invalid("invalid destination host"));
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err(invalid("invalid destination host"));
    }
    // Non-canonical numeric hosts can be interpreted differently by browsers,
    // resolvers and HTTP stacks. Require normal IP syntax or a real DNS label.
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(invalid("non-canonical IP literal"));
    }
    Ok(host.to_ascii_lowercase())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use GatewayDomainRule::{Exact, Subdomains};

    #[test]
    fn mapped_literals_share_ipv4_authority_in_host_target_and_raw_ip_apis() {
        let policy = Policy::new(Vec::new(), vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        for host in [
            "10.1.2.3",
            "::ffff:10.1.2.3",
            "::ffff:a01:203",
            "0:0:0:0:0:ffff:10.1.2.3",
            "0000:0000:0000:0000:0000:FFFF:0A01:0203",
        ] {
            assert_eq!(normalize_host(host).unwrap(), "10.1.2.3", "{host}");
            assert!(policy.allows_host(host), "{host}");
            assert!(policy.allows_ip(host.parse().unwrap()), "{host}");
            // Target fields and the IpAddr API are public; neither may bypass
            // normalization merely because Target::new was not called.
            assert!(policy.allows(&crate::proxy::Target {
                host: host.into(),
                port: 443,
            }));
            assert_eq!(
                crate::proxy::Target::new(host, 443).unwrap().host,
                "10.1.2.3"
            );
        }
        assert_eq!(normalize_host("::ffff:10.1.2.3.").unwrap(), "10.1.2.3");
        for host in [
            "::ffff:11.0.0.1",
            "::ffff:b00:1",
            "2001:db8::1",
            "::a01:203",
        ] {
            assert!(!policy.allows_host(host), "{host}");
            assert!(!policy.allows_ip(host.parse().unwrap()), "{host}");
        }
        assert_eq!(normalize_host("2001:DB8::1").unwrap(), "2001:db8::1");
        assert_eq!(normalize_host("::10.1.2.3").unwrap(), "::a01:203");
    }

    #[test]
    fn ipv4_and_mapped_exclusions_reject_both_aliases_without_erasing_history() {
        for excluded in ["10.2.0.0/16", "::ffff:10.2.0.0/112"] {
            let policy = Policy::new(Vec::new(), vec!["10.0.0.0/8".parse().unwrap()])
                .unwrap()
                .with_excludes(vec![excluded.parse().unwrap()]);
            for host in ["10.2.3.4", "::ffff:10.2.3.4", "::ffff:a02:304"] {
                assert!(
                    policy.excludes_ip(host.parse().unwrap()),
                    "{host}/{excluded}"
                );
                assert!(!policy.allows_host(host), "{host}/{excluded}");
                assert!(
                    !policy.allows_ip(host.parse().unwrap()),
                    "{host}/{excluded}"
                );
            }
            for host in ["10.1.255.255", "::ffff:10.3.0.0"] {
                assert!(policy.allows_host(host), "{host}/{excluded}");
            }
            // Historical classification remains conservative even when the
            // current generation removes permission for the IPv4 destination.
            let empty = Policy::new(Vec::new(), Vec::new()).unwrap();
            let history = empty.merge_classification(&policy).unwrap();
            assert!(history.allows_host("::ffff:10.2.3.4"));
        }
    }

    #[test]
    fn every_explicit_mapped_cidr_matches_its_ipv4_boundaries_and_exclusions() {
        for prefix in 0..=32 {
            let v4 = Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 129), prefix)
                .unwrap()
                .trunc();
            let mapped: IpNet = format!("::ffff:203.0.113.129/{}", prefix + 96)
                .parse()
                .unwrap();
            let include = Policy::new(Vec::new(), vec![mapped, IpNet::V4(v4)]).unwrap();
            assert_eq!(include.networks(), &[IpNet::V4(v4)], "/{prefix}");
            let excluded = Policy::new(Vec::new(), vec!["0.0.0.0/0".parse().unwrap()])
                .unwrap()
                .with_excludes(vec![mapped]);
            let first = u32::from(v4.network());
            let last = u32::from(v4.broadcast());
            for value in [
                Some(first),
                Some(last),
                first.checked_sub(1),
                last.checked_add(1),
            ]
            .into_iter()
            .flatten()
            {
                let address = Ipv4Addr::from(value);
                let inside = first <= value && value <= last;
                for ip in [IpAddr::V4(address), IpAddr::V6(address.to_ipv6_mapped())] {
                    assert_eq!(include.allows_ip(ip), inside, "{ip}/{prefix}");
                    assert_eq!(
                        include.allows_host(&ip.to_string()),
                        inside,
                        "{ip}/{prefix}"
                    );
                    assert_eq!(excluded.excludes_ip(ip), inside, "{ip}/{prefix}");
                    assert_eq!(excluded.allows_ip(ip), !inside, "{ip}/{prefix}");
                }
            }
        }
    }

    #[test]
    fn broad_ipv6_rules_do_not_grant_or_exclude_actual_ipv4_destinations() {
        for network in ["::/0", "::ffff:0:0/80", "::ffff:0:0/95", "2001:db8::/32"] {
            let network: IpNet = network.parse().unwrap();
            let include = Policy::new(Vec::new(), vec![network]).unwrap();
            assert_eq!(include.networks(), &[network.trunc()]);
            let excluded = Policy::new(Vec::new(), vec!["0.0.0.0/0".parse().unwrap()])
                .unwrap()
                .with_excludes(vec![network]);
            for host in ["10.1.2.3", "::ffff:10.1.2.3", "::ffff:a01:203"] {
                assert!(!include.allows_host(host), "{host}/{network}");
                assert!(
                    !include.allows_ip(host.parse().unwrap()),
                    "{host}/{network}"
                );
                assert!(
                    !excluded.excludes_ip(host.parse().unwrap()),
                    "{host}/{network}"
                );
                assert!(excluded.allows_host(host), "{host}/{network}");
            }
        }
        let ordinary = Policy::new(Vec::new(), vec!["2001:db8::/32".parse().unwrap()]).unwrap();
        assert!(ordinary.allows_host("2001:db8::1"));
        assert!(!ordinary.allows_host("2001:db9::1"));
    }

    #[test]
    fn malformed_mapped_hosts_never_become_authorized_names_or_addresses() {
        let policy = Policy::new(Vec::new(), vec!["0.0.0.0/0".parse().unwrap()]).unwrap();
        for host in [
            "::ffff:010.1.2.3",
            "::ffff:256.1.2.3",
            "::ffff:10.1.2",
            "::ffff:10.1.2.3:4",
            "::ffff:10.1.2.3::",
            ":::ffff:a01:203",
            "::ffff:00000:203",
            "::ffff:a01:203%1",
            "::ffff:a01:203\n",
            "::ffff:a01:203\0",
            "[::ffff:a01:203",
            "::ffff:a01:203]",
            "0:0:0:0:0:ffff:a01:203:0",
        ] {
            assert!(normalize_host(host).is_err(), "{host:?}");
            assert!(!policy.allows_host(host), "{host:?}");
            assert!(crate::proxy::Target::new(host, 443).is_err(), "{host:?}");
        }
        for host in ["::ffff:10.1.2.3", "::ffff:a01:203"] {
            assert!(Policy::new(vec![host.into()], Vec::new()).is_err());
            assert!(Policy::new(Vec::new(), Vec::new())
                .unwrap()
                .with_gateway_domains(vec![Exact(host.into())], Vec::new())
                .is_err());
        }
    }

    #[test]
    fn gateway_domains_preserve_exact_and_subdomain_semantics() {
        let policy = Policy::new(Vec::new(), Vec::new())
            .unwrap()
            .with_gateway_domains(
                vec![Exact("Jira.Corp.".into()), Subdomains("svc.corp".into())],
                Vec::new(),
            )
            .unwrap();
        for host in ["jira.corp", "JIRA.CORP.", "a.svc.corp", "a.b.svc.corp"] {
            assert!(policy.allows_host(host), "{host}");
        }
        for host in [
            "other.jira.corp",
            "svc.corp",
            "evilsvc.corp",
            "a.svc.corp.evil",
        ] {
            assert!(!policy.allows_host(host), "{host}");
        }
        let pac = policy.pac("127.0.0.1:8080".parse().unwrap());
        assert!(pac.contains("host === \"jira.corp\""));
        assert!(!pac.contains("dnsDomainIs(host, \".jira.corp\")"));
        assert!(pac.contains("dnsDomainIs(host, \".svc.corp\")"));
        assert!(!pac.contains("host === \"svc.corp\""));
        for domain in ["10.1.2.3", "a\".corp", "*.corp"] {
            assert!(Policy::new(Vec::new(), Vec::new())
                .unwrap()
                .with_gateway_domains(vec![Exact(domain.into())], Vec::new())
                .is_err());
        }
    }

    #[test]
    fn gateway_exclusions_override_local_allow_but_do_not_erase_pac_history() {
        let old = Policy::new(Vec::new(), Vec::new())
            .unwrap()
            .with_gateway_domains(vec![Exact("retired.example".into())], Vec::new())
            .unwrap();
        let current = Policy::new(vec!["corp".into()], vec!["10.0.0.0/8".parse().unwrap()])
            .unwrap()
            .with_gateway_domains(
                Vec::new(),
                vec![Exact("jira.corp".into()), Subdomains("secret.corp".into())],
            )
            .unwrap();
        assert!(!current.allows_host("jira.corp"));
        assert!(current.allows_host("other.jira.corp"));
        assert!(current.allows_host("secret.corp"));
        assert!(!current.allows_host("a.secret.corp"));
        assert!(!current.allows_host("retired.example"));
        let pac_policy = old.merge_classification(&current).unwrap();
        assert!(pac_policy.allows_host("retired.example"));
        assert!(pac_policy.allows_host("jira.corp"));
        assert!(pac_policy.allows_host("a.secret.corp"));
        let pac = pac_policy.pac("127.0.0.1:8080".parse().unwrap());
        assert!(!pac.contains("; DIRECT"));
    }

    #[test]
    fn cumulative_classification_deduplicates_and_stops_at_the_limit() {
        let full = Policy::new(
            (0..16384).map(|i| format!("h{i}.corp")).collect(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(full.merge_classification(&full).unwrap(), full);
        let next = Policy::new(vec!["new.corp".into()], Vec::new()).unwrap();
        assert!(full.merge_classification(&next).is_err());
        let routes = Policy::new(
            Vec::new(),
            vec!["10.1.2.3/8".parse().unwrap(), "10.0.0.0/8".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(routes.networks(), &["10.0.0.0/8".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn domains_are_label_bounded_and_ips_need_explicit_routes() {
        let policy = Policy::new(
            vec!["Corp.Example.".into()],
            vec!["10.0.0.0/8".parse().unwrap()],
        )
        .unwrap();
        assert!(policy.allows_host("CORP.EXAMPLE"));
        assert!(policy.allows_host("api.corp.example."));
        assert!(!policy.allows_host("evilcorp.example"));
        assert!(!policy.allows_host("corp.example.attacker.test"));
        assert!(policy.allows_host("10.1.2.3"));
        assert!(!policy.allows_host("127.0.0.1"));
        assert!(!policy.allows_host("010.1.2.3"));
    }

    #[test]
    fn rejects_script_injection_and_invalid_names() {
        for bad in [
            "*.example",
            "a\";return DIRECT",
            "a\r\nb",
            "-a.example",
            "a..example",
            "https://example",
        ] {
            assert!(Policy::new(vec![bad.into()], vec![]).is_err());
        }
    }

    #[test]
    fn excludes_override_ip_authorization_without_pac_direct_fallback() {
        let policy = Policy::new(vec![], vec!["10.0.0.0/8".parse().unwrap()])
            .unwrap()
            .with_excludes(vec!["10.2.0.0/16".parse().unwrap()]);
        assert!(policy.allows_ip("10.1.2.3".parse().unwrap()));
        assert!(!policy.allows_ip("10.2.3.4".parse().unwrap()));
        assert!(policy.excludes_ip("10.2.3.4".parse().unwrap()));
        let pac = policy.pac("127.0.0.1:8080".parse().unwrap());
        assert!(!pac.contains("10.2.0.0"));
        assert!(pac.contains("(v4 & 4278190080) >>> 0) === 167772160"));
    }

    #[test]
    fn pac_has_no_direct_fallback_or_dns_lookup_for_corporate_targets() {
        let policy = Policy::new(
            vec!["corp.example".into()],
            vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()],
        )
        .unwrap();
        let pac = policy.pac("127.0.0.1:8080".parse().unwrap());
        assert!(pac.contains("PROXY 127.0.0.1:8080\""));
        assert!(!pac.contains("; DIRECT"));
        assert!(!pac.contains("dnsResolve"));
        assert!(!pac.contains("isInNet"));
        assert!(pac.contains("(v4 & 4278190080) >>> 0) === 167772160"));
        assert!(pac.contains("host.indexOf(':')"));
    }
}
