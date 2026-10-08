use crate::config::WafConfig;
use regex::Regex;

#[derive(Clone)]
pub struct WafEngine {
    enabled: bool,
    block_sqli: bool,
    block_xss: bool,
    block_path_traversal: bool,
    sqli_regex: Regex,
    xss_regex: Regex,
    path_traversal_regex: Regex,
    bad_agents_regex: Regex,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WafResult {
    Allowed,
    Blocked { rule: &'static str, pattern: String },
}

impl WafEngine {
    pub fn new(config: &WafConfig) -> Self {
        let sqli_regex = Regex::new(
            r"(?i)(\b(union(\s+all)?\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|information_schema|or\s+1\s*=\s*1|'\s*or\s*'\w+'\s*=\s*'\w+)\b)|(--|#|/\*)"
        ).expect("Valid SQLi regex");

        let xss_regex = Regex::new(
            r"(?i)(<script[\s>]|javascript:|onload\s*=|onerror\s*=|onclick\s*=|eval\s*\(|alert\s*\(|<img\s+[^>]*onerror)"
        ).expect("Valid XSS regex");

        let path_traversal_regex =
            Regex::new(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)")
                .expect("Valid Path Traversal regex");

        let bad_agents_regex =
            Regex::new(r"(?i)(sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|nmap|acunetix)")
                .expect("Valid Scanner regex");

        Self {
            enabled: config.enabled,
            block_sqli: config.block_sqli,
            block_xss: config.block_xss,
            block_path_traversal: config.block_path_traversal,
            sqli_regex,
            xss_regex,
            path_traversal_regex,
            bad_agents_regex,
        }
    }

    pub fn inspect_with_tenant_policy(
        &self,
        uri_str: &str,
        user_agent: Option<&str>,
        body_sample: Option<&str>,
        tenant_sec: Option<&crate::router::DomainSecurityPolicy>,
    ) -> WafResult {
        // 1. Always inspect bad scanner User-Agents as a platform baseline guard
        if let Some(ua) = user_agent {
            if self.bad_agents_regex.is_match(ua) {
                return WafResult::Blocked {
                    rule: "KNOWN_MALICIOUS_SCANNER",
                    pattern: ua.to_string(),
                };
            }
        }

        // 2. Resolve effective inspection flags (Tenant policy takes precedence if present)
        let (enabled, block_traversal, block_sqli, block_xss) = match tenant_sec {
            Some(t) => {
                if !t.waf_enabled {
                    return WafResult::Allowed;
                }
                (true, t.block_path_traversal, t.block_sqli, t.block_xss)
            }
            None => {
                if !self.enabled {
                    return WafResult::Allowed;
                }
                (
                    self.enabled,
                    self.block_path_traversal,
                    self.block_sqli,
                    self.block_xss,
                )
            }
        };

        if !enabled {
            return WafResult::Allowed;
        }

        // 3. Inspect URI / Path Traversal
        if block_traversal && self.path_traversal_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "PATH_TRAVERSAL_DETECTED",
                pattern: uri_str.to_string(),
            };
        }

        // 4. Inspect SQL Injection in URI
        if block_sqli && self.sqli_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "SQLI_IN_URI",
                pattern: uri_str.to_string(),
            };
        }

        // 5. Inspect XSS in URI
        if block_xss && self.xss_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "XSS_IN_URI",
                pattern: uri_str.to_string(),
            };
        }

        // 6. Inspect Request Body sample if available
        if let Some(body) = body_sample {
            if block_sqli && self.sqli_regex.is_match(body) {
                return WafResult::Blocked {
                    rule: "SQLI_IN_BODY",
                    pattern: body.chars().take(80).collect(),
                };
            }

            if block_xss && self.xss_regex.is_match(body) {
                return WafResult::Blocked {
                    rule: "XSS_IN_BODY",
                    pattern: body.chars().take(80).collect(),
                };
            }
        }

        WafResult::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafConfig;
    use crate::router::DomainSecurityPolicy;

    fn test_waf() -> WafEngine {
        WafEngine::new(&WafConfig {
            enabled: true,
            block_sqli: true,
            block_xss: true,
            block_path_traversal: true,
        })
    }

    #[test]
    fn test_baseline_scanners_always_blocked() {
        let waf = test_waf();
        let disabled_policy = DomainSecurityPolicy {
            waf_enabled: false,
            block_sqli: false,
            block_xss: false,
            block_path_traversal: false,
            blocked_paths: vec![],
            rate_limit_enabled: false,
            requests_per_second: 0,
            burst_capacity: 0,
        };

        // Even if tenant disabled WAF, scanner signature (sqlmap) is blocked at infrastructure baseline
        let res = waf.inspect_with_tenant_policy(
            "/api/data",
            Some("sqlmap/1.0"),
            None,
            Some(&disabled_policy),
        );
        assert!(matches!(
            res,
            WafResult::Blocked {
                rule: "KNOWN_MALICIOUS_SCANNER",
                ..
            }
        ));
    }

    #[test]
    fn test_tenant_waf_disabled_allows_sqli() {
        let waf = test_waf();
        let disabled_policy = DomainSecurityPolicy {
            waf_enabled: false,
            block_sqli: false,
            block_xss: false,
            block_path_traversal: false,
            blocked_paths: vec![],
            rate_limit_enabled: false,
            requests_per_second: 0,
            burst_capacity: 0,
        };

        let res = waf.inspect_with_tenant_policy(
            "/api/users?id=1%20UNION%20SELECT%20password",
            Some("curl/7.68.0"),
            None,
            Some(&disabled_policy),
        );
        assert_eq!(res, WafResult::Allowed);
    }

    #[test]
    fn test_tenant_waf_selective_rule_toggles() {
        let waf = test_waf();
        let selective_policy = DomainSecurityPolicy {
            waf_enabled: true,
            block_sqli: false,
            block_xss: true,
            block_path_traversal: true,
            blocked_paths: vec![],
            rate_limit_enabled: false,
            requests_per_second: 0,
            burst_capacity: 0,
        };

        // SQLi allowed because block_sqli is false for this tenant
        let res_sqli = waf.inspect_with_tenant_policy(
            "/api/users?id=1%20UNION%20SELECT%201",
            Some("curl/7.68.0"),
            None,
            Some(&selective_policy),
        );
        assert_eq!(res_sqli, WafResult::Allowed);

        // XSS blocked because block_xss is true
        let res_xss = waf.inspect_with_tenant_policy(
            "/search?q=<script>alert(1)</script>",
            Some("curl/7.68.0"),
            None,
            Some(&selective_policy),
        );
        assert!(matches!(
            res_xss,
            WafResult::Blocked {
                rule: "XSS_IN_URI",
                ..
            }
        ));

        // Path traversal blocked because block_path_traversal is true
        let res_traversal = waf.inspect_with_tenant_policy(
            "/static/../../etc/passwd",
            Some("curl/7.68.0"),
            None,
            Some(&selective_policy),
        );
        assert!(matches!(
            res_traversal,
            WafResult::Blocked {
                rule: "PATH_TRAVERSAL_DETECTED",
                ..
            }
        ));
    }
}
