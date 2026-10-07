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

        let path_traversal_regex = Regex::new(
            r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)"
        ).expect("Valid Path Traversal regex");

        let bad_agents_regex = Regex::new(
            r"(?i)(sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|nmap|acunetix)"
        ).expect("Valid Scanner regex");

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

    pub fn inspect(&self, uri_str: &str, user_agent: Option<&str>, body_sample: Option<&str>) -> WafResult {
        if !self.enabled {
            return WafResult::Allowed;
        }

        // 1. Inspect User-Agent
        if let Some(ua) = user_agent {
            if self.bad_agents_regex.is_match(ua) {
                return WafResult::Blocked {
                    rule: "MALICIOUS_SCANNER_USER_AGENT",
                    pattern: ua.to_string(),
                };
            }
        }

        // 2. Inspect URI / Path Traversal
        if self.block_path_traversal && self.path_traversal_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "PATH_TRAVERSAL_DETECTED",
                pattern: uri_str.to_string(),
            };
        }

        // 3. Inspect SQL Injection in URI
        if self.block_sqli && self.sqli_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "SQLI_IN_URI",
                pattern: uri_str.to_string(),
            };
        }

        // 4. Inspect XSS in URI
        if self.block_xss && self.xss_regex.is_match(uri_str) {
            return WafResult::Blocked {
                rule: "XSS_IN_URI",
                pattern: uri_str.to_string(),
            };
        }

        // 5. Inspect Request Body sample if available
        if let Some(body) = body_sample {
            if self.block_sqli && self.sqli_regex.is_match(body) {
                return WafResult::Blocked {
                    rule: "SQLI_IN_BODY",
                    pattern: body.chars().take(80).collect(),
                };
            }

            if self.block_xss && self.xss_regex.is_match(body) {
                return WafResult::Blocked {
                    rule: "XSS_IN_BODY",
                    pattern: body.chars().take(80).collect(),
                };
            }
        }

        WafResult::Allowed
    }
}
