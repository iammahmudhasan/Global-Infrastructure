use crate::config::GatewayConfig;
use crate::dns::PinnedDnsResolver;
use crate::router::{HealthProbeTarget, Router};
use reqwest::Client as HttpClient;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

/// Constructs the probe URL and Host header for a synthetic target.
/// Ensures virtual hosts receive domain-based TLS SNI and HTTP Host header
/// rather than bare IP addresses which cause 400 Bad Request / SSL mismatch on shared web servers.
pub fn construct_probe_request_params(
    target: &HealthProbeTarget,
    health_path: &str,
) -> (String, String) {
    let clean_path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{}", health_path)
    };

    let parsed_url = reqwest::Url::parse(&target.url).ok();
    let scheme = parsed_url.as_ref().map(|u| u.scheme()).unwrap_or("http");
    let port_suffix = parsed_url
        .as_ref()
        .and_then(|u| u.port())
        .map(|p| format!(":{}", p))
        .unwrap_or_default();

    let (probe_host, host_header) = if let Some(ref sni) = target.sni {
        (sni.as_str(), sni.clone())
    } else if !target.host_header.is_empty() {
        (target.host_header.as_str(), target.host_header.clone())
    } else if let Some(ref u) = parsed_url {
        let h = u.host_str().unwrap_or("localhost");
        (h, h.to_string())
    } else {
        ("localhost", "localhost".to_string())
    };

    let check_url = format!("{}://{}{}{}", scheme, probe_host, port_suffix, clean_path);
    (check_url, host_header)
}

/// Builds an active synthetic probing HTTP client with anti-SSRF protections,
/// zero redirect policy, and DNS resolution bound to PinnedDnsResolver.
pub fn create_health_client(
    timeout_ms: u64,
    dns_resolver: Arc<PinnedDnsResolver>,
) -> Result<HttpClient, reqwest::Error> {
    HttpClient::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::none()) // Prevent SSRF / open-redirect attacks
        .dns_resolver(dns_resolver)
        .pool_max_idle_per_host(64)
        .tcp_nodelay(true)
        .build()
}

/// Executes a single synthetic probe against an upstream target and returns (canonical_url, is_healthy, latency_ms).
pub async fn probe_single_target(
    client: &HttpClient,
    target: &HealthProbeTarget,
    health_path: &str,
) -> (String, bool, u64) {
    let (check_url, host_header) = construct_probe_request_params(target, health_path);
    let start = std::time::Instant::now();

    let is_healthy = match client
        .get(&check_url)
        .header(reqwest::header::HOST, &host_header)
        .header(reqwest::header::USER_AGENT, "NexusEdge-HealthMonitor/1.0")
        .header("X-NexusEdge-HealthCheck", "true")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            status.is_success() || status.is_redirection()
        }
        Err(err) => {
            debug!(
                target = %target.url,
                probe_url = %check_url,
                error = %err,
                "Synthetic health probe failed"
            );
            false
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;
    (target.url.clone(), is_healthy, latency_ms)
}

/// Spawns the autonomous background synthetic health prober task.
pub fn spawn_active_health_prober(
    router: Router,
    config: &GatewayConfig,
    dns_resolver: Arc<PinnedDnsResolver>,
) -> tokio::task::JoinHandle<()> {
    let health_client = match create_health_client(config.upstream.timeout_ms, dns_resolver) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create synthetic health client: {:?}", e);
            return tokio::spawn(async {});
        }
    };

    let health_path = config.upstream.health_check_path.clone();
    let interval_secs = config.upstream.health_check_interval_secs.max(1);

    info!(
        interval_secs = interval_secs,
        health_path = %health_path,
        "Starting autonomous synthetic health prober"
    );

    tokio::spawn(async move {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(32));
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            let current_targets = router.health_probe_targets();
            if current_targets.is_empty() {
                continue;
            }

            let mut join_set = tokio::task::JoinSet::new();
            for target in current_targets {
                let client = health_client.clone();
                let path = health_path.clone();
                let permit = semaphore.clone();
                join_set.spawn(async move {
                    let _permit = permit.acquire().await;
                    probe_single_target(&client, &target, &path).await
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Ok((target_url, is_healthy, latency_ms)) = res {
                    router.mark_health(&target_url, is_healthy, latency_ms);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_probe_request_params_with_sni() {
        let target = HealthProbeTarget {
            url: "https://185.232.14.188:443".to_string(),
            host_header: "aeitron.com".to_string(),
            sni: Some("aeitron.com".to_string()),
            destination_addr: Some("185.232.14.188:443".parse().unwrap()),
        };

        let (url, host) = construct_probe_request_params(&target, "/healthz");
        assert_eq!(url, "https://aeitron.com:443/healthz");
        assert_eq!(host, "aeitron.com");
    }

    #[test]
    fn test_construct_probe_request_params_without_sni() {
        let target = HealthProbeTarget {
            url: "http://origin-1.internal:8080".to_string(),
            host_header: "shop.example.com".to_string(),
            sni: None,
            destination_addr: None,
        };

        let (url, host) = construct_probe_request_params(&target, "status");
        assert_eq!(url, "http://shop.example.com:8080/status");
        assert_eq!(host, "shop.example.com");
    }
}
