use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct UpstreamNode {
    pub url: String,
    pub healthy: bool,
    pub latency_ms: u64,
    pub ewma_latency_ms: f64,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Router {
    nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    index: Arc<AtomicUsize>,
    timeout: Duration,
}

impl Router {
    const EWMA_ALPHA: f64 = 0.2;

    pub fn new(targets: Vec<String>, timeout_ms: u64) -> Self {
        let nodes = targets
            .into_iter()
            .map(|url| UpstreamNode {
                url,
                healthy: true,
                latency_ms: 10,
                ewma_latency_ms: 10.0,
            })
            .collect();

        Self {
            nodes: Arc::new(RwLock::new(nodes)),
            index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Selects lowest latency healthy upstream node using smoothed EWMA
    pub fn select_upstream(&self) -> Option<String> {
        let nodes = self.nodes.read().unwrap();
        let mut healthy_nodes: Vec<&UpstreamNode> = nodes.iter().filter(|n| n.healthy).collect();

        if healthy_nodes.is_empty() {
            // Invariant (Audit Finding 13): Never forward traffic to known unhealthy backends
            return None;
        }

        // Sort by smoothed EWMA latency (lowest latency preferred)
        healthy_nodes.sort_by(|a, b| {
            a.ewma_latency_ms
                .partial_cmp(&b.ewma_latency_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let min_latency = healthy_nodes[0].ewma_latency_ms;
        let tied_best_nodes: Vec<&&UpstreamNode> = healthy_nodes
            .iter()
            .filter(|n| (n.ewma_latency_ms - min_latency).abs() < 1e-6)
            .collect();

        let idx = self.index.fetch_add(1, Ordering::Relaxed) % tied_best_nodes.len();
        Some(tied_best_nodes[idx].url.clone())
    }

    #[allow(dead_code)]
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.iter_mut().find(|n| n.url == url) {
            node.healthy = healthy;
            node.latency_ms = latency_ms;
            if healthy && latency_ms > 0 {
                if node.ewma_latency_ms <= 0.0 {
                    node.ewma_latency_ms = latency_ms as f64;
                } else {
                    node.ewma_latency_ms = Self::EWMA_ALPHA * (latency_ms as f64)
                        + (1.0 - Self::EWMA_ALPHA) * node.ewma_latency_ms;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_upstream_healthy_and_unhealthy() {
        let targets = vec![
            "https://origin-1.example.com".to_string(),
            "https://origin-2.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        // Initially both are healthy -> selects upstream
        let u1 = router.select_upstream();
        assert!(u1.is_some());

        // Mark origin-1 unhealthy
        router.mark_health("https://origin-1.example.com", false, 999);
        let u2 = router.select_upstream().unwrap();
        assert_eq!(u2, "https://origin-2.example.com");

        // Mark origin-2 also unhealthy -> must return None (NO fallback to dead node)
        router.mark_health("https://origin-2.example.com", false, 999);
        let u3 = router.select_upstream();
        assert!(
            u3.is_none(),
            "expected None when all upstreams are unhealthy"
        );

        // Recover origin-1 -> resumes routing
        router.mark_health("https://origin-1.example.com", true, 12);
        let u4 = router.select_upstream();
        assert_eq!(u4, Some("https://origin-1.example.com".to_string()));
    }

    #[test]
    fn test_ewma_latency_routing_preference() {
        let targets = vec![
            "https://slow-origin.example.com".to_string(),
            "https://fast-origin.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        // Set slow origin to 150ms
        router.mark_health("https://slow-origin.example.com", true, 150);
        // Set fast origin to 5ms
        router.mark_health("https://fast-origin.example.com", true, 5);

        // Router should prioritize lowest EWMA latency
        let selected = router.select_upstream().unwrap();
        assert_eq!(selected, "https://fast-origin.example.com");
    }
}
