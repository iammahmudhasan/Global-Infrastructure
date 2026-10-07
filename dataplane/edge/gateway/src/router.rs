use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct UpstreamNode {
    pub url: String,
    pub healthy: bool,
    pub latency_ms: u64,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Router {
    nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    index: Arc<AtomicUsize>,
    timeout: Duration,
}

impl Router {
    pub fn new(targets: Vec<String>, timeout_ms: u64) -> Self {
        let nodes = targets
            .into_iter()
            .map(|url| UpstreamNode {
                url,
                healthy: true,
                latency_ms: 10,
            })
            .collect();

        Self {
            nodes: Arc::new(RwLock::new(nodes)),
            index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Selects next healthy upstream node using round-robin
    pub fn select_upstream(&self) -> Option<String> {
        let nodes = self.nodes.read().unwrap();
        let healthy_nodes: Vec<&UpstreamNode> = nodes.iter().filter(|n| n.healthy).collect();

        if healthy_nodes.is_empty() {
            // Invariant (Audit Finding 13): Never forward traffic to known unhealthy backends
            return None;
        }

        let idx = self.index.fetch_add(1, Ordering::Relaxed) % healthy_nodes.len();
        Some(healthy_nodes[idx].url.clone())
    }

    #[allow(dead_code)]
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(node) = nodes.iter_mut().find(|n| n.url == url) {
            node.healthy = healthy;
            node.latency_ms = latency_ms;
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

        // Initially both are healthy -> selects upstreams
        let u1 = router.select_upstream();
        assert!(u1.is_some());

        // Mark origin-1 unhealthy
        router.mark_health("https://origin-1.example.com", false, 999);
        let u2 = router.select_upstream().unwrap();
        assert_eq!(u2, "https://origin-2.example.com");

        // Mark origin-2 also unhealthy -> must return None (NO fallback to dead node)
        router.mark_health("https://origin-2.example.com", false, 999);
        let u3 = router.select_upstream();
        assert!(u3.is_none(), "expected None when all upstreams are unhealthy");

        // Recover origin-1 -> resumes routing
        router.mark_health("https://origin-1.example.com", true, 12);
        let u4 = router.select_upstream();
        assert_eq!(u4, Some("https://origin-1.example.com".to_string()));
    }
}
