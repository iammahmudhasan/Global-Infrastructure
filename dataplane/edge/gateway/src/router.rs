use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
        let nodes = self.nodes.read();
        let healthy_nodes: Vec<&UpstreamNode> = nodes.iter().filter(|n| n.healthy).collect();

        if healthy_nodes.is_empty() {
            // Fallback to first node even if deemed unhealthy
            return nodes.first().map(|n| n.url.clone());
        }

        let idx = self.index.fetch_add(1, Ordering::Relaxed) % healthy_nodes.len();
        Some(healthy_nodes[idx].url.clone())
    }

    #[allow(dead_code)]
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        let mut nodes = self.nodes.write();
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
