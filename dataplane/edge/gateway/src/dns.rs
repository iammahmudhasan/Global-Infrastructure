use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Thread-safe DNS resolver supporting pinned IP destinations.
/// Ensures HTTPS connections to origins use the origin hostname for TLS SNI and certificate validation
/// while connecting directly to pre-resolved / pinned IP addresses without DNS rebinding vulnerabilities.
#[derive(Clone, Default)]
pub struct PinnedDnsResolver {
    pinned: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinnedDnsResolver {
    pub fn new() -> Self {
        Self {
            pinned: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_all(&self, mappings: HashMap<String, Vec<SocketAddr>>) {
        let mut map = self.pinned.write().unwrap();
        *map = mappings;
    }
}

impl Resolve for PinnedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_ascii_lowercase();
        if let Some(addrs) = self.pinned.read().unwrap().get(&domain).cloned() {
            let boxed: Addrs = Box::new(addrs.into_iter());
            return Box::pin(std::future::ready(Ok(boxed)));
        }

        Box::pin(async move {
            let host_port = format!("{}:0", domain);
            let addrs = tokio::net::lookup_host(host_port)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let boxed: Addrs = Box::new(addrs);
            Ok(boxed)
        })
    }
}
