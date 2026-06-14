use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;
use crate::config::Settings;

async fn check_health(addr: &str, timeout: Duration) -> bool {
    match tokio::net::lookup_host(addr).await {
        Ok(mut addrs) => {
            if let Some(socket_addr) = addrs.next() {
                match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
                    Ok(Ok(_)) => true,
                    _ => false,
                }
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

pub async fn run_health_check_worker(
    settings: Arc<RwLock<Settings>>,
    healthy_backends: Arc<RwLock<HashMap<String, bool>>>,
) {
    loop {
        // Collect all unique backends from current config
        let (backends_to_check, all_backends): (Vec<String>, Vec<String>) = {
            let s = settings.read().unwrap();
            let mut addrs_to_check = std::collections::HashSet::new();
            let mut all_addrs = std::collections::HashSet::new();
            
            for r in &s.upstream.routes {
                for b in &r.backends {
                    all_addrs.insert(b.clone());
                    if r.health_check {
                        addrs_to_check.insert(b.clone());
                    }
                }
            }
            
            if let Some(f) = &s.upstream.fallback {
                for b in &f.backends {
                    all_addrs.insert(b.clone());
                    if f.health_check {
                        addrs_to_check.insert(b.clone());
                    }
                }
            }
            
            (addrs_to_check.into_iter().collect(), all_addrs.into_iter().collect())
        };

        if !all_backends.is_empty() {
            let mut results = HashMap::new();

            // Explicitly set unchecked backends as healthy (true)
            for addr in &all_backends {
                if !backends_to_check.contains(addr) {
                    results.insert(addr.clone(), true);
                }
            }

            // Probe checked backends in parallel using tokio tasks
            if !backends_to_check.is_empty() {
                let mut tasks = Vec::new();

                for addr in backends_to_check {
                    let addr_clone = addr.clone();
                    tasks.push(tokio::spawn(async move {
                        let is_healthy = check_health(&addr_clone, Duration::from_secs(2)).await;
                        (addr_clone, is_healthy)
                    }));
                }

                for task in tasks {
                    if let Ok((addr, is_healthy)) = task.await {
                        if !is_healthy {
                            warn!("Backend upstream {} is UNHEALTHY", addr);
                        }
                        results.insert(addr, is_healthy);
                    }
                }
            }

            // Update active status
            {
                let mut guard = healthy_backends.write().unwrap();
                *guard = results;
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
