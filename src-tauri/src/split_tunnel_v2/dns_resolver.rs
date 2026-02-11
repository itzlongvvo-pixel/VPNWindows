//! Resolves domain rules to IP addresses and keeps them updated.

use crate::split_tunnel_v2::types::*;
use dashmap::DashMap;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock};
use tokio::time;
use tracing::{debug, info, warn};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    /// domain → resolved IPs
    cache: Arc<DashMap<String, Vec<IpAddr>>>,
    /// Signal to stop the refresh loop
    stop_tx: RwLock<Option<watch::Sender<bool>>>,
}

impl DnsResolver {
    pub fn new() -> Result<Self, SplitTunnelError> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 256;
        opts.use_hosts_file = true;
        opts.positive_min_ttl = Some(Duration::from_secs(60));

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            opts,
        );

        Ok(Self {
            resolver,
            cache: Arc::new(DashMap::new()),
            stop_tx: RwLock::new(None),
        })
    }

    /// Resolve a single domain and cache results
    pub async fn resolve_domain(&self, domain: &str) -> Result<Vec<IpAddr>, SplitTunnelError> {
        let lookup = self.resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| SplitTunnelError::DnsError(
                format!("Failed to resolve {domain}: {e}")
            ))?;

        let ips: Vec<IpAddr> = lookup.iter().collect();
        debug!("Resolved {domain} → {:?}", ips);

        self.cache.insert(domain.to_string(), ips.clone());
        Ok(ips)
    }

    /// Resolve all domain rules and return combined IpNet list
    pub async fn resolve_all_domains(
        &self,
        domains: &[String],
    ) -> Result<Vec<IpNet>, SplitTunnelError> {
        let mut all_nets = Vec::new();

        for domain in domains {
            match self.resolve_domain(domain).await {
                Ok(ips) => {
                    for ip in ips {
                        let net = match ip {
                            IpAddr::V4(_) => format!("{}/32", ip).parse::<IpNet>(),
                            IpAddr::V6(_) => format!("{}/128", ip).parse::<IpNet>(),
                        };

                        if let Ok(net) = net {
                            all_nets.push(net);
                        }
                    }
                }
                Err(e) => {
                    warn!("DNS resolution failed for {domain}: {e}");
                    // Continue with other domains — don't fail entirely
                }
            }
        }

        Ok(all_nets)
    }

    /// Start a background task that re-resolves domains periodically
    pub async fn start_refresh_loop<F>(
        &self,
        domains: Vec<String>,
        interval_secs: u64,
        on_update: F,
    ) where
        F: Fn(Vec<IpNet>) + Send + Sync + 'static,
    {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        *self.stop_tx.write().await = Some(stop_tx);

        let resolver = self.resolver.clone();
        let cache = self.cache.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval_secs));
            interval.tick().await; // skip first immediate tick

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut updated_nets = Vec::new();
                        for domain in &domains {
                            match resolver.lookup_ip(domain.as_str()).await {
                                Ok(lookup) => {
                                    let ips: Vec<IpAddr> = lookup.iter().collect();
                                    let old_ips = cache.get(domain).map(|v| v.clone());

                                    let changed = old_ips.as_ref() != Some(&ips);
                                    cache.insert(domain.clone(), ips.clone());

                                    if changed {
                                        info!("DNS updated for {domain}: {:?}", ips);
                                    }

                                    for ip in ips {
                                        if let Ok(net) = format!("{}/32", ip).parse::<IpNet>() {
                                            updated_nets.push(net);
                                        }
                                    }
                                }
                                Err(e) => warn!("DNS refresh failed for {domain}: {e}"),
                            }
                        }

                        if !updated_nets.is_empty() {
                            on_update(updated_nets);
                        }
                    }
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            info!("DNS refresh loop stopped");
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Stop the refresh loop
    pub async fn stop_refresh_loop(&self) {
        if let Some(tx) = self.stop_tx.write().await.take() {
            let _ = tx.send(true);
        }
    }

    /// Get current cache contents
    pub fn get_cache(&self) -> Vec<(String, Vec<IpAddr>)> {
        self.cache.iter().map(|entry| {
            (entry.key().clone(), entry.value().clone())
        }).collect()
    }
}
