use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures_util::future::join_all;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{
    addr::TargetAddr,
    config::{ProxyGroupConfig, ProxyGroupType},
    error::{ProxyError, Result},
    outbound::DynOutbound,
    tracker::TelemetryHub,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelayHistoryItem {
    pub time: u64,
    pub delay: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyInfoSnapshot {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_outbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    pub history: Vec<DelayHistoryItem>,
}

/// Thread-safe latency history store shared between Concrete Outbounds and Proxy Groups.
#[derive(Default)]
pub struct DelayStore {
    records: DashMap<String, VecDeque<DelayHistoryItem>>,
}

impl DelayStore {
    pub fn record(&self, name: &str, delay_ms: u64) {
        let mut entry = self.records.entry(name.to_string()).or_default();
        if entry.len() >= 16 {
            entry.pop_front();
        }
        entry.push_back(DelayHistoryItem {
            time: TelemetryHub::now_ms(),
            delay: delay_ms,
        });
    }

    pub fn record_failure(&self, name: &str) {
        self.record(name, 0);
    }

    pub fn latest_delay(&self, name: &str) -> Option<u64> {
        self.records
            .get(name)
            .and_then(|q| q.back().map(|item| item.delay))
            .filter(|d| *d > 0)
    }

    pub fn history(&self, name: &str) -> Vec<DelayHistoryItem> {
        self.records
            .get(name)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn import_from(&self, prev: &DelayStore, valid_names: &std::collections::HashSet<String>) {
        for item in prev.records.iter() {
            if valid_names.contains(item.key()) {
                self.records
                    .insert(item.key().clone(), item.value().clone());
            }
        }
    }
}

pub struct ProxyGroup {
    pub name: String,
    pub group_type: ProxyGroupType,
    pub members: Vec<String>,
    pub test_url: String,
    pub interval: Duration,
    pub tolerance_ms: u64,
    pub consistent_hash: bool,
    selected: RwLock<String>,
    rr_cursor: AtomicUsize,
    last_evaluated: Mutex<Option<Instant>>,
}

impl ProxyGroup {
    pub fn from_config(cfg: &ProxyGroupConfig) -> Self {
        let initial = cfg
            .proxies
            .first()
            .cloned()
            .unwrap_or_else(|| "REJECT".to_string());
        let consistent_hash = cfg
            .strategy
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("consistent-hashing"));
        Self {
            name: cfg.name.clone(),
            group_type: cfg.group_type,
            members: cfg.proxies.clone(),
            test_url: cfg.url.clone(),
            interval: Duration::from_secs(cfg.interval.max(10)),
            tolerance_ms: cfg.tolerance,
            consistent_hash,
            selected: RwLock::new(initial),
            rr_cursor: AtomicUsize::new(0),
            last_evaluated: Mutex::new(None),
        }
    }

    pub fn is_due_for_periodic_probe(&self, now: Instant) -> bool {
        match *self.last_evaluated.lock() {
            None => true,
            Some(prev) => now.duration_since(prev) >= self.interval,
        }
    }

    pub fn mark_evaluated(&self, now: Instant) {
        *self.last_evaluated.lock() = Some(now);
    }

    pub fn current(&self) -> String {
        self.selected.read().clone()
    }

    pub fn pick_member(&self, target: &TargetAddr, delays: &DelayStore) -> String {
        match self.group_type {
            ProxyGroupType::Select | ProxyGroupType::UrlTest | ProxyGroupType::Fallback => {
                self.selected.read().clone()
            }
            ProxyGroupType::LoadBalance => {
                // Prefer members that didn't fail their most recent probe (if probed)
                let healthy: Vec<&String> = self
                    .members
                    .iter()
                    .filter(|m| {
                        delays
                            .records
                            .get(*m)
                            .and_then(|q| q.back().map(|i| i.delay > 0))
                            .unwrap_or(true)
                    })
                    .collect();
                let pool: Vec<&String> = if healthy.is_empty() {
                    self.members.iter().collect()
                } else {
                    healthy
                };
                if pool.is_empty() {
                    return "REJECT".to_string();
                }
                if self.consistent_hash {
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    target.host.hash(&mut hasher);
                    let idx = (hasher.finish() as usize) % pool.len();
                    pool[idx].clone()
                } else {
                    let idx = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % pool.len();
                    pool[idx].clone()
                }
            }
        }
    }

    pub fn select_manual(&self, choice: &str) -> Result<()> {
        if self.group_type != ProxyGroupType::Select {
            return Err(ProxyError::Routing(format!(
                "proxy group '{}' is type {:?}, not Selector",
                self.name, self.group_type
            )));
        }
        if !self.members.iter().any(|m| m == choice) {
            return Err(ProxyError::Routing(format!(
                "proxy '{choice}' is not a member of group '{}'",
                self.name
            )));
        }
        *self.selected.write() = choice.to_string();
        Ok(())
    }

    /// Apply member latency probe results (preserving `self.members` config order) to update
    /// `selected` for `URLTest` (with `tolerance_ms` hysteresis), `Fallback`, and `LoadBalance`.
    pub fn apply_probe_results(&self, map: &HashMap<String, Option<u64>>, delays: &DelayStore) {
        match self.group_type {
            ProxyGroupType::UrlTest => {
                if let Some((best_name, best_ms)) = self
                    .members
                    .iter()
                    .filter_map(|m| map.get(m).and_then(|v| *v).map(|ms| (m, ms)))
                    .min_by_key(|(_, ms)| *ms)
                {
                    let current = self.selected.read().clone();
                    let current_ms = map.get(&current).and_then(|v| *v);
                    let should_switch = match current_ms {
                        None => true,
                        Some(cur) => cur > best_ms.saturating_add(self.tolerance_ms),
                    };
                    if should_switch {
                        *self.selected.write() = best_name.clone();
                    }
                    delays.record(&self.name, best_ms);
                }
            }
            ProxyGroupType::Fallback => {
                if let Some((first_alive, ms)) = self
                    .members
                    .iter()
                    .find_map(|m| map.get(m).and_then(|v| *v).map(|ms| (m, ms)))
                {
                    *self.selected.write() = first_alive.clone();
                    delays.record(&self.name, ms);
                }
            }
            ProxyGroupType::LoadBalance => {
                if let Some(best_ms) = self
                    .members
                    .iter()
                    .filter_map(|m| map.get(m).and_then(|v| *v))
                    .min()
                {
                    delays.record(&self.name, best_ms);
                }
            }
            ProxyGroupType::Select => {}
        }
    }

    /// Run bounded concurrent latency benchmark across all concrete outbounds referenced by this group,
    /// updating `selected` for `URLTest` (with `tolerance_ms` hysteresis), `Fallback`, and `LoadBalance`.
    pub async fn evaluate_health(
        &self,
        outbounds: &HashMap<String, DynOutbound>,
        delays: &DelayStore,
        override_url: Option<&str>,
        timeout: Duration,
    ) -> HashMap<String, Option<u64>> {
        self.evaluate_health_with_mode(outbounds, delays, override_url, timeout, true)
            .await
    }

    /// Run bounded concurrent latency benchmark with explicit `unified_delay` selection.
    pub async fn evaluate_health_with_mode(
        &self,
        outbounds: &HashMap<String, DynOutbound>,
        delays: &DelayStore,
        override_url: Option<&str>,
        timeout: Duration,
        unified_delay: bool,
    ) -> HashMap<String, Option<u64>> {
        let probe_url = override_url.unwrap_or(&self.test_url);
        let sem = Arc::new(Semaphore::new(16));
        let futs = self.members.iter().map(|member_name| {
            let member = member_name.clone();
            let outbound_opt = outbounds.get(&member).cloned();
            let sem_clone = Arc::clone(&sem);
            async move {
                let Some(outbound) = outbound_opt else {
                    return (member, None);
                };
                let _permit = sem_clone.acquire().await.ok();
                match outbound
                    .latency_test_with_mode(probe_url, timeout, unified_delay)
                    .await
                {
                    Ok(ms) => {
                        delays.record(&member, ms);
                        (member, Some(ms))
                    }
                    Err(_) => {
                        delays.record_failure(&member);
                        (member, None)
                    }
                }
            }
        });

        let results: Vec<(String, Option<u64>)> = join_all(futs).await;
        let map: HashMap<String, Option<u64>> = results.into_iter().collect();
        self.mark_evaluated(Instant::now());
        self.apply_probe_results(&map, delays);
        map
    }

    pub fn peek_member(&self, delays: &DelayStore) -> String {
        match self.group_type {
            ProxyGroupType::Select | ProxyGroupType::UrlTest | ProxyGroupType::Fallback => {
                self.selected.read().clone()
            }
            ProxyGroupType::LoadBalance => {
                let healthy: Vec<&String> = self
                    .members
                    .iter()
                    .filter(|m| {
                        delays
                            .records
                            .get(*m)
                            .and_then(|q| q.back().map(|i| i.delay > 0))
                            .unwrap_or(true)
                    })
                    .collect();
                let pool: Vec<&String> = if healthy.is_empty() {
                    self.members.iter().collect()
                } else {
                    healthy
                };
                if pool.is_empty() {
                    return "REJECT".to_string();
                }
                let idx = self.rr_cursor.load(Ordering::Relaxed) % pool.len();
                pool[idx].clone()
            }
        }
    }

    pub fn snapshot(&self, delays: &DelayStore) -> ProxyInfoSnapshot {
        ProxyInfoSnapshot {
            name: self.name.clone(),
            proxy_type: self.group_type.as_clash_type().to_string(),
            udp: true,
            now: Some(self.current()),
            all: Some(self.members.clone()),
            effective_outbound: None,
            effective_protocol: None,
            chains: None,
            history: delays.history(&self.name),
        }
    }
}
