use std::{
    collections::{HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
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
    revision: AtomicU64,
}

impl DelayStore {
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    pub fn record(&self, name: &str, delay_ms: u64) {
        let mut entry = self.records.entry(name.to_string()).or_default();
        if entry.len() >= 16 {
            entry.pop_front();
        }
        entry.push_back(DelayHistoryItem {
            time: TelemetryHub::now_ms(),
            delay: delay_ms,
        });
        drop(entry);
        self.revision.fetch_add(1, Ordering::Release);
    }

    pub fn record_failure(&self, name: &str) {
        self.record(name, 0);
    }

    pub fn latest_delay(&self, name: &str) -> Option<u64> {
        self.latest_delay_with_time(name).map(|(_, d)| d)
    }

    pub fn latest_delay_with_time(&self, name: &str) -> Option<(u64, u64)> {
        self.records
            .get(name)
            .and_then(|q| q.back().map(|item| (item.time, item.delay)))
            .filter(|(_, d)| *d > 0)
    }

    pub fn is_known_failed(&self, name: &str) -> bool {
        self.records
            .get(name)
            .and_then(|q| q.back().map(|item| item.delay == 0))
            .unwrap_or(false)
    }

    pub fn clear(&self, name: &str) {
        if self.records.remove(name).is_some() {
            self.revision.fetch_add(1, Ordering::Release);
        }
    }

    pub fn seed_if_absent(&self, name: &str, delay_ms: u64) {
        if delay_ms == 0 {
            return;
        }
        if self.records.get(name).is_some_and(|q| !q.is_empty()) {
            return;
        }
        let mut entry = self.records.entry(name.to_string()).or_default();
        if entry.is_empty() {
            entry.push_back(DelayHistoryItem {
                time: TelemetryHub::now_ms(),
                delay: delay_ms,
            });
            drop(entry);
            self.revision.fetch_add(1, Ordering::Release);
        }
    }

    pub fn record_passive_if_stale(&self, name: &str, rtt_ms: u64, max_age_ms: u64) {
        if rtt_ms == 0 {
            return;
        }
        let now_ms = TelemetryHub::now_ms();
        match self.latest_delay_with_time(name) {
            None => self.record(name, rtt_ms),
            Some(_) if max_age_ms == 0 => self.record(name, rtt_ms),
            Some((last_time, last_delay)) => {
                if now_ms.saturating_sub(last_time) >= max_age_ms {
                    // Dampen single-connection RRC-wakeup / bootstrap outliers when refreshing a
                    // previously healthy node so one slow handshake does not pin a multi-second badge.
                    let effective_ms = if rtt_ms > last_delay.saturating_mul(2)
                        && rtt_ms.saturating_sub(last_delay) >= 200
                    {
                        ((last_delay.saturating_mul(2) + rtt_ms) / 3)
                            .min(last_delay.saturating_mul(3))
                    } else {
                        rtt_ms
                    };
                    self.record(name, effective_ms.max(1));
                } else if last_delay >= 250
                    && rtt_ms.saturating_mul(2) <= last_delay
                    && last_delay.saturating_sub(rtt_ms) >= 150
                {
                    // Fast downward outlier recovery: if an initial cold-start / radio-wake dial
                    // recorded an inflated RTT (e.g. 3094ms or 467ms) and a subsequent connection
                    // completes in <= half that time (e.g. 105ms), immediately correct it downward.
                    self.record(name, rtt_ms);
                }
            }
        }
    }

    pub fn history(&self, name: &str) -> Vec<DelayHistoryItem> {
        self.records
            .get(name)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn import_from(&self, prev: &DelayStore, valid_names: &std::collections::HashSet<String>) {
        let mut imported = false;
        for item in prev.records.iter() {
            if valid_names.contains(item.key()) {
                self.records
                    .insert(item.key().clone(), item.value().clone());
                imported = true;
            }
        }
        if imported {
            self.revision.fetch_add(1, Ordering::Release);
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

    /// Idempotently update `selected` for `URLTest` (with `tolerance_ms` hysteresis), `Fallback`,
    /// and `LoadBalance` from `map` without mutating `DelayStore`, returning the group's resulting
    /// effective probe latency (`Some(ms)`) or `None` if all members failed / selected member failed.
    pub fn update_selection_from_probes(&self, map: &HashMap<String, Option<u64>>) -> Option<u64> {
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
                        Some(best_ms)
                    } else {
                        current_ms.or(Some(best_ms))
                    }
                } else {
                    None
                }
            }
            ProxyGroupType::Fallback => {
                if let Some((first_alive, ms)) = self
                    .members
                    .iter()
                    .find_map(|m| map.get(m).and_then(|v| *v).map(|ms| (m, ms)))
                {
                    *self.selected.write() = first_alive.clone();
                    Some(ms)
                } else {
                    None
                }
            }
            ProxyGroupType::LoadBalance => self
                .members
                .iter()
                .filter_map(|m| map.get(m).and_then(|v| *v))
                .min(),
            ProxyGroupType::Select => {
                let current = self.selected.read().clone();
                map.get(&current).and_then(|v| *v)
            }
        }
    }

    /// Apply member latency probe results (preserving `self.members` config order) to update
    /// `selected` for `URLTest` (with `tolerance_ms` hysteresis), `Fallback`, and `LoadBalance`,
    /// and record the group's resulting latency (or failure when all candidate/selected members fail)
    /// in `delays` so dead groups never retain stale pre-outage delays.
    pub fn apply_probe_results(&self, map: &HashMap<String, Option<u64>>, delays: &DelayStore) {
        match self.update_selection_from_probes(map) {
            Some(ms) => delays.record(&self.name, ms),
            None => delays.record_failure(&self.name),
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
    /// Non-concrete members (nested `ProxyGroup`s) resolve their current delay from `delays`.
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
                    let sub_delay = delays.latest_delay(&member);
                    return (member, sub_delay);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_store_seed_if_absent_and_passive_stale_refresh() {
        let store = DelayStore::default();
        store.seed_if_absent("node-a", 0);
        assert!(store.latest_delay("node-a").is_none());

        store.seed_if_absent("node-a", 120);
        assert_eq!(store.latest_delay("node-a"), Some(120));
        assert!(store.latest_delay_with_time("node-a").is_some());

        // Subsequent seed_if_absent must NOT overwrite an existing entry.
        store.seed_if_absent("node-a", 45);
        assert_eq!(store.latest_delay("node-a"), Some(120));

        // Passive RTT should NOT overwrite a fresh sample (< 180_000ms old).
        store.record_passive_if_stale("node-a", 80, 180_000);
        assert_eq!(store.latest_delay("node-a"), Some(120));

        // Passive RTT SHOULD record when max_age_ms == 0 or absent.
        store.record_passive_if_stale("node-a", 80, 0);
        assert_eq!(store.latest_delay("node-a"), Some(80));

        store.record_passive_if_stale("node-b", 65, 180_000);
        assert_eq!(store.latest_delay("node-b"), Some(65));

        // Failed probe should not be overwritten by offline cache seed.
        store.record_failure("node-c");
        assert!(store.is_known_failed("node-c"));
        store.seed_if_absent("node-c", 99);
        assert_eq!(store.latest_delay("node-c"), None);
        store.clear("node-c");
        assert!(!store.is_known_failed("node-c"));
    }

    #[test]
    fn apply_probe_results_clears_stale_group_delay_and_preserves_hysteresis_rtt() {
        let store = DelayStore::default();
        let grp = ProxyGroup::from_config(&ProxyGroupConfig {
            name: "HK-Auto".to_string(),
            group_type: ProxyGroupType::UrlTest,
            proxies: vec!["hk-1".to_string(), "hk-2".to_string()],
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval: 60,
            tolerance: 30,
            strategy: None,
        });

        // Initial healthy probe: hk-1=60ms, hk-2=45ms -> within 30ms tolerance so hk-1 stays selected (60ms)
        let mut initial = HashMap::new();
        initial.insert("hk-1".to_string(), Some(60));
        initial.insert("hk-2".to_string(), Some(45));
        grp.apply_probe_results(&initial, &store);
        assert_eq!(grp.current(), "hk-1");
        assert_eq!(store.latest_delay("HK-Auto"), Some(60));

        // Total outage: both hk-1 and hk-2 fail -> HK-Auto MUST record failure and clear stale 60ms delay
        let mut outage = HashMap::new();
        outage.insert("hk-1".to_string(), None);
        outage.insert("hk-2".to_string(), None);
        grp.apply_probe_results(&outage, &store);
        assert_eq!(store.latest_delay("HK-Auto"), None);
        assert!(store.is_known_failed("HK-Auto"));
    }

    #[test]
    fn passive_delay_dampens_upward_wake_spike_and_recovers_fast_downward() {
        let store = DelayStore::default();

        // 1. Cold-start cellular RRC-wake spike (3094ms) followed immediately by normal 105ms traffic
        store.record_passive_if_stale("sg-vless", 3094, 180_000);
        assert_eq!(store.latest_delay("sg-vless"), Some(3094));
        store.record_passive_if_stale("sg-vless", 105, 180_000);
        assert_eq!(store.latest_delay("sg-vless"), Some(105));

        // Normal jitter around 105ms (e.g. 88ms or 140ms) must NOT churn fresh entry
        let rev_after_recovery = store.revision();
        store.record_passive_if_stale("sg-vless", 88, 180_000);
        store.record_passive_if_stale("sg-vless", 140, 180_000);
        assert_eq!(store.latest_delay("sg-vless"), Some(105));
        assert_eq!(store.revision(), rev_after_recovery);

        // 2. Moderate spike (467ms) followed by normal 128ms handshake also recovers immediately
        store.record("sg-vless", 467);
        store.record_passive_if_stale("sg-vless", 128, 180_000);
        assert_eq!(store.latest_delay("sg-vless"), Some(128));

        // 3. Stale refresh with a 3094ms single-connection outlier is dampened (<= 3x prior 128ms)
        store.record_passive_if_stale("sg-vless", 3094, 1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        store.record_passive_if_stale("sg-vless", 3094, 1);
        let dampened = store.latest_delay("sg-vless").unwrap();
        assert!(
            dampened <= 128 * 3 * 3,
            "expected dampened spike <= 1152ms, got {dampened}ms"
        );
        // Next normal 105ms connection brings it right back down without waiting 3 minutes
        store.record_passive_if_stale("sg-vless", 105, 180_000);
        assert_eq!(store.latest_delay("sg-vless"), Some(105));
    }
}
