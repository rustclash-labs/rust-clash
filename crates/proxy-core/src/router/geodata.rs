use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{
    addr::TargetAddr,
    config::uri::redact_sensitive_text,
    crypto::tls::build_tls_client_config,
    dns::{
        upstream::BootstrapDnsServer,
        wire::{DnsAnswerData, QTYPE_A, QTYPE_AAAA, build_dns_query, extract_dns_response_meta},
    },
    error::{ProxyError, Result},
    outbound::DynOutbound,
    platform::socket_protect::{global_socket_protector, has_custom_socket_protector},
    router::{
        Router,
        geoip_data::{GeoIpMatcher, lookup_builtin_geoip},
        geosite_data::{
            GeoSiteMatcher, lookup_builtin_geosite, lookup_builtin_geosite_cn_subset,
            parse_geosite_category_and_attrs,
        },
        mmdb::MmdbReader,
    },
};

/// Default staleness window for persisted GeoSite/GeoIP datasets (7 days).
pub const DEFAULT_GEODATA_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_GEODATA_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;

const GEOSITE_CN_FILE: &str = "geosite_cn.txt";
const GEOSITE_NON_CN_FILE: &str = "geosite_geolocation_not_cn.txt";
const GEOIP_CN_FILE: &str = "geoip_cn.txt";
const MMDB_FILE: &str = "Country.mmdb";
const MANIFEST_FILE: &str = "manifest.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoUpdateUrls {
    pub label: String,
    pub geosite_cn_url: String,
    pub geosite_non_cn_url: String,
    pub geoip_cn_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmdb_url: Option<String>,
}

impl GeoUpdateUrls {
    pub fn default_mirrors() -> Vec<Self> {
        vec![
            Self {
                label: "jsdelivr-testingcf (Loyalsoldier/clash-rules)".to_string(),
                geosite_cn_url:
                    "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
                        .to_string(),
                geosite_non_cn_url:
                    "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
                        .to_string(),
                geoip_cn_url:
                    "https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
                        .to_string(),
                mmdb_url: Some(
                    "https://testingcf.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
                        .to_string(),
                ),
            },
            Self {
                label: "jsdelivr-fastly (Loyalsoldier/clash-rules)".to_string(),
                geosite_cn_url:
                    "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
                        .to_string(),
                geosite_non_cn_url:
                    "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
                        .to_string(),
                geoip_cn_url:
                    "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
                        .to_string(),
                mmdb_url: Some(
                    "https://fastly.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
                        .to_string(),
                ),
            },
            Self {
                label: "github-raw (Loyalsoldier/clash-rules)".to_string(),
                geosite_cn_url:
                    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt"
                        .to_string(),
                geosite_non_cn_url:
                    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt"
                        .to_string(),
                geoip_cn_url:
                    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt"
                        .to_string(),
                mmdb_url: Some(
                    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"
                        .to_string(),
                ),
            },
        ]
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GeoManifest {
    #[serde(default)]
    last_updated_ms: u64,
    #[serde(default)]
    expires_at_ms: u64,
    #[serde(default)]
    last_attempt_ms: u64,
    #[serde(default)]
    source_label: String,
    #[serde(default)]
    using_persisted_data: bool,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoDataStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    pub using_persisted_data: bool,
    pub builtin_fallback_active: bool,
    pub is_expired: bool,
    pub last_updated_ms: u64,
    pub expires_at_ms: u64,
    pub last_attempt_ms: u64,
    pub source_label: String,
    pub geosite_cn_entries: usize,
    pub geosite_non_cn_entries: usize,
    pub geoip_cn_ranges: usize,
    pub mmdb_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Immutable compiled GeoSite + GeoIP overlay combining built-in baseline datasets
/// with optional persisted/downloaded rule-sets and MaxMind `.mmdb`.
pub struct GeoDataset {
    pub geosite_cn: GeoSiteMatcher,
    pub geosite_non_cn: GeoSiteMatcher,
    pub geoip_cn: GeoIpMatcher,
    pub mmdb: Option<Arc<MmdbReader>>,
    pub using_persisted_data: bool,
}

impl GeoDataset {
    pub fn builtin_only() -> Self {
        let geosite_cn = lookup_builtin_geosite("cn")
            .cloned()
            .unwrap_or_else(GeoSiteMatcher::default);
        let geosite_non_cn = lookup_builtin_geosite("geolocation-!cn")
            .cloned()
            .unwrap_or_else(GeoSiteMatcher::default);
        let geoip_cn = lookup_builtin_geoip("CN")
            .cloned()
            .unwrap_or_else(GeoIpMatcher::default);
        Self {
            geosite_cn,
            geosite_non_cn,
            geoip_cn,
            mmdb: None,
            using_persisted_data: false,
        }
    }
}

static LIVE_GEODATA: LazyLock<RwLock<Arc<GeoDataset>>> =
    LazyLock::new(|| RwLock::new(Arc::new(GeoDataset::builtin_only())));

pub fn current_geodata() -> Arc<GeoDataset> {
    Arc::clone(&LIVE_GEODATA.read())
}

pub fn install_live_geodata(dataset: Arc<GeoDataset>) {
    *LIVE_GEODATA.write() = dataset;
}

/// Evaluate a `GEOSITE` rule dynamically against the live `GeoDataset` overlay (for `cn` and
/// `geolocation-!cn`), built-in category tables, and `@cn` / `@!cn` / `@ads` / `@!ads` attribute filters.
pub fn matches_geosite_dynamic(
    category: &str,
    builtin: &'static GeoSiteMatcher,
    host: &str,
) -> bool {
    let (norm, attrs) = parse_geosite_category_and_attrs(category);
    let base_matched = match norm.as_str() {
        "cn" | "china" | "geolocation-cn" => LIVE_GEODATA.read().geosite_cn.matches_domain(host),
        "geolocation-!cn" | "gfw" | "proxy" | "tld-!cn" => {
            let ds = LIVE_GEODATA.read();
            if attrs.is_empty() {
                ds.geosite_non_cn
                    .match_specificity(host)
                    .is_some_and(|non_cn_spec| {
                        ds.geosite_cn
                            .match_specificity(host)
                            .is_none_or(|cn_spec| non_cn_spec > cn_spec)
                    })
            } else {
                ds.geosite_non_cn.matches_domain(host)
            }
        }
        "google-cn" | "apple-cn" | "microsoft-cn" | "steam-cn" => {
            lookup_builtin_geosite_cn_subset(&norm).is_some_and(|m| m.matches_domain(host))
        }
        _ => builtin.matches_domain(host),
    };
    if !base_matched || attrs.is_empty() {
        return base_matched;
    }

    for attr in attrs {
        let attr_matched = match attr.name.as_str() {
            "cn" => {
                if let Some(cn_sub) = lookup_builtin_geosite_cn_subset(&norm) {
                    cn_sub.matches_domain(host)
                } else {
                    LIVE_GEODATA.read().geosite_cn.matches_domain(host)
                }
            }
            "ads" => lookup_builtin_geosite("ads").is_some_and(|m| m.matches_domain(host)),
            _ => false,
        };
        if attr.negated {
            if attr_matched {
                return false;
            }
        } else if !attr_matched {
            return false;
        }
    }
    true
}

/// Evaluate a `GEOIP` rule dynamically against explicit `.mmdb`, live persisted `.mmdb`,
/// live `GeoDataset` `CN` CIDR overlay, or built-in country CIDRs.
pub fn matches_geoip_dynamic(
    code_upper: &str,
    builtin: Option<&'static GeoIpMatcher>,
    rule_mmdb: Option<&Arc<MmdbReader>>,
    ip: IpAddr,
) -> bool {
    let is_lan_or_private =
        code_upper.eq_ignore_ascii_case("LAN") || code_upper.eq_ignore_ascii_case("PRIVATE");
    let iso_matches = |iso: &str| -> bool {
        iso.eq_ignore_ascii_case(code_upper)
            || (is_lan_or_private
                && (iso.eq_ignore_ascii_case("LAN") || iso.eq_ignore_ascii_case("PRIVATE")))
    };
    if is_lan_or_private && builtin.is_some_and(|b| b.contains(ip)) {
        return true;
    }
    if let Some(reader) = rule_mmdb
        && let Some(iso) = reader.lookup_country_code(ip)
    {
        return iso_matches(&iso);
    }
    let live = LIVE_GEODATA.read();
    if let Some(ref reader) = live.mmdb
        && let Some(iso) = reader.lookup_country_code(ip)
    {
        return iso_matches(&iso);
    }
    if code_upper == "CN" {
        return live.geoip_cn.contains(ip);
    }
    builtin.is_some_and(|b| b.contains(ip))
}

/// Persistent manager for updatable `GEOSITE` and `GEOIP` datasets under `<state_dir>/geodata/`.
///
/// Guarantees:
/// - **Offline startup**: Always initializes immediately from persisted cache on disk or built-in baseline.
/// - **Safe failure handling**: Download/parse failures never clobber existing persisted files or live rules.
/// - **Staleness tracking**: Tracks `last_updated_ms`, `expires_at_ms`, and `is_expired` across restarts.
pub struct GeoDataManager {
    geodata_dir: PathBuf,
    manifest: Mutex<GeoManifest>,
    dataset: RwLock<Arc<GeoDataset>>,
    ttl_ms: u64,
    extra_ca_der: Vec<CertificateDer<'static>>,
    router_slot: RwLock<Option<Weak<RwLock<Arc<Router>>>>>,
}

impl GeoDataManager {
    pub fn new(state_dir: impl AsRef<Path>, extra_ca_der: Vec<CertificateDer<'static>>) -> Self {
        Self::with_ttl(state_dir, DEFAULT_GEODATA_TTL_MS, extra_ca_der)
    }

    pub fn with_ttl(
        state_dir: impl AsRef<Path>,
        ttl_ms: u64,
        extra_ca_der: Vec<CertificateDer<'static>>,
    ) -> Self {
        let geodata_dir = state_dir.as_ref().join("geodata");
        let _ = fs::create_dir_all(&geodata_dir);

        let manifest_path = geodata_dir.join(MANIFEST_FILE);
        let mut manifest: GeoManifest = fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let (dataset, load_err) = load_persisted_dataset(&geodata_dir);
        if let Some(err) = load_err {
            manifest.last_error = Some(err);
        }
        manifest.using_persisted_data = dataset.using_persisted_data;
        if manifest.source_label.is_empty() {
            manifest.source_label = if dataset.using_persisted_data {
                "persisted-cache".to_string()
            } else {
                "built-in-baseline".to_string()
            };
        }

        let arc_ds = Arc::new(dataset);
        install_live_geodata(Arc::clone(&arc_ds));

        Self {
            geodata_dir,
            manifest: Mutex::new(manifest),
            dataset: RwLock::new(arc_ds),
            ttl_ms: ttl_ms.max(1_000),
            extra_ca_der,
            router_slot: RwLock::new(None),
        }
    }

    pub fn attach_router_slot(&self, slot: Weak<RwLock<Arc<Router>>>) {
        *self.router_slot.write() = Some(slot);
    }

    fn fallback_proxy_outbound(&self) -> Option<DynOutbound> {
        let weak = self.router_slot.read().clone()?;
        let slot = weak.upgrade()?;
        let router = Arc::clone(&slot.read());
        router.fallback_proxy_outbound()
    }

    pub fn geodata_dir(&self) -> &Path {
        &self.geodata_dir
    }

    pub fn mmdb_reader(&self) -> Option<Arc<MmdbReader>> {
        self.dataset.read().mmdb.clone()
    }

    pub fn builtin_status() -> GeoDataStatus {
        let ds = current_geodata();
        GeoDataStatus {
            state_dir: None,
            using_persisted_data: ds.using_persisted_data,
            builtin_fallback_active: !ds.using_persisted_data,
            is_expired: true,
            last_updated_ms: 0,
            expires_at_ms: 0,
            last_attempt_ms: 0,
            source_label: "built-in-baseline".to_string(),
            geosite_cn_entries: ds.geosite_cn.entry_count(),
            geosite_non_cn_entries: ds.geosite_non_cn.entry_count(),
            geoip_cn_ranges: ds.geoip_cn.range_count(),
            mmdb_present: ds.mmdb.is_some(),
            last_error: None,
        }
    }

    pub fn status(&self) -> GeoDataStatus {
        let m = self.manifest.lock().clone();
        let ds = Arc::clone(&self.dataset.read());
        let now = now_unix_ms();
        let is_expired =
            !ds.using_persisted_data || m.last_updated_ms == 0 || now > m.expires_at_ms;
        GeoDataStatus {
            state_dir: Some(self.geodata_dir.display().to_string()),
            using_persisted_data: ds.using_persisted_data,
            builtin_fallback_active: !ds.using_persisted_data,
            is_expired,
            last_updated_ms: m.last_updated_ms,
            expires_at_ms: m.expires_at_ms,
            last_attempt_ms: m.last_attempt_ms,
            source_label: m.source_label,
            geosite_cn_entries: ds.geosite_cn.entry_count(),
            geosite_non_cn_entries: ds.geosite_non_cn.entry_count(),
            geoip_cn_ranges: ds.geoip_cn.range_count(),
            mmdb_present: ds.mmdb.is_some(),
            last_error: None.or(m.last_error),
        }
    }

    pub async fn update_default_mirrors(&self) -> Result<GeoDataStatus> {
        let mirrors = GeoUpdateUrls::default_mirrors();
        let mut errors = Vec::new();
        for mirror in &mirrors {
            match self.update_from_urls(mirror).await {
                Ok(st) => return Ok(st),
                Err(e) => {
                    errors.push(format!(
                        "{}: {}",
                        mirror.label,
                        redact_sensitive_text(&e.to_string())
                    ));
                }
            }
        }
        let combined = format!("all GeoData mirrors failed ({})", errors.join("; "));
        self.record_failure(&combined);
        Err(ProxyError::Config(combined))
    }

    pub async fn refresh_if_expired(&self) -> Option<Result<GeoDataStatus>> {
        if self.status().is_expired {
            Some(self.update_default_mirrors().await)
        } else {
            None
        }
    }

    pub async fn update_from_urls(&self, urls: &GeoUpdateUrls) -> Result<GeoDataStatus> {
        let attempt_ms = now_unix_ms();
        let fallback_proxy = self.fallback_proxy_outbound();
        let result: Result<Arc<GeoDataset>> = async {
            let cn_bytes = fetch_http_bytes_protected_with_proxy(
                &urls.geosite_cn_url,
                &self.extra_ca_der,
                fallback_proxy.as_ref(),
            )
            .await?;
            let non_cn_bytes = fetch_http_bytes_protected_with_proxy(
                &urls.geosite_non_cn_url,
                &self.extra_ca_der,
                fallback_proxy.as_ref(),
            )
            .await?;
            let ip_cn_bytes = fetch_http_bytes_protected_with_proxy(
                &urls.geoip_cn_url,
                &self.extra_ca_der,
                fallback_proxy.as_ref(),
            )
            .await?;

            let cn_text = String::from_utf8(cn_bytes).map_err(|e| {
                ProxyError::Config(format!("geosite_cn payload is not valid UTF-8: {e}"))
            })?;
            let non_cn_text = String::from_utf8(non_cn_bytes).map_err(|e| {
                ProxyError::Config(format!("geosite_non_cn payload is not valid UTF-8: {e}"))
            })?;
            let ip_cn_text = String::from_utf8(ip_cn_bytes).map_err(|e| {
                ProxyError::Config(format!("geoip_cn payload is not valid UTF-8: {e}"))
            })?;

            let parsed_cn = GeoSiteMatcher::from_rule_text(&cn_text);
            if parsed_cn.entry_count() == 0 {
                return Err(ProxyError::Config(
                    "downloaded geosite_cn contained zero valid domain rules".into(),
                ));
            }
            let parsed_non_cn = GeoSiteMatcher::from_rule_text(&non_cn_text);
            if parsed_non_cn.entry_count() == 0 {
                return Err(ProxyError::Config(
                    "downloaded geosite_non_cn contained zero valid domain rules".into(),
                ));
            }
            let parsed_ip_cn = GeoIpMatcher::from_cidr_text(&ip_cn_text);
            if parsed_ip_cn.range_count() == 0 {
                return Err(ProxyError::Config(
                    "downloaded geoip_cn contained zero valid IP CIDR ranges".into(),
                ));
            }

            let parsed_mmdb = if let Some(ref mmdb_url) = urls.mmdb_url
                && !mmdb_url.trim().is_empty()
            {
                match fetch_http_bytes_protected_with_proxy(
                    mmdb_url,
                    &self.extra_ca_der,
                    fallback_proxy.as_ref(),
                )
                .await
                .and_then(|mmdb_bytes| {
                    let reader = MmdbReader::from_bytes(mmdb_bytes.clone())?;
                    write_bytes_atomic(&self.geodata_dir.join(MMDB_FILE), &mmdb_bytes)?;
                    Ok(Arc::new(reader))
                }) {
                    Ok(reader) => Some(reader),
                    Err(err) => {
                        tracing::warn!(
                            "Optional Country.mmdb download from '{}' failed ({}); continuing with GeoSite/GeoIP-CN rulesets and any existing MMDB cache",
                            redact_sensitive_text(mmdb_url),
                            redact_sensitive_text(&err.to_string())
                        );
                        load_optional_mmdb(&self.geodata_dir.join(MMDB_FILE))
                    }
                }
            } else {
                load_optional_mmdb(&self.geodata_dir.join(MMDB_FILE))
            };

            fs::create_dir_all(&self.geodata_dir)?;
            write_bytes_atomic(&self.geodata_dir.join(GEOSITE_CN_FILE), cn_text.as_bytes())?;
            write_bytes_atomic(
                &self.geodata_dir.join(GEOSITE_NON_CN_FILE),
                non_cn_text.as_bytes(),
            )?;
            write_bytes_atomic(&self.geodata_dir.join(GEOIP_CN_FILE), ip_cn_text.as_bytes())?;

            let base = GeoDataset::builtin_only();
            Ok(Arc::new(GeoDataset {
                geosite_cn: base.geosite_cn.merged_with(&parsed_cn),
                geosite_non_cn: base.geosite_non_cn.merged_with(&parsed_non_cn),
                geoip_cn: base.geoip_cn.merged_with(&parsed_ip_cn),
                mmdb: parsed_mmdb,
                using_persisted_data: true,
            }))
        }
        .await;

        match result {
            Ok(new_ds) => {
                let completed_ms = now_unix_ms();
                *self.dataset.write() = Arc::clone(&new_ds);
                install_live_geodata(new_ds);

                {
                    let mut m = self.manifest.lock();
                    m.last_attempt_ms = attempt_ms;
                    m.last_updated_ms = completed_ms;
                    m.expires_at_ms = completed_ms.saturating_add(self.ttl_ms);
                    m.source_label = urls.label.clone();
                    m.using_persisted_data = true;
                    m.last_error = None;
                    if let Err(err) =
                        save_manifest_atomic(&self.geodata_dir.join(MANIFEST_FILE), &m)
                    {
                        tracing::warn!("Failed persisting geodata manifest.json: {err}");
                    }
                }
                Ok(self.status())
            }
            Err(err) => {
                let safe_msg = redact_sensitive_text(&err.to_string());
                self.record_failure_at(attempt_ms, &safe_msg);
                Err(ProxyError::Config(safe_msg))
            }
        }
    }

    fn record_failure(&self, msg: &str) {
        self.record_failure_at(now_unix_ms(), msg);
    }

    fn record_failure_at(&self, attempt_ms: u64, msg: &str) {
        let mut m = self.manifest.lock();
        m.last_attempt_ms = attempt_ms;
        m.last_error = Some(msg.to_string());
        if let Err(err) = save_manifest_atomic(&self.geodata_dir.join(MANIFEST_FILE), &m) {
            tracing::warn!("Failed persisting geodata failure manifest.json: {err}");
        }
    }
}

fn load_optional_mmdb(path: &Path) -> Option<Arc<MmdbReader>> {
    if !path.is_file() {
        return None;
    }
    MmdbReader::from_file(path).ok().map(Arc::new)
}

fn load_persisted_dataset(geodata_dir: &Path) -> (GeoDataset, Option<String>) {
    let base = GeoDataset::builtin_only();
    let cn_path = geodata_dir.join(GEOSITE_CN_FILE);
    let non_cn_path = geodata_dir.join(GEOSITE_NON_CN_FILE);
    let ip_cn_path = geodata_dir.join(GEOIP_CN_FILE);
    let mmdb = load_optional_mmdb(&geodata_dir.join(MMDB_FILE));

    let any_exists = cn_path.is_file() || non_cn_path.is_file() || ip_cn_path.is_file();
    if !any_exists {
        return (GeoDataset { mmdb, ..base }, None);
    }

    let mut errors = Vec::new();
    let mut loaded_any = false;

    let geosite_cn = match fs::read_to_string(&cn_path) {
        Ok(txt) => {
            let parsed = GeoSiteMatcher::from_rule_text(&txt);
            if parsed.entry_count() > 0 {
                loaded_any = true;
                base.geosite_cn.merged_with(&parsed)
            } else {
                errors.push(
                    "cached geosite_cn.txt was empty or invalid; using built-in baseline"
                        .to_string(),
                );
                base.geosite_cn
            }
        }
        Err(e) if cn_path.exists() => {
            errors.push(format!("failed reading geosite_cn.txt: {e}"));
            base.geosite_cn
        }
        Err(_) => base.geosite_cn,
    };

    let geosite_non_cn = match fs::read_to_string(&non_cn_path) {
        Ok(txt) => {
            let parsed = GeoSiteMatcher::from_rule_text(&txt);
            if parsed.entry_count() > 0 {
                loaded_any = true;
                base.geosite_non_cn.merged_with(&parsed)
            } else {
                errors.push(
                    "cached geosite_geolocation_not_cn.txt was empty or invalid; using built-in baseline"
                        .to_string(),
                );
                base.geosite_non_cn
            }
        }
        Err(e) if non_cn_path.exists() => {
            errors.push(format!(
                "failed reading geosite_geolocation_not_cn.txt: {e}"
            ));
            base.geosite_non_cn
        }
        Err(_) => base.geosite_non_cn,
    };

    let geoip_cn = match fs::read_to_string(&ip_cn_path) {
        Ok(txt) => {
            let parsed = GeoIpMatcher::from_cidr_text(&txt);
            if parsed.range_count() > 0 {
                loaded_any = true;
                base.geoip_cn.merged_with(&parsed)
            } else {
                errors.push(
                    "cached geoip_cn.txt was empty or invalid; using built-in baseline".to_string(),
                );
                base.geoip_cn
            }
        }
        Err(e) if ip_cn_path.exists() => {
            errors.push(format!("failed reading geoip_cn.txt: {e}"));
            base.geoip_cn
        }
        Err(_) => base.geoip_cn,
    };

    let err_summary = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };

    (
        GeoDataset {
            geosite_cn,
            geosite_non_cn,
            geoip_cn,
            mmdb,
            using_persisted_data: loaded_any,
        },
        err_summary,
    )
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("geodata.dat");
    let tmp = path.with_file_name(format!(".{file_name}.tmp"));
    {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn save_manifest_atomic(path: &Path, manifest: &GeoManifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|e| ProxyError::Config(format!("failed serializing geodata manifest: {e}")))?;
    write_bytes_atomic(path, &bytes)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn is_rfc2544_fake_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| is_rfc2544_fake_ip(IpAddr::V4(v4))),
    }
}

/// Resolve a hostname for outbound control-plane operations (GeoData download, subscription fetch,
/// or proxy server dial fallback) while strictly rejecting `198.18.0.0/15` Fake-IPs that Android `netd`
/// may return when `VpnService` is active.
pub async fn resolve_host_bypassing_fake_ip(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if clean.eq_ignore_ascii_case("localhost") {
        return Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)]);
    }

    // When an OS TUN / Android VpnService `SocketProtector` is active, skip unprotected OS
    // `getaddrinfo` (`lookup_host`) because libc resolver sockets are NOT protected by
    // `VpnService.protect(fd)` / `SO_MARK` and would loop back into TUN or leak Fake-IPs.
    if !has_custom_socket_protector()
        && let Ok(iter) = tokio::net::lookup_host((clean, port)).await
    {
        let non_fake: Vec<SocketAddr> = iter.filter(|sa| !is_rfc2544_fake_ip(sa.ip())).collect();
        if !non_fake.is_empty() {
            return Ok(non_fake);
        }
    }

    // Query Mainland-reachable + global public literal DNS servers directly over
    // `SocketProtector`-protected UDP sockets so Android/OS VPN never loops into Fake-IP!
    let bootstrap_specs = ["223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"];
    let query_a = build_dns_query(rand::random(), clean, QTYPE_A);
    let query_aaaa = build_dns_query(rand::random(), clean, QTYPE_AAAA);
    for spec in bootstrap_specs {
        let Ok(bs) = BootstrapDnsServer::parse(spec) else {
            continue;
        };
        let (resp_a, resp_aaaa) = tokio::join!(bs.exchange(&query_a), bs.exchange(&query_aaaa));
        let mut resolved = Vec::new();
        for resp in [resp_a, resp_aaaa].into_iter().flatten() {
            if let Ok(meta) = extract_dns_response_meta(&resp)
                && meta.rcode == 0
            {
                for ans in meta.answers {
                    let ip = match ans {
                        DnsAnswerData::A(v4) => Some(IpAddr::V4(v4)),
                        DnsAnswerData::Aaaa(v6) => Some(IpAddr::V6(v6)),
                        DnsAnswerData::Txt(_) => None,
                    };
                    if let Some(ip) = ip
                        && !is_rfc2544_fake_ip(ip)
                    {
                        let sa = SocketAddr::new(ip, port);
                        if !resolved.contains(&sa) {
                            resolved.push(sa);
                        }
                    }
                }
            }
        }
        if !resolved.is_empty() {
            return Ok(resolved);
        }
    }

    Err(ProxyError::Dns(format!(
        "unable to resolve real IP for host '{clean}' (bypassing Fake-IP)"
    )))
}

enum DirectFetchError {
    SsrfBlocked(ProxyError),
    Transport(ProxyError),
}

fn is_loopback_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    clean
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

fn validate_geodata_host(host: &str, allow_loopback: bool) -> Result<()> {
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if clean.is_empty() {
        return Err(ProxyError::Config("GeoData URL missing host".into()));
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if allow_loopback && ip.to_canonical().is_loopback() {
            return Ok(());
        }
        if crate::probe::is_restricted_probe_ip(ip) {
            return Err(ProxyError::Config(format!(
                "refusing GeoData connection to restricted address '{clean}' (blocked by SSRF protection)"
            )));
        }
        return Ok(());
    }
    if allow_loopback && is_loopback_host(clean) {
        return Ok(());
    }
    if crate::probe::is_restricted_probe_hostname(clean) {
        return Err(ProxyError::Config(format!(
            "refusing GeoData connection to restricted internal hostname '{clean}' (blocked by SSRF protection)"
        )));
    }
    Ok(())
}

fn validate_geodata_resolved_ip(ip: IpAddr, allow_loopback: bool) -> Result<()> {
    if allow_loopback && ip.to_canonical().is_loopback() {
        return Ok(());
    }
    if crate::probe::is_restricted_probe_ip(ip) {
        return Err(ProxyError::Config(format!(
            "refusing GeoData connection to restricted resolved IP {ip} (blocked by SSRF protection)"
        )));
    }
    Ok(())
}

async fn connect_protected_http_tcp_with_addrs(
    host: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
    allow_loopback: bool,
) -> std::result::Result<tokio::net::TcpStream, DirectFetchError> {
    if addrs.is_empty() {
        return Err(DirectFetchError::Transport(ProxyError::Dns(format!(
            "unable to resolve real IP for host '{host}'"
        ))));
    }
    for target in &addrs {
        if let Err(err) = validate_geodata_resolved_ip(target.ip(), allow_loopback) {
            return Err(DirectFetchError::SsrfBlocked(err));
        }
    }

    let mut last_err = None;
    for target in addrs {
        let domain = if target.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock =
            match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(ProxyError::Io(e));
                    continue;
                }
            };
        if let Err(e) = sock.set_nonblocking(true) {
            last_err = Some(ProxyError::Io(e));
            continue;
        }
        let _ = sock.set_nodelay(true);
        if let Err(e) = global_socket_protector().protect_tcp(&sock, target) {
            last_err = Some(ProxyError::Io(e));
            continue;
        }
        let t_sock = tokio::net::TcpSocket::from_std_stream(sock.into());
        match tokio::time::timeout(Duration::from_secs(8), t_sock.connect(target)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(ProxyError::Io(e)),
            Err(_) => {
                last_err = Some(ProxyError::Config("GeoData TCP connect timed out".into()));
            }
        }
    }
    Err(DirectFetchError::Transport(last_err.unwrap_or_else(|| {
        ProxyError::Config(format!("failed connecting to '{host}:{port}'"))
    })))
}

/// Download an HTTPS (or loopback HTTP for tests) GeoData resource over a `SocketProtector`-protected socket.
pub async fn fetch_http_bytes_protected(
    raw_url: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<Vec<u8>> {
    fetch_http_bytes_protected_with_proxy(raw_url, extra_ca_der, None).await
}

/// Download an HTTPS (or loopback HTTP for tests) resource over a `SocketProtector`-protected socket,
/// automatically falling back to an active concrete proxy outbound (with full end-to-end TLS verification)
/// when direct egress is unreachable or blocked on non-loopback HTTPS hosts.
pub async fn fetch_http_bytes_protected_with_proxy(
    raw_url: &str,
    extra_ca_der: &[CertificateDer<'static>],
    fallback_proxy: Option<&DynOutbound>,
) -> Result<Vec<u8>> {
    fetch_http_bytes_protected_inner(raw_url, extra_ca_der, fallback_proxy, |h, p| async move {
        resolve_host_bypassing_fake_ip(&h, p).await
    })
    .await
}

async fn fetch_http_bytes_protected_inner<F, Fut>(
    raw_url: &str,
    extra_ca_der: &[CertificateDer<'static>],
    fallback_proxy: Option<&DynOutbound>,
    mut resolver: F,
) -> Result<Vec<u8>>
where
    F: FnMut(String, u16) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<SocketAddr>>>,
{
    let mut current = Url::parse(raw_url.trim())
        .map_err(|e| ProxyError::Config(format!("invalid GeoData URL: {e}")))?;
    let mut allow_loopback = current.host_str().is_some_and(is_loopback_host);

    for _hop in 0..=3 {
        if !current.username().is_empty() || current.password().is_some() {
            return Err(ProxyError::Config(
                "GeoData URL must not contain userinfo credentials".into(),
            ));
        }
        let scheme = current.scheme().to_ascii_lowercase();
        let host = current
            .host_str()
            .ok_or_else(|| ProxyError::Config("GeoData URL missing host".into()))?
            .to_string();
        allow_loopback = allow_loopback && is_loopback_host(&host);

        let is_https = match scheme.as_str() {
            "https" => true,
            "http" if allow_loopback && is_loopback_host(&host) => false,
            "http" => {
                return Err(ProxyError::Config(
                    "cleartext http:// GeoData URLs are rejected for security; use https://".into(),
                ));
            }
            other => {
                return Err(ProxyError::Config(format!(
                    "unsupported GeoData URL scheme '{other}'"
                )));
            }
        };

        validate_geodata_host(&host, allow_loopback)?;

        let port = current
            .port_or_known_default()
            .unwrap_or(if is_https { 443 } else { 80 });
        let mut path_and_query = current.path().to_string();
        if path_and_query.is_empty() {
            path_and_query.push('/');
        }
        if let Some(q) = current.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }

        let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };

        let req_bytes = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: rust-clash/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );

        let resolved_direct = resolver(host.clone(), port)
            .await
            .map_err(DirectFetchError::Transport);
        let direct_attempt: std::result::Result<Vec<u8>, DirectFetchError> = match resolved_direct {
            Ok(addrs) => {
                let tcp =
                    connect_protected_http_tcp_with_addrs(&host, port, addrs, allow_loopback).await;
                match tcp {
                    Ok(tcp) => {
                        if is_https {
                            exchange_https_over_stream(tcp, &host, &req_bytes, extra_ca_der)
                                .await
                                .map_err(DirectFetchError::Transport)
                        } else {
                            let mut tcp = tcp;
                            match tcp.write_all(req_bytes.as_bytes()).await {
                                Ok(()) => read_bounded_bytes(&mut tcp)
                                    .await
                                    .map_err(DirectFetchError::Transport),
                                Err(e) => Err(DirectFetchError::Transport(ProxyError::Io(e))),
                            }
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        let raw_resp = match direct_attempt {
            Ok(bytes) => bytes,
            Err(DirectFetchError::SsrfBlocked(err)) => return Err(err),
            Err(DirectFetchError::Transport(direct_err)) => {
                if is_https
                    && !is_loopback_host(&host)
                    && let Some(proxy_ob) = fallback_proxy
                {
                    let target = TargetAddr::new_domain(&host, port).or_else(|_| {
                        let clean = host.trim_start_matches('[').trim_end_matches(']');
                        clean
                            .parse::<IpAddr>()
                            .map(|ip| TargetAddr::new_ip(ip, port))
                            .map_err(|_| {
                                ProxyError::Config(format!("invalid GeoData target host '{host}'"))
                            })
                    })?;
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        proxy_ob.connect_tcp(&target),
                    )
                    .await
                    {
                        Ok(Ok(proxy_stream)) => {
                            match exchange_https_over_stream(
                                proxy_stream,
                                &host,
                                &req_bytes,
                                extra_ca_der,
                            )
                            .await
                            {
                                Ok(bytes) => bytes,
                                Err(_) => return Err(direct_err),
                            }
                        }
                        _ => return Err(direct_err),
                    }
                } else {
                    return Err(direct_err);
                }
            }
        };

        let (status, headers, body) = parse_http_response(&raw_resp)?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| {
                    ProxyError::Config(format!("HTTP {status} redirect missing Location header"))
                })?;
            let next_url = current
                .join(loc)
                .map_err(|e| ProxyError::Config(format!("invalid redirect Location: {e}")))?;
            if !next_url.username().is_empty() || next_url.password().is_some() {
                return Err(ProxyError::Config(
                    "GeoData redirect URL must not contain userinfo credentials".into(),
                ));
            }
            let next_scheme = next_url.scheme().to_ascii_lowercase();
            if is_https && next_scheme == "http" {
                return Err(ProxyError::Config(
                    "refusing HTTPS-to-HTTP downgrade redirect on GeoData URL".into(),
                ));
            }
            if !matches!(next_scheme.as_str(), "https" | "http") {
                return Err(ProxyError::Config(format!(
                    "unsupported GeoData redirect URL scheme '{next_scheme}'"
                )));
            }
            let next_host = next_url
                .host_str()
                .ok_or_else(|| ProxyError::Config("GeoData redirect URL missing host".into()))?;
            if !allow_loopback && is_loopback_host(next_host) {
                return Err(ProxyError::Config(
                    "refusing remote GeoData redirect to local loopback host".into(),
                ));
            }
            let next_allow_loopback = allow_loopback && is_loopback_host(next_host);
            if next_scheme == "http" && !(next_allow_loopback && is_loopback_host(next_host)) {
                return Err(ProxyError::Config(
                    "cleartext http:// GeoData redirects are rejected for security; use https://"
                        .into(),
                ));
            }
            validate_geodata_host(next_host, next_allow_loopback)?;
            allow_loopback = next_allow_loopback;
            current = next_url;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(ProxyError::Config(format!(
                "GeoData server returned HTTP {status}"
            )));
        }
        return Ok(body);
    }

    Err(ProxyError::Config(
        "too many HTTP redirects while downloading GeoData".into(),
    ))
}

async fn exchange_https_over_stream<S>(
    stream: S,
    host: &str,
    req_bytes: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<Vec<u8>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let tls_cfg = build_tls_client_config(false, extra_ca_der, &[b"http/1.1".to_vec()])
        .map_err(|e| ProxyError::Config(format!("GeoData TLS config failed: {e}")))?;
    let connector = TlsConnector::from(tls_cfg);
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let server_name = rustls::pki_types::ServerName::try_from(clean_host.to_string())
        .map_err(|e| ProxyError::Config(format!("invalid TLS SNI '{clean_host}': {e}")))?;
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProxyError::Config("GeoData TLS handshake timed out".into()))?
    .map_err(|e| ProxyError::Config(format!("GeoData TLS verify failed: {e}")))?;
    tls_stream
        .write_all(req_bytes.as_bytes())
        .await
        .map_err(ProxyError::Io)?;
    read_bounded_bytes(&mut tls_stream).await
}

async fn read_bounded_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(16384);
    let mut buf = [0u8; 16384];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ProxyError::Config("GeoData download timed out".into()));
        }
        let n = tokio::time::timeout(remaining, stream.read(&mut buf))
            .await
            .map_err(|_| ProxyError::Config("GeoData download timed out".into()))?
            .map_err(ProxyError::Io)?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_GEODATA_DOWNLOAD_BYTES {
            return Err(ProxyError::Config(
                "GeoData download exceeds 32 MiB safety limit".into(),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

type ParsedHttpResponse = (u16, Vec<(String, String)>, Vec<u8>);

fn parse_http_response(raw: &[u8]) -> Result<ParsedHttpResponse> {
    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(ProxyError::Config("malformed HTTP response".into()));
    };
    let head_str = std::str::from_utf8(&raw[..hdr_end])
        .map_err(|_| ProxyError::Config("non-ASCII HTTP response headers".into()))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::Config("missing HTTP status line".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| ProxyError::Config(format!("invalid HTTP status line '{status_line}'")))?;

    let mut headers = Vec::new();
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
            headers.push((key, val));
        }
    }

    let body_slice = &raw[hdr_end + 4..];
    let body = if is_chunked {
        crate::config::decode_http_chunked_body(body_slice, MAX_GEODATA_DOWNLOAD_BYTES)?
    } else {
        body_slice.to_vec()
    };
    Ok((status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{addr::TargetAddr, router::rules::CompiledRule};

    #[test]
    fn geosite_cn_and_not_cn_attributes_partition_domains_accurately() {
        let google_cn_rule = CompiledRule::parse("GEOSITE,google@cn,DIRECT").unwrap();
        let google_not_cn_rule = CompiledRule::parse("GEOSITE,google@!cn,PROXY").unwrap();
        let apple_cn_rule = CompiledRule::parse("GEOSITE,apple@cn,DIRECT").unwrap();
        let openai_cn_rule = CompiledRule::parse("GEOSITE,openai@cn,DIRECT").unwrap();

        let dl_google = TargetAddr::new_domain("dl.google.com", 443).unwrap();
        let www_google = TargetAddr::new_domain("www.google.com", 443).unwrap();
        let gstatic_cn = TargetAddr::new_domain("fonts.gstatic.cn", 443).unwrap();
        let apple_cdn = TargetAddr::new_domain("is1-ssl.mzstatic.com", 443).unwrap();
        let icloud_global = TargetAddr::new_domain("www.icloud.com", 443).unwrap();
        let chatgpt = TargetAddr::new_domain("chatgpt.com", 443).unwrap();

        assert!(google_cn_rule.matches(None, &dl_google));
        assert!(!google_not_cn_rule.matches(None, &dl_google));

        assert!(google_cn_rule.matches(None, &gstatic_cn));
        assert!(!google_not_cn_rule.matches(None, &gstatic_cn));

        assert!(!google_cn_rule.matches(None, &www_google));
        assert!(google_not_cn_rule.matches(None, &www_google));

        assert!(apple_cn_rule.matches(None, &apple_cdn));
        assert!(!apple_cn_rule.matches(None, &icloud_global));

        assert!(!openai_cn_rule.matches(None, &chatgpt));
    }

    #[test]
    fn geosite_from_rule_text_strips_v2ray_attribute_tags() {
        let sample = "\
            domain:google.cn:@cn\n\
            full:dl.google.com @cn @ads\n\
            apple.com.cn:@cn\n\
        ";
        let matcher = GeoSiteMatcher::from_rule_text(sample);
        assert!(matcher.matches_domain("maps.google.cn"));
        assert!(matcher.matches_domain("dl.google.com"));
        assert!(!matcher.matches_domain("www.google.com"));
        assert!(matcher.matches_domain("www.apple.com.cn"));
    }

    #[test]
    fn default_mirrors_include_https_country_mmdb_urls() {
        let mirrors = GeoUpdateUrls::default_mirrors();
        assert!(!mirrors.is_empty());
        for mirror in &mirrors {
            let mmdb = mirror
                .mmdb_url
                .as_deref()
                .expect("default GeoData mirror must populate mmdb_url");
            assert!(mmdb.starts_with("https://"));
            assert!(mmdb.ends_with("Country.mmdb"));
        }
    }

    #[test]
    fn geosite_dynamic_specificity_disambiguates_cn_ntp_from_proxy_ntp_suffix() {
        static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
        let _serial = TEST_LOCK.lock();

        struct LiveGeodataRestoreGuard(Arc<GeoDataset>);
        impl Drop for LiveGeodataRestoreGuard {
            fn drop(&mut self) {
                install_live_geodata(Arc::clone(&self.0));
            }
        }
        let _restore = LiveGeodataRestoreGuard(current_geodata());

        let cn_builtin = lookup_builtin_geosite("cn").unwrap();
        let non_cn_builtin = lookup_builtin_geosite("geolocation-!cn").unwrap();

        // 1. Offline built-in dataset: cn.pool.ntp.org matches `cn` and NOT `geolocation-!cn`
        install_live_geodata(Arc::new(GeoDataset::builtin_only()));
        assert!(!matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "cn.pool.ntp.org"
        ));
        assert!(matches_geosite_dynamic("cn", cn_builtin, "cn.pool.ntp.org"));
        assert!(matches_geosite_dynamic(
            "cn",
            cn_builtin,
            "0.cn.pool.ntp.org"
        ));

        // 2. Dynamic persisted dataset where proxy has `domain:ntp.org` + `domain:cloudflare.com`
        //    and direct has `domain:cn.pool.ntp.org`: longer CN suffix wins over broader proxy suffix
        let base = GeoDataset::builtin_only();
        let direct_rules = GeoSiteMatcher::from_rule_text("domain:cn.pool.ntp.org\n");
        let proxy_rules = GeoSiteMatcher::from_rule_text(
            "domain:ntp.org\ndomain:cloudflare.com\ndomain:blocked-sub.example.cn\n",
        );
        install_live_geodata(Arc::new(GeoDataset {
            geosite_cn: base.geosite_cn.merged_with(&direct_rules),
            geosite_non_cn: base.geosite_non_cn.merged_with(&proxy_rules),
            geoip_cn: base.geoip_cn,
            mmdb: None,
            using_persisted_data: true,
        }));

        assert!(!matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "cn.pool.ntp.org"
        ));
        assert!(!matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "2.cn.pool.ntp.org"
        ));
        assert!(matches_geosite_dynamic("cn", cn_builtin, "cn.pool.ntp.org"));

        // Non-CN NTP hosts still match `geolocation-!cn`
        assert!(matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "pool.ntp.org"
        ));
        assert!(matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "time.cloudflare.com"
        ));

        // Conversely, a more specific proxy subdomain under `.cn` still wins for `geolocation-!cn`
        assert!(matches_geosite_dynamic(
            "geolocation-!cn",
            non_cn_builtin,
            "api.blocked-sub.example.cn"
        ));
    }

    #[tokio::test]
    async fn geodata_ssrf_blocks_private_ula_metadata_userinfo_redirects_and_never_uses_fallback_proxy()
     {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("::ffff:127.0.0.1"));
        assert!(is_loopback_host("[::ffff:127.0.0.1]"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("169.254.169.254"));

        struct CountingFallbackProxy {
            hits: Arc<AtomicUsize>,
            forward_to: Option<SocketAddr>,
        }
        #[async_trait::async_trait]
        impl crate::outbound::OutboundHandler for CountingFallbackProxy {
            fn name(&self) -> &str {
                "CountingGeoFallback"
            }
            fn protocol(&self) -> &'static str {
                "socks5"
            }
            async fn connect_tcp(
                &self,
                _target: &TargetAddr,
            ) -> std::io::Result<crate::outbound::BoxedStream> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                if let Some(addr) = self.forward_to {
                    let s = tokio::net::TcpStream::connect(addr).await?;
                    Ok(Box::new(s))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "mock proxy refused",
                    ))
                }
            }
        }

        let hits = Arc::new(AtomicUsize::new(0));
        let counting_proxy: DynOutbound = Arc::new(CountingFallbackProxy {
            hits: Arc::clone(&hits),
            forward_to: None,
        });

        // 1. Direct literal restricted IPs, internal hostnames, userinfo, and non-HTTP schemes MUST fail
        //    WITHOUT ever invoking fallback_proxy!
        for blocked_url in [
            "https://10.0.0.1/Country.mmdb",
            "https://172.16.0.1/Country.mmdb",
            "https://192.168.1.1/Country.mmdb",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fd00:ec2::254]/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://internal-service.local/Country.mmdb",
            "https://user:pass@example.com/Country.mmdb",
            "ftp://example.com/Country.mmdb",
        ] {
            let err =
                fetch_http_bytes_protected_with_proxy(blocked_url, &[], Some(&counting_proxy))
                    .await
                    .expect_err("GeoData SSRF/bad URL must be blocked");
            assert!(
                matches!(err, ProxyError::Config(_)),
                "expected Config error for {blocked_url}, got {err:?}"
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "fallback_proxy must NEVER be invoked on SSRF-blocked GeoData URLs"
        );

        // 2. Post-DNS resolution to restricted IPs (DNS rebinding) returns SsrfBlocked and MUST NOT
        //    invoke fallback_proxy!
        for rebound_ip in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "fd00:ec2::254",
        ] {
            let ip: IpAddr = rebound_ip.parse().unwrap();
            let err = fetch_http_bytes_protected_inner(
                "https://rebind-geo.example.com/Country.mmdb",
                &[],
                Some(&counting_proxy),
                move |_h, port| async move { Ok(vec![SocketAddr::new(ip, port)]) },
            )
            .await
            .expect_err("DNS-rebound GeoData IP must be blocked");
            assert!(
                matches!(err, ProxyError::Config(_)),
                "expected Config error for rebinding to {rebound_ip}, got {err:?}"
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "fallback_proxy must NEVER be invoked when DNS resolution triggers SsrfBlocked"
        );

        // 3. Remote HTTPS server behind fallback_proxy redirecting to loopback / IPv4-mapped loopback /
        //    IMDS / internal hostname MUST be blocked before following the redirect!
        let (tls_cfg, ca_der) = crate::crypto::tls::generate_self_signed_server_config(
            &["redirect-geo.invalid".into()],
            &[],
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(tls_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = listener.local_addr().unwrap();

        let redirect_locations = Arc::new(parking_lot::Mutex::new(
            std::collections::VecDeque::from(vec![
                "https://127.0.0.1:9090/configs".to_string(),
                "https://[::ffff:127.0.0.1]:9090/configs".to_string(),
                "https://169.254.169.254/latest/meta-data/".to_string(),
                "https://[fd00:ec2::254]/latest/meta-data/".to_string(),
                "https://metadata.google.internal/computeMetadata/v1/".to_string(),
            ]),
        ));
        let locs_bg = Arc::clone(&redirect_locations);
        let srv_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acceptor.clone();
                let loc = locs_bg
                    .lock()
                    .pop_front()
                    .unwrap_or_else(|| "https://127.0.0.1:9090/".into());
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(tcp).await {
                        let mut buf = [0u8; 1024];
                        let _ = tls.read(&mut buf).await;
                        let resp = format!(
                            "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        for i in 1..=5usize {
            let redir_hits = Arc::new(AtomicUsize::new(0));
            let redir_proxy: DynOutbound = Arc::new(CountingFallbackProxy {
                hits: Arc::clone(&redir_hits),
                forward_to: Some(srv_addr),
            });
            let err = fetch_http_bytes_protected_inner(
                "https://redirect-geo.invalid/Country.mmdb",
                std::slice::from_ref(&ca_der),
                Some(&redir_proxy),
                |_h, _p| async { Err(ProxyError::Dns("direct blocked".into())) },
            )
            .await
            .expect_err("proxied remote redirect to restricted target must fail");
            assert!(
                matches!(err, ProxyError::Config(_)),
                "case #{i}: expected Config error on restricted redirect, got {err:?}"
            );
            assert_eq!(
                redir_hits.load(Ordering::SeqCst),
                1,
                "case #{i}: fallback_proxy must only be used for initial hop, never for SSRF redirect target"
            );
        }

        srv_task.abort();
    }
}
