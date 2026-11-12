export type RunMode = "rule" | "global" | "direct";

export interface VersionInfo {
  version: string;
  meta: boolean;
  premium: boolean;
  features: string[];
}

export interface DemoInfo {
  enabled: boolean;
  http_benchmark_origin: string;
  endpoints: Record<string, string>;
}

export interface TunHealthSnapshot {
  platform: string;
  backend: string;
  active: boolean;
  device_name?: string | null;
  mtu: number;
  ipv4_cidr?: string | null;
  ipv6_cidr?: string | null;
  auto_route_applied: boolean;
  strict_route_applied: boolean;
  route_table_id?: number | null;
  default_egress_iface?: string | null;
  default_egress_gateway?: string | null;
  socket_protector: string;
  privilege_ok: boolean;
  privilege_hint?: string | null;
  driver_loaded: boolean;
  network_transitions: number;
  rx_packets: number;
  tx_packets: number;
  last_error?: string | null;
}

export interface SysProxyStatus {
  supported: boolean;
  enabled: boolean;
  host?: string | null;
  port?: number | null;
  bypass: string[];
  backend: string;
  last_error?: string | null;
}

export interface AutostartStatus {
  supported: boolean;
  enabled: boolean;
  mechanism: string;
  entry_path?: string | null;
}

export interface EffectiveOutboundSummary {
  mode: RunMode;
  primary_group?: string | null;
  selected_member?: string | null;
  effective_outbound: string;
  effective_protocol: string;
  chains: string[];
}

export interface ConfigSnapshot {
  "mixed-port": number;
  "mixed-listen": string;
  "dns-listen": string | null;
  "allow-lan": boolean;
  "lan-allowed-ips"?: string[];
  "authentication-enabled"?: boolean;
  "secret-configured"?: boolean;
  "bind-address": string;
  mode: RunMode;
  "effective-outbound"?: EffectiveOutboundSummary;
  "selected-groups"?: Record<string, string>;
  "log-level": string;
  ipv6: boolean;
  tun: {
    enable: boolean;
    "virtual-enable"?: boolean;
    "runtime-mode"?: "disabled" | "virtual" | "os-tun";
    "os-attached"?: boolean;
    stack: string;
    device: string;
    "auto-route": boolean;
    "strict-route"?: boolean;
    ipv6?: boolean;
    mtu: number;
    "last-error"?: string | null;
    health?: TunHealthSnapshot;
  };
  dns: {
    enable: boolean;
    "configured-enable"?: boolean;
    "enhanced-mode": string;
    ipv6?: boolean;
    "fake-ip-range": string;
    "fake-ip-entries": number;
  };
  sysproxy?: SysProxyStatus;
  autostart?: AutostartStatus;
  demo: DemoInfo;
}

export type ProfileKind =
  | "starter"
  | "local-yaml"
  | "share-uris"
  | "subscription";

export interface SubscriptionUserInfo {
  upload_bytes: number;
  download_bytes: number;
  total_bytes?: number | null;
  expire_unix_secs?: number | null;
}

export interface ProfileMetadata {
  id: string;
  name: string;
  kind: ProfileKind;
  subscription_url_redacted?: string | null;
  auto_update_interval_secs?: number | null;
  last_updated_ms: number;
  last_error?: string | null;
  userinfo?: SubscriptionUserInfo | null;
  proxy_count: number;
  rule_count: number;
  last_skipped_count?: number;
  selected_groups?: Record<string, string>;
}

export interface ProfilesSnapshot {
  active_profile_id: string;
  onboarding_completed: boolean;
  secret_backend: string;
  profiles: ProfileMetadata[];
}

export interface CreateProfileSpec {
  name: string;
  yaml?: string;
  uris?: string;
  subscription_url?: string;
  auto_update_interval_secs?: number;
  activate?: boolean;
}

export interface WsTransportOptions {
  path?: string;
  headers?: Record<string, string>;
  "max-early-data"?: number;
  "early-data-header-name"?: string | null;
}

export type ProxyNodeConfigPayload =
  | {
      type: "ss";
      name: string;
      server: string;
      port: number;
      cipher: string;
      password: string;
      udp?: boolean;
    }
  | {
      type: "vless";
      name: string;
      server: string;
      port: number;
      uuid: string;
      encryption?: string;
      tls?: boolean;
      servername?: string | null;
      "skip-cert-verify"?: boolean;
      alpn?: string[];
      flow?: string | null;
      network?: string | null;
      "ws-opts"?: WsTransportOptions | null;
      udp?: boolean;
    }
  | {
      type: "trojan";
      name: string;
      server: string;
      port: number;
      password: string;
      tls?: boolean;
      sni?: string | null;
      "skip-cert-verify"?: boolean;
      alpn?: string[];
      network?: string | null;
      "ws-opts"?: WsTransportOptions | null;
      udp?: boolean;
    }
  | {
      type: "anytls";
      name: string;
      server: string;
      port: number;
      password: string;
      sni?: string | null;
      "skip-cert-verify"?: boolean;
      alpn?: string[];
      "idle-session-check-interval"?: number;
      "idle-session-timeout"?: number;
      "min-idle-session"?: number;
      udp?: boolean;
    }
  | {
      type: "socks5";
      name: string;
      server: string;
      port: number;
      username?: string | null;
      password?: string | null;
      tls?: boolean;
      sni?: string | null;
      "skip-cert-verify"?: boolean;
      udp?: boolean;
    }
  | {
      type: "http";
      name: string;
      server: string;
      port: number;
      username?: string | null;
      password?: string | null;
      tls?: boolean;
      sni?: string | null;
      "skip-cert-verify"?: boolean;
    };

export interface SkippedProxyEntry {
  name?: string | null;
  protocol: string;
  reason: string;
}

export interface ImportNodesResponse {
  applied: boolean;
  "input-kind"?: string;
  count: number;
  "added-nodes"?: string[];
  "skipped-duplicates"?: number;
  "skipped-unsupported"?: SkippedProxyEntry[];
  "total-nodes"?: number;
  "selected-groups"?: Record<string, string>;
  "effective-outbound"?: EffectiveOutboundSummary;
}

export interface ActiveNodesResponse {
  "active-profile-id": string;
  nodes: ProxyNodeConfigPayload[];
  "added-nodes"?: string[];
  "updated-node"?: string | null;
  "removed-nodes"?: string[];
  "skipped-duplicates"?: number;
  "total-nodes"?: number;
  "selected-groups": Record<string, string>;
  "effective-outbound": EffectiveOutboundSummary;
}

export type RoutingPresetChoice = "smart-cn" | "global" | "direct" | "custom";

export interface RoutingPresetSnapshot {
  active_choice: RoutingPresetChoice;
  mode: RunMode;
  rule_preset: "smart-cn" | "custom";
  primary_group: string;
  rule_count: number;
  has_custom_rules_backup: boolean;
  selected_groups: Record<string, string>;
}

export interface GeoDataStatus {
  state_dir?: string | null;
  using_persisted_data: boolean;
  builtin_fallback_active: boolean;
  is_expired: boolean;
  last_updated_ms: number;
  expires_at_ms: number;
  last_attempt_ms: number;
  source_label: string;
  geosite_cn_entries: number;
  geosite_non_cn_entries: number;
  geoip_cn_ranges: number;
  mmdb_present: boolean;
  last_error?: string | null;
}

export interface RuleExplainResponse {
  input: string;
  normalized_target: string;
  restored_from_fake_ip?: string | null;
  mode: RunMode;
  rule_type: string;
  rule_payload: string;
  chains: string[];
  outbound: string;
  protocol: string;
  exit_type?: string;
  remote_endpoint?: string;
}

export interface DnsFlushResponse {
  flushed: boolean;
  cached_records: number;
}

export interface AndroidPlatformInfo {
  platform: "android";
  vpnState: string;
  lockdownWarning?: string | null;
}

export interface DelayHistoryItem {
  time: string;
  delay: number;
}

export interface ProxyInfo {
  name: string;
  type: string;
  udp: boolean;
  now?: string | null;
  effective_outbound?: string | null;
  effective_protocol?: string | null;
  chains?: string[] | null;
  all?: string[] | null;
  history: DelayHistoryItem[];
}

export interface RuleItem {
  type: string;
  payload: string;
  proxy: string;
  hits: number;
}

export interface ConnectionMetadata {
  id: string;
  network: string;
  type: string;
  source: string;
  destination_ip?: string | null;
  destination_port: number;
  host: string;
  fake_ip?: string | null;
}

export interface ConnectionItem {
  id: string;
  metadata: ConnectionMetadata;
  upload: number;
  download: number;
  start_epoch_ms: number;
  chains: string[];
  rule: string;
  rule_payload: string;
  effective_outbound?: string;
  effective_protocol?: string;
  exit_type?: string;
  remote_endpoint?: string;
  status?: string;
  error?: string | null;
  end_epoch_ms?: number | null;
}

export interface ConnectionsResponse {
  downloadTotal: number;
  uploadTotal: number;
  connections: ConnectionItem[];
  memory: number;
}

export interface TrafficPoint {
  timestamp_ms: number;
  up: number;
  down: number;
  total_up: number;
  total_down: number;
}

export interface LogEntry {
  timestamp_ms: number;
  type: string;
  payload: string;
}

export interface FakeIpEntry {
  ip: string;
  domain: string;
}

export interface FakeIpPoolResponse {
  cidr: string;
  gateway: string;
  enhanced_mode?: string;
  cached_records?: number;
  count: number;
  entries: FakeIpEntry[];
}

export interface DnsQueryAnswer {
  type: string;
  data: string;
  is_fake_ip: boolean;
  restored_domain?: string | null;
}

export interface DnsQueryResponse {
  Status: number;
  Question: { name: string; type: string };
  bypass_fake_ip: boolean;
  Answer: DnsQueryAnswer[];
}

export interface VlessKeypairResponse {
  mode: string;
  rtt: string;
  uuid: string;
  encryption: string;
  decryption: string;
  x25519_public_key: string;
  mlkem768_encapsulation_key_bytes: number;
  client_yaml_snippet: string;
}

export interface BenchmarkResponse {
  streams: number;
  total_bytes: number;
  elapsed_ms: number;
  throughput_mbps: number;
  active_proxy_group_selection?: string | null;
}

export type AuditSeverity = "high" | "medium" | "low" | "info";

export interface AuditSeverityCounts {
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AuditFinding {
  code: string;
  severity: AuditSeverity;
  category: string;
  title: string;
  location: string;
  detail: string;
  remediation: string;
}

export interface LeakSimulationRow {
  label: string;
  category: string;
  target: string;
  matched_rule: string;
  chains: string[];
  effective_outbound: string;
  exit_type: string;
  triggered_local_dns_by_rule?: string | null;
  ip_rules_skipped_without_dns?: boolean;
  dns_strategy: string;
  risk_level: "ok" | "warning" | "high" | "pass" | "warn" | string;
  note: string;
}

export interface ConfigAuditReport {
  score: number;
  grade: string;
  mode: RunMode;
  simulation_basis?: string;
  proxy_count: number;
  group_count: number;
  rule_count: number;
  counts: AuditSeverityCounts;
  findings: AuditFinding[];
  leak_matrix: LeakSimulationRow[];
}

export interface ProxyDiffEntry {
  name: string;
  protocol: string;
  server: string;
  port: number;
  tls: boolean;
  skip_cert_verify: boolean;
  udp: boolean;
}

export interface ProxyChangeEntry {
  name: string;
  changes: string[];
}

export interface ConfigDiffSummary {
  score_before: number;
  grade_before: string;
  score_after: number;
  grade_after: string;
  added_proxies: ProxyDiffEntry[];
  removed_proxies: string[];
  changed_proxies: ProxyChangeEntry[];
  newly_insecure_nodes: string[];
  dns_changed: boolean;
  dns_changes: string[];
  rules_prev_count: number;
  rules_next_count: number;
  rules_added_count: number;
  rules_removed_count: number;
  rules_added_sample: string[];
  rules_removed_sample: string[];
}

export type ProbeVerdict =
  | "reachable"
  | "auth_required"
  | "rate_limited"
  | "blocked_or_challenged"
  | "server_error"
  | "unreachable";

export interface UdpProbeResult {
  status: "verified" | "blackholed" | "unsupported" | string;
  configured_udp: boolean;
  target?: string | null;
  rtt_ms?: number | null;
  detail: string;
}

export interface WaterfallProbeReport {
  requested_proxy: string;
  effective_outbound: string;
  protocol: string;
  chains: string[];
  url: string;
  target_host: string;
  target_port: number;
  remote_dns: boolean;
  dns_mode: string;
  dns_resolve_ms?: number | null;
  tunnel_connect_ms?: number | null;
  tls_handshake_ms?: number | null;
  http_ttfb_ms?: number | null;
  total_ms: number;
  overall_probe_duration_ms?: number;
  tls_version?: string | null;
  alpn?: string | null;
  http_status?: number | null;
  server_header?: string | null;
  cf_mitigated: boolean;
  verdict: ProbeVerdict;
  failed_stage?: string | null;
  note: string;
  error?: string | null;
  udp_probe?: UdpProbeResult | null;
}

export interface EndpointMatrixItem {
  id: string;
  label: string;
  category: string;
  report: WaterfallProbeReport;
}

export interface EndpointMatrixReport {
  requested_proxy: string;
  effective_outbound: string;
  protocol: string;
  chains: string[];
  reachable_count: number;
  auth_required_count: number;
  rate_limited_count: number;
  blocked_count: number;
  unreachable_count: number;
  ai_egress_unblocked: boolean;
  ai_status_note: string;
  udp_probe: UdpProbeResult;
  items: EndpointMatrixItem[];
}

