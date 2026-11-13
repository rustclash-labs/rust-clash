import type {
  ActiveNodesResponse,
  AndroidPlatformInfo,
  AutostartStatus,
  BenchmarkResponse,
  ConfigAuditReport,
  ConfigDiffSummary,
  ConfigSnapshot,
  ConnectionItem,
  ConnectionsResponse,
  CreateProfileSpec,
  DemoInfo,
  DesktopPrefs,
  DnsFlushResponse,
  DnsQueryResponse,
  EndpointMatrixReport,
  ExitIpInfo,
  FakeIpPoolResponse,
  GeoDataStatus,
  ImportNodesResponse,
  LogEntry,
  ProfileMetadata,
  ProfilesSnapshot,
  ProxyInfo,
  ProxyNodeConfigPayload,
  RoutingPresetChoice,
  RoutingPresetSnapshot,
  RuleExplainResponse,
  RuleItem,
  RunMode,
  SkippedProxyEntry,
  SysProxyStatus,
  TrafficPoint,
  VersionInfo,
  VlessKeypairResponse,
  WaterfallProbeReport,
} from "./types";

export interface ControllerSettings {
  baseUrl: string;
  secret: string;
}

export class ApiHttpError extends Error {
  public readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiHttpError";
    this.status = status;
  }
}

interface AndroidNativeBridge {
  getPlatformInfoJson?: () => string;
  disconnectVpn?: () => void;
  openPerAppSelector?: () => void;
  readClipboard?: () => string;
  requestQrScan?: () => void;
}

interface HostWindow extends Window {
  __RUST_CLASH_API_BASE__?: string;
  __TAURI_INTERNALS__?: {
    invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  };
  RustClashAndroid?: AndroidNativeBridge;
}

const STORAGE_KEY = "rust_clash_controller_v1";
const SESSION_SECRET_KEY = "rust_clash_session_secret_v1";
let discoveredDesktopBaseUrl: string | null = null;
let discoveredDesktopSecret: string | null = null;
let capturedBootSecret: string | null = null;
let desktopDiscoveryPromise: Promise<string> | null = null;

function captureSecretFromUrlOnBoot(): void {
  if (typeof window === "undefined") return;
  try {
    const params = new URLSearchParams(window.location.search);
    const urlSecret = (params.get("secret") ?? params.get("token"))?.trim();
    if (urlSecret) {
      capturedBootSecret = urlSecret;
      try {
        sessionStorage.setItem(SESSION_SECRET_KEY, urlSecret);
      } catch {
        // ignore sessionStorage restrictions
      }
      const existing = loadControllerSettings();
      saveControllerSettings({ ...existing, secret: urlSecret });

      params.delete("secret");
      params.delete("token");
      const restQuery = params.toString();
      const cleanUrl =
        window.location.pathname +
        (restQuery ? `?${restQuery}` : "") +
        window.location.hash;
      window.history.replaceState({}, document.title, cleanUrl);
    } else {
      try {
        const fromSession = sessionStorage.getItem(SESSION_SECRET_KEY);
        if (fromSession) {
          capturedBootSecret = fromSession;
        }
      } catch {
        // ignore
      }
    }
  } catch {
    // ignore URL parsing issues
  }
}

captureSecretFromUrlOnBoot();

export function isTauriDesktop(): boolean {
  return (
    typeof window !== "undefined" &&
    Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
  );
}

function isTauriWebview(): boolean {
  if (typeof window === "undefined") return false;
  const w = window as HostWindow;
  return (
    Boolean(w.__TAURI_INTERNALS__) ||
    window.location.protocol === "tauri:" ||
    window.location.hostname === "tauri.localhost"
  );
}

export async function fetchDesktopPrefs(): Promise<DesktopPrefs> {
  if (typeof window === "undefined") return { close_to_tray: true };
  const w = window as HostWindow;
  if (w.__TAURI_INTERNALS__?.invoke) {
    const res = await w.__TAURI_INTERNALS__.invoke<DesktopPrefs>(
      "desktop_get_prefs",
    );
    return {
      close_to_tray: Boolean(res?.close_to_tray ?? true),
    };
  }
  return { close_to_tray: true };
}

export async function updateDesktopPrefs(
  closeToTray: boolean,
): Promise<DesktopPrefs> {
  if (typeof window === "undefined") return { close_to_tray: closeToTray };
  const w = window as HostWindow;
  if (w.__TAURI_INTERNALS__?.invoke) {
    const res = await w.__TAURI_INTERNALS__.invoke<DesktopPrefs>(
      "desktop_set_prefs",
      {
        close_to_tray: closeToTray,
        closeToTray,
      },
    );
    return {
      close_to_tray: Boolean(res?.close_to_tray ?? closeToTray),
    };
  }
  return { close_to_tray: closeToTray };
}

export const androidBridge = {
  isAvailable(): boolean {
    if (typeof window === "undefined") return false;
    return Boolean((window as HostWindow).RustClashAndroid);
  },
  canScanQr(): boolean {
    if (typeof window === "undefined") return false;
    return typeof (window as HostWindow).RustClashAndroid?.requestQrScan === "function";
  },
  readClipboard(): string | null {
    if (typeof window === "undefined") return null;
    const raw = (window as HostWindow).RustClashAndroid?.readClipboard?.();
    return typeof raw === "string" ? raw : null;
  },
  requestQrScan(): void {
    if (typeof window === "undefined") return;
    (window as HostWindow).RustClashAndroid?.requestQrScan?.();
  },
  getPlatformInfo(): AndroidPlatformInfo | null {
    if (typeof window === "undefined") return null;
    const raw = (window as HostWindow).RustClashAndroid?.getPlatformInfoJson?.();
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as {
        platform?: string;
        vpnState?: string;
        lockdownWarning?: string | null;
      };
      return {
        platform: "android",
        vpnState: parsed.vpnState ?? "UNKNOWN",
        lockdownWarning:
          typeof parsed.lockdownWarning === "string"
            ? parsed.lockdownWarning
            : null,
      };
    } catch {
      return null;
    }
  },
  disconnectVpn(): void {
    if (typeof window === "undefined") return;
    (window as HostWindow).RustClashAndroid?.disconnectVpn?.();
  },
  openPerAppSelector(): void {
    if (typeof window === "undefined") return;
    (window as HostWindow).RustClashAndroid?.openPerAppSelector?.();
  },
};

export async function readClipboardText(): Promise<string | null> {
  const nativeText = androidBridge.readClipboard();
  if (nativeText !== null && nativeText.trim().length > 0) {
    return nativeText;
  }
  if (typeof navigator !== "undefined" && navigator.clipboard?.readText) {
    try {
      const txt = await navigator.clipboard.readText();
      return txt;
    } catch {
      return null;
    }
  }
  return null;
}

async function resolveRuntimeBaseUrl(configuredBase: string): Promise<string> {
  if (configuredBase) return configuredBase;
  if (typeof window === "undefined") return "";
  const w = window as HostWindow;
  if (w.__RUST_CLASH_API_BASE__) {
    return w.__RUST_CLASH_API_BASE__.replace(/\/+$/, "");
  }
  if (discoveredDesktopBaseUrl !== null) {
    return discoveredDesktopBaseUrl;
  }
  if (isTauriWebview()) {
    if (!desktopDiscoveryPromise) {
      desktopDiscoveryPromise = (async () => {
        try {
          if (w.__TAURI_INTERNALS__?.invoke) {
            const status = await w.__TAURI_INTERNALS__.invoke<{
              api_base_url: string;
              api_secret?: string | null;
            }>("get_desktop_status");
            if (status?.api_secret) {
              discoveredDesktopSecret = status.api_secret;
            }
            if (status?.api_base_url) {
              discoveredDesktopBaseUrl = status.api_base_url.replace(/\/+$/, "");
              return discoveredDesktopBaseUrl;
            }
          }
        } catch {
          // Fallback to default local controller port
        }
        discoveredDesktopBaseUrl = "http://127.0.0.1:9090";
        return discoveredDesktopBaseUrl;
      })();
    }
    return desktopDiscoveryPromise;
  }
  return "";
}

export async function ensureRuntimeApiReady(): Promise<void> {
  const settings = loadControllerSettings();
  await resolveRuntimeBaseUrl(settings.baseUrl);
}

export function loadControllerSettings(): ControllerSettings {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved) as Partial<ControllerSettings>;
      return {
        baseUrl: (parsed.baseUrl ?? "").replace(/\/+$/, ""),
        secret: parsed.secret || capturedBootSecret || "",
      };
    }
  } catch {
    // ignore storage errors
  }
  return { baseUrl: "", secret: capturedBootSecret || "" };
}

export function saveControllerSettings(settings: ControllerSettings): void {
  const cleanSecret = settings.secret.trim();
  if (cleanSecret) {
    capturedBootSecret = cleanSecret;
  }
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        baseUrl: settings.baseUrl.replace(/\/+$/, ""),
        secret: cleanSecret,
      }),
    );
  } catch {
    // ignore storage errors in restricted webviews
  }
}

function effectiveSecret(settings: ControllerSettings): string {
  return (
    settings.secret ||
    capturedBootSecret ||
    discoveredDesktopSecret ||
    ""
  );
}

async function apiFetch<T>(
  path: string,
  init?: RequestInit,
  settings: ControllerSettings = loadControllerSettings(),
): Promise<T> {
  const base = await resolveRuntimeBaseUrl(settings.baseUrl);
  const url = `${base}${path}`;
  const headers = new Headers(init?.headers);
  const secret = effectiveSecret(settings);
  if (secret) {
    headers.set("Authorization", `Bearer ${secret}`);
  }
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  let resp: Response;
  try {
    resp = await fetch(url, { ...init, headers });
  } catch (err) {
    const detail = err instanceof Error && err.message ? ` (${err.message})` : "";
    throw new Error(
      `Cannot reach RustClash controller API — check that the daemon is running${detail}.`,
    );
  }
  if (!resp.ok) {
    let errText = `${resp.status} ${resp.statusText}`.trim();
    try {
      const rawBody = await resp.text();
      if (rawBody.trim().length > 0) {
        try {
          const parsed = JSON.parse(rawBody) as {
            message?: string;
            error?: string;
          };
          const msg = parsed.message || parsed.error;
          if (msg && msg.trim().length > 0) {
            errText = msg.trim();
          } else {
            errText = rawBody.trim().slice(0, 300);
          }
        } catch {
          errText = rawBody.trim().slice(0, 300);
        }
      }
    } catch {
      // ignore body read error
    }
    errText = errText.replace(/^(Configuration error:\s*)+/i, "Configuration error: ");
    throw new ApiHttpError(resp.status, errText);
  }
  if (resp.status === 204) {
    return undefined as T;
  }
  return (await resp.json()) as T;
}

export interface ConfigPatchPayload {
  mode?: RunMode;
  "unified-delay"?: boolean;
  "allow-lan"?: boolean;
  ipv6?: boolean;
  "mixed-port"?: number;
  "log-level"?: string;
  tun?: {
    enable?: boolean;
    "strict-route"?: boolean;
    ipv6?: boolean;
  };
}

export async function fetchExitIp(refresh = false): Promise<ExitIpInfo> {
  const suffix = refresh ? "?refresh=1" : "";
  return apiFetch<ExitIpInfo>(`/tools/ip${suffix}`);
}

export async function testProxyDelay(
  name: string,
  url?: string,
  timeoutMs = 4000,
): Promise<{ delay: number }> {
  const q = new URLSearchParams({ timeout: String(timeoutMs) });
  if (url?.trim()) {
    q.set("url", url.trim());
  }
  return apiFetch<{ delay: number }>(
    `/proxies/${encodeURIComponent(name)}/delay?${q.toString()}`,
  );
}

export async function patchConfig(patch: ConfigPatchPayload): Promise<void> {
  return apiFetch<void>("/configs", {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export async function setSysProxy(
  enable: boolean,
  bypass?: string[],
): Promise<SysProxyStatus> {
  return apiFetch<SysProxyStatus>("/sysproxy", {
    method: "PATCH",
    body: JSON.stringify({ enable, bypass }),
  });
}

export async function updateProfileSettings(
  id: string,
  patch: { name?: string; auto_update_interval_secs?: number | null },
): Promise<ProfileMetadata> {
  const raw = await apiFetch<
    ProfileMetadata | { profile: ProfileMetadata; snapshot?: ProfilesSnapshot }
  >(`/profiles/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  if (raw && typeof raw === "object" && "profile" in raw && raw.profile) {
    return raw.profile;
  }
  return raw as ProfileMetadata;
}

export async function importProfile(
  input: string,
  name?: string,
  activate = true,
  autoUpdateIntervalSecs?: number | null,
): Promise<ImportNodesResponse> {
  const cleanName = name?.trim() || undefined;
  return apiFetch<ImportNodesResponse>("/profiles/import", {
    method: "POST",
    body: JSON.stringify({
      uris: input,
      input,
      name: cleanName,
      profile_name: cleanName,
      apply: activate,
      activate,
      deduplicate: true,
      auto_select: true,
      auto_update_interval_secs: autoUpdateIntervalSecs,
    }),
  });
}

export async function importActiveNodes(
  uris: string,
  opts?: { deduplicate?: boolean; autoSelect?: boolean },
): Promise<ImportNodesResponse> {
  return apiFetch<ImportNodesResponse>("/profiles/import", {
    method: "POST",
    body: JSON.stringify({
      uris,
      apply: true,
      deduplicate: opts?.deduplicate ?? true,
      auto_select: opts?.autoSelect ?? true,
    }),
  });
}

export async function upsertActiveNode(
  node: ProxyNodeConfigPayload,
  originalName?: string | null,
  autoSelect = true,
): Promise<ActiveNodesResponse> {
  if (originalName) {
    return apiFetch<ActiveNodesResponse>(
      `/profiles/active/nodes/${encodeURIComponent(originalName)}`,
      {
        method: "PUT",
        body: JSON.stringify({ node, auto_select: autoSelect }),
      },
    );
  }
  return apiFetch<ActiveNodesResponse>("/profiles/active/nodes", {
    method: "POST",
    body: JSON.stringify({ node, auto_select: autoSelect }),
  });
}

export async function runDiagnosticsWaterfall(
  name: string,
  opts?: { url?: string; checkUdp?: boolean; timeoutMs?: number },
): Promise<WaterfallProbeReport> {
  return apiFetch<WaterfallProbeReport>(
    `/proxies/${encodeURIComponent(name)}/probe`,
    {
      method: "POST",
      body: JSON.stringify({
        url: opts?.url,
        check_udp: opts?.checkUdp ?? true,
        timeout: opts?.timeoutMs ?? 5000,
      }),
    },
  );
}

export async function exportDiagnosticsBundle(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/diagnostics/export");
}

export async function toggleDemoMode(
  enable: boolean,
): Promise<{ demo: DemoInfo; mode: RunMode }> {
  return apiFetch<{ demo: DemoInfo; mode: RunMode }>("/demo/toggle", {
    method: "POST",
    body: JSON.stringify({ enable }),
  });
}

export async function generateVlessKeypair(opts: {
  mode: string;
  zero_rtt: boolean;
  post_quantum: boolean;
}): Promise<VlessKeypairResponse> {
  return apiFetch<VlessKeypairResponse>("/tools/vless-keypair", {
    method: "POST",
    body: JSON.stringify(opts),
  });
}

export async function runBenchmark(
  streams = 4,
  payloadBytes = 262_144,
): Promise<BenchmarkResponse> {
  return apiFetch<BenchmarkResponse>("/tools/benchmark", {
    method: "POST",
    body: JSON.stringify({ streams, payload_bytes: payloadBytes }),
  });
}

export const clashApi = {
  getVersion: () => apiFetch<VersionInfo>("/version"),
  getConfigs: () => apiFetch<ConfigSnapshot>("/configs"),
  patchConfigs: patchConfig,
  getExitIp: fetchExitIp,
  getRawYaml: (includeSensitive = false) =>
    apiFetch<{ yaml: string; uris: string[]; redacted?: boolean }>(
      includeSensitive ? "/configs/raw?include_sensitive=true" : "/configs/raw",
    ),
  reloadYaml: (payload: string) =>
    apiFetch<void>("/configs", {
      method: "PUT",
      body: JSON.stringify({ payload }),
    }),
  getProxies: () => apiFetch<{ proxies: Record<string, ProxyInfo> }>("/proxies"),
  selectProxy: (groupName: string, memberName: string) =>
    apiFetch<void>(`/proxies/${encodeURIComponent(groupName)}`, {
      method: "PUT",
      body: JSON.stringify({ name: memberName }),
    }),
  testDelay: (name: string, timeoutMs = 5000, url?: string) =>
    testProxyDelay(name, url, timeoutMs),
  getRules: () => apiFetch<{ rules: RuleItem[] }>("/rules"),
  explainRule: (target: string, srcIp?: string) => {
    const q = new URLSearchParams({ target });
    if (srcIp?.trim()) q.set("src_ip", srcIp.trim());
    return apiFetch<RuleExplainResponse>(`/rules/explain?${q.toString()}`);
  },
  getRoutingPreset: () => apiFetch<RoutingPresetSnapshot>("/routing/preset"),
  setRoutingPreset: (preset: RoutingPresetChoice) =>
    apiFetch<RoutingPresetSnapshot>("/routing/preset", {
      method: "PUT",
      body: JSON.stringify({ preset }),
    }),
  getCustomRules: () => apiFetch<{ rules: string[] }>("/routing/custom-rules"),
  saveCustomRules: (rules: string[]) =>
    apiFetch<RoutingPresetSnapshot>("/routing/custom-rules", {
      method: "PUT",
      body: JSON.stringify({ rules }),
    }),
  getGeoDataStatus: () => apiFetch<GeoDataStatus>("/geodata"),
  updateGeoData: () =>
    apiFetch<GeoDataStatus>("/geodata/update", { method: "POST" }),
  getConnections: () => apiFetch<ConnectionsResponse>("/connections"),
  closeAllConnections: () =>
    apiFetch<void>("/connections", { method: "DELETE" }),
  closeConnection: (id: string) =>
    apiFetch<void>(`/connections/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  getConnectionDiagnostics: (limit = 150) =>
    apiFetch<{ diagnostics: ConnectionItem[] }>(
      `/connections/diagnostics?limit=${limit}`,
    ),
  clearConnectionDiagnostics: () =>
    apiFetch<void>("/connections/diagnostics", { method: "DELETE" }),
  queryDns: (name: string, qtype: "A" | "AAAA" = "A") =>
    apiFetch<DnsQueryResponse>(
      `/dns/query?name=${encodeURIComponent(name)}&type=${qtype}`,
    ),
  flushDnsCache: () =>
    apiFetch<DnsFlushResponse>("/dns/flush", { method: "POST" }),
  getFakeIpPool: () => apiFetch<FakeIpPoolResponse>("/dns/fakeip"),
  generateVlessKeys: generateVlessKeypair,
  importUris: (
    uris: string,
    apply = true,
    opts?: {
      deduplicate?: boolean;
      autoSelect?: boolean;
      profileName?: string;
      autoUpdateIntervalSecs?: number | null;
    },
  ) =>
    apiFetch<ImportNodesResponse>("/profiles/import", {
      method: "POST",
      body: JSON.stringify({
        uris,
        input: uris,
        apply,
        activate: apply,
        deduplicate: opts?.deduplicate ?? true,
        auto_select: opts?.autoSelect ?? true,
        profile_name: opts?.profileName,
        name: opts?.profileName,
        auto_update_interval_secs: opts?.autoUpdateIntervalSecs,
      }),
    }),
  importProfile,
  importActiveNodes,
  upsertActiveNode,
  getActiveNodes: () => apiFetch<ActiveNodesResponse>("/profiles/active/nodes"),
  createActiveNode: (node: ProxyNodeConfigPayload, autoSelect = true) =>
    upsertActiveNode(node, null, autoSelect),
  updateActiveNode: (
    originalName: string,
    node: ProxyNodeConfigPayload,
    autoSelect = false,
  ) => upsertActiveNode(node, originalName, autoSelect),
  deleteActiveNode: (name: string) =>
    apiFetch<ActiveNodesResponse>(
      `/profiles/active/nodes/${encodeURIComponent(name)}`,
      { method: "DELETE" },
    ),
  deduplicateActiveNodes: () =>
    apiFetch<ActiveNodesResponse>("/profiles/active/nodes/deduplicate", {
      method: "POST",
    }),
  getProfiles: () => apiFetch<ProfilesSnapshot>("/profiles"),
  createProfile: (spec: CreateProfileSpec) =>
    apiFetch<{
      profile: ProfileMetadata;
      "skipped-unsupported"?: SkippedProxyEntry[];
      snapshot: ProfilesSnapshot;
    }>("/profiles", {
      method: "POST",
      body: JSON.stringify(spec),
    }),
  updateProfileSettings,
  activateProfile: (id: string) =>
    apiFetch<ProfilesSnapshot>(
      `/profiles/${encodeURIComponent(id)}/activate`,
      { method: "PUT" },
    ),
  refreshProfile: (id: string) =>
    apiFetch<{
      profile: ProfileMetadata;
      snapshot: ProfilesSnapshot;
      diff?: ConfigDiffSummary | null;
      audit_score?: number;
      audit_grade?: string;
    }>(`/profiles/${encodeURIComponent(id)}/refresh`, { method: "POST" }),
  deleteProfile: (id: string) =>
    apiFetch<ProfilesSnapshot>(`/profiles/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  toggleDemoSandbox: toggleDemoMode,
  getSysProxy: () => apiFetch<SysProxyStatus>("/sysproxy"),
  patchSysProxy: setSysProxy,
  getAutostart: () => apiFetch<AutostartStatus>("/autostart"),
  patchAutostart: (enable: boolean) =>
    apiFetch<AutostartStatus>("/autostart", {
      method: "PATCH",
      body: JSON.stringify({ enable }),
    }),
  exportDiagnostics: exportDiagnosticsBundle,
  getConfigAudit: (resolveDns = false) =>
    apiFetch<ConfigAuditReport>(
      resolveDns
        ? "/diagnostics/audit?resolve_dns=true"
        : "/diagnostics/audit",
    ),
  postConfigAudit: (yaml: string, diffAgainstActive = true) =>
    apiFetch<{ audit: ConfigAuditReport; diff?: ConfigDiffSummary | null }>(
      "/diagnostics/audit",
      {
        method: "POST",
        body: JSON.stringify({
          yaml,
          diff_against_active: diffAgainstActive,
        }),
      },
    ),
  probeWaterfall: runDiagnosticsWaterfall,
  probeEndpointMatrix: (name: string, timeoutMs = 4500) =>
    apiFetch<EndpointMatrixReport>(
      `/proxies/${encodeURIComponent(name)}/matrix`,
      {
        method: "POST",
        body: JSON.stringify({ timeout: timeoutMs }),
      },
    ),
  runBenchmark,
  getTrafficSnapshot: () =>
    apiFetch<{
      up: number;
      down: number;
      total_up: number;
      total_down: number;
      history: TrafficPoint[];
    }>("/traffic"),
  getLogsSnapshot: () => apiFetch<{ logs: LogEntry[] }>("/logs"),
};

export function buildWsUrl(path: string): string {
  const settings = loadControllerSettings();
  const w = (typeof window !== "undefined" ? window : {}) as HostWindow;
  const fallbackOrigin = isTauriWebview()
    ? discoveredDesktopBaseUrl ||
      w.__RUST_CLASH_API_BASE__ ||
      "http://127.0.0.1:9090"
    : window.location.origin;
  const base = settings.baseUrl || fallbackOrigin;
  const wsBase = base.replace(/^http/i, "ws");
  const sep = path.includes("?") ? "&" : "?";
  const secret = effectiveSecret(settings);
  const authQuery = secret ? `${sep}token=${encodeURIComponent(secret)}` : "";
  return `${wsBase}${path}${authQuery}`;
}
