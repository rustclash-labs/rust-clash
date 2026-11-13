import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  androidBridge,
  clashApi,
  importActiveNodes,
  readClipboardText,
  testProxyDelay,
  upsertActiveNode,
} from "../api";
import {
  BoltIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CloseIcon,
  PlusIcon,
  SearchIcon,
} from "../components/Icons";
import { useI18n } from "../i18n";
import type {
  ConfigSnapshot,
  ProxyInfo,
  ProxyNodeConfigPayload,
} from "../types";
import {
  nodeProtocolBadge,
  prettyProtocolLabel,
  protocolBadgeVariant,
} from "../utils/format";

interface ProxiesViewProps {
  config: ConfigSnapshot | null;
  proxies: Record<string, ProxyInfo>;
  onRefreshProxies: () => Promise<void>;
  openAddModalSignal?: number;
  focusGroup?: string | null;
  onOpenProfiles?: () => void;
}

const GROUP_TYPES = new Set(["Selector", "URLTest", "Fallback", "LoadBalance"]);
const REDACTED_SECRET = "***REDACTED***";
const NIL_UUID = "00000000-0000-0000-0000-000000000000";

const SS_CIPHERS = [
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-ietf-poly1305",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-chacha20-poly1305",
];

type SortOrder = "default" | "latency" | "name";
type ModalMode = "paste" | "manual";
type NodeProto = "vless" | "trojan" | "ss" | "anytls" | "socks5" | "http";

export const ProxiesView: React.FC<ProxiesViewProps> = ({
  config,
  proxies,
  onRefreshProxies,
  openAddModalSignal = 0,
  focusGroup = null,
  onOpenProfiles,
}) => {
  const { tr } = useI18n();

  const [searchQuery, setSearchQuery] = useState("");
  const [sortOrder, setSortOrder] = useState<SortOrder>("default");
  const [testingMap, setTestingMap] = useState<Record<string, boolean>>({});
  const [probingAll, setProbingAll] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(
    {},
  );
  const [managerOpen, setManagerOpen] = useState(false);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const [activeNodes, setActiveNodes] = useState<ProxyNodeConfigPayload[]>([]);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<ModalMode>("paste");
  const [modalError, setModalError] = useState<string | null>(null);
  const [editingOriginalName, setEditingOriginalName] = useState<string | null>(
    null,
  );
  const [editingOriginalProto, setEditingOriginalProto] =
    useState<NodeProto | null>(null);

  // Paste tab
  const [pasteInput, setPasteInput] = useState("");
  const [dedupOnImport, setDedupOnImport] = useState(true);
  const [autoSelectOnImport, setAutoSelectOnImport] = useState(true);

  // Form tab
  const [proto, setProto] = useState<NodeProto>("vless");
  const [nodeName, setNodeName] = useState("");
  const [serverHost, setServerHost] = useState("");
  const [serverPort, setServerPort] = useState("443");
  const [udpEnabled, setUdpEnabled] = useState(true);
  const [autoSelectManual, setAutoSelectManual] = useState(true);

  // Protocol-specific fields
  const [ssCipher, setSsCipher] = useState("aes-256-gcm");
  const [ssPassword, setSsPassword] = useState("");

  const [vlessUuid, setVlessUuid] = useState("");
  const [vlessEncryption, setVlessEncryption] = useState("none");
  const [vlessHadRedactedEnc, setVlessHadRedactedEnc] = useState(false);
  const [vlessTls, setVlessTls] = useState(true);
  const [vlessServername, setVlessServername] = useState("");
  const [vlessSkipVerify, setVlessSkipVerify] = useState(false);
  const [vlessAlpn, setVlessAlpn] = useState("");

  const [trojanPassword, setTrojanPassword] = useState("");
  const [trojanTls, setTrojanTls] = useState(true);
  const [trojanSni, setTrojanSni] = useState("");
  const [trojanSkipVerify, setTrojanSkipVerify] = useState(false);
  const [trojanAlpn, setTrojanAlpn] = useState("h2, http/1.1");

  const [transportNet, setTransportNet] = useState<"tcp" | "ws">("tcp");
  const [wsPath, setWsPath] = useState("/");
  const [wsHost, setWsHost] = useState("");
  const [wsMaxEarlyData, setWsMaxEarlyData] = useState("");

  const [anytlsPassword, setAnytlsPassword] = useState("");
  const [anytlsSni, setAnytlsSni] = useState("");
  const [anytlsSkipVerify, setAnytlsSkipVerify] = useState(false);
  const [anytlsAlpn, setAnytlsAlpn] = useState("h2, http/1.1");

  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authHadSavedPassword, setAuthHadSavedPassword] = useState(false);
  const [proxyTls, setProxyTls] = useState(false);
  const [proxySni, setProxySni] = useState("");
  const [proxySkipVerify, setProxySkipVerify] = useState(false);

  const groupRefs = useRef<Record<string, HTMLElement | null>>({});

  const groups = useMemo(() => {
    const list = Object.values(proxies).filter(
      (p) => GROUP_TYPES.has(p.type) && p.all && p.all.length > 0,
    );
    list.sort((a, b) => {
      if (a.name === "GLOBAL") return 1;
      if (b.name === "GLOBAL") return -1;
      return 0;
    });
    return list;
  }, [proxies]);

  const primaryGroupName = useMemo(() => {
    const primary =
      groups.find(
        (g) =>
          g.type === "Selector" &&
          (g.name === "PROXY" || g.name === "🚀 Proxy"),
      ) ??
      groups.find((g) => g.type === "Selector" && g.name !== "GLOBAL") ??
      groups[0];
    return primary?.name ?? null;
  }, [groups]);

  // Expand primary group by default
  useEffect(() => {
    if (!primaryGroupName) return;
    setExpandedGroups((prev) => {
      if (Object.keys(prev).length > 0) return prev;
      return { [primaryGroupName]: true };
    });
  }, [primaryGroupName]);

  // Expand and scroll when navigated from Dashboard mini-card
  useEffect(() => {
    if (!focusGroup) return;
    setExpandedGroups((prev) => ({ ...prev, [focusGroup]: true }));
    window.setTimeout(() => {
      groupRefs.current[focusGroup]?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 60);
  }, [focusGroup]);

  const loadActiveNodes = useCallback(async () => {
    try {
      const snap = await clashApi.getActiveNodes();
      setActiveNodes(snap.nodes);
    } catch {
      // ignore if profile manager unavailable
    }
  }, []);

  useEffect(() => {
    void loadActiveNodes();
  }, [loadActiveNodes, proxies]);

  const nodeByName = useMemo(() => {
    const map: Record<string, ProxyNodeConfigPayload> = {};
    for (const n of activeNodes) {
      map[n.name] = n;
    }
    return map;
  }, [activeNodes]);

  const resetManualForm = useCallback(() => {
    setEditingOriginalName(null);
    setEditingOriginalProto(null);
    setProto("vless");
    setNodeName("");
    setServerHost("");
    setServerPort("443");
    setUdpEnabled(true);
    setAutoSelectManual(true);
    setSsCipher("aes-256-gcm");
    setSsPassword("");
    setVlessUuid("");
    setVlessEncryption("none");
    setVlessHadRedactedEnc(false);
    setVlessTls(true);
    setVlessServername("");
    setVlessSkipVerify(false);
    setVlessAlpn("");
    setTrojanPassword("");
    setTrojanTls(true);
    setTrojanSni("");
    setTrojanSkipVerify(false);
    setTrojanAlpn("h2, http/1.1");
    setTransportNet("tcp");
    setWsPath("/");
    setWsHost("");
    setWsMaxEarlyData("");
    setAnytlsPassword("");
    setAnytlsSni("");
    setAnytlsSkipVerify(false);
    setAnytlsAlpn("h2, http/1.1");
    setAuthUsername("");
    setAuthPassword("");
    setAuthHadSavedPassword(false);
    setProxyTls(false);
    setProxySni("");
    setProxySkipVerify(false);
  }, []);

  const openCreateModal = useCallback(
    (initialTab: ModalMode = "paste") => {
      resetManualForm();
      setModalError(null);
      setModalMode(initialTab);
      setModalOpen(true);
    },
    [resetManualForm],
  );

  useEffect(() => {
    if (openAddModalSignal > 0) {
      openCreateModal("paste");
    }
  }, [openAddModalSignal, openCreateModal]);

  const openEditModal = (node: ProxyNodeConfigPayload) => {
    resetManualForm();
    setModalError(null);
    setEditingOriginalName(node.name);
    setEditingOriginalProto(node.type);
    setModalMode("manual");
    setProto(node.type);
    setNodeName(node.name);
    setServerHost(node.server);
    setServerPort(String(node.port));
    setUdpEnabled("udp" in node ? (node.udp ?? true) : false);
    setAutoSelectManual(false);

    if (node.type === "ss") {
      setSsCipher(node.cipher);
      setSsPassword("");
    } else if (node.type === "vless") {
      setVlessUuid("");
      const rawEnc = node.encryption ?? "none";
      if (rawEnc === REDACTED_SECRET) {
        setVlessHadRedactedEnc(true);
        setVlessEncryption("");
      } else {
        setVlessHadRedactedEnc(false);
        setVlessEncryption(rawEnc);
      }
      setVlessTls(node.tls ?? false);
      setVlessServername(node.servername ?? "");
      setVlessSkipVerify(Boolean(node["skip-cert-verify"]));
      setVlessAlpn((node.alpn ?? []).join(", "));
      const isWs =
        (node.network ?? "").toLowerCase() === "ws" || Boolean(node["ws-opts"]);
      setTransportNet(isWs ? "ws" : "tcp");
      setWsPath(node["ws-opts"]?.path ?? "/");
      setWsHost(
        node["ws-opts"]?.headers?.Host ?? node["ws-opts"]?.headers?.host ?? "",
      );
      setWsMaxEarlyData(
        node["ws-opts"]?.["max-early-data"]
          ? String(node["ws-opts"]["max-early-data"])
          : "",
      );
    } else if (node.type === "trojan") {
      setTrojanPassword("");
      setTrojanTls(node.tls ?? true);
      setTrojanSni(node.sni ?? "");
      setTrojanSkipVerify(Boolean(node["skip-cert-verify"]));
      setTrojanAlpn((node.alpn ?? []).join(", "));
      const isWs =
        (node.network ?? "").toLowerCase() === "ws" || Boolean(node["ws-opts"]);
      setTransportNet(isWs ? "ws" : "tcp");
      setWsPath(node["ws-opts"]?.path ?? "/");
      setWsHost(
        node["ws-opts"]?.headers?.Host ?? node["ws-opts"]?.headers?.host ?? "",
      );
      setWsMaxEarlyData(
        node["ws-opts"]?.["max-early-data"]
          ? String(node["ws-opts"]["max-early-data"])
          : "",
      );
    } else if (node.type === "anytls") {
      setAnytlsPassword("");
      setAnytlsSni(node.sni ?? "");
      setAnytlsSkipVerify(Boolean(node["skip-cert-verify"]));
      setAnytlsAlpn((node.alpn ?? []).join(", "));
    } else if (node.type === "socks5" || node.type === "http") {
      setAuthUsername(node.username ?? "");
      setAuthPassword("");
      setAuthHadSavedPassword(Boolean(node.password));
      setProxyTls(Boolean(node.tls));
      setProxySni(node.sni ?? "");
      setProxySkipVerify(Boolean(node["skip-cert-verify"]));
    }
    setModalOpen(true);
  };

  const latestDelay = (name: string): number | undefined => {
    const info = proxies[name];
    if (!info || info.history.length === 0) return undefined;
    return info.history[info.history.length - 1]?.delay;
  };

  const handleSelectMember = async (group: ProxyInfo, memberName: string) => {
    if (group.type !== "Selector") return;
    setToast(null);
    try {
      await clashApi.selectProxy(group.name, memberName);
      if (config?.mode === "direct") {
        await clashApi.patchConfigs({ mode: "rule" });
      }
      await onRefreshProxies();
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const handleProbeSingle = async (
    e: React.MouseEvent,
    targetName: string,
  ) => {
    e.stopPropagation();
    setTestingMap((prev) => ({ ...prev, [targetName]: true }));
    try {
      await testProxyDelay(targetName, undefined, 4000);
      await onRefreshProxies();
    } catch {
      await onRefreshProxies();
    } finally {
      setTestingMap((prev) => ({ ...prev, [targetName]: false }));
    }
  };

  const handleProbeGroup = async (group: ProxyInfo) => {
    const members = group.all ?? [];
    const flags: Record<string, boolean> = { [group.name]: true };
    for (const m of members) flags[m] = true;
    setTestingMap((prev) => ({ ...prev, ...flags }));

    try {
      await Promise.allSettled(
        members.map((m) => testProxyDelay(m, undefined, 4000)),
      );
      await testProxyDelay(group.name, undefined, 4000).catch(() => undefined);
      await onRefreshProxies();
    } finally {
      const clear: Record<string, boolean> = { [group.name]: false };
      for (const m of members) clear[m] = false;
      setTestingMap((prev) => ({ ...prev, ...clear }));
    }
  };

  const handleTestAll = async () => {
    if (probingAll) return;
    setProbingAll(true);
    try {
      for (const grp of groups) {
        await handleProbeGroup(grp);
      }
    } finally {
      setProbingAll(false);
    }
  };

  const handleImportPaste = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = pasteInput.trim();
    if (!trimmed) {
      setModalError(
        tr(
          "请粘贴节点链接（如 vless://、vmess://、ss://、trojan://、hy2://、tuic://）、Base64 列表或 Clash YAML",
          "Please paste share links (vless://, vmess://, ss://, trojan://, hy2://, tuic://), Base64 list, or Clash YAML",
        ),
      );
      return;
    }
    setBusyAction("import");
    setModalError(null);
    try {
      const res = await importActiveNodes(trimmed, {
        deduplicate: dedupOnImport,
        autoSelect: autoSelectOnImport,
      });
      await onRefreshProxies();
      await loadActiveNodes();
      setPasteInput("");
      setModalOpen(false);
      const dup = res["skipped-duplicates"] ?? 0;
      setToast({
        ok: true,
        text: tr(
          `成功导入 ${res.count} 个节点${dup > 0 ? `（已自动跳过 ${dup} 个重复节点）` : ""}，已受手动节点保护。`,
          `Imported ${res.count} node(s)${dup > 0 ? ` (${dup} duplicates skipped)` : ""} with manual-node protection.`,
        ),
      });
    } catch (err) {
      setModalError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const handleReadClipboardToPaste = async () => {
    setModalError(null);
    const clip = await readClipboardText();
    if (clip && clip.trim()) {
      setPasteInput((prev) =>
        prev.trim() ? `${prev.trim()}\n${clip.trim()}` : clip.trim(),
      );
    } else {
      setModalError(
        tr(
          "剪贴板为空或未授予读取权限，请在下方输入框直接按 Ctrl+V / Cmd+V 粘贴",
          "Clipboard is empty or blocked — press Ctrl+V / Cmd+V directly into the box below",
        ),
      );
    }
  };

  const buildWsTransportPayload = () => {
    if (transportNet !== "ws") {
      return { network: "tcp", wsOpts: undefined };
    }
    const headers: Record<string, string> = {};
    if (wsHost.trim()) headers.Host = wsHost.trim();
    const trimmedEarly = wsMaxEarlyData.trim();
    let earlyNum = 0;
    if (trimmedEarly.length > 0) {
      earlyNum = Number.parseInt(trimmedEarly, 10);
      if (!Number.isFinite(earlyNum) || earlyNum < 0 || earlyNum > 65535) {
        throw new Error(
          tr(
            "WebSocket max-early-data 需为 0–65535 的整数",
            "WebSocket max-early-data must be between 0 and 65535",
          ),
        );
      }
    }
    return {
      network: "ws",
      wsOpts: {
        path: wsPath.trim() || "/",
        ...(Object.keys(headers).length > 0 ? { headers } : {}),
        ...(earlyNum > 0
          ? {
              "max-early-data": earlyNum,
              "early-data-header-name": "Sec-WebSocket-Protocol",
            }
          : {}),
      },
    };
  };

  const buildNodePayloadFromForm = (): ProxyNodeConfigPayload => {
    const cleanName = nodeName.trim();
    const cleanHost = serverHost.trim();
    const portNum = Number.parseInt(serverPort.trim(), 10);
    if (!cleanName) {
      throw new Error(tr("请填写节点名称", "Node name is required"));
    }
    if (!cleanHost) {
      throw new Error(tr("请填写服务器地址", "Server address is required"));
    }
    if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error(
        tr("端口必须在 1 到 65535 之间", "Port must be between 1 and 65535"),
      );
    }
    const isEditing = Boolean(editingOriginalName);
    const sameProto = isEditing && editingOriginalProto === proto;

    if (proto === "ss") {
      const pass = ssPassword.trim();
      if (!sameProto && !pass) {
        throw new Error(
          tr("请填写 Shadowsocks 密码", "Shadowsocks password is required"),
        );
      }
      return {
        type: "ss",
        name: cleanName,
        server: cleanHost,
        port: portNum,
        cipher: ssCipher,
        password: pass || REDACTED_SECRET,
        udp: udpEnabled,
      };
    }

    if (proto === "vless") {
      const rawUuid = vlessUuid.trim();
      if (!sameProto && !rawUuid) {
        throw new Error(tr("请填写 VLESS UUID", "VLESS UUID is required"));
      }
      const encTrimmed = vlessEncryption.trim();
      const effectiveEnc =
        sameProto && !encTrimmed && vlessHadRedactedEnc
          ? REDACTED_SECRET
          : encTrimmed || "none";
      const alpnList = vlessAlpn
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const wsCfg = buildWsTransportPayload();
      return {
        type: "vless",
        name: cleanName,
        server: cleanHost,
        port: portNum,
        uuid: rawUuid || NIL_UUID,
        encryption: effectiveEnc,
        tls: vlessTls,
        servername: vlessServername.trim() || null,
        "skip-cert-verify": vlessSkipVerify,
        alpn: alpnList,
        network: wsCfg.network,
        ...(wsCfg.wsOpts ? { "ws-opts": wsCfg.wsOpts } : {}),
        udp: udpEnabled,
      };
    }

    if (proto === "trojan") {
      const pass = trojanPassword.trim();
      if (!sameProto && !pass) {
        throw new Error(tr("请填写 Trojan 密码", "Trojan password is required"));
      }
      const alpnList = trojanAlpn
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const wsCfg = buildWsTransportPayload();
      return {
        type: "trojan",
        name: cleanName,
        server: cleanHost,
        port: portNum,
        password: pass || REDACTED_SECRET,
        tls: trojanTls,
        sni: trojanSni.trim() || null,
        "skip-cert-verify": trojanSkipVerify,
        alpn: alpnList,
        network: wsCfg.network,
        ...(wsCfg.wsOpts ? { "ws-opts": wsCfg.wsOpts } : {}),
        udp: udpEnabled,
      };
    }

    if (proto === "socks5") {
      const passTrimmed = authPassword.trim();
      const resolvedPass = passTrimmed
        ? passTrimmed
        : sameProto && authHadSavedPassword
          ? REDACTED_SECRET
          : null;
      return {
        type: "socks5",
        name: cleanName,
        server: cleanHost,
        port: portNum,
        username: authUsername.trim() || null,
        password: resolvedPass,
        tls: proxyTls,
        sni: proxySni.trim() || null,
        "skip-cert-verify": proxySkipVerify,
        udp: udpEnabled,
      };
    }

    if (proto === "http") {
      const passTrimmed = authPassword.trim();
      const resolvedPass = passTrimmed
        ? passTrimmed
        : sameProto && authHadSavedPassword
          ? REDACTED_SECRET
          : null;
      return {
        type: "http",
        name: cleanName,
        server: cleanHost,
        port: portNum,
        username: authUsername.trim() || null,
        password: resolvedPass,
        tls: proxyTls,
        sni: proxySni.trim() || null,
        "skip-cert-verify": proxySkipVerify,
      };
    }

    const pass = anytlsPassword.trim();
    if (!sameProto && !pass) {
      throw new Error(tr("请填写 AnyTLS 密码", "AnyTLS password is required"));
    }
    const alpnList = anytlsAlpn
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      type: "anytls",
      name: cleanName,
      server: cleanHost,
      port: portNum,
      password: pass || REDACTED_SECRET,
      sni: anytlsSni.trim() || null,
      "skip-cert-verify": anytlsSkipVerify,
      alpn: alpnList,
      udp: udpEnabled,
    };
  };

  const handleSaveManualNode = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);
    let payload: ProxyNodeConfigPayload;
    try {
      payload = buildNodePayloadFromForm();
    } catch (err) {
      setModalError(err instanceof Error ? err.message : String(err));
      return;
    }

    setBusyAction("save-node");
    try {
      const res = await upsertActiveNode(
        payload,
        editingOriginalName,
        autoSelectManual,
      );
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      setModalOpen(false);
      setToast({
        ok: true,
        text: editingOriginalName
          ? tr(`已更新节点「${payload.name}」`, `Updated node '${payload.name}'`)
          : tr(
              `已添加手动节点「${payload.name}」（订阅更新时自动保留）`,
              `Added manual node '${payload.name}' (protected across updates)`,
            ),
      });
    } catch (err) {
      setModalError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeleteNode = async (targetName: string) => {
    setBusyAction(`del:${targetName}`);
    setToast(null);
    try {
      const res = await clashApi.deleteActiveNode(targetName);
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      setToast({
        ok: true,
        text: tr(`已删除节点「${targetName}」`, `Deleted node '${targetName}'`),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeduplicate = async () => {
    setBusyAction("dedup");
    setToast(null);
    try {
      const res = await clashApi.deduplicateActiveNodes();
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      const removed = res["removed-nodes"]?.length ?? 0;
      setToast({
        ok: true,
        text:
          removed > 0
            ? tr(
                `已清理 ${removed} 个重复节点，保留 ${res.nodes.length} 个唯一节点`,
                `Removed ${removed} duplicate node(s), ${res.nodes.length} unique remaining`,
              )
            : tr("未发现重复节点", "No duplicate nodes found"),
      });
    } catch (err) {
      setToast({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusyAction(null);
    }
  };

  const filterAndSortMembers = (members: string[]): string[] => {
    const q = searchQuery.trim().toLowerCase();
    const filtered = q
      ? members.filter((m) => {
          const info = proxies[m];
          const protoText = info?.type ?? "";
          return (
            m.toLowerCase().includes(q) || protoText.toLowerCase().includes(q)
          );
        })
      : members.slice();

    if (sortOrder === "name") {
      filtered.sort((a, b) => a.localeCompare(b));
    } else if (sortOrder === "latency") {
      filtered.sort((a, b) => {
        const da = latestDelay(a);
        const db = latestDelay(b);
        const va = da && da > 0 ? da : Number.MAX_SAFE_INTEGER;
        const vb = db && db > 0 ? db : Number.MAX_SAFE_INTEGER;
        return va - vb;
      });
    }
    return filtered;
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
      {toast && (
        <div className={`banner ${toast.ok ? "banner-ok" : "banner-err"}`}>
          <span>{toast.text}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setToast(null)}
          >
            {tr("知道了", "Dismiss")}
          </button>
        </div>
      )}

      {/* Top Toolbar Card */}
      <section className="bento-card" style={{ padding: "12px 16px" }}>
        <div className="toolbar">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              flexWrap: "wrap",
              flex: "1 1 320px",
            }}
          >
            <div
              style={{
                position: "relative",
                flex: "1 1 210px",
                maxWidth: 300,
              }}
            >
              <span
                style={{
                  position: "absolute",
                  left: 11,
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "var(--text-muted)",
                  display: "inline-flex",
                }}
              >
                <SearchIcon size={14} />
              </span>
              <input
                type="text"
                className="input"
                style={{ width: "100%", paddingLeft: 32 }}
                placeholder={tr(
                  "搜索节点名称或协议...",
                  "Search node name or protocol...",
                )}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="segmented" role="group" aria-label={tr("排序方式", "Sort order")}>
              <button
                type="button"
                className={`seg-btn ${sortOrder === "default" ? "active" : ""}`}
                onClick={() => setSortOrder("default")}
              >
                {tr("默认排序", "Default")}
              </button>
              <button
                type="button"
                className={`seg-btn ${sortOrder === "latency" ? "active" : ""}`}
                onClick={() => setSortOrder("latency")}
              >
                {tr("按延迟", "Latency")}
              </button>
              <button
                type="button"
                className={`seg-btn ${sortOrder === "name" ? "active" : ""}`}
                onClick={() => setSortOrder("name")}
              >
                {tr("按名称", "Name")}
              </button>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className="btn"
              disabled={probingAll || groups.length === 0}
              onClick={() => void handleTestAll()}
            >
              <BoltIcon size={14} />
              <span>
                {probingAll
                  ? tr("测速中...", "Testing...")
                  : tr("一键测速", "Test All")}
              </span>
            </button>

            {activeNodes.length > 0 && (
              <button
                type="button"
                className="btn"
                onClick={() => setManagerOpen((v) => !v)}
              >
                <span>
                  {tr("节点管理", "Manage Nodes")} ({activeNodes.length})
                </span>
              </button>
            )}

            <button
              id="open-add-node-modal-btn"
              type="button"
              className="btn btn-primary"
              onClick={() => openCreateModal("paste")}
            >
              <PlusIcon size={14} />
              <span>{tr("手动添加节点", "Add Node")}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Collapsible Node Manager Drawer */}
      {managerOpen && activeNodes.length > 0 && (
        <section className="bento-card">
          <div className="bento-card-head" style={{ marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 14.5, fontWeight: 650 }}>
                {tr("节点管理", "Node Manager")}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {tr(
                  "编辑、删除或清理当前配置中的节点。手动新增的节点在订阅更新时会自动保留。",
                  "Edit, remove, or deduplicate nodes. Manually added nodes are preserved when subscriptions refresh.",
                )}
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm"
                disabled={busyAction === "dedup"}
                onClick={() => void handleDeduplicate()}
              >
                {busyAction === "dedup"
                  ? tr("去重中...", "Deduplicating...")
                  : tr("一键去重", "Deduplicate")}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setManagerOpen(false)}
              >
                {tr("收起", "Hide")}
              </button>
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
              gap: 9,
              maxHeight: 280,
              overflowY: "auto",
            }}
          >
            {activeNodes.map((n) => (
              <div
                key={n.name}
                className="sub-pill-box"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={n.name}
                  >
                    {n.name}
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-muted)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {nodeProtocolBadge(n)} · {n.server}:{n.port}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => openEditModal(n)}
                  >
                    {tr("编辑", "Edit")}
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    disabled={busyAction === `del:${n.name}`}
                    onClick={() => void handleDeleteNode(n.name)}
                  >
                    {tr("删除", "Delete")}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Policy Groups Section */}
      {groups.length === 0 ? (
        <section
          className="bento-card"
          style={{ padding: "36px 24px", textAlign: "center" }}
        >
          <div style={{ fontSize: 16, fontWeight: 650, marginBottom: 6 }}>
            {tr("还没有代理节点", "No Proxy Nodes Yet")}
          </div>
          <div
            style={{
              fontSize: 13,
              color: "var(--text-muted)",
              maxWidth: 460,
              margin: "0 auto 16px",
            }}
          >
            {tr(
              "您可以直接粘贴节点分享链接快速使用，或者前往「订阅配置」导入机场订阅地址。",
              "Paste share links right away or import a subscription URL in Profiles.",
            )}
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              gap: 10,
              flexWrap: "wrap",
            }}
          >
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => openCreateModal("paste")}
            >
              <PlusIcon size={14} />
              <span>{tr("粘贴节点链接", "Paste Node Links")}</span>
            </button>
            {onOpenProfiles && (
              <button type="button" className="btn" onClick={onOpenProfiles}>
                {tr("导入订阅配置", "Import Subscription")}
              </button>
            )}
          </div>
        </section>
      ) : (
        groups.map((group) => {
          const isExpanded = Boolean(expandedGroups[group.name]);
          const members = filterAndSortMembers(group.all ?? []);
          const currentSelected = group.now ?? group.effective_outbound ?? "";
          const canSelect = group.type === "Selector";

          return (
            <section
              key={group.name}
              ref={(el) => {
                groupRefs.current[group.name] = el;
              }}
              className="bento-card"
              style={{ padding: "14px 18px" }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 10,
                  cursor: "pointer",
                  userSelect: "none",
                }}
                onClick={() =>
                  setExpandedGroups((prev) => ({
                    ...prev,
                    [group.name]: !prev[group.name],
                  }))
                }
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    minWidth: 0,
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: "var(--text-muted)", display: "inline-flex" }}>
                    {isExpanded ? (
                      <ChevronDownIcon size={16} />
                    ) : (
                      <ChevronRightIcon size={16} />
                    )}
                  </span>
                  <span style={{ fontSize: 15, fontWeight: 650 }}>
                    {group.name}
                  </span>
                  <span className="badge badge-neutral">
                    {prettyProtocolLabel(group.type)}
                  </span>
                  <span className="badge badge-sky">
                    {currentSelected || "DIRECT"}
                  </span>
                  <span
                    className="tabular"
                    style={{ fontSize: 12, color: "var(--text-muted)" }}
                  >
                    {members.length} {tr("个节点", "nodes")}
                  </span>
                </div>

                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={Boolean(testingMap[group.name])}
                  onClick={(e) => {
                    e.stopPropagation();
                    void handleProbeGroup(group);
                  }}
                  title={tr("测试本组延迟", "Test group latency")}
                >
                  <BoltIcon size={13} />
                  <span>
                    {testingMap[group.name]
                      ? tr("测速中", "Testing")
                      : tr("测速", "Test")}
                  </span>
                </button>
              </div>

              {isExpanded && (
                <div className="node-grid" style={{ marginTop: 13 }}>
                  {members.length === 0 ? (
                    <div
                      style={{
                        gridColumn: "1 / -1",
                        padding: "16px 8px",
                        textAlign: "center",
                        color: "var(--text-muted)",
                      }}
                    >
                      {tr("没有匹配的节点", "No matching nodes")}
                    </div>
                  ) : (
                    members.map((memberName) => {
                      const isSelected = group.now === memberName;
                      const info = proxies[memberName];
                      const cfgNode = nodeByName[memberName];
                      const protoText = cfgNode
                        ? nodeProtocolBadge(cfgNode, info?.type)
                        : prettyProtocolLabel(info?.type ?? "Node");
                      const delay = latestDelay(memberName);
                      const isTesting = Boolean(testingMap[memberName]);

                      const latencyClass =
                        delay && delay > 0
                          ? delay < 150
                            ? "fast"
                            : delay < 400
                              ? "mid"
                              : "slow"
                          : "";

                      return (
                        <div
                          key={memberName}
                          role={canSelect ? "button" : undefined}
                          tabIndex={canSelect ? 0 : undefined}
                          className={`node-tile ${isSelected ? "selected" : ""}`}
                          style={{ cursor: canSelect ? "pointer" : "default" }}
                          onClick={() => {
                            if (canSelect) {
                              void handleSelectMember(group, memberName);
                            }
                          }}
                          onKeyDown={(ev) => {
                            if (
                              canSelect &&
                              (ev.key === "Enter" || ev.key === " ")
                            ) {
                              ev.preventDefault();
                              void handleSelectMember(group, memberName);
                            }
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "space-between",
                              gap: 6,
                              minWidth: 0,
                            }}
                          >
                            <span className="node-name" title={memberName}>
                              {memberName}
                            </span>
                            {isSelected && (
                              <span
                                style={{
                                  width: 8,
                                  height: 8,
                                  borderRadius: "50%",
                                  background: "var(--accent-blue)",
                                  flexShrink: 0,
                                }}
                              />
                            )}
                          </div>

                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "space-between",
                              gap: 6,
                            }}
                          >
                            <span
                              className={`badge ${protocolBadgeVariant(protoText)}`}
                            >
                              {protoText}
                            </span>

                            <button
                              type="button"
                              className={`latency-pill tabular ${latencyClass}`}
                              onClick={(e) => void handleProbeSingle(e, memberName)}
                              title={tr("点击单点测速", "Click to re-test latency")}
                            >
                              {isTesting
                                ? "..."
                                : delay && delay > 0
                                  ? `${delay} ms`
                                  : tr("测速", "Test")}
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </section>
          );
        })
      )}

      {/* Add / Edit Manual Node Modal */}
      {modalOpen && (
        <div
          className="modal-backdrop"
          onClick={() => {
            if (!busyAction) setModalOpen(false);
          }}
        >
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
              }}
            >
              <div style={{ fontSize: 16.5, fontWeight: 650 }}>
                {editingOriginalName
                  ? tr(`编辑节点：${editingOriginalName}`, `Edit Node: ${editingOriginalName}`)
                  : tr("手动添加节点", "Add Manual Node")}
              </div>
              <button
                type="button"
                className="bento-icon-action"
                onClick={() => {
                  if (!busyAction) setModalOpen(false);
                }}
              >
                <CloseIcon size={15} />
              </button>
            </div>

            {!editingOriginalName && (
              <div className="segmented" style={{ alignSelf: "flex-start" }}>
                <button
                  type="button"
                  className={`seg-btn ${modalMode === "paste" ? "active" : ""}`}
                  onClick={() => {
                    setModalMode("paste");
                    setModalError(null);
                  }}
                >
                  {tr("快速粘贴链接 / 二维码文本", "Paste Share Links")}
                </button>
                <button
                  type="button"
                  className={`seg-btn ${modalMode === "manual" ? "active" : ""}`}
                  onClick={() => {
                    setModalMode("manual");
                    setModalError(null);
                  }}
                >
                  {tr("表单新建 / 编辑节点", "Form Builder")}
                </button>
              </div>
            )}

            <div className="banner banner-ok" style={{ fontSize: 12 }}>
              <span>
                🛡{" "}
                {tr(
                  "手动添加的节点会自动独立保存，订阅自动更新时绝不会被覆盖或删除。",
                  "Manually added nodes are saved independently and will never be overwritten or deleted when subscriptions auto-update.",
                )}
              </span>
            </div>

            {modalError && (
              <div className="banner banner-err">
                <span>{modalError}</span>
              </div>
            )}

            {modalMode === "paste" ? (
              <form
                onSubmit={handleImportPaste}
                style={{ display: "flex", flexDirection: "column", gap: 12 }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                    {tr(
                      "支持 vless://、vmess://、ss://、trojan://、hy2://、tuic://、anytls://、Base64 列表与 Clash YAML",
                      "Supports vless://, vmess://, ss://, trojan://, hy2://, tuic://, anytls://, Base64 lists & Clash YAML",
                    )}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => void handleReadClipboardToPaste()}
                    >
                      {tr("从剪贴板粘贴", "Paste Clipboard")}
                    </button>
                    {androidBridge.canScanQr() && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => androidBridge.requestQrScan()}
                      >
                        {tr("扫码导入", "Scan QR")}
                      </button>
                    )}
                  </div>
                </div>

                <textarea
                  className="code-editor"
                  rows={6}
                  placeholder="vless://...&#10;trojan://...&#10;ss://..."
                  value={pasteInput}
                  onChange={(e) => setPasteInput(e.target.value)}
                />

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                    <label
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12.5,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={dedupOnImport}
                        onChange={(e) => setDedupOnImport(e.target.checked)}
                      />
                      {tr("自动跳过重复节点", "Skip duplicates")}
                    </label>
                    <label
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12.5,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={autoSelectOnImport}
                        onChange={(e) =>
                          setAutoSelectOnImport(e.target.checked)
                        }
                      />
                      {tr("导入后自动选中", "Select after import")}
                    </label>
                  </div>

                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      type="button"
                      className="btn"
                      disabled={busyAction === "import"}
                      onClick={() => setModalOpen(false)}
                    >
                      {tr("取消", "Cancel")}
                    </button>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={busyAction === "import"}
                    >
                      {busyAction === "import"
                        ? tr("导入中...", "Importing...")
                        : tr("立即导入", "Import Nodes")}
                    </button>
                  </div>
                </div>
              </form>
            ) : (
              <form
                onSubmit={handleSaveManualNode}
                style={{ display: "flex", flexDirection: "column", gap: 12 }}
              >
                <div className="form-grid">
                  <div className="form-field">
                    <label className="form-label">
                      {tr("协议类型", "Protocol")}
                    </label>
                    <select
                      className="select"
                      value={proto}
                      onChange={(e) => setProto(e.target.value as NodeProto)}
                    >
                      <option value="vless">VLESS</option>
                      <option value="trojan">Trojan</option>
                      <option value="ss">Shadowsocks (SS / SS-2022)</option>
                      <option value="anytls">AnyTLS v2</option>
                      <option value="socks5">SOCKS5</option>
                      <option value="http">HTTP / HTTPS</option>
                    </select>
                  </div>

                  <div className="form-field">
                    <label className="form-label">
                      {tr("节点名称", "Node Name")}
                    </label>
                    <input
                      className="input"
                      placeholder={tr("例如：香港高速 01", "e.g. HK Edge 01")}
                      value={nodeName}
                      onChange={(e) => setNodeName(e.target.value)}
                    />
                  </div>

                  <div className="form-field">
                    <label className="form-label">
                      {tr("服务器地址", "Server Host / IP")}
                    </label>
                    <input
                      className="input mono"
                      placeholder="edge.example.com"
                      value={serverHost}
                      onChange={(e) => setServerHost(e.target.value)}
                    />
                  </div>

                  <div className="form-field">
                    <label className="form-label">{tr("端口", "Port")}</label>
                    <input
                      className="input tabular"
                      placeholder="443"
                      value={serverPort}
                      onChange={(e) => setServerPort(e.target.value)}
                    />
                  </div>

                  {proto === "ss" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("加密方式", "Cipher")}
                        </label>
                        <select
                          className="select"
                          value={ssCipher}
                          onChange={(e) => setSsCipher(e.target.value)}
                        >
                          {SS_CIPHERS.map((c) => (
                            <option key={c} value={c}>
                              {c}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("密码 / PSK", "Password / PSK")}
                        </label>
                        <input
                          type="password"
                          className="input mono"
                          placeholder={
                            editingOriginalName
                              ? tr("留空保持原密码不变", "Leave blank to keep saved")
                              : tr("输入连接密码", "Enter password")
                          }
                          value={ssPassword}
                          onChange={(e) => setSsPassword(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {proto === "vless" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">UUID</label>
                        <input
                          className="input mono"
                          placeholder={
                            editingOriginalName
                              ? tr("留空保持原 UUID", "Leave blank to keep saved")
                              : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          }
                          value={vlessUuid}
                          onChange={(e) => setVlessUuid(e.target.value)}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("SNI / 域名", "Server Name (SNI)")}
                        </label>
                        <input
                          className="input mono"
                          placeholder="edge.example.com"
                          value={vlessServername}
                          onChange={(e) => setVlessServername(e.target.value)}
                        />
                      </div>
                      <div className="form-field full">
                        <label className="form-label">
                          {tr("VLESS 加密参数 (可选 PQ)", "Encryption (none or mlkem768x25519plus...)")}
                        </label>
                        <input
                          className="input mono"
                          placeholder="none"
                          value={vlessEncryption}
                          onChange={(e) => setVlessEncryption(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {proto === "trojan" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("密码", "Password")}
                        </label>
                        <input
                          type="password"
                          className="input mono"
                          placeholder={
                            editingOriginalName
                              ? tr("留空保持原密码", "Leave blank to keep saved")
                              : tr("输入 Trojan 密码", "Enter Trojan password")
                          }
                          value={trojanPassword}
                          onChange={(e) => setTrojanPassword(e.target.value)}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label">SNI</label>
                        <input
                          className="input mono"
                          placeholder="edge.example.com"
                          value={trojanSni}
                          onChange={(e) => setTrojanSni(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {proto === "anytls" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("密码", "Password")}
                        </label>
                        <input
                          type="password"
                          className="input mono"
                          placeholder={
                            editingOriginalName
                              ? tr("留空保持原密码", "Leave blank to keep saved")
                              : tr("输入 AnyTLS 密码", "Enter AnyTLS password")
                          }
                          value={anytlsPassword}
                          onChange={(e) => setAnytlsPassword(e.target.value)}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label">SNI</label>
                        <input
                          className="input mono"
                          placeholder="edge.example.com"
                          value={anytlsSni}
                          onChange={(e) => setAnytlsSni(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {(proto === "socks5" || proto === "http") && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("用户名 (可选)", "Username (optional)")}
                        </label>
                        <input
                          className="input"
                          value={authUsername}
                          onChange={(e) => setAuthUsername(e.target.value)}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("密码 (可选)", "Password (optional)")}
                        </label>
                        <input
                          type="password"
                          className="input"
                          value={authPassword}
                          onChange={(e) => setAuthPassword(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {(proto === "vless" || proto === "trojan") && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          {tr("传输层协议", "Transport")}
                        </label>
                        <select
                          className="select"
                          value={transportNet}
                          onChange={(e) =>
                            setTransportNet(e.target.value as "tcp" | "ws")
                          }
                        >
                          <option value="tcp">TCP</option>
                          <option value="ws">WebSocket (WS)</option>
                        </select>
                      </div>
                      {transportNet === "ws" && (
                        <>
                          <div className="form-field">
                            <label className="form-label">WS Path</label>
                            <input
                              className="input mono"
                              placeholder="/ws"
                              value={wsPath}
                              onChange={(e) => setWsPath(e.target.value)}
                            />
                          </div>
                          <div className="form-field full">
                            <label className="form-label">
                              WS Host Header ({tr("可选", "optional")})
                            </label>
                            <input
                              className="input mono"
                              placeholder="cdn.example.com"
                              value={wsHost}
                              onChange={(e) => setWsHost(e.target.value)}
                            />
                          </div>
                        </>
                      )}
                    </>
                  )}
                </div>

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                    {proto !== "http" && (
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={udpEnabled}
                          onChange={(e) => setUdpEnabled(e.target.checked)}
                        />
                        {tr("启用 UDP 转发", "Enable UDP")}
                      </label>
                    )}
                    <label
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12.5,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={autoSelectManual}
                        onChange={(e) => setAutoSelectManual(e.target.checked)}
                      />
                      {tr("保存后立即选中", "Select after save")}
                    </label>
                  </div>

                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      type="button"
                      className="btn"
                      disabled={busyAction === "save-node"}
                      onClick={() => setModalOpen(false)}
                    >
                      {tr("取消", "Cancel")}
                    </button>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={busyAction === "save-node"}
                    >
                      {busyAction === "save-node"
                        ? tr("保存中...", "Saving...")
                        : tr("保存节点", "Save Node")}
                    </button>
                  </div>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
