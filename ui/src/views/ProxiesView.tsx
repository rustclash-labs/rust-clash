import React, { useCallback, useEffect, useRef, useState } from "react";
import { androidBridge, clashApi, readClipboardText } from "../api";
import type {
  ConfigSnapshot,
  EndpointMatrixReport,
  ProxyInfo,
  ProxyNodeConfigPayload,
  WaterfallProbeReport,
} from "../types";
import {
  delayBadgeVariant,
  nodeProtocolBadge,
  protocolBadgeVariant,
} from "../utils/format";
import { renderInlineCode } from "../utils/inlineCode";

interface ProxiesViewProps {
  config: ConfigSnapshot | null;
  proxies: Record<string, ProxyInfo>;
  onRefreshProxies: () => Promise<void>;
  openAddModalSignal?: number;
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

type ModalMode = "paste" | "manual";
type NodeProto = "ss" | "vless" | "trojan" | "anytls" | "socks5" | "http";

export const ProxiesView: React.FC<ProxiesViewProps> = ({
  config,
  proxies,
  onRefreshProxies,
  openAddModalSignal = 0,
}) => {
  const [testingMap, setTestingMap] = useState<Record<string, boolean>>({});
  const [probingAll, setProbingAll] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [okBanner, setOkBanner] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const [activeNodes, setActiveNodes] = useState<ProxyNodeConfigPayload[]>([]);
  const [quickPasteText, setQuickPasteText] = useState("");

  // Add / Edit Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<ModalMode>("paste");
  const [editingOriginalName, setEditingOriginalName] = useState<string | null>(
    null,
  );
  const [editingOriginalProto, setEditingOriginalProto] =
    useState<NodeProto | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);
  const modalErrorRef = useRef<HTMLDivElement | null>(null);

  // Paste tab state
  const [pasteInput, setPasteInput] = useState("");
  const [dedupOnImport, setDedupOnImport] = useState(true);
  const [autoSelectOnImport, setAutoSelectOnImport] = useState(true);

  // Manual / Edit node form state
  const [proto, setProto] = useState<NodeProto>("ss");
  const [nodeName, setNodeName] = useState("");
  const [serverHost, setServerHost] = useState("");
  const [serverPort, setServerPort] = useState("443");
  const [udpEnabled, setUdpEnabled] = useState(true);
  const [autoSelectManual, setAutoSelectManual] = useState(true);

  // SS fields
  const [ssCipher, setSsCipher] = useState("aes-256-gcm");
  const [ssPassword, setSsPassword] = useState("");

  // VLESS fields
  const [vlessUuid, setVlessUuid] = useState("");
  const [vlessEncryption, setVlessEncryption] = useState("none");
  const [vlessHadRedactedEnc, setVlessHadRedactedEnc] = useState(false);
  const [vlessTls, setVlessTls] = useState(true);
  const [vlessServername, setVlessServername] = useState("");
  const [vlessSkipVerify, setVlessSkipVerify] = useState(false);
  const [vlessAlpn, setVlessAlpn] = useState("");

  // Trojan fields
  const [trojanPassword, setTrojanPassword] = useState("");
  const [trojanTls, setTrojanTls] = useState(true);
  const [trojanSni, setTrojanSni] = useState("");
  const [trojanSkipVerify, setTrojanSkipVerify] = useState(false);
  const [trojanAlpn, setTrojanAlpn] = useState("h2, http/1.1");

  // WebSocket transport fields (shared by VLESS & Trojan)
  const [transportNet, setTransportNet] = useState<"tcp" | "ws">("tcp");
  const [wsPath, setWsPath] = useState("/");
  const [wsHost, setWsHost] = useState("");
  const [wsMaxEarlyData, setWsMaxEarlyData] = useState("");

  // AnyTLS fields
  const [anytlsPassword, setAnytlsPassword] = useState("");
  const [anytlsSni, setAnytlsSni] = useState("");
  const [anytlsSkipVerify, setAnytlsSkipVerify] = useState(false);
  const [anytlsAlpn, setAnytlsAlpn] = useState("h2, http/1.1");

  // SOCKS5 / HTTP fields
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authHadSavedPassword, setAuthHadSavedPassword] = useState(false);
  const [proxyTls, setProxyTls] = useState(false);
  const [proxySni, setProxySni] = useState("");
  const [proxySkipVerify, setProxySkipVerify] = useState(false);

  const modalInflight =
    busyAction === "import" || busyAction === "save-node";

  const requestCloseModal = useCallback(() => {
    if (busyAction === "import" || busyAction === "save-node") return;
    setModalError(null);
    setModalOpen(false);
  }, [busyAction]);

  useEffect(() => {
    if (!modalOpen || !modalError) return;
    modalErrorRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "nearest",
    });
  }, [modalOpen, modalError]);

  useEffect(() => {
    if (!modalOpen) return;
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        requestCloseModal();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [modalOpen, requestCloseModal]);

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

  useEffect(() => {
    if (openAddModalSignal > 0) {
      openCreateModal("paste");
    }
  }, [openAddModalSignal]);

  const groups = Object.values(proxies).filter(
    (p) => GROUP_TYPES.has(p.type) && p.all && p.all.length > 0,
  );

  groups.sort((a, b) => {
    if (a.name === "GLOBAL") return 1;
    if (b.name === "GLOBAL") return -1;
    return 0;
  });

  const primarySelectorGroup =
    groups.find(
      (g) =>
        g.type === "Selector" &&
        (g.name === "PROXY" || g.name === "🚀 Proxy"),
    ) ?? groups.find((g) => g.type === "Selector" && g.name !== "GLOBAL");

  const effectiveSummary = config?.["effective-outbound"];
  const effectiveName =
    effectiveSummary?.effective_outbound ??
    primarySelectorGroup?.effective_outbound ??
    primarySelectorGroup?.now ??
    "DIRECT";
  const effectiveProto =
    effectiveSummary?.effective_protocol ??
    primarySelectorGroup?.effective_protocol ??
    "DIRECT";
  const effectiveChains =
    effectiveSummary?.chains ?? primarySelectorGroup?.chains ?? [];

  const resetManualForm = () => {
    setEditingOriginalName(null);
    setEditingOriginalProto(null);
    setProto("ss");
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
  };

  const openCreateModal = (initialTab: ModalMode = "paste") => {
    resetManualForm();
    setModalError(null);
    setModalMode(initialTab);
    setModalOpen(true);
  };

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
        node["ws-opts"]?.headers?.Host ??
          node["ws-opts"]?.headers?.host ??
          "",
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
        node["ws-opts"]?.headers?.Host ??
          node["ws-opts"]?.headers?.host ??
          "",
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

  const latestDelay = (info: ProxyInfo | undefined): number | undefined => {
    if (!info || info.history.length === 0) return undefined;
    return info.history[info.history.length - 1]?.delay;
  };

  const executeImportText = async (
    rawText: string,
    opts?: { deduplicate?: boolean; autoSelect?: boolean; closeModal?: boolean },
  ) => {
    const trimmed = rawText.trim();
    if (!trimmed) {
      const msg =
        "Please paste one or more ss://, vless://, trojan://, anytls://, socks5://, or http-proxy:// links, Base64 subscription, Clash YAML, or HTTPS subscription URL.";
      if (opts?.closeModal) setModalError(msg);
      else setErrorBanner(msg);
      return;
    }

    setBusyAction("import");
    setErrorBanner(null);
    setOkBanner(null);
    setModalError(null);
    try {
      const res = await clashApi.importUris(trimmed, true, {
        deduplicate: opts?.deduplicate ?? true,
        autoSelect: opts?.autoSelect ?? true,
      });
      await onRefreshProxies();
      await loadActiveNodes();
      setPasteInput("");
      setQuickPasteText("");
      if (opts?.closeModal) {
        setModalOpen(false);
      }
      const effAfter =
        res["effective-outbound"]?.effective_outbound ?? "updated";
      const dupNote =
        res["skipped-duplicates"] && res["skipped-duplicates"] > 0
          ? ` (${res["skipped-duplicates"]} duplicate skipped)`
          : "";
      const skippedUnsupported = res["skipped-unsupported"] ?? [];
      const skippedProtos = Array.from(
        new Set(skippedUnsupported.map((s) => s.protocol)),
      ).join(", ");
      const unsupportedNote =
        skippedUnsupported.length > 0
          ? ` [${skippedUnsupported.length} unsupported skipped: ${skippedProtos}]`
          : "";
      setOkBanner(
        `Saved ${res.count} node(s) to active profile${dupNote}${unsupportedNote}. Effective outbound: ${effAfter}.`,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (opts?.closeModal) {
        setModalError(msg);
      } else {
        setErrorBanner(msg);
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handlePasteFromClipboardAndImport = async () => {
    setErrorBanner(null);
    setOkBanner(null);
    const clip = await readClipboardText();
    if (clip && clip.trim().length > 0) {
      await executeImportText(clip, {
        deduplicate: true,
        autoSelect: true,
        closeModal: false,
      });
    } else {
      openCreateModal("paste");
      setModalError(
        "Clipboard is empty or requires browser permission — press Ctrl+V / Cmd+V (or long-press Paste) below to import immediately.",
      );
    }
  };

  const handleFillModalFromClipboard = async () => {
    setModalError(null);
    const clip = await readClipboardText();
    if (clip && clip.trim().length > 0) {
      setPasteInput((prev) =>
        prev.trim() ? `${prev.trim()}\n${clip.trim()}` : clip.trim(),
      );
    } else {
      setModalError(
        "Clipboard is empty or blocked by browser permissions — please paste directly into the text box.",
      );
    }
  };

  const buildWsTransportPayload = () => {
    if (transportNet !== "ws") {
      return { network: "tcp", wsOpts: undefined };
    }
    const headers: Record<string, string> = {};
    if (wsHost.trim()) {
      headers.Host = wsHost.trim();
    }
    const trimmedEarly = wsMaxEarlyData.trim();
    let earlyNum = 0;
    if (trimmedEarly.length > 0) {
      if (!/^\d+$/.test(trimmedEarly)) {
        throw new Error(
          "WebSocket 0-RTT max-early-data must be an integer between 0 and 65535.",
        );
      }
      earlyNum = Number.parseInt(trimmedEarly, 10);
      if (!Number.isFinite(earlyNum) || earlyNum < 0 || earlyNum > 65535) {
        throw new Error(
          "WebSocket 0-RTT max-early-data must be between 0 and 65535.",
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
      throw new Error("Node name is required.");
    }
    if (!cleanHost) {
      throw new Error("Server hostname or IP is required.");
    }
    if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error("Port must be between 1 and 65535.");
    }
    const isEditing = Boolean(editingOriginalName);
    const sameProtoAsExisting =
      isEditing && editingOriginalProto === proto;

    if (proto === "ss") {
      const pass = ssPassword.trim();
      if (!sameProtoAsExisting && !pass) {
        throw new Error(
          isEditing
            ? "Switching node protocol to Shadowsocks requires entering a new password / PSK."
            : "Shadowsocks password / PSK is required.",
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
      if (!sameProtoAsExisting && !rawUuid) {
        throw new Error(
          isEditing
            ? "Switching node protocol to VLESS requires entering a valid UUID."
            : "VLESS UUID is required.",
        );
      }
      const encTrimmed = vlessEncryption.trim();
      const effectiveEnc =
        sameProtoAsExisting && !encTrimmed && vlessHadRedactedEnc
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
      if (!sameProtoAsExisting && !pass) {
        throw new Error(
          isEditing
            ? "Switching node protocol to Trojan requires entering a Trojan password."
            : "Trojan password is required.",
        );
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
        : sameProtoAsExisting && authHadSavedPassword
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
        : sameProtoAsExisting && authHadSavedPassword
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
    if (!sameProtoAsExisting && !pass) {
      throw new Error(
        isEditing
          ? "Switching node protocol to AnyTLS requires entering an AnyTLS password."
          : "AnyTLS password is required.",
      );
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
    } catch (validationErr) {
      setModalError(
        validationErr instanceof Error
          ? validationErr.message
          : String(validationErr),
      );
      return;
    }

    setBusyAction("save-node");
    try {
      const res = editingOriginalName
        ? await clashApi.updateActiveNode(
            editingOriginalName,
            payload,
            autoSelectManual,
          )
        : await clashApi.createActiveNode(payload, autoSelectManual);
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      setModalOpen(false);
      setOkBanner(
        editingOriginalName
          ? `Updated node '${payload.name}'. Effective outbound: ${res["effective-outbound"].effective_outbound}.`
          : `Added node '${payload.name}'. Effective outbound: ${res["effective-outbound"].effective_outbound}.`,
      );
    } catch (err) {
      setModalError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeleteNode = async (e: React.MouseEvent, targetName: string) => {
    e.stopPropagation();
    setBusyAction(`del:${targetName}`);
    setErrorBanner(null);
    setOkBanner(null);
    try {
      const res = await clashApi.deleteActiveNode(targetName);
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      setOkBanner(
        `Deleted node '${targetName}'. Effective outbound: ${res["effective-outbound"].effective_outbound}.`,
      );
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeduplicateNodes = async () => {
    setBusyAction("dedup");
    setErrorBanner(null);
    setOkBanner(null);
    try {
      const res = await clashApi.deduplicateActiveNodes();
      await onRefreshProxies();
      setActiveNodes(res.nodes);
      const removedCount = res["removed-nodes"]?.length ?? 0;
      setOkBanner(
        removedCount > 0
          ? `Removed ${removedCount} duplicate node(s). ${res.nodes.length} unique node(s) remain.`
          : "No duplicate proxy nodes found.",
      );
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  };

  const handleSelectConcreteNodeQuick = async (targetNodeName: string) => {
    if (!primarySelectorGroup) return;
    setErrorBanner(null);
    setOkBanner(null);
    try {
      await clashApi.selectProxy(primarySelectorGroup.name, targetNodeName);
      if (config?.mode === "direct") {
        await clashApi.patchConfigs({ mode: "rule" });
      }
      await onRefreshProxies();
      setOkBanner(
        `Selected '${targetNodeName}' in ${primarySelectorGroup.name}.`,
      );
    } catch (e) {
      setErrorBanner(e instanceof Error ? e.message : String(e));
    }
  };

  const handleSelectMember = async (group: ProxyInfo, memberName: string) => {
    if (group.type !== "Selector") return;
    setErrorBanner(null);
    try {
      await clashApi.selectProxy(group.name, memberName);
      await onRefreshProxies();
    } catch (e) {
      setErrorBanner(e instanceof Error ? e.message : String(e));
    }
  };

  const handleProbeSingle = async (
    e: React.MouseEvent,
    targetName: string,
  ) => {
    e.stopPropagation();
    setTestingMap((prev) => ({ ...prev, [targetName]: true }));
    try {
      await clashApi.testDelay(targetName, 4000);
      await onRefreshProxies();
    } catch {
      await onRefreshProxies();
    } finally {
      setTestingMap((prev) => ({ ...prev, [targetName]: false }));
    }
  };

  const handleProbeGroup = async (group: ProxyInfo) => {
    const members = group.all ?? [];
    const nextFlags: Record<string, boolean> = { [group.name]: true };
    for (const m of members) nextFlags[m] = true;
    setTestingMap((prev) => ({ ...prev, ...nextFlags }));

    try {
      await Promise.allSettled(
        members.map((m) => clashApi.testDelay(m, 4000)),
      );
      await clashApi.testDelay(group.name, 4000).catch(() => undefined);
      await onRefreshProxies();
    } finally {
      const clearFlags: Record<string, boolean> = { [group.name]: false };
      for (const m of members) clearFlags[m] = false;
      setTestingMap((prev) => ({ ...prev, ...clearFlags }));
    }
  };

  const handleProbeAllGroups = async () => {
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

  // Deep Waterfall Probe & AI Endpoint Matrix state
  const defaultProbeProxy =
    primarySelectorGroup?.name ??
    (effectiveName && effectiveName !== "DIRECT" ? effectiveName : "DIRECT");
  const [selectedProbeTarget, setSelectedProbeTarget] = useState<string>("");
  const [probeUrl, setProbeUrl] = useState<string>("https://api.github.com/");
  const [waterfallRes, setWaterfallRes] = useState<WaterfallProbeReport | null>(
    null,
  );
  const [matrixRes, setMatrixRes] = useState<EndpointMatrixReport | null>(null);
  const [deepProbeBusy, setDeepProbeBusy] = useState<
    "waterfall" | "matrix" | null
  >(null);
  const [deepProbeErr, setDeepProbeErr] = useState<string | null>(null);

  const effectiveProbeProxy =
    selectedProbeTarget && proxies[selectedProbeTarget]
      ? selectedProbeTarget
      : defaultProbeProxy;

  const concreteProxyNames = Object.values(proxies)
    .filter(
      (p) =>
        !GROUP_TYPES.has(p.type) &&
        p.name !== "DIRECT" &&
        p.name !== "REJECT",
    )
    .map((p) => p.name);

  const handleRunWaterfallProbe = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setDeepProbeBusy("waterfall");
    setDeepProbeErr(null);
    try {
      const targetUrl =
        probeUrl.trim() ||
        (config?.demo.enabled && config.demo.http_benchmark_origin
          ? `${config.demo.http_benchmark_origin}/generate_204`
          : "https://api.github.com/");
      const rep = await clashApi.probeWaterfall(effectiveProbeProxy, {
        url: targetUrl,
        checkUdp: true,
        timeoutMs: 5000,
      });
      setWaterfallRes(rep);
    } catch (err) {
      setDeepProbeErr(err instanceof Error ? err.message : String(err));
    } finally {
      setDeepProbeBusy(null);
    }
  };

  const handleRunEndpointMatrix = async () => {
    setDeepProbeBusy("matrix");
    setDeepProbeErr(null);
    try {
      const rep = await clashApi.probeEndpointMatrix(effectiveProbeProxy, 4500);
      setMatrixRes(rep);
      if (rep.items.length > 0 && !waterfallRes) {
        setWaterfallRes(rep.items[0].report);
      }
    } catch (err) {
      setDeepProbeErr(err instanceof Error ? err.message : String(err));
    } finally {
      setDeepProbeBusy(null);
    }
  };

  const verdictBadgeClass = (verdict: WaterfallProbeReport["verdict"]) => {
    if (verdict === "reachable") return "badge-emerald";
    if (verdict === "auth_required") return "badge-sky";
    if (
      verdict === "rate_limited" ||
      verdict === "blocked_or_challenged" ||
      verdict === "server_error"
    ) {
      return "badge-amber";
    }
    return "badge-rose";
  };

  const verdictLabel = (r: WaterfallProbeReport) => {
    if (r.verdict === "reachable") {
      return r.http_status ? `REACHABLE (HTTP ${r.http_status})` : "REACHABLE";
    }
    if (r.verdict === "auth_required") {
      return `AUTH REQ / UNBLOCKED (HTTP ${r.http_status ?? 401})`;
    }
    if (r.verdict === "rate_limited") {
      return `RATE LIMITED (HTTP ${r.http_status ?? 429})`;
    }
    if (r.verdict === "blocked_or_challenged") {
      return r.cf_mitigated
        ? `WAF CHALLENGE (HTTP ${r.http_status ?? 403})`
        : `GEO / WAF BLOCKED (HTTP ${r.http_status ?? 403})`;
    }
    if (r.verdict === "server_error") {
      return `ORIGIN 5XX (HTTP ${r.http_status ?? 500})`;
    }
    return r.failed_stage
      ? `FAILED @ ${r.failed_stage.toUpperCase()}`
      : "UNREACHABLE";
  };

  const activeNodeMap = new Map(activeNodes.map((n) => [n.name, n]));
  const isDirectWarning =
    effectiveName === "DIRECT" &&
    activeNodes.length > 0 &&
    config?.mode !== "direct";

  return (
    <div className="group-stack">
      {/* Top Action Bar & Effective Outbound Status */}
      <section className="card">
        <div
          className="toolbar"
          style={{ alignItems: "flex-start", gap: 14 }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: "var(--text-secondary)",
                }}
              >
                Effective Outbound:
              </span>
              <span
                id="effective-outbound-badge"
                className={`badge ${
                  effectiveName === "DIRECT"
                    ? "badge-amber"
                    : effectiveName === "REJECT"
                      ? "badge-rose"
                      : "badge-emerald"
                }`}
                style={{ fontSize: 12, padding: "3px 9px" }}
              >
                {effectiveName} ({effectiveProto})
              </span>
              <span className="badge badge-neutral">
                Mode: {(config?.mode ?? "rule").toUpperCase()}
              </span>
              <span className="badge badge-sky">
                Saved Nodes: {activeNodes.length}
              </span>
            </div>

            {effectiveChains.length > 1 && (
              <div
                className="mono"
                style={{
                  fontSize: 11.5,
                  color: "var(--text-muted)",
                  overflowWrap: "anywhere",
                }}
              >
                Chain: {[...effectiveChains].reverse().join(" → ")}
              </div>
            )}
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              id="proxies-add-node-btn"
              type="button"
              className="btn btn-primary"
              onClick={() => openCreateModal("paste")}
            >
              + Add Node / 添加节点
            </button>
            <button
              id="proxies-paste-clipboard-btn"
              type="button"
              className="btn"
              disabled={busyAction === "import"}
              onClick={() => void handlePasteFromClipboardAndImport()}
            >
              {busyAction === "import" ? "Importing..." : "Paste Clipboard"}
            </button>
            {androidBridge.canScanQr() && (
              <button
                id="proxies-scan-qr-btn"
                type="button"
                className="btn"
                onClick={() => androidBridge.requestQrScan()}
              >
                Scan QR
              </button>
            )}
            <button
              id="proxies-dedup-btn"
              type="button"
              className="btn"
              disabled={activeNodes.length < 2 || busyAction === "dedup"}
              onClick={() => void handleDeduplicateNodes()}
            >
              {busyAction === "dedup" ? "Deduplicating..." : "Deduplicate"}
            </button>
            <button
              id="proxies-probe-all-btn"
              type="button"
              className="btn"
              disabled={concreteProxyNames.length === 0 || probingAll}
              onClick={() => void handleProbeAllGroups()}
            >
              {probingAll ? "Probing..." : "Probe All"}
            </button>
          </div>
        </div>
      </section>

      {errorBanner && (
        <div id="proxies-error-banner" className="banner banner-err">
          <span>{renderInlineCode(errorBanner)}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setErrorBanner(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {okBanner && (
        <div id="proxies-ok-banner" className="banner banner-ok">
          <span>{renderInlineCode(okBanner)}</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setOkBanner(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {isDirectWarning && activeNodes[0] && (
        <div className="banner banner-warn">
          <span>
            <strong>Notice:</strong> Current effective outbound is{" "}
            <strong>DIRECT</strong> while {activeNodes.length} proxy node(s) are
            available. Select a node below to route traffic through your proxy.
          </span>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() =>
              void handleSelectConcreteNodeQuick(activeNodes[0].name)
            }
          >
            Use {activeNodes[0].name}
          </button>
        </div>
      )}

      {/* Inline Quick Import Card when Blank / Zero Saved Nodes */}
      {activeNodes.length === 0 && !config?.demo.enabled && (
        <section className="onboarding-card" style={{ alignItems: "stretch" }}>
          <div style={{ width: "100%", minWidth: 0 }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 10,
                flexWrap: "wrap",
                marginBottom: 8,
              }}
            >
              <div>
                <div style={{ fontSize: 14.5, fontWeight: 700 }}>
                  Quick Node Import — Paste &amp; Connect Immediately
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  Paste single or multiple{" "}
                  <code className="mono">ss://</code>,{" "}
                  <code className="mono">vless://</code>,{" "}
                  <code className="mono">trojan://</code>,{" "}
                  <code className="mono">anytls://</code>,{" "}
                  <code className="mono">socks5://</code>, or{" "}
                  <code className="mono">http-proxy://</code> links, a Base64
                  subscription, Clash YAML, or an{" "}
                  <code className="mono">https://</code> subscription URL.
                  Saved automatically across restarts.
                </div>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => openCreateModal("manual")}
              >
                Manual Node Form
              </button>
            </div>

            <textarea
              id="quick-paste-uris-input"
              className="code-editor"
              rows={3}
              placeholder={"ss://2022-blake3-aes-256-gcm:...@example.com:8388#HK-Node\nvless://uuid@example.com:443?type=ws&path=%2Fws&security=tls&sni=example.com#JP-WS\ntrojan://password@example.com:443?sni=example.com#SG-Trojan"}
              value={quickPasteText}
              onChange={(ev) => {
                if (errorBanner) setErrorBanner(null);
                setQuickPasteText(ev.target.value);
              }}
            />

            <div
              style={{
                marginTop: 10,
                display: "flex",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <button
                id="quick-import-submit-btn"
                type="button"
                className="btn btn-primary"
                disabled={busyAction === "import"}
                onClick={() =>
                  void executeImportText(quickPasteText, {
                    deduplicate: true,
                    autoSelect: true,
                  })
                }
              >
                {busyAction === "import"
                  ? "Importing..."
                  : "Save & Select Node"}
              </button>
              <button
                type="button"
                className="btn"
                disabled={busyAction === "import"}
                onClick={() => void handlePasteFromClipboardAndImport()}
              >
                Paste from Clipboard
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Deep Per-Stage Timing Waterfall & AI / Dev Endpoint Readiness Matrix */}
      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">
              Deep Timing Waterfall &amp; AI / Dev Endpoint Readiness Matrix
            </h2>
            <div className="card-subtitle">
              Decompose TCP latency into{" "}
              <code className="mono">DNS → Tunnel → TLS → HTTP TTFB</code>{" "}
              (isolated from parallel UDP checks), and distinguish HTTP{" "}
              <code className="mono">401</code> auth-required,{" "}
              <code className="mono">429</code> rate-limits, and{" "}
              <code className="mono">403</code> Geo/WAF blocks
            </div>
          </div>
          {waterfallRes?.udp_probe && (
            <span
              className={`badge ${
                waterfallRes.udp_probe.status === "verified"
                  ? "badge-emerald"
                  : waterfallRes.udp_probe.status === "blackholed"
                    ? "badge-rose"
                    : "badge-neutral"
              }`}
              title={waterfallRes.udp_probe.detail}
            >
              UDP: {waterfallRes.udp_probe.status.toUpperCase()}
              {waterfallRes.udp_probe.rtt_ms != null
                ? ` (${waterfallRes.udp_probe.rtt_ms.toFixed(0)} ms)`
                : ""}
            </span>
          )}
        </div>

        <form
          onSubmit={(e) => void handleRunWaterfallProbe(e)}
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            minWidth: 0,
            marginBottom: deepProbeErr || waterfallRes || matrixRes ? 12 : 0,
          }}
        >
          <select
            id="waterfall-proxy-select"
            className="select"
            style={{
              flex: "1 1 180px",
              width: 0,
              minWidth: 150,
              maxWidth: "100%",
            }}
            value={effectiveProbeProxy}
            onChange={(ev) => setSelectedProbeTarget(ev.target.value)}
          >
            {groups.length > 0 && (
              <optgroup label="Policy Groups">
                {groups.map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.name} ({g.now ?? g.type})
                  </option>
                ))}
              </optgroup>
            )}
            {concreteProxyNames.length > 0 && (
              <optgroup label="Concrete Nodes">
                {concreteProxyNames.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </optgroup>
            )}
            <optgroup label="Built-in">
              <option value="DIRECT">DIRECT</option>
            </optgroup>
          </select>

          <input
            id="waterfall-url-input"
            className="input mono"
            style={{ flex: "1 1 240px" }}
            value={probeUrl}
            onChange={(ev) => setProbeUrl(ev.target.value)}
            placeholder="https://api.openai.com/v1/models (public URL)"
          />

          <button
            id="run-waterfall-probe-btn"
            type="submit"
            className="btn btn-primary"
            disabled={deepProbeBusy !== null}
          >
            {deepProbeBusy === "waterfall"
              ? "Probing Waterfall..."
              : "Waterfall + UDP Probe"}
          </button>

          <button
            id="run-ai-matrix-btn"
            type="button"
            className="btn"
            disabled={deepProbeBusy !== null}
            onClick={() => void handleRunEndpointMatrix()}
          >
            {deepProbeBusy === "matrix"
              ? "Scanning Matrix..."
              : "1-Click AI & Dev Matrix"}
          </button>
        </form>

        {deepProbeErr && (
          <div className="banner banner-err" style={{ marginBottom: 12 }}>
            <span>{deepProbeErr}</span>
          </div>
        )}

        {waterfallRes && (
          <div
            className="kv-box"
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 10,
              marginBottom: matrixRes ? 12 : 0,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  flexWrap: "wrap",
                }}
              >
                <strong className="mono">{waterfallRes.url}</strong>
                <span className="badge badge-neutral">
                  {waterfallRes.effective_outbound} ({waterfallRes.protocol})
                </span>
                {waterfallRes.tls_version && (
                  <span className="badge badge-sky">
                    {waterfallRes.tls_version}
                    {waterfallRes.alpn ? ` · ${waterfallRes.alpn}` : ""}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span
                  className={`badge ${verdictBadgeClass(waterfallRes.verdict)}`}
                >
                  {verdictLabel(waterfallRes)}
                </span>
                <span
                  className="badge badge-neutral tabular"
                  title={
                    waterfallRes.overall_probe_duration_ms != null
                      ? `TCP Waterfall: ${waterfallRes.total_ms.toFixed(1)} ms · Overall wall-clock (incl. parallel UDP): ${waterfallRes.overall_probe_duration_ms.toFixed(1)} ms`
                      : undefined
                  }
                >
                  TCP {waterfallRes.total_ms.toFixed(1)} ms
                </span>
              </div>
            </div>

            {/* Segmented Timing Waterfall Bar */}
            {(() => {
              const d = waterfallRes.dns_resolve_ms ?? 0;
              const c = waterfallRes.tunnel_connect_ms ?? 0;
              const t = waterfallRes.tls_handshake_ms ?? 0;
              const h = waterfallRes.http_ttfb_ms ?? 0;
              const sum = Math.max(d + c + t + h, 0.1);
              return (
                <div>
                  <div
                    style={{
                      display: "flex",
                      height: 10,
                      borderRadius: 999,
                      overflow: "hidden",
                      background: "var(--bg-elevated)",
                      marginBottom: 8,
                    }}
                  >
                    {d > 0 && (
                      <div
                        style={{
                          width: `${(d / sum) * 100}%`,
                          background: "#38bdf8",
                        }}
                        title={`DNS Resolve: ${d.toFixed(1)} ms`}
                      />
                    )}
                    {c > 0 && (
                      <div
                        style={{
                          width: `${(c / sum) * 100}%`,
                          background: "#f59e0b",
                        }}
                        title={`Tunnel Connect: ${c.toFixed(1)} ms`}
                      />
                    )}
                    {t > 0 && (
                      <div
                        style={{
                          width: `${(t / sum) * 100}%`,
                          background: "#818cf8",
                        }}
                        title={`TLS Handshake: ${t.toFixed(1)} ms`}
                      />
                    )}
                    {h > 0 && (
                      <div
                        style={{
                          width: `${(h / sum) * 100}%`,
                          background: "#10b981",
                        }}
                        title={`HTTP TTFB: ${h.toFixed(1)} ms`}
                      />
                    )}
                  </div>

                  <div
                    className="tabular"
                    style={{
                      display: "flex",
                      gap: 14,
                      flexWrap: "wrap",
                      fontSize: 11.5,
                      color: "var(--text-secondary)",
                    }}
                  >
                    <span>
                      <strong style={{ color: "#38bdf8" }}>● DNS:</strong>{" "}
                      {waterfallRes.dns_resolve_ms != null
                        ? `${waterfallRes.dns_resolve_ms.toFixed(1)} ms`
                        : waterfallRes.remote_dns
                          ? "Remote Tunnel DNS"
                          : "Literal IP"}
                    </span>
                    <span>
                      <strong style={{ color: "#f59e0b" }}>● Tunnel:</strong>{" "}
                      {waterfallRes.tunnel_connect_ms != null
                        ? `${waterfallRes.tunnel_connect_ms.toFixed(1)} ms`
                        : "—"}
                    </span>
                    <span>
                      <strong style={{ color: "#818cf8" }}>● TLS:</strong>{" "}
                      {waterfallRes.tls_handshake_ms != null
                        ? `${waterfallRes.tls_handshake_ms.toFixed(1)} ms`
                        : "n/a"}
                    </span>
                    <span>
                      <strong style={{ color: "#10b981" }}>● HTTP TTFB:</strong>{" "}
                      {waterfallRes.http_ttfb_ms != null
                        ? `${waterfallRes.http_ttfb_ms.toFixed(1)} ms`
                        : "—"}
                    </span>
                  </div>
                </div>
              );
            })()}

            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              {waterfallRes.note}
              {waterfallRes.udp_probe
                ? ` · UDP Check: ${waterfallRes.udp_probe.detail}`
                : ""}
            </div>
          </div>
        )}

        {matrixRes && (
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
                marginBottom: 8,
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: "var(--text-secondary)",
                }}
              >
                AI &amp; Developer Endpoint Matrix via{" "}
                <span className="mono">{matrixRes.effective_outbound}</span> (
                {matrixRes.protocol}) — {matrixRes.ai_status_note}
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <span
                  className={`badge ${matrixRes.ai_egress_unblocked ? "badge-emerald" : "badge-amber"}`}
                  title={matrixRes.ai_status_note}
                >
                  AI Egress:{" "}
                  {matrixRes.ai_egress_unblocked
                    ? "UNBLOCKED (AUTH REQ)"
                    : matrixRes.rate_limited_count > 0
                      ? "RATE-LIMITED (429)"
                      : "BLOCKED / PARTIAL"}
                </span>
                <span className="badge badge-sky tabular">
                  Unblocked {matrixRes.reachable_count}/{matrixRes.items.length}
                </span>
                {matrixRes.rate_limited_count > 0 && (
                  <span className="badge badge-amber tabular">
                    429 Rate-Limited: {matrixRes.rate_limited_count}
                  </span>
                )}
                <span
                  className={`badge ${
                    matrixRes.udp_probe.status === "verified"
                      ? "badge-emerald"
                      : matrixRes.udp_probe.status === "blackholed"
                        ? "badge-rose"
                        : "badge-neutral"
                  }`}
                >
                  UDP: {matrixRes.udp_probe.status.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Verdict</th>
                    <th>Tunnel</th>
                    <th>TLS</th>
                    <th>HTTP TTFB</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {matrixRes.items.map((item) => {
                    const p = item.report;
                    return (
                      <tr
                        key={item.id}
                        style={{ cursor: "pointer" }}
                        onClick={() => {
                          setProbeUrl(p.url);
                          setWaterfallRes(p);
                        }}
                      >
                        <td>
                          <div style={{ fontWeight: 600 }}>{item.label}</div>
                          <div
                            className="mono"
                            style={{ fontSize: 11, color: "var(--text-muted)" }}
                          >
                            {p.target_host}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`badge ${verdictBadgeClass(p.verdict)}`}
                          >
                            {verdictLabel(p)}
                          </span>
                        </td>
                        <td className="tabular">
                          {p.tunnel_connect_ms != null
                            ? `${p.tunnel_connect_ms.toFixed(0)} ms`
                            : "—"}
                        </td>
                        <td className="tabular">
                          {p.tls_handshake_ms != null
                            ? `${p.tls_handshake_ms.toFixed(0)} ms`
                            : "n/a"}
                        </td>
                        <td className="tabular">
                          {p.http_ttfb_ms != null
                            ? `${p.http_ttfb_ms.toFixed(0)} ms`
                            : "—"}
                        </td>
                        <td className="tabular" style={{ fontWeight: 600 }}>
                          {p.total_ms.toFixed(0)} ms
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Saved Proxy Nodes Management Card */}
      {activeNodes.length > 0 && !config?.demo.enabled && (
        <section className="card">
          <div
            className="card-header"
            style={{
              marginBottom: collapsed["__saved_nodes__"] ? 0 : 12,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <h2 className="card-title" style={{ fontSize: 15 }}>
                Saved Proxy Nodes ({activeNodes.length})
              </h2>
              <span className="badge badge-sky">Persistent Profile</span>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => openCreateModal("manual")}
              >
                + Manual Node
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() =>
                  setCollapsed((prev) => ({
                    ...prev,
                    __saved_nodes__: !prev["__saved_nodes__"],
                  }))
                }
              >
                {collapsed["__saved_nodes__"]
                  ? `Expand (${activeNodes.length})`
                  : "Collapse"}
              </button>
            </div>
          </div>

          {!collapsed["__saved_nodes__"] && (
            <div className="node-grid">
              {activeNodes.map((node) => {
                const liveInfo = proxies[node.name];
                const rtt = latestDelay(liveInfo);
                const isEffective = effectiveName === node.name;
                const isTesting = Boolean(testingMap[node.name]);
                const protoLabel = nodeProtocolBadge(
                  node,
                  liveInfo?.type ?? node.type.toUpperCase(),
                );

                return (
                  <div
                    key={node.name}
                    className={`node-tile ${isEffective ? "selected" : ""}`}
                    onClick={() => void handleSelectConcreteNodeQuick(node.name)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(ev) => {
                      if (ev.key === "Enter" || ev.key === " ") {
                        ev.preventDefault();
                        void handleSelectConcreteNodeQuick(node.name);
                      }
                    }}
                  >
                    <div className="node-tile-top">
                      <div style={{ minWidth: 0 }}>
                        <div className="node-name">{node.name}</div>
                        <div
                          className="mono"
                          style={{
                            fontSize: 11,
                            color: "var(--text-muted)",
                            marginTop: 2,
                            overflowWrap: "anywhere",
                          }}
                        >
                          {node.server}:{node.port}
                        </div>
                      </div>
                      <span
                        className={`badge tabular ${delayBadgeVariant(rtt)}`}
                        onClick={(e) => void handleProbeSingle(e, node.name)}
                        title="Click to probe latency"
                      >
                        {isTesting
                          ? "..."
                          : rtt && rtt > 0
                            ? `${rtt} ms`
                            : "Probe"}
                      </span>
                    </div>

                    <div className="node-tile-bottom">
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 5,
                          flexWrap: "wrap",
                        }}
                      >
                        <span
                          className={`badge ${protocolBadgeVariant(protoLabel)}`}
                        >
                          {protoLabel}
                        </span>
                        {isEffective && (
                          <span className="badge badge-emerald">Active</span>
                        )}
                      </div>

                      <div className="node-tile-actions">
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            openEditModal(node);
                          }}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          disabled={busyAction === `del:${node.name}`}
                          onClick={(e) => void handleDeleteNode(e, node.name)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      )}

      {/* Policy Groups */}
      {groups.map((grp) => {
        const isCollapsed = Boolean(collapsed[grp.name]);
        const isGroupTesting = Boolean(testingMap[grp.name]);
        const leafDiffers =
          grp.effective_outbound &&
          grp.now &&
          grp.effective_outbound !== grp.now;

        return (
          <section key={grp.name} className="card">
            <div
              className="card-header"
              style={{ marginBottom: isCollapsed ? 0 : 12 }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  flexWrap: "wrap",
                }}
              >
                <h2 className="card-title" style={{ fontSize: 15 }}>
                  {grp.name}
                </h2>
                <span className="badge badge-neutral">{grp.type}</span>
                {grp.now && (
                  <span
                    className={`badge ${
                      grp.now === "DIRECT" ? "badge-amber" : "badge-emerald"
                    }`}
                  >
                    Selected: {grp.now}
                  </span>
                )}
                {leafDiffers && (
                  <span className="badge badge-sky">
                    Effective: {grp.effective_outbound}
                  </span>
                )}
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={isGroupTesting}
                  onClick={() => void handleProbeGroup(grp)}
                >
                  {isGroupTesting ? "Probing..." : "Latency Test"}
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    setCollapsed((prev) => ({
                      ...prev,
                      [grp.name]: !prev[grp.name],
                    }))
                  }
                >
                  {isCollapsed
                    ? `Expand (${grp.all?.length ?? 0})`
                    : "Collapse"}
                </button>
              </div>
            </div>

            {!isCollapsed && (
              <div className="node-grid">
                {(grp.all ?? []).map((memberName) => {
                  const node = proxies[memberName];
                  const editableCfg = activeNodeMap.get(memberName);
                  const isSelected = grp.now === memberName;
                  const rtt = latestDelay(node);
                  const protoLabel = editableCfg
                    ? nodeProtocolBadge(editableCfg, node?.type)
                    : (node?.type ?? "Unknown");
                  const isTesting = Boolean(testingMap[memberName]);

                  return (
                    <div
                      key={memberName}
                      role="button"
                      tabIndex={0}
                      className={`node-tile ${isSelected ? "selected" : ""}`}
                      onClick={() => void handleSelectMember(grp, memberName)}
                      onKeyDown={(ev) => {
                        if (ev.key === "Enter" || ev.key === " ") {
                          ev.preventDefault();
                          void handleSelectMember(grp, memberName);
                        }
                      }}
                    >
                      <div className="node-tile-top">
                        <span className="node-name">{memberName}</span>
                        <span
                          className={`badge tabular ${delayBadgeVariant(rtt)}`}
                          onClick={(e) => void handleProbeSingle(e, memberName)}
                          title="Click to probe node latency"
                        >
                          {isTesting
                            ? "..."
                            : rtt && rtt > 0
                              ? `${rtt} ms`
                              : "Probe"}
                        </span>
                      </div>

                      <div className="node-tile-bottom">
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                          }}
                        >
                          <span
                            className={`badge ${protocolBadgeVariant(protoLabel)}`}
                          >
                            {protoLabel}
                          </span>
                          <span
                            style={{
                              fontSize: 11,
                              color: "var(--text-muted)",
                            }}
                          >
                            {node?.udp ? "TCP + UDP" : "TCP"}
                          </span>
                        </div>

                        {editableCfg && !config?.demo.enabled && (
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              openEditModal(editableCfg);
                            }}
                          >
                            Edit
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        );
      })}

      {/* Add / Edit / Paste Node Modal */}
      {modalOpen && (
        <div
          className="modal-backdrop"
          onClick={() => requestCloseModal()}
          role="presentation"
        >
          <div
            className="modal-card"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={
              editingOriginalName
                ? `Edit Node ${editingOriginalName}`
                : "Add Proxy Node"
            }
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <h2 className="card-title" style={{ fontSize: 16 }}>
                  {editingOriginalName
                    ? `Edit / Rename Node: ${editingOriginalName}`
                    : "Add Proxy Node / 添加节点"}
                </h2>
                <div className="card-subtitle">
                  {editingOriginalName
                    ? "Renaming updates all policy groups, routing rules, and saved selections automatically."
                    : "Persists directly to your active profile and survives hot-reloads & restarts."}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                disabled={modalInflight}
                onClick={() => requestCloseModal()}
              >
                Close
              </button>
            </div>

            {!editingOriginalName && (
              <div className="segmented" style={{ alignSelf: "flex-start" }}>
                <button
                  type="button"
                  className={`seg-btn ${modalMode === "paste" ? "active" : ""}`}
                  disabled={modalInflight}
                  onClick={() => {
                    setModalError(null);
                    setModalMode("paste");
                  }}
                >
                  Paste Share Link / Subscription
                </button>
                <button
                  type="button"
                  className={`seg-btn ${modalMode === "manual" ? "active" : ""}`}
                  disabled={modalInflight}
                  onClick={() => {
                    setModalError(null);
                    setModalMode("manual");
                  }}
                >
                  Manual Node Configuration
                </button>
              </div>
            )}

            {modalError && (
              <div
                ref={modalErrorRef}
                id="modal-inline-error-banner"
                className="banner banner-err"
              >
                <span>{renderInlineCode(modalError)}</span>
              </div>
            )}

            {modalMode === "paste" && !editingOriginalName ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={modalInflight}
                    onClick={() => void handleFillModalFromClipboard()}
                  >
                    Read Clipboard
                  </button>
                  {androidBridge.canScanQr() && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={modalInflight}
                      onClick={() => {
                        requestCloseModal();
                        androidBridge.requestQrScan();
                      }}
                    >
                      Scan QR Code
                    </button>
                  )}
                </div>

                <textarea
                  id="modal-paste-uris-textarea"
                  className="code-editor"
                  rows={6}
                  placeholder={"Paste one or multiple share links (one per line), Base64 subscription, Clash YAML, or HTTPS subscription URL:\nss://...\nvless://...\ntrojan://...\nanytls://...\nsocks5://...\nhttp-proxy://..."}
                  value={pasteInput}
                  onChange={(e) => {
                    if (modalError) setModalError(null);
                    setPasteInput(e.target.value);
                  }}
                />

                <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                  <label
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 12.5,
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={dedupOnImport}
                      onChange={(e) => setDedupOnImport(e.target.checked)}
                    />
                    Skip duplicate nodes
                  </label>
                  <label
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 12.5,
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={autoSelectOnImport}
                      onChange={(e) => setAutoSelectOnImport(e.target.checked)}
                    />
                    Select &amp; activate immediately
                  </label>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "flex-end",
                    gap: 8,
                  }}
                >
                  <button
                    type="button"
                    className="btn"
                    disabled={modalInflight}
                    onClick={() => requestCloseModal()}
                  >
                    Cancel
                  </button>
                  <button
                    id="modal-import-submit-btn"
                    type="button"
                    className="btn btn-primary"
                    disabled={busyAction === "import"}
                    onClick={() =>
                      void executeImportText(pasteInput, {
                        deduplicate: dedupOnImport,
                        autoSelect: autoSelectOnImport,
                        closeModal: true,
                      })
                    }
                  >
                    {busyAction === "import"
                      ? "Importing..."
                      : "Import & Save"}
                  </button>
                </div>
              </div>
            ) : (
              <form
                onSubmit={(e) => void handleSaveManualNode(e)}
                style={{ display: "flex", flexDirection: "column", gap: 12 }}
              >
                <div className="form-grid">
                  <div className="form-field">
                    <label className="form-label">Protocol</label>
                    <select
                      id="manual-node-proto-select"
                      className="select"
                      value={proto}
                      onChange={(e) => {
                        if (modalError) setModalError(null);
                        setProto(e.target.value as NodeProto);
                      }}
                    >
                      <option value="ss">Shadowsocks / SS-2022</option>
                      <option value="vless">VLESS / VLESS+PQ (TCP / WS)</option>
                      <option value="trojan">Trojan (TLS / WS)</option>
                      <option value="anytls">AnyTLS v2 (TLS 1.3 Mux)</option>
                      <option value="socks5">SOCKS5 / SOCKS5+TLS</option>
                      <option value="http">HTTP / HTTPS CONNECT</option>
                    </select>
                  </div>

                  <div className="form-field">
                    <label className="form-label">Node Name</label>
                    <input
                      className="input"
                      type="text"
                      placeholder="e.g. HK-IEPL-01"
                      value={nodeName}
                      onChange={(e) => {
                        if (modalError) setModalError(null);
                        setNodeName(e.target.value);
                      }}
                      required
                    />
                  </div>

                  <div className="form-field">
                    <label className="form-label">Server Host / IP</label>
                    <input
                      className="input"
                      type="text"
                      placeholder="edge.example.com"
                      value={serverHost}
                      onChange={(e) => {
                        if (modalError) setModalError(null);
                        setServerHost(e.target.value);
                      }}
                      required
                    />
                  </div>

                  <div className="form-field">
                    <label className="form-label">Port</label>
                    <input
                      className="input tabular"
                      type="number"
                      min={1}
                      max={65535}
                      value={serverPort}
                      onChange={(e) => {
                        if (modalError) setModalError(null);
                        setServerPort(e.target.value);
                      }}
                      required
                    />
                  </div>

                  {proto === "ss" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">Cipher</label>
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
                          Password / Base64 PSK
                        </label>
                        <input
                          className="input"
                          type="password"
                          autoComplete="off"
                          placeholder={
                            editingOriginalName && editingOriginalProto === "ss"
                              ? "Leave blank to keep saved password"
                              : "Password or Base64 PSK"
                          }
                          value={ssPassword}
                          onChange={(e) => {
                            if (modalError) setModalError(null);
                            setSsPassword(e.target.value);
                          }}
                        />
                      </div>
                    </>
                  )}

                  {proto === "vless" && (
                    <>
                      <div className="form-field full">
                        <label className="form-label">UUID</label>
                        <input
                          className="input mono"
                          type="password"
                          autoComplete="off"
                          placeholder={
                            editingOriginalName &&
                            editingOriginalProto === "vless"
                              ? "Leave blank to keep saved UUID"
                              : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          }
                          value={vlessUuid}
                          onChange={(e) => {
                            if (modalError) setModalError(null);
                            setVlessUuid(e.target.value);
                          }}
                        />
                      </div>

                      <div className="form-field full">
                        <label className="form-label">
                          Client Encryption (<code className="mono">none</code>{" "}
                          or{" "}
                          <code className="mono">mlkem768x25519plus...</code>)
                        </label>
                        <input
                          className="input mono"
                          type="text"
                          placeholder={
                            editingOriginalName && vlessHadRedactedEnc
                              ? "Leave blank to keep saved PQ key, or enter 'none'"
                              : "none"
                          }
                          value={vlessEncryption}
                          onChange={(e) => setVlessEncryption(e.target.value)}
                        />
                      </div>

                      <div className="form-field">
                        <label className="form-label">SNI / Servername</label>
                        <input
                          className="input"
                          type="text"
                          placeholder="Optional TLS SNI"
                          value={vlessServername}
                          onChange={(e) => setVlessServername(e.target.value)}
                        />
                      </div>

                      <div className="form-field">
                        <label className="form-label">
                          ALPN (comma-separated)
                        </label>
                        <input
                          className="input"
                          type="text"
                          placeholder="h2, http/1.1"
                          value={vlessAlpn}
                          onChange={(e) => setVlessAlpn(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {proto === "trojan" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">Password</label>
                        <input
                          className="input"
                          type="password"
                          autoComplete="off"
                          placeholder={
                            editingOriginalName &&
                            editingOriginalProto === "trojan"
                              ? "Leave blank to keep saved password"
                              : "Trojan password"
                          }
                          value={trojanPassword}
                          onChange={(e) => {
                            if (modalError) setModalError(null);
                            setTrojanPassword(e.target.value);
                          }}
                        />
                      </div>

                      <div className="form-field">
                        <label className="form-label">TLS SNI</label>
                        <input
                          className="input"
                          type="text"
                          placeholder="Defaults to server host"
                          value={trojanSni}
                          onChange={(e) => setTrojanSni(e.target.value)}
                        />
                      </div>

                      <div className="form-field full">
                        <label className="form-label">
                          ALPN (comma-separated)
                        </label>
                        <input
                          className="input"
                          type="text"
                          placeholder="h2, http/1.1"
                          value={trojanAlpn}
                          onChange={(e) => setTrojanAlpn(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {(proto === "vless" || proto === "trojan") && (
                    <>
                      <div className="form-field">
                        <label className="form-label">Transport</label>
                        <select
                          className="select"
                          value={transportNet}
                          onChange={(e) =>
                            setTransportNet(e.target.value as "tcp" | "ws")
                          }
                        >
                          <option value="tcp">TCP</option>
                          <option value="ws">WebSocket (WS / CDN)</option>
                        </select>
                      </div>

                      {transportNet === "ws" && (
                        <>
                          <div className="form-field">
                            <label className="form-label">WS Path</label>
                            <input
                              className="input mono"
                              type="text"
                              placeholder="/ws"
                              value={wsPath}
                              onChange={(e) => setWsPath(e.target.value)}
                            />
                          </div>

                          <div className="form-field">
                            <label className="form-label">
                              WS Host Header (optional)
                            </label>
                            <input
                              className="input"
                              type="text"
                              placeholder="cdn.example.com"
                              value={wsHost}
                              onChange={(e) => setWsHost(e.target.value)}
                            />
                          </div>

                          <div className="form-field">
                            <label className="form-label">
                              0-RTT Max Early Data (bytes)
                            </label>
                            <input
                              className="input tabular"
                              type="number"
                              min={0}
                              max={65535}
                              placeholder="0 (or 2048 for 0-RTT)"
                              value={wsMaxEarlyData}
                              onChange={(e) => {
                                if (modalError) setModalError(null);
                                setWsMaxEarlyData(e.target.value);
                              }}
                            />
                          </div>
                        </>
                      )}
                    </>
                  )}

                  {proto === "anytls" && (
                    <>
                      <div className="form-field">
                        <label className="form-label">Password</label>
                        <input
                          className="input"
                          type="password"
                          autoComplete="off"
                          placeholder={
                            editingOriginalName &&
                            editingOriginalProto === "anytls"
                              ? "Leave blank to keep saved password"
                              : "AnyTLS password"
                          }
                          value={anytlsPassword}
                          onChange={(e) => {
                            if (modalError) setModalError(null);
                            setAnytlsPassword(e.target.value);
                          }}
                        />
                      </div>

                      <div className="form-field">
                        <label className="form-label">TLS SNI</label>
                        <input
                          className="input"
                          type="text"
                          placeholder="Defaults to server host"
                          value={anytlsSni}
                          onChange={(e) => setAnytlsSni(e.target.value)}
                        />
                      </div>

                      <div className="form-field full">
                        <label className="form-label">
                          ALPN (comma-separated)
                        </label>
                        <input
                          className="input"
                          type="text"
                          placeholder="h2, http/1.1"
                          value={anytlsAlpn}
                          onChange={(e) => setAnytlsAlpn(e.target.value)}
                        />
                      </div>
                    </>
                  )}

                  {(proto === "socks5" || proto === "http") && (
                    <>
                      <div className="form-field">
                        <label className="form-label">
                          Username (optional)
                        </label>
                        <input
                          className="input"
                          type="text"
                          autoComplete="off"
                          placeholder="Optional username"
                          value={authUsername}
                          onChange={(e) => setAuthUsername(e.target.value)}
                        />
                      </div>

                      <div className="form-field">
                        <label className="form-label">
                          Password (optional)
                        </label>
                        <input
                          className="input"
                          type="password"
                          autoComplete="off"
                          placeholder={
                            editingOriginalName && authHadSavedPassword
                              ? "Leave blank to keep saved password"
                              : "Optional password"
                          }
                          value={authPassword}
                          onChange={(e) => setAuthPassword(e.target.value)}
                        />
                      </div>

                      {proxyTls && (
                        <div className="form-field full">
                          <label className="form-label">TLS SNI</label>
                          <input
                            className="input"
                            type="text"
                            placeholder="Defaults to server host"
                            value={proxySni}
                            onChange={(e) => setProxySni(e.target.value)}
                          />
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                  {proto !== "http" && (
                    <label
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12.5,
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={udpEnabled}
                        onChange={(e) => setUdpEnabled(e.target.checked)}
                      />
                      Enable UDP Relay
                    </label>
                  )}

                  {proto === "vless" && (
                    <>
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={vlessTls}
                          onChange={(e) => setVlessTls(e.target.checked)}
                        />
                        TLS Enabled
                      </label>
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={vlessSkipVerify}
                          onChange={(e) => setVlessSkipVerify(e.target.checked)}
                        />
                        Skip Cert Verify
                      </label>
                    </>
                  )}

                  {proto === "trojan" && (
                    <>
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={trojanTls}
                          onChange={(e) => setTrojanTls(e.target.checked)}
                        />
                        TLS Enabled
                      </label>
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={trojanSkipVerify}
                          onChange={(e) =>
                            setTrojanSkipVerify(e.target.checked)
                          }
                        />
                        Skip Cert Verify
                      </label>
                    </>
                  )}

                  {proto === "anytls" && (
                    <label
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12.5,
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={anytlsSkipVerify}
                        onChange={(e) => setAnytlsSkipVerify(e.target.checked)}
                      />
                      Skip Cert Verify
                    </label>
                  )}

                  {(proto === "socks5" || proto === "http") && (
                    <>
                      <label
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 12.5,
                          cursor: "pointer",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={proxyTls}
                          onChange={(e) => setProxyTls(e.target.checked)}
                        />
                        TLS / HTTPS Upstream
                      </label>
                      {proxyTls && (
                        <label
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 6,
                            fontSize: 12.5,
                            cursor: "pointer",
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={proxySkipVerify}
                            onChange={(e) =>
                              setProxySkipVerify(e.target.checked)
                            }
                          />
                          Skip Cert Verify
                        </label>
                      )}
                    </>
                  )}

                  <label
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 12.5,
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={autoSelectManual}
                      onChange={(e) => setAutoSelectManual(e.target.checked)}
                    />
                    Select immediately in PROXY group
                  </label>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "flex-end",
                    gap: 8,
                    marginTop: 4,
                  }}
                >
                  <button
                    type="button"
                    className="btn"
                    disabled={modalInflight}
                    onClick={() => requestCloseModal()}
                  >
                    Cancel
                  </button>
                  <button
                    id="modal-save-node-btn"
                    type="submit"
                    className="btn btn-primary"
                    disabled={busyAction === "save-node"}
                  >
                    {busyAction === "save-node"
                      ? "Saving..."
                      : editingOriginalName
                        ? "Save Changes"
                        : "Add & Save Node"}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
