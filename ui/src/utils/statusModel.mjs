// Pure, dependency-free state derivation helpers for RustClash Desktop/Web UI.
// Guarantees zero fabricated metrics, zero guessed countries, and strict separation
// of Core Engine, System Takeover, and Internet Connectivity states.

/**
 * @param {object} input
 * @param {boolean} input.online
 * @param {boolean} input.sysproxyEnabled
 * @param {boolean} input.tunEnabled
 * @param {number} [input.mixedPort]
 * @param {"rule" | "global" | "direct"} [input.mode]
 * @param {boolean} [input.demoEnabled]
 * @param {boolean} [input.probing]
 * @param {number | null | undefined} [input.googleMs]
 * @param {number | null | undefined} [input.githubMs]
 * @param {boolean | null | undefined} [input.exitIpOk]
 */
export function deriveThreeLayerStatus(input) {
  const {
    online,
    sysproxyEnabled,
    tunEnabled,
    mixedPort = 7890,
    mode = "rule",
    demoEnabled = false,
    probing = false,
    googleMs,
    githubMs,
    exitIpOk,
  } = input;

  const core = online
    ? {
        state: "online",
        tone: "emerald",
        zh: "正常运行",
        en: "Running",
      }
    : {
        state: "offline",
        tone: "rose",
        zh: "未连接",
        en: "Offline",
      };

  const takeoverActive = Boolean(online && (sysproxyEnabled || tunEnabled));
  let takeover;
  if (!online) {
    takeover = {
      state: "offline",
      active: false,
      tone: "neutral",
      zh: "未启用",
      en: "Inactive",
    };
  } else if (sysproxyEnabled && tunEnabled) {
    takeover = {
      state: "sysproxy_and_tun",
      active: true,
      tone: mode === "direct" ? "amber" : "emerald",
      zh: "系统代理 + TUN",
      en: "SysProxy + TUN",
    };
  } else if (tunEnabled) {
    takeover = {
      state: "tun",
      active: true,
      tone: mode === "direct" ? "amber" : "emerald",
      zh: "TUN 虚拟网卡",
      en: "TUN Active",
    };
  } else if (sysproxyEnabled) {
    takeover = {
      state: "sysproxy",
      active: true,
      tone: mode === "direct" ? "amber" : "emerald",
      zh: "系统代理已启用",
      en: "System Proxy",
    };
  } else {
    takeover = {
      state: "port_only",
      active: false,
      tone: "neutral",
      zh: `仅端口监听 (:${mixedPort})`,
      en: `Port Only (:${mixedPort})`,
    };
  }

  const gOk = typeof googleMs === "number" && googleMs > 0;
  const ghOk = typeof githubMs === "number" && githubMs > 0;
  const ipOk = exitIpOk === true;
  const anyServiceAttempted = googleMs !== undefined || githubMs !== undefined;
  const anyAttempted = anyServiceAttempted || exitIpOk !== undefined;

  let connectivity;
  if (!online) {
    connectivity = {
      state: "offline",
      tone: "neutral",
      zh: "核心离线",
      en: "Core Offline",
    };
  } else if (demoEnabled) {
    if (gOk || ghOk) {
      const bestMs =
        gOk && ghOk ? Math.min(googleMs, githubMs) : gOk ? googleMs : githubMs;
      connectivity = {
        state: "reachable",
        tone: "emerald",
        zh: `沙盒回环正常 (${bestMs} ms)`,
        en: `Sandbox OK (${bestMs} ms)`,
      };
    } else if (probing) {
      connectivity = {
        state: "checking",
        tone: "sky",
        zh: "检测中…",
        en: "Checking...",
      };
    } else {
      connectivity = {
        state: "unchecked",
        tone: "neutral",
        zh: "本地演练沙盒",
        en: "Demo Sandbox",
      };
    }
  } else if (probing && !anyServiceAttempted) {
    connectivity = {
      state: "checking",
      tone: "sky",
      zh: "正在检测…",
      en: "Checking...",
    };
  } else if (!anyAttempted) {
    connectivity = {
      state: "unchecked",
      tone: "neutral",
      zh: "尚未检测",
      en: "Not Checked",
    };
  } else if (gOk && ghOk) {
    const bestMs = Math.min(googleMs, githubMs);
    connectivity = {
      state: "reachable",
      tone: "emerald",
      zh: `连通正常 (${bestMs} ms)`,
      en: `Reachable (${bestMs} ms)`,
    };
  } else if (gOk || ghOk || (ipOk && !anyServiceAttempted)) {
    connectivity = {
      state: "degraded",
      tone: "amber",
      zh: gOk || ghOk ? "部分服务可达" : "出口可达 · 服务待测",
      en: gOk || ghOk ? "Partially Reachable" : "Exit OK · Services Pending",
    };
  } else {
    connectivity = {
      state: "unreachable",
      tone: "rose",
      zh: "检测失败",
      en: "Unreachable",
    };
  }

  let hero;
  if (!online) {
    hero = {
      pillClass: "offline",
      zh: "核心未连接",
      en: "Core Offline",
      directModeWarning: false,
    };
  } else if (takeoverActive && mode === "direct") {
    hero = {
      pillClass: "warn",
      zh: "全局直连中",
      en: "Direct Mode Active",
      directModeWarning: true,
    };
  } else if (takeoverActive) {
    if (connectivity.state === "unreachable") {
      hero = {
        pillClass: "error",
        zh: "已启用接管 · 联网异常",
        en: "Takeover On · Unreachable",
        directModeWarning: false,
      };
    } else if (connectivity.state === "degraded") {
      hero = {
        pillClass: "warn",
        zh: "已接管 · 部分受限",
        en: "Connected · Degraded",
        directModeWarning: false,
      };
    } else if (connectivity.state === "reachable") {
      hero = {
        pillClass: "running",
        zh: "已连接 · 网络正常",
        en: "Connected · Online",
        directModeWarning: false,
      };
    } else if (connectivity.state === "checking") {
      hero = {
        pillClass: "checking",
        zh: "已启用接管 · 检测中",
        en: "Takeover On · Checking",
        directModeWarning: false,
      };
    } else {
      hero = {
        pillClass: "checking",
        zh: "已启用接管 · 待检测",
        en: "Takeover On · Unverified",
        directModeWarning: false,
      };
    }
  } else {
    hero = {
      pillClass: "direct",
      zh: "待机（仅本地端口）",
      en: "Standby (Port Only)",
      directModeWarning: false,
    };
  }

  return { core, takeover, connectivity, hero };
}

/**
 * Computes honest memory metrics without fabricating a 28 MiB core baseline
 * or a synthetic 0.36x UI heap estimate.
 *
 * @param {number | null | undefined} coreRssBytes
 * @param {number | null | undefined} jsHeapBytes
 */
export function deriveMemoryDisplay(coreRssBytes, jsHeapBytes) {
  const hasCore = typeof coreRssBytes === "number" && Number.isFinite(coreRssBytes) && coreRssBytes > 0;
  const hasUi = typeof jsHeapBytes === "number" && Number.isFinite(jsHeapBytes) && jsHeapBytes > 0;
  const safeCore = hasCore ? Math.round(coreRssBytes) : null;
  const safeUi = hasUi ? Math.round(jsHeapBytes) : null;
  const available = hasCore || hasUi;
  const totalBytes = available ? (safeCore ?? 0) + (safeUi ?? 0) : null;

  let corePct = 0;
  let uiPct = 0;
  if (hasCore && hasUi && totalBytes && totalBytes > 0) {
    corePct = Math.max(8, Math.min(92, Math.round((safeCore / totalBytes) * 100)));
    uiPct = 100 - corePct;
  } else if (hasCore) {
    corePct = 100;
    uiPct = 0;
  } else if (hasUi) {
    corePct = 0;
    uiPct = 100;
  }

  return {
    available,
    totalBytes,
    coreBytes: safeCore,
    uiBytes: safeUi,
    corePct,
    uiPct,
  };
}

/**
 * Resolves honest Exit IP, verified country badge, and quality tag without guessing
 * countries from proxy node names or fabricating "质量正常" when unprobed.
 *
 * @param {object} input
 * @param {boolean} input.online
 * @param {boolean} input.ipLoading
 * @param {object | null | undefined} input.exitIp
 * @param {boolean} [input.demoEnabled]
 * @param {string} [input.effectiveOutbound]
 * @param {string} [input.effectiveProto]
 */
export function deriveExitIpDisplay(input) {
  const {
    online,
    ipLoading,
    exitIp,
    demoEnabled = false,
    effectiveOutbound = "DIRECT",
  } = input;

  const verified = Boolean(
    online &&
      exitIp &&
      exitIp.ok !== false &&
      typeof exitIp.ip === "string" &&
      exitIp.ip.trim() !== "" &&
      exitIp.ip.trim() !== "--",
  );

  if (!online) {
    return {
      verified: false,
      badgeCode: "—",
      headlineZh: "核心未连接",
      headlineEn: "Core Offline",
      qualityZh: "离线",
      qualityEn: "Offline",
      orgZh: "等待连接本地代理核心",
      orgEn: "Waiting for local proxy core",
    };
  }

  if (verified && exitIp) {
    const rawCc = typeof exitIp.country_code === "string" ? exitIp.country_code.trim().toUpperCase() : "";
    const validCc = /^[A-Z]{2}$/.test(rawCc) && rawCc !== "XX" ? rawCc : "IP";
    const latencyLabel =
      typeof exitIp.latency_ms === "number" && exitIp.latency_ms > 0
        ? `${exitIp.latency_ms} ms`
        : null;
    const rawQuality =
      typeof exitIp.quality === "string" && exitIp.quality.trim() !== ""
        ? exitIp.quality.trim()
        : null;
    const org =
      (typeof exitIp.organization === "string" && exitIp.organization.trim()) ||
      (typeof exitIp.isp === "string" && exitIp.isp.trim()) ||
      effectiveOutbound ||
      "Verified Exit";

    return {
      verified: true,
      badgeCode: demoEnabled && validCc === "IP" ? "LAB" : validCc,
      headlineZh: exitIp.ip.trim(),
      headlineEn: exitIp.ip.trim(),
      qualityZh: latencyLabel ?? rawQuality ?? "已验证出口",
      qualityEn: latencyLabel ?? rawQuality ?? "Verified Exit",
      orgZh: org,
      orgEn: org,
    };
  }

  if (ipLoading) {
    return {
      verified: false,
      badgeCode: "···",
      headlineZh: "正在检测出口 IP…",
      headlineEn: "Probing exit IP...",
      qualityZh: "检测中",
      qualityEn: "Checking",
      orgZh: effectiveOutbound || "Probing",
      orgEn: effectiveOutbound || "Probing",
    };
  }

  if (demoEnabled) {
    return {
      verified: false,
      badgeCode: "LAB",
      headlineZh: "127.0.0.1 (演练沙盒)",
      headlineEn: "127.0.0.1 (Demo Sandbox)",
      qualityZh: "本地回环",
      qualityEn: "Loopback",
      orgZh: "RustClash Local Sandbox",
      orgEn: "RustClash Local Sandbox",
    };
  }

  if (exitIp && exitIp.ok === false) {
    return {
      verified: false,
      badgeCode: "!",
      headlineZh: "出口检测失败",
      headlineEn: "Exit Check Failed",
      qualityZh: "不可达",
      qualityEn: "Unreachable",
      orgZh: effectiveOutbound ? `当前出站：${effectiveOutbound}` : "出口未响应",
      orgEn: effectiveOutbound ? `Outbound: ${effectiveOutbound}` : "Exit unreachable",
    };
  }

  return {
    verified: false,
    badgeCode: "—",
    headlineZh: "出口尚未检测",
    headlineEn: "Exit Not Checked",
    qualityZh: "尚未检测",
    qualityEn: "Not Checked",
    orgZh: effectiveOutbound ? `当前出站：${effectiveOutbound}` : "点击左侧按钮检测真实出口",
    orgEn: effectiveOutbound ? `Outbound: ${effectiveOutbound}` : "Click badge to verify exit IP",
  };
}

/**
 * Resolves real LAN / TUN interface IPv4 address without falling back to Fake-IP `198.18.0.1`.
 *
 * @param {object | null | undefined} config
 * @returns {string | null}
 */
export function resolveIntranetIpDisplay(config) {
  if (!config) return null;
  const candidates = [
    config["intranet-ip"],
    config["lan-ip"],
    config["tun-ip"],
    config.tun?.health?.ipv4_cidr?.split("/")[0],
  ];
  for (const raw of candidates) {
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed && trimmed !== "0.0.0.0" && trimmed !== "127.0.0.1" && trimmed !== "--") {
        return trimmed;
      }
    }
  }
  return null;
}

/**
 * Plans predictable Master Connection Switch behavior:
 * - NEVER mutates `config.mode` (`Rule` / `Global` / `Direct` remains strictly user-controlled).
 * - Remembers the user's active takeover combination (`sysproxy` / `tun`) when pausing and
 *   symmetrically restores it when resuming.
 *
 * @param {object} current
 * @param {boolean} current.sysproxyEnabled
 * @param {boolean} current.tunEnabled
 * @param {boolean} [current.sysproxySupported]
 * @param {{ sysproxy?: boolean; tun?: boolean } | null} [savedPref]
 */
export function planMasterToggle(current, savedPref) {
  const {
    sysproxyEnabled,
    tunEnabled,
    sysproxySupported = true,
  } = current;

  if (sysproxyEnabled || tunEnabled) {
    return {
      action: "disable",
      nextSavedPref: {
        sysproxy: Boolean(sysproxyEnabled),
        tun: Boolean(tunEnabled),
      },
      targetSysproxy: false,
      targetTun: false,
    };
  }

  let wantSysproxy = Boolean(savedPref?.sysproxy);
  let wantTun = Boolean(savedPref?.tun);
  if (!sysproxySupported) {
    wantSysproxy = false;
  }
  if (!wantSysproxy && !wantTun) {
    if (sysproxySupported) {
      wantSysproxy = true;
    } else {
      wantTun = true;
    }
  }

  return {
    action: "enable",
    nextSavedPref: {
      sysproxy: wantSysproxy,
      tun: wantTun,
    },
    targetSysproxy: wantSysproxy,
    targetTun: wantTun,
  };
}

const PROTOCOL_DISPLAY_NAMES = {
  vmess: "VMess",
  hysteria: "Hysteria",
  hysteria2: "Hysteria2",
  hy2: "Hysteria2",
  tuic: "TUIC",
  wireguard: "WireGuard",
  ssr: "ShadowsocksR",
  snell: "Snell",
  vless: "VLESS (不兼容传输/流控)",
  ss: "Shadowsocks (不兼容加密/插件)",
  trojan: "Trojan (不兼容传输)",
  http: "HTTP",
  socks5: "SOCKS5",
};

/**
 * Groups skipped/unsupported proxy entries from subscription import by protocol.
 *
 * @param {Array<{ name?: string; protocol?: string; reason?: string }> | null | undefined} entries
 */
export function summarizeSkippedUnsupported(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      total: 0,
      groups: [],
      protocolsSummaryZh: "",
      protocolsSummaryEn: "",
    };
  }

  /** @type {Map<string, { protocol: string; label: string; count: number; sampleNames: string[]; sampleReason: string }>} */
  const map = new Map();
  for (const item of entries) {
    const rawProto = typeof item?.protocol === "string" && item.protocol.trim()
      ? item.protocol.trim().toLowerCase()
      : "unknown";
    const label = PROTOCOL_DISPLAY_NAMES[rawProto] || rawProto.toUpperCase();
    const existing = map.get(rawProto);
    const name = typeof item?.name === "string" ? item.name.trim() : "";
    const reason = typeof item?.reason === "string" ? item.reason.trim() : "";
    if (existing) {
      existing.count += 1;
      if (name && existing.sampleNames.length < 3 && !existing.sampleNames.includes(name)) {
        existing.sampleNames.push(name);
      }
      if (!existing.sampleReason && reason) {
        existing.sampleReason = reason;
      }
    } else {
      map.set(rawProto, {
        protocol: rawProto,
        label,
        count: 1,
        sampleNames: name ? [name] : [],
        sampleReason: reason,
      });
    }
  }

  const groups = Array.from(map.values()).sort((a, b) => b.count - a.count);
  const topLabels = groups.slice(0, 4).map((g) => `${g.label} (${g.count})`);

  return {
    total: entries.length,
    groups,
    protocolsSummaryZh: topLabels.join("、"),
    protocolsSummaryEn: topLabels.join(", "),
  };
}
