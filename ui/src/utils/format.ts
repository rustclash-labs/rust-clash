import type { Lang } from "../i18n";
import type { ProxyNodeConfigPayload } from "../types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export function splitBytesParts(bytes: number): { value: string; unit: string } {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return { value: "0", unit: "B" };
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return {
    value: val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(1),
    unit: units[idx],
  };
}

export function splitSpeedParts(bytesPerSec: number): {
  value: string;
  unit: string;
} {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) {
    return { value: "0.0", unit: "KB/s" };
  }
  if (bytesPerSec < 1024) {
    return {
      value: (bytesPerSec / 1024).toFixed(1),
      unit: "KB/s",
    };
  }
  const parts = splitBytesParts(bytesPerSec);
  return { value: parts.value, unit: `${parts.unit}/s` };
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatDurationHms(totalSeconds: number): string {
  const safe = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(safe / 3600);
  const m = Math.floor((safe % 3600) / 60);
  const s = safe % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

export function formatCompactCount(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 100_000) return `${Math.round(n / 1000)}K`;
  return n.toLocaleString();
}

export function formatAge(startEpochMs: number): string {
  const diffSec = Math.max(0, Math.floor((Date.now() - startEpochMs) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const m = Math.floor(diffSec / 60);
  const s = diffSec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function formatRelativeTime(epochMs: number, lang: Lang): string {
  if (!epochMs || epochMs <= 0) {
    return lang === "zh" ? "刚刚" : "Just now";
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - epochMs) / 1000));
  if (diffSec < 60) return lang === "zh" ? "刚刚" : "Just now";
  const m = Math.floor(diffSec / 60);
  if (m < 60) return lang === "zh" ? `${m} 分钟前` : `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return lang === "zh" ? `${h} 小时前` : `${h}h ago`;
  const d = Math.floor(h / 24);
  return lang === "zh" ? `${d} 天前` : `${d}d ago`;
}

export function formatClockTime(epochMs: number): string {
  const d = new Date(epochMs);
  return d.toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function extractBadgeInitial(rawLabel: string): string {
  const cleaned = rawLabel
    .replace(
      /[\u{1F1E6}-\u{1F1FF}\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu,
      "",
    )
    .trim();
  if (cleaned.length > 0) {
    const ch = Array.from(cleaned)[0];
    return /[a-z]/i.test(ch) ? ch.toUpperCase() : ch;
  }
  const fallback = Array.from(rawLabel.trim())[0];
  return fallback ?? "P";
}

export function delayBadgeVariant(delay: number | undefined): string {
  if (!delay || delay === 0) return "badge-neutral";
  if (delay < 150) return "badge-emerald";
  if (delay < 400) return "badge-amber";
  return "badge-rose";
}

export function protocolBadgeVariant(proto: string): string {
  const lower = proto.toLowerCase();
  if (lower.includes("vless") || lower.includes("pq")) return "badge-sky";
  if (lower.includes("anytls") || lower.includes("trojan") || lower.includes("hy")) {
    return "badge-emerald";
  }
  if (lower.includes("2022") || lower.includes("ss") || lower.includes("shadowsocks")) {
    return "badge-amber";
  }
  return "badge-neutral";
}

export function prettyProtocolLabel(rawType: string): string {
  const lower = rawType.toLowerCase();
  if (lower === "vless") return "VLESS";
  if (lower === "trojan") return "Trojan";
  if (lower === "ss" || lower === "shadowsocks") return "SS";
  if (lower === "anytls") return "AnyTLS";
  if (lower === "vmess") return "VMess";
  if (lower === "hysteria2" || lower === "hy2") return "Hysteria2";
  if (lower === "tuic") return "TUIC";
  if (lower === "wireguard") return "WireGuard";
  if (lower === "socks5") return "SOCKS5";
  if (lower === "http") return "HTTP";
  if (lower === "selector") return "Selector";
  if (lower === "urltest") return "URLTest";
  if (lower === "fallback") return "Fallback";
  if (lower === "loadbalance") return "LoadBalance";
  return rawType;
}

export function nodeProtocolBadge(
  node: ProxyNodeConfigPayload | undefined,
  fallbackLabel?: string,
): string {
  if (!node) return fallbackLabel ? prettyProtocolLabel(fallbackLabel) : "Node";
  const isWs =
    (node.type === "vless" || node.type === "trojan") &&
    ((node.network ?? "").toLowerCase() === "ws" || Boolean(node["ws-opts"]));
  switch (node.type) {
    case "vless":
      return isWs ? "VLESS·WS" : "VLESS";
    case "trojan":
      return isWs ? "Trojan·WS" : "Trojan";
    case "anytls":
      return "AnyTLS";
    case "ss":
      return node.cipher.startsWith("2022-") ? "SS-2022" : "SS";
    case "socks5":
      return "SOCKS5";
    case "http":
      return node.tls ? "HTTPS" : "HTTP";
  }
}
