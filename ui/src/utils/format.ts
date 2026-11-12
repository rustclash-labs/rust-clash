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

export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
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

export function formatClockTime(epochMs: number): string {
  const d = new Date(epochMs);
  return d.toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function delayBadgeVariant(delay: number | undefined): string {
  if (!delay || delay === 0) return "badge-neutral";
  if (delay < 150) return "badge-emerald";
  if (delay < 400) return "badge-amber";
  return "badge-rose";
}

import type { ProxyNodeConfigPayload } from "../types";

export function protocolBadgeVariant(proto: string): string {
  const lower = proto.toLowerCase();
  if (lower.includes("vless") || lower.includes("pq")) return "badge-emerald";
  if (lower.includes("anytls") || lower.includes("trojan")) return "badge-sky";
  if (lower.includes("2022") || lower.includes("ss") || lower.includes("shadowsocks")) {
    return "badge-amber";
  }
  return "badge-neutral";
}

export function nodeProtocolBadge(
  node: ProxyNodeConfigPayload | undefined,
  fallbackLabel?: string,
): string {
  if (!node) return fallbackLabel ?? "Unknown";
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

