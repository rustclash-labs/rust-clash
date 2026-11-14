import type { ConfigSnapshot, ExitIpInfo, SkippedProxyEntry, RunMode } from "../types";

export type LayerTone = "emerald" | "sky" | "amber" | "rose" | "neutral";

export interface LayerBadgeInfo {
  state: string;
  tone: LayerTone;
  zh: string;
  en: string;
  active?: boolean;
}

export interface HeroStatusInfo {
  pillClass: "running" | "checking" | "warn" | "error" | "direct" | "offline";
  zh: string;
  en: string;
  directModeWarning: boolean;
}

export interface ThreeLayerStatus {
  core: LayerBadgeInfo;
  takeover: LayerBadgeInfo & { active: boolean };
  connectivity: LayerBadgeInfo;
  hero: HeroStatusInfo;
}

export function deriveThreeLayerStatus(input: {
  online: boolean;
  sysproxyEnabled: boolean;
  tunEnabled: boolean;
  mixedPort?: number;
  mode?: RunMode;
  demoEnabled?: boolean;
  probing?: boolean;
  googleMs?: number | null;
  githubMs?: number | null;
  exitIpOk?: boolean | null;
}): ThreeLayerStatus;

export interface MemoryDisplayModel {
  available: boolean;
  totalBytes: number | null;
  coreBytes: number | null;
  uiBytes: number | null;
  corePct: number;
  uiPct: number;
}

export function deriveMemoryDisplay(
  coreRssBytes?: number | null,
  jsHeapBytes?: number | null,
): MemoryDisplayModel;

export interface ExitIpDisplayModel {
  verified: boolean;
  badgeCode: string;
  headlineZh: string;
  headlineEn: string;
  qualityZh: string;
  qualityEn: string;
  orgZh: string;
  orgEn: string;
}

export function deriveExitIpDisplay(input: {
  online: boolean;
  ipLoading: boolean;
  exitIp?: ExitIpInfo | null;
  demoEnabled?: boolean;
  effectiveOutbound?: string;
  effectiveProto?: string;
}): ExitIpDisplayModel;

export function resolveIntranetIpDisplay(
  config?: ConfigSnapshot | null,
): string | null;

export interface TakeoverPref {
  sysproxy: boolean;
  tun: boolean;
}

export interface MasterTogglePlan {
  action: "enable" | "disable";
  nextSavedPref: TakeoverPref;
  targetSysproxy: boolean;
  targetTun: boolean;
}

export function planMasterToggle(
  current: {
    sysproxyEnabled: boolean;
    tunEnabled: boolean;
    sysproxySupported?: boolean;
  },
  savedPref?: Partial<TakeoverPref> | null,
): MasterTogglePlan;

export interface SkippedProtocolGroup {
  protocol: string;
  label: string;
  count: number;
  sampleNames: string[];
  sampleReason: string;
}

export function summarizeSkippedUnsupported(
  entries?: SkippedProxyEntry[] | null,
): {
  total: number;
  groups: SkippedProtocolGroup[];
  protocolsSummaryZh: string;
  protocolsSummaryEn: string;
};
