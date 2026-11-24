export type DashboardProbeAction = "probe" | "invalidate";

export function isCurrentProbe(
  seq: number,
  currentSeq: number,
  mounted: boolean,
): boolean;

export function decideMasterToggleProbeAction(params: {
  action: "enable" | "disable";
  demoEnabled?: boolean;
}): DashboardProbeAction;

export function decideSysProxyToggleProbeAction(params: {
  nextSysproxyEnabled: boolean;
  tunEnabled: boolean;
  demoEnabled?: boolean;
}): DashboardProbeAction;

export function decideTunToggleProbeAction(params: {
  sysproxyEnabled: boolean;
  nextTunEnabled: boolean;
  demoEnabled?: boolean;
}): DashboardProbeAction;

export function decideModeSwitchProbeAction(params: {
  proxyRunning: boolean;
  demoEnabled?: boolean;
}): DashboardProbeAction;
