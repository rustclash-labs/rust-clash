// Pure monotonic probe guards and post-toggle probe decision helpers for DashboardView.
// Prevents slower earlier exit-IP or connectivity probes from overwriting newer probe
// results, prematurely clearing loading indicators, or firing while proxy takeover is off.

/**
 * Returns `true` strictly when the component is still mounted and `seq` still matches
 * the latest monotonic sequence number (`currentSeq`).
 *
 * @param {number} seq
 * @param {number} currentSeq
 * @param {boolean} mounted
 * @returns {boolean}
 */
export function isCurrentProbe(seq, currentSeq, mounted) {
  return Boolean(mounted) && seq === currentSeq;
}

/**
 * Decides whether `handleMasterToggle` should trigger fresh exit-IP / connectivity probes
 * (`"probe"`) or invalidate in-flight probes and reset loading indicators (`"invalidate"`).
 *
 * Only probes when enabling takeover (`action === "enable"`) or when Demo Mode stays active.
 *
 * @param {{ action: "enable" | "disable"; demoEnabled?: boolean }} params
 * @returns {"probe" | "invalidate"}
 */
export function decideMasterToggleProbeAction({ action, demoEnabled = false }) {
  return action === "enable" || Boolean(demoEnabled) ? "probe" : "invalidate";
}

/**
 * Decides whether `handleSysProxySwitch` should probe or invalidate in-flight probes.
 * Only probes when system proxy is turning ON, TUN remains active, or Demo Mode is active.
 *
 * @param {{ nextSysproxyEnabled: boolean; tunEnabled: boolean; demoEnabled?: boolean }} params
 * @returns {"probe" | "invalidate"}
 */
export function decideSysProxyToggleProbeAction({
  nextSysproxyEnabled,
  tunEnabled,
  demoEnabled = false,
}) {
  return nextSysproxyEnabled || tunEnabled || Boolean(demoEnabled)
    ? "probe"
    : "invalidate";
}

/**
 * Decides whether `handleTunSwitch` should probe or invalidate in-flight probes.
 * Only probes when TUN is turning ON, system proxy remains active, or Demo Mode is active.
 *
 * @param {{ sysproxyEnabled: boolean; nextTunEnabled: boolean; demoEnabled?: boolean }} params
 * @returns {"probe" | "invalidate"}
 */
export function decideTunToggleProbeAction({
  sysproxyEnabled,
  nextTunEnabled,
  demoEnabled = false,
}) {
  return sysproxyEnabled || nextTunEnabled || Boolean(demoEnabled)
    ? "probe"
    : "invalidate";
}

/**
 * Decides whether `handleModeSwitch` should probe or invalidate in-flight probes.
 * Only probes when proxy takeover is running or Demo Mode is active.
 *
 * @param {{ proxyRunning: boolean; demoEnabled?: boolean }} params
 * @returns {"probe" | "invalidate"}
 */
export function decideModeSwitchProbeAction({
  proxyRunning,
  demoEnabled = false,
}) {
  return proxyRunning || Boolean(demoEnabled) ? "probe" : "invalidate";
}
