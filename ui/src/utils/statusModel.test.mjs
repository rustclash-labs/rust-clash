import test from "node:test";
import assert from "node:assert/strict";
import {
  deriveExitIpDisplay,
  deriveMemoryDisplay,
  deriveThreeLayerStatus,
  planMasterToggle,
  resolveIntranetIpDisplay,
  summarizeSkippedUnsupported,
} from "./statusModel.mjs";

test("deriveMemoryDisplay never fabricates 28 MiB core or 0.36x UI heap", () => {
  const unavailable = deriveMemoryDisplay(0, 0);
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.totalBytes, null);
  assert.equal(unavailable.coreBytes, null);
  assert.equal(unavailable.uiBytes, null);

  // Non-Chromium WebView (no performance.memory) with real Core RSS
  const coreOnly = deriveMemoryDisplay(42 * 1024 * 1024, 0);
  assert.equal(coreOnly.available, true);
  assert.equal(coreOnly.coreBytes, 42 * 1024 * 1024);
  assert.equal(coreOnly.uiBytes, null);
  assert.equal(coreOnly.totalBytes, 42 * 1024 * 1024);
  assert.equal(coreOnly.corePct, 100);
  assert.equal(coreOnly.uiPct, 0);
});

test("deriveExitIpDisplay never guesses country from node text or claims Quality Normal when unprobed", () => {
  const unprobed = deriveExitIpDisplay({
    online: true,
    ipLoading: false,
    exitIp: null,
    effectiveOutbound: "🇯🇵 东京 IEPL 01",
  });
  assert.equal(unprobed.verified, false);
  assert.equal(unprobed.badgeCode, "—");
  assert.equal(unprobed.qualityZh, "尚未检测");
  assert.notEqual(unprobed.badgeCode, "JP");

  const directUnprobed = deriveExitIpDisplay({
    online: true,
    ipLoading: false,
    exitIp: null,
    effectiveOutbound: "DIRECT",
  });
  assert.notEqual(directUnprobed.badgeCode, "CN");

  const failed = deriveExitIpDisplay({
    online: true,
    ipLoading: false,
    exitIp: { ip: "", ok: false },
    effectiveOutbound: "US-Node-1",
  });
  assert.equal(failed.verified, false);
  assert.equal(failed.badgeCode, "!");
  assert.equal(failed.qualityZh, "不可达");

  const verified = deriveExitIpDisplay({
    online: true,
    ipLoading: false,
    exitIp: {
      ip: "203.0.113.88",
      country_code: "jp",
      latency_ms: 68,
      organization: "NTT",
      ok: true,
    },
    effectiveOutbound: "Node-A",
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.badgeCode, "JP");
  assert.equal(verified.headlineZh, "203.0.113.88");
  assert.equal(verified.qualityZh, "68 ms");
});

test("deriveThreeLayerStatus separates Core, System Takeover, and Internet Connectivity", () => {
  // SysProxy enabled, but probes timed out -> must NOT claim Connected/Normal!
  const brokenNet = deriveThreeLayerStatus({
    online: true,
    sysproxyEnabled: true,
    tunEnabled: false,
    mode: "rule",
    probing: false,
    googleMs: null,
    githubMs: null,
    exitIpOk: false,
  });
  assert.equal(brokenNet.core.state, "online");
  assert.equal(brokenNet.takeover.state, "sysproxy");
  assert.equal(brokenNet.connectivity.state, "unreachable");
  assert.equal(brokenNet.hero.pillClass, "error");
  assert.match(brokenNet.hero.zh, /联网异常/);

  // Direct mode with takeover active -> explicit warning pill
  const directTakeover = deriveThreeLayerStatus({
    online: true,
    sysproxyEnabled: true,
    tunEnabled: true,
    mode: "direct",
    probing: false,
    googleMs: 85,
    githubMs: 120,
    exitIpOk: true,
  });
  assert.equal(directTakeover.takeover.state, "sysproxy_and_tun");
  assert.equal(directTakeover.hero.directModeWarning, true);
  assert.equal(directTakeover.hero.pillClass, "warn");
});

test("planMasterToggle preserves takeover combination symmetrically and never touches routing mode", () => {
  // User enabled both SysProxy + TUN, then clicks Master Switch to pause
  const pausePlan = planMasterToggle(
    { sysproxyEnabled: true, tunEnabled: true, sysproxySupported: true },
    null,
  );
  assert.equal(pausePlan.action, "disable");
  assert.deepEqual(pausePlan.nextSavedPref, { sysproxy: true, tun: true });
  assert.equal("mode" in pausePlan, false);

  // User clicks Master Switch again to resume -> restores BOTH SysProxy + TUN
  const resumePlan = planMasterToggle(
    { sysproxyEnabled: false, tunEnabled: false, sysproxySupported: true },
    pausePlan.nextSavedPref,
  );
  assert.equal(resumePlan.action, "enable");
  assert.equal(resumePlan.targetSysproxy, true);
  assert.equal(resumePlan.targetTun, true);
});

test("resolveIntranetIpDisplay never fabricates 198.18.0.1", () => {
  assert.equal(resolveIntranetIpDisplay(null), null);
  assert.equal(resolveIntranetIpDisplay({}), null);
  assert.equal(
    resolveIntranetIpDisplay({ "intranet-ip": "192.168.31.45" }),
    "192.168.31.45",
  );
});

test("summarizeSkippedUnsupported groups protocols by count with sample names", () => {
  const summary = summarizeSkippedUnsupported([
    { name: "HK-VMess-1", protocol: "vmess", reason: "unsupported proxy type 'vmess'" },
    { name: "HK-VMess-2", protocol: "vmess", reason: "unsupported proxy type 'vmess'" },
    { name: "JP-Hy2-1", protocol: "hysteria2", reason: "unsupported proxy type 'hysteria2'" },
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.groups.length, 2);
  assert.equal(summary.groups[0].label, "VMess");
  assert.equal(summary.groups[0].count, 2);
  assert.equal(summary.groups[1].label, "Hysteria2");
  assert.equal(summary.groups[1].count, 1);
  assert.match(summary.protocolsSummaryZh, /VMess \(2\)/);
});
