import test from "node:test";
import assert from "node:assert/strict";
import {
  decideMasterToggleProbeAction,
  decideModeSwitchProbeAction,
  decideSysProxyToggleProbeAction,
  decideTunToggleProbeAction,
  isCurrentProbe,
} from "./dashboardProbes.mjs";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test("isCurrentProbe enforces monotonic sequence and mounted invariants", () => {
  assert.equal(isCurrentProbe(1, 1, true), true);
  assert.equal(isCurrentProbe(1, 2, true), false);
  assert.equal(isCurrentProbe(2, 2, false), false);
  assert.equal(isCurrentProbe(1, 2, false), false);
});

test("monotonic sequence prevents out-of-order probes from overwriting newer results or clearing loading early", async () => {
  const seqRef = { current: 0 };
  const mountedRef = { current: true };
  let loading = false;
  let value = null;

  const runProbe = async (promise) => {
    const seq = ++seqRef.current;
    loading = true;
    try {
      const result = await promise;
      if (!isCurrentProbe(seq, seqRef.current, mountedRef.current)) return;
      value = result;
    } catch {
      if (!isCurrentProbe(seq, seqRef.current, mountedRef.current)) return;
      value = "error";
    } finally {
      if (isCurrentProbe(seq, seqRef.current, mountedRef.current)) {
        loading = false;
      }
    }
  };

  // Start slow probe #1, then fast probe #2.
  const p1 = deferred();
  const p2 = deferred();
  const task1 = runProbe(p1.promise);
  const task2 = runProbe(p2.promise);
  assert.equal(loading, true);

  // Probe #2 completes first -> applies result and stops loading.
  p2.resolve("JP-203.0.113.2");
  await task2;
  assert.equal(value, "JP-203.0.113.2");
  assert.equal(loading, false);

  // Slow probe #1 settles later -> ignored completely!
  p1.resolve("US-198.51.100.1");
  await task1;
  assert.equal(value, "JP-203.0.113.2");
  assert.equal(loading, false);

  // Now test early settlement of superseded probe NOT clearing loading while newer probe is still running.
  const p3 = deferred();
  const p4 = deferred();
  const task3 = runProbe(p3.promise);
  const task4 = runProbe(p4.promise);
  p3.reject(new Error("aborted old node"));
  await task3;
  assert.equal(loading, true, "superseded probe must not clear loading for probe #4");
  assert.equal(value, "JP-203.0.113.2");

  // Disable proxy invalidates in-flight probe #4 immediately.
  seqRef.current += 1;
  loading = false;
  p4.resolve("SG-192.0.2.4");
  await task4;
  assert.equal(value, "JP-203.0.113.2", "invalidated probe must not overwrite after turn-off");
  assert.equal(loading, false);

  // Unmount suppresses state mutations even when seq matches.
  const p5 = deferred();
  const task5 = runProbe(p5.promise);
  mountedRef.current = false;
  p5.resolve("DE-192.0.2.5");
  await task5;
  assert.equal(value, "JP-203.0.113.2");
});

test("decideMasterToggleProbeAction only probes on enable or demo mode, invalidates on disable", () => {
  assert.equal(
    decideMasterToggleProbeAction({ action: "enable", demoEnabled: false }),
    "probe",
  );
  assert.equal(
    decideMasterToggleProbeAction({ action: "disable", demoEnabled: false }),
    "invalidate",
  );
  assert.equal(
    decideMasterToggleProbeAction({ action: "disable", demoEnabled: true }),
    "probe",
  );
});

test("decideSysProxyToggleProbeAction invalidates when turning off sysproxy with TUN and demo off", () => {
  assert.equal(
    decideSysProxyToggleProbeAction({
      nextSysproxyEnabled: false,
      tunEnabled: false,
      demoEnabled: false,
    }),
    "invalidate",
  );
  assert.equal(
    decideSysProxyToggleProbeAction({
      nextSysproxyEnabled: true,
      tunEnabled: false,
      demoEnabled: false,
    }),
    "probe",
  );
  assert.equal(
    decideSysProxyToggleProbeAction({
      nextSysproxyEnabled: false,
      tunEnabled: true,
      demoEnabled: false,
    }),
    "probe",
  );
  assert.equal(
    decideSysProxyToggleProbeAction({
      nextSysproxyEnabled: false,
      tunEnabled: false,
      demoEnabled: true,
    }),
    "probe",
  );
});

test("decideTunToggleProbeAction invalidates when turning off TUN with sysproxy and demo off", () => {
  assert.equal(
    decideTunToggleProbeAction({
      sysproxyEnabled: false,
      nextTunEnabled: false,
      demoEnabled: false,
    }),
    "invalidate",
  );
  assert.equal(
    decideTunToggleProbeAction({
      sysproxyEnabled: false,
      nextTunEnabled: true,
      demoEnabled: false,
    }),
    "probe",
  );
  assert.equal(
    decideTunToggleProbeAction({
      sysproxyEnabled: true,
      nextTunEnabled: false,
      demoEnabled: false,
    }),
    "probe",
  );
  assert.equal(
    decideTunToggleProbeAction({
      sysproxyEnabled: false,
      nextTunEnabled: false,
      demoEnabled: true,
    }),
    "probe",
  );
});

test("decideModeSwitchProbeAction only probes when proxyRunning or demoEnabled", () => {
  assert.equal(
    decideModeSwitchProbeAction({ proxyRunning: false, demoEnabled: false }),
    "invalidate",
  );
  assert.equal(
    decideModeSwitchProbeAction({ proxyRunning: true, demoEnabled: false }),
    "probe",
  );
  assert.equal(
    decideModeSwitchProbeAction({ proxyRunning: false, demoEnabled: true }),
    "probe",
  );
});
