import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_PROBE_CONCURRENCY,
  collectUniqueProbeTargets,
  createGuardedPoller,
  runWithConcurrency,
} from "./asyncGuards.mjs";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test("runWithConcurrency enforces default concurrency limit of 4 across large proxy lists", async () => {
  assert.equal(DEFAULT_PROBE_CONCURRENCY, 4);

  const items = Array.from({ length: 20 }, (_, i) => `node-${i}`);
  let active = 0;
  let peakActive = 0;
  const settledOrder = [];

  const results = await runWithConcurrency(items, undefined, async (name, idx) => {
    active += 1;
    peakActive = Math.max(peakActive, active);
    // Vary completion durations so fast items settle progressively without waiting on slow peers.
    const delayMs = idx % 4 === 0 ? 18 : 2;
    await new Promise((r) => setTimeout(r, delayMs));
    active -= 1;
    settledOrder.push(name);
    return `${name}:ok`;
  });

  assert.equal(active, 0);
  assert.equal(peakActive, 4);
  assert.equal(results.length, items.length);
  assert.equal(settledOrder.length, items.length);
  for (let i = 0; i < items.length; i += 1) {
    assert.deepEqual(results[i], {
      status: "fulfilled",
      value: `node-${i}:ok`,
    });
  }
});

test("runWithConcurrency settles items progressively without blocking on a slow worker", async () => {
  const gates = [deferred(), deferred(), deferred(), deferred(), deferred(), deferred()];
  const cleared = [];

  const runPromise = runWithConcurrency(
    ["slow-0", "fast-1", "fast-2", "fast-3", "fast-4", "fast-5"],
    4,
    async (name, idx) => {
      try {
        return await gates[idx].promise;
      } finally {
        cleared.push(name);
      }
    },
  );

  // Resolve fast-1 while slow-0 is still pending; fast-1 should settle and free a slot for fast-4.
  gates[1].resolve(11);
  await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(cleared, ["fast-1"]);

  // Now fast-4 is running while slow-0 is still blocked!
  gates[4].resolve(44);
  gates[2].resolve(22);
  gates[3].resolve(33);
  gates[5].resolve(55);
  await new Promise((r) => setTimeout(r, 5));
  assert.ok(cleared.includes("fast-4"));
  assert.ok(cleared.includes("fast-5"));
  assert.ok(!cleared.includes("slow-0"));

  // Finally resolve slow-0.
  gates[0].resolve(100);
  const results = await runPromise;
  assert.equal(cleared[cleared.length - 1], "slow-0");
  assert.deepEqual(
    results.map((r) => (r.status === "fulfilled" ? r.value : null)),
    [100, 11, 22, 33, 44, 55],
  );
});

test("runWithConcurrency isolates async rejections and sync throws without aborting remaining nodes", async () => {
  const visited = [];
  const results = await runWithConcurrency(
    ["ok-0", "async-fail-1", "sync-fail-2", "ok-3", "ok-4", "ok-5"],
    2,
    (name) => {
      visited.push(name);
      if (name === "sync-fail-2") {
        throw new Error("sync boom");
      }
      if (name === "async-fail-1") {
        return Promise.reject(new Error("timeout 4000ms"));
      }
      return Promise.resolve(name.toUpperCase());
    },
  );

  assert.equal(visited.length, 6);
  assert.equal(results[0].status, "fulfilled");
  assert.equal(results[1].status, "rejected");
  assert.match(results[1].reason.message, /timeout 4000ms/);
  assert.equal(results[2].status, "rejected");
  assert.match(results[2].reason.message, /sync boom/);
  assert.deepEqual(results[3], { status: "fulfilled", value: "OK-3" });
  assert.deepEqual(results[4], { status: "fulfilled", value: "OK-4" });
  assert.deepEqual(results[5], { status: "fulfilled", value: "OK-5" });
});

test("runWithConcurrency handles empty/null lists and invalid limits safely", async () => {
  assert.deepEqual(await runWithConcurrency([], 4, async () => 1), []);
  assert.deepEqual(await runWithConcurrency(null, 4, async () => 1), []);

  let active = 0;
  let peak = 0;
  const res = await runWithConcurrency(["a", "b", "c", "d", "e"], 0, async (x) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 2));
    active -= 1;
    return x;
  });
  assert.equal(peak, DEFAULT_PROBE_CONCURRENCY);
  assert.equal(res.length, 5);
});

test("collectUniqueProbeTargets deduplicates within a group and across overlapping groups", () => {
  const seen = new Set();

  const groupA = collectUniqueProbeTargets(
    ["HK-01", "JP-01", "HK-01", "", "US-01"],
    seen,
  );
  assert.deepEqual(groupA, ["HK-01", "JP-01", "US-01"]);

  const groupB = collectUniqueProbeTargets(
    ["JP-01", "SG-01", "US-01", "DE-01"],
    seen,
  );
  assert.deepEqual(groupB, ["SG-01", "DE-01"]);

  const globalGroup = collectUniqueProbeTargets(
    ["DIRECT", "HK-01", "JP-01", "SG-01", "DE-01"],
    seen,
  );
  assert.deepEqual(globalGroup, ["DIRECT"]);

  // Standalone call without shared `seen` only deduplicates within the single list.
  assert.deepEqual(collectUniqueProbeTargets(["A", "B", "A"]), ["A", "B"]);
});

test("createGuardedPoller prevents overlapping inFlight ticks and skips when document is hidden", async () => {
  let scheduledCallback = null;
  let clearCount = 0;
  let hidden = false;
  const gates = [];
  const successes = [];

  const poller = createGuardedPoller({
    intervalMs: 2000,
    isHidden: () => hidden,
    poll: () => {
      const d = deferred();
      gates.push(d);
      return d.promise;
    },
    onSuccess: (v) => successes.push(v),
    setIntervalFn: (fn) => {
      scheduledCallback = fn;
      return 101;
    },
    clearIntervalFn: (id) => {
      assert.equal(id, 101);
      clearCount += 1;
      scheduledCallback = null;
    },
  });

  poller.start();
  // Idempotent second start does not register another interval.
  poller.start();
  assert.equal(poller.isRunning(), true);
  assert.equal(typeof scheduledCallback, "function");

  // Tick 1 starts poll #1.
  scheduledCallback();
  assert.equal(gates.length, 1);
  assert.equal(poller.isInFlight(), true);

  // Ticks 2 & 3 while poll #1 is still in flight MUST NOT fire overlapping polls.
  scheduledCallback();
  scheduledCallback();
  assert.equal(gates.length, 1);

  // Even stopping and restarting while poll #1 is still in flight must NOT overlap.
  poller.stop();
  assert.equal(clearCount, 1);
  poller.start();
  scheduledCallback();
  assert.equal(gates.length, 1);

  // Resolve poll #1 -> clears inFlight and invokes onSuccess.
  gates[0].resolve("snap-1");
  await Promise.resolve();
  await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(poller.isInFlight(), false);
  assert.deepEqual(successes, ["snap-1"]);

  // When hidden, tick must not fire poll.
  hidden = true;
  scheduledCallback();
  assert.equal(gates.length, 1);

  // When visible again, tick fires poll #2.
  hidden = false;
  scheduledCallback();
  assert.equal(gates.length, 2);
  gates[1].resolve("snap-2");
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(successes, ["snap-1", "snap-2"]);

  poller.dispose();
  assert.equal(poller.isDisposed(), true);
  assert.equal(poller.isRunning(), false);
  assert.equal(clearCount, 2);
});

test("createGuardedPoller suppresses both onSuccess and onError after dispose()", async () => {
  const gateOk = deferred();
  const gateErr = deferred();
  const successes = [];
  const errors = [];

  const pollerOk = createGuardedPoller({
    intervalMs: 2000,
    poll: () => gateOk.promise,
    onSuccess: (v) => successes.push(v),
    onError: (e) => errors.push(e),
    setIntervalFn: () => 1,
    clearIntervalFn: () => {},
  });
  pollerOk.triggerTick();
  assert.equal(pollerOk.isInFlight(), true);
  pollerOk.dispose();
  gateOk.resolve("stale-data");
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(successes, []);
  assert.equal(pollerOk.isInFlight(), false);

  const pollerErr = createGuardedPoller({
    intervalMs: 2000,
    poll: () => gateErr.promise,
    onSuccess: (v) => successes.push(v),
    onError: (e) => errors.push(e),
    setIntervalFn: () => 2,
    clearIntervalFn: () => {},
  });
  pollerErr.triggerTick();
  pollerErr.dispose();
  gateErr.reject(new Error("stale-network-failure"));
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(errors, []);
  assert.equal(pollerErr.isInFlight(), false);

  // Subsequent start() or triggerTick() after dispose() are complete no-ops.
  pollerErr.start();
  assert.equal(pollerErr.isRunning(), false);
  pollerErr.triggerTick();
  assert.equal(pollerErr.isInFlight(), false);
});
