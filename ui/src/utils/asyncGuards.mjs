// Pure, dependency-free async concurrency & polling lifecycle helpers for Web UI.
// Prevents HTTP/1.1 connection-pool starvation during latency storms and eliminates
// overlapping fallback polls or stale post-cleanup state mutations.

export const DEFAULT_PROBE_CONCURRENCY = 4;

/**
 * Runs `worker(item, index)` over `items` with at most `limit` concurrent executions
 * (defaulting to `DEFAULT_PROBE_CONCURRENCY = 4`).
 *
 * Unlike `Promise.all`, a failing/rejecting worker settles individually and never
 * aborts the remaining items; unlike fixed batch chunks, workers pick up the next
 * item immediately as each item settles (progressive completion).
 *
 * @template T, R
 * @param {Iterable<T> | null | undefined} items
 * @param {number | undefined} limit
 * @param {(item: T, index: number) => Promise<R> | R} worker
 * @returns {Promise<Array<PromiseSettledResult<R>>>}
 */
export async function runWithConcurrency(
  items,
  limit = DEFAULT_PROBE_CONCURRENCY,
  worker,
) {
  const list = items ? Array.from(items) : [];
  if (list.length === 0) {
    return [];
  }
  const resolvedLimit =
    typeof limit === "number" && Number.isFinite(limit) && limit >= 1
      ? Math.floor(limit)
      : DEFAULT_PROBE_CONCURRENCY;
  const workerCount = Math.min(list.length, resolvedLimit);
  /** @type {Array<PromiseSettledResult<R>>} */
  const results = new Array(list.length);
  let nextIndex = 0;

  const runWorker = async () => {
    while (true) {
      const idx = nextIndex;
      nextIndex += 1;
      if (idx >= list.length) {
        break;
      }
      try {
        const value = await worker(list[idx], idx);
        results[idx] = { status: "fulfilled", value };
      } catch (reason) {
        results[idx] = { status: "rejected", reason };
      }
    }
  };

  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  return results;
}

/**
 * Returns unique non-empty member names from `members` that are not already in `seen`,
 * inserting each accepted name into `seen` so overlapping proxy groups do not re-probe
 * the same nodes redundantly during `Test All`.
 *
 * @param {Iterable<string> | null | undefined} members
 * @param {Set<string>} [seen]
 * @returns {string[]}
 */
export function collectUniqueProbeTargets(members, seen = new Set()) {
  /** @type {string[]} */
  const targets = [];
  if (!members) {
    return targets;
  }
  for (const name of members) {
    if (typeof name !== "string" || name.length === 0) {
      continue;
    }
    if (seen.has(name)) {
      continue;
    }
    seen.add(name);
    targets.push(name);
  }
  return targets;
}

/**
 * Creates a single-flight, disposal-safe interval poller for WebSocket fallback polling.
 *
 * Guarantees:
 * - At most one `poll()` request is in flight at any time (`inFlight` guard across
 *   ticks and across `stop()`/`start()` cycles).
 * - Ticks are skipped while `disposed` or `isHidden()` is true.
 * - Neither `onSuccess` nor `onError` is invoked after `dispose()`, even if an
 *   in-flight poll settles later.
 *
 * @template T, TTimer
 * @param {{
 *   intervalMs: number;
 *   poll: () => Promise<T>;
 *   onSuccess?: (value: T) => void;
 *   onError?: (err: unknown) => void;
 *   isHidden?: () => boolean;
 *   setIntervalFn?: (fn: () => void, ms: number) => TTimer;
 *   clearIntervalFn?: (id: TTimer) => void;
 * }} options
 */
export function createGuardedPoller({
  intervalMs,
  poll,
  onSuccess,
  onError,
  isHidden = () => false,
  setIntervalFn = /** @type {(fn: () => void, ms: number) => any} */ (
    (fn, ms) => globalThis.setInterval(fn, ms)
  ),
  clearIntervalFn = /** @type {(id: any) => void} */ (
    (id) => globalThis.clearInterval(id)
  ),
}) {
  /** @type {TTimer | null} */
  let timerId = null;
  let inFlight = false;
  let disposed = false;

  const tick = () => {
    if (disposed || isHidden() || inFlight) {
      return;
    }
    inFlight = true;
    let pending;
    try {
      pending = Promise.resolve(poll());
    } catch (err) {
      pending = Promise.reject(err);
    }
    void pending
      .then((value) => {
        if (disposed) return;
        onSuccess?.(value);
      })
      .catch((err) => {
        if (disposed) return;
        onError?.(err);
      })
      .finally(() => {
        inFlight = false;
      });
  };

  return {
    start() {
      if (disposed || timerId !== null) return;
      timerId = setIntervalFn(tick, intervalMs);
    },
    stop() {
      if (timerId !== null) {
        clearIntervalFn(timerId);
        timerId = null;
      }
    },
    dispose() {
      disposed = true;
      if (timerId !== null) {
        clearIntervalFn(timerId);
        timerId = null;
      }
    },
    triggerTick() {
      tick();
    },
    isRunning() {
      return timerId !== null;
    },
    isInFlight() {
      return inFlight;
    },
    isDisposed() {
      return disposed;
    },
  };
}
