// Pure, dependency-free state helpers for ConnectionsView.
// Guarantees a referentially stable empty list when `connections` is null/undefined
// and snapshots live items strictly on Pause transitions (avoiding render-loop effects).

/** @type {readonly never[]} */
export const EMPTY_CONNECTIONS = Object.freeze([]);

/**
 * Returns the live connection items from a `/connections` snapshot, falling back
 * to a module-scoped stable empty array when `connections` is null or undefined.
 *
 * @template T
 * @param {{ connections?: readonly T[] | null } | null | undefined} connections
 * @returns {readonly T[]}
 */
export function resolveLiveConnections(connections) {
  return connections?.connections ?? EMPTY_CONNECTIONS;
}

/**
 * Selects either the frozen snapshot (while paused) or the live items list.
 *
 * @template T
 * @param {boolean} paused
 * @param {readonly T[]} liveItems
 * @param {readonly T[]} frozenItems
 * @returns {readonly T[]}
 */
export function resolveDisplayedConnections(paused, liveItems, frozenItems) {
  return paused ? frozenItems : liveItems;
}

/**
 * Pure transition for toggling the Connections table Pause/Resume control.
 * Snapshots `liveItems` ONLY when transitioning from live -> paused, and clears
 * `frozenItems` back to `EMPTY_CONNECTIONS` on resume so stale snapshots are released.
 *
 * @template T
 * @param {{ paused: boolean; frozenItems: readonly T[] }} state
 * @param {readonly T[]} liveItems
 * @returns {{ paused: boolean; frozenItems: readonly T[] }}
 */
export function transitionConnectionsPauseState(state, liveItems) {
  if (!state.paused) {
    return {
      paused: true,
      frozenItems: liveItems,
    };
  }
  return {
    paused: false,
    frozenItems: EMPTY_CONNECTIONS,
  };
}
