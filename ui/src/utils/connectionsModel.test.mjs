import test from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_CONNECTIONS,
  resolveDisplayedConnections,
  resolveLiveConnections,
  transitionConnectionsPauseState,
} from "./connectionsModel.mjs";

test("resolveLiveConnections returns a referentially stable frozen EMPTY_CONNECTIONS when connections is null or undefined", () => {
  const r1 = resolveLiveConnections(null);
  const r2 = resolveLiveConnections(null);
  const r3 = resolveLiveConnections(undefined);
  const r4 = resolveLiveConnections({});

  assert.strictEqual(r1, EMPTY_CONNECTIONS);
  assert.strictEqual(r1, r2);
  assert.strictEqual(r1, r3);
  assert.strictEqual(r1, r4);
  assert.equal(r1.length, 0);
  assert.equal(Object.isFrozen(EMPTY_CONNECTIONS), true);

  const live = [{ id: "conn-1" }, { id: "conn-2" }];
  assert.strictEqual(resolveLiveConnections({ connections: live }), live);
});

test("pause/resume preserves the frozen snapshot across live updates and resumes cleanly without render-loop mutations", () => {
  // Initial unpaused state with null connections keeps stable EMPTY_CONNECTIONS reference.
  let state = { paused: false, frozenItems: EMPTY_CONNECTIONS };
  const initialLive = resolveLiveConnections(null);
  const initialDisplay = resolveDisplayedConnections(
    state.paused,
    initialLive,
    state.frozenItems,
  );
  assert.strictEqual(initialDisplay, EMPTY_CONNECTIONS);

  // Live tick 1 arrives while unpaused -> displays live snapshot directly.
  const tick1 = [{ id: "c1" }, { id: "c2" }];
  const live1 = resolveLiveConnections({ connections: tick1 });
  assert.strictEqual(
    resolveDisplayedConnections(state.paused, live1, state.frozenItems),
    tick1,
  );

  // User clicks Pause -> captures tick1 snapshot atomically.
  state = transitionConnectionsPauseState(state, live1);
  assert.equal(state.paused, true);
  assert.strictEqual(state.frozenItems, tick1);

  // Live tick 2 arrives (and even transient null) while paused -> display stays frozen at tick1!
  const tick2 = [{ id: "c3" }];
  const live2 = resolveLiveConnections({ connections: tick2 });
  assert.strictEqual(
    resolveDisplayedConnections(state.paused, live2, state.frozenItems),
    tick1,
  );
  assert.strictEqual(
    resolveDisplayedConnections(
      state.paused,
      resolveLiveConnections(null),
      state.frozenItems,
    ),
    tick1,
  );

  // User clicks Resume -> clears frozen snapshot and displays latest live items immediately.
  state = transitionConnectionsPauseState(state, live2);
  assert.equal(state.paused, false);
  assert.strictEqual(state.frozenItems, EMPTY_CONNECTIONS);
  assert.strictEqual(
    resolveDisplayedConnections(state.paused, live2, state.frozenItems),
    tick2,
  );
});

test("pausing while connections is null freezes EMPTY_CONNECTIONS until resumed", () => {
  let state = { paused: false, frozenItems: EMPTY_CONNECTIONS };
  const nullLive = resolveLiveConnections(null);

  state = transitionConnectionsPauseState(state, nullLive);
  assert.equal(state.paused, true);
  assert.strictEqual(state.frozenItems, EMPTY_CONNECTIONS);

  const arrivedLater = [{ id: "late-1" }];
  assert.strictEqual(
    resolveDisplayedConnections(
      state.paused,
      resolveLiveConnections({ connections: arrivedLater }),
      state.frozenItems,
    ),
    EMPTY_CONNECTIONS,
  );

  state = transitionConnectionsPauseState(state, arrivedLater);
  assert.equal(state.paused, false);
  assert.strictEqual(
    resolveDisplayedConnections(
      state.paused,
      resolveLiveConnections({ connections: arrivedLater }),
      state.frozenItems,
    ),
    arrivedLater,
  );
});
