import test from "node:test";
import assert from "node:assert/strict";
import { verifyAndCommitControllerSecret } from "./controllerAuth.mjs";
import {
  readScopedSessionSecret,
  serializeScopedSessionSecret,
} from "./controllerSecret.mjs";

test("verifyAndCommitControllerSecret does NOT call saveSettings when probe rejects with 401", async () => {
  const stored = {
    baseUrl: "http://192.168.1.50:9090",
    rawSession: serializeScopedSessionSecret(
      "existing-good-secret",
      "http://192.168.1.50:9090",
    ),
  };
  const callOrder = [];

  await assert.rejects(
    () =>
      verifyAndCommitControllerSecret({
        loadSettings: () => ({
          baseUrl: stored.baseUrl,
          secret: readScopedSessionSecret(stored.rawSession, stored.baseUrl),
        }),
        probeSettings: async (candidate) => {
          callOrder.push(["probe", candidate]);
          const err = new Error("Unauthorized");
          err.status = 401;
          throw err;
        },
        saveSettings: (next) => {
          callOrder.push(["save", next]);
          stored.rawSession = serializeScopedSessionSecret(
            next.secret,
            next.baseUrl,
          );
        },
        candidateSecret: "wrong-typo-secret",
      }),
    (err) => err instanceof Error && err.status === 401,
  );

  assert.deepEqual(callOrder, [
    [
      "probe",
      { baseUrl: "http://192.168.1.50:9090", secret: "wrong-typo-secret" },
    ],
  ]);
  assert.equal(
    readScopedSessionSecret(stored.rawSession, stored.baseUrl),
    "existing-good-secret",
  );
});

test("verifyAndCommitControllerSecret does NOT call saveSettings on network error", async () => {
  let saved = false;

  await assert.rejects(
    () =>
      verifyAndCommitControllerSecret({
        loadSettings: () => ({ baseUrl: "", secret: "local-good-secret" }),
        probeSettings: async () => {
          throw new Error("Cannot reach RustClash controller API");
        },
        saveSettings: () => {
          saved = true;
        },
        candidateSecret: "new-secret",
      }),
    /Cannot reach RustClash controller API/,
  );

  assert.equal(saved, false);
});

test("verifyAndCommitControllerSecret probes first and commits scoped secret only after probe succeeds", async () => {
  const stored = {
    baseUrl: "http://10.0.0.8:9090",
    rawSession: serializeScopedSessionSecret(
      "old-secret",
      "http://10.0.0.8:9090",
    ),
  };
  const callOrder = [];

  const result = await verifyAndCommitControllerSecret({
    loadSettings: () => ({
      baseUrl: stored.baseUrl,
      secret: readScopedSessionSecret(stored.rawSession, stored.baseUrl),
    }),
    probeSettings: async (candidate) => {
      callOrder.push(["probe", candidate]);
      // Confirm storage still holds old secret while probing.
      assert.equal(
        readScopedSessionSecret(stored.rawSession, stored.baseUrl),
        "old-secret",
      );
      return { version: "0.5.15" };
    },
    saveSettings: (next) => {
      callOrder.push(["save", next]);
      stored.rawSession = serializeScopedSessionSecret(
        next.secret,
        next.baseUrl,
      );
    },
    candidateSecret: "fresh-valid-secret",
  });

  assert.deepEqual(result, {
    settings: { baseUrl: "http://10.0.0.8:9090", secret: "fresh-valid-secret" },
    version: { version: "0.5.15" },
  });
  assert.deepEqual(callOrder, [
    [
      "probe",
      { baseUrl: "http://10.0.0.8:9090", secret: "fresh-valid-secret" },
    ],
    [
      "save",
      { baseUrl: "http://10.0.0.8:9090", secret: "fresh-valid-secret" },
    ],
  ]);
  assert.equal(
    readScopedSessionSecret(stored.rawSession, stored.baseUrl),
    "fresh-valid-secret",
  );
  // M2 scoping invariant: secret saved for 10.0.0.8 is NOT readable for another host.
  assert.equal(
    readScopedSessionSecret(stored.rawSession, "http://10.0.0.9:9090"),
    "",
  );
});
