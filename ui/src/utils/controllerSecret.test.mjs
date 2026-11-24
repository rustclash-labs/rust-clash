import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeControllerBaseUrl,
  readScopedSessionSecret,
  resolveEffectiveSecret,
  serializeScopedSessionSecret,
} from "./controllerSecret.mjs";

test("normalizeControllerBaseUrl trims whitespace and strips trailing slashes", () => {
  assert.equal(normalizeControllerBaseUrl(""), "");
  assert.equal(normalizeControllerBaseUrl("   "), "");
  assert.equal(normalizeControllerBaseUrl("///"), "");
  assert.equal(normalizeControllerBaseUrl("  ///  "), "");
  assert.equal(normalizeControllerBaseUrl(null), "");
  assert.equal(normalizeControllerBaseUrl(undefined), "");
  assert.equal(
    normalizeControllerBaseUrl("https://remote.example:9090"),
    "https://remote.example:9090",
  );
  assert.equal(
    normalizeControllerBaseUrl("http://10.0.0.2:9090/"),
    "http://10.0.0.2:9090",
  );
  assert.equal(
    normalizeControllerBaseUrl("  https://evil.test:9090///  "),
    "https://evil.test:9090",
  );
});

test("resolveEffectiveSecret falls back to sessionSecret then desktopSecret for local empty baseUrl", () => {
  for (const localBase of ["", "   ", "///", "  /  "]) {
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: localBase, secret: "" },
        "  session-token  ",
        "desktop-secret",
      ),
      "session-token",
    );
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: localBase, secret: "   " },
        "",
        "  desktop-secret  ",
      ),
      "desktop-secret",
    );
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: localBase, secret: "" },
        "   ",
        "desktop-secret",
      ),
      "desktop-secret",
    );
    assert.equal(
      resolveEffectiveSecret({ baseUrl: localBase, secret: "" }, "", ""),
      "",
    );
    assert.equal(
      resolveEffectiveSecret({ baseUrl: localBase, secret: "" }),
      "",
    );
  }
});

test("resolveEffectiveSecret uses trimmed explicit secret for local baseUrl", () => {
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "", secret: "  explicit-local-secret  " },
      "session-token",
      "desktop-secret",
    ),
    "explicit-local-secret",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "   ", secret: "explicit-local" },
      "",
      "desktop-secret",
    ),
    "explicit-local",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "///", secret: "\texplicit-slash\n" },
      "session-token",
      "desktop-secret",
    ),
    "explicit-slash",
  );
});

test("resolveEffectiveSecret NEVER leaks desktopSecret or stale sessionSecret to remote baseUrl", () => {
  const remoteBases = [
    "https://remote.example:9090",
    "http://10.0.0.2:9090/",
    "  https://evil.test:9090/  ",
    "  http://127.0.0.1:9999/// ",
    "https://controller.internal/api/",
  ];

  for (const remoteBase of remoteBases) {
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: remoteBase, secret: "" },
        "stale-session-secret",
        "tauri-desktop-secret",
      ),
      "",
      `must not leak secrets to remote baseUrl ${JSON.stringify(remoteBase)}`,
    );
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: remoteBase, secret: "   " },
        "stale-session-secret",
        "tauri-desktop-secret",
      ),
      "",
      `whitespace-only secret must not fall back to local secrets for ${JSON.stringify(remoteBase)}`,
    );
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: remoteBase, secret: "" },
        "",
        "tauri-desktop-secret",
      ),
      "",
      `probe path must not leak desktopSecret to ${JSON.stringify(remoteBase)}`,
    );
    assert.equal(
      resolveEffectiveSecret(
        { baseUrl: remoteBase, secret: "" },
        "stale-session-secret",
        "",
      ),
      "",
      `must not leak sessionSecret to ${JSON.stringify(remoteBase)}`,
    );
  }
});

test("resolveEffectiveSecret returns trimmed explicit secret for remote baseUrl", () => {
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "https://remote.example:9090", secret: "  remote-key-123  " },
      "stale-session-secret",
      "tauri-desktop-secret",
    ),
    "remote-key-123",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "  http://10.0.0.2:9090/  ", secret: "remote-token" },
      "",
      "tauri-desktop-secret",
    ),
    "remote-token",
  );
});

test("resolveEffectiveSecret handles null, undefined, and whitespace edge cases safely", () => {
  assert.equal(
    resolveEffectiveSecret(null, "session-only", "desktop-only"),
    "session-only",
  );
  assert.equal(
    resolveEffectiveSecret(undefined, null, "desktop-only"),
    "desktop-only",
  );
  assert.equal(
    resolveEffectiveSecret({}, undefined, null),
    "",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: null, secret: undefined },
      "   ",
      "  fallback-desktop  ",
    ),
    "fallback-desktop",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "https://remote.example:9090", secret: null },
      "session-secret",
      "desktop-secret",
    ),
    "",
  );
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "https://remote.example:9090", secret: undefined },
      "session-secret",
      "desktop-secret",
    ),
    "",
  );
});

test("resolveEffectiveSecret matches probeControllerSettings contract (no stale sessionSecret)", () => {
  // Local probe with cleared secret input ignores sessionSecret (passed as "")
  // and falls back only to discovered desktopSecret.
  assert.equal(
    resolveEffectiveSecret({ baseUrl: "", secret: "" }, "", "tauri-desktop-secret"),
    "tauri-desktop-secret",
  );
  assert.equal(
    resolveEffectiveSecret({ baseUrl: "", secret: "" }, "", ""),
    "",
  );
  // Remote probe with empty secret never sends discovered desktopSecret.
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "https://remote.example:9090", secret: "" },
      "",
      "tauri-desktop-secret",
    ),
    "",
  );
  // Remote probe with explicit secret sends trimmed explicit secret.
  assert.equal(
    resolveEffectiveSecret(
      { baseUrl: "https://remote.example:9090/", secret: "  probe-token  " },
      "",
      "tauri-desktop-secret",
    ),
    "probe-token",
  );
});

test("serializeScopedSessionSecret trims secret, normalizes baseUrl, and returns empty for blank secrets", () => {
  assert.equal(serializeScopedSessionSecret("", "https://remote.example:9090"), "");
  assert.equal(serializeScopedSessionSecret("   \t\n ", "https://remote.example:9090"), "");
  assert.equal(serializeScopedSessionSecret(null, ""), "");
  assert.equal(serializeScopedSessionSecret(undefined, undefined), "");

  assert.deepEqual(
    JSON.parse(serializeScopedSessionSecret("  local-boot-token  ", "")),
    { v: 1, baseUrl: "", secret: "local-boot-token" },
  );
  assert.deepEqual(
    JSON.parse(serializeScopedSessionSecret("local-token", "  ///  ")),
    { v: 1, baseUrl: "", secret: "local-token" },
  );
  assert.deepEqual(
    JSON.parse(
      serializeScopedSessionSecret(
        "  remote-a-secret  ",
        "  https://controller-a.test:9090///  ",
      ),
    ),
    {
      v: 1,
      baseUrl: "https://controller-a.test:9090",
      secret: "remote-a-secret",
    },
  );
});

test("readScopedSessionSecret rejects legacy bare-string sessionStorage values for all remote baseUrls", () => {
  const remoteBases = [
    "https://attacker.test:9090",
    "http://10.0.0.5:9090/",
    "  https://attacker.test:9090/  ",
    "//attacker.test:9090",
    "http://127.0.0.1:9999",
    "https://attacker.test:9090\t\n",
    "\thttps://attacker.test:9090/\r\n",
  ];

  for (const legacyRaw of ["STALE_LOCAL_SESSION_SECRET", "  legacy-tok  ", "123456"]) {
    // Legacy bare strings remain usable for local origin ("") only.
    for (const localBase of ["", "   ", "///", null, undefined]) {
      assert.equal(
        readScopedSessionSecret(legacyRaw, localBase),
        legacyRaw.trim(),
      );
    }
    // Never returned for any non-empty remote baseUrl.
    for (const remoteBase of remoteBases) {
      assert.equal(
        readScopedSessionSecret(legacyRaw, remoteBase),
        "",
        `legacy bare string must not leak to remote baseUrl ${JSON.stringify(remoteBase)}`,
      );
    }
  }
});

test("readScopedSessionSecret isolates local URL-boot secrets from remote baseUrls", () => {
  const localBootStored = serializeScopedSessionSecret(
    "LOCAL_EPHEMERAL_SECRET_256BIT",
    "",
  );
  const remoteBases = [
    "https://attacker.test:9090",
    "http://10.0.0.5:9090/",
    "  https://attacker.test:9090/  ",
    "//attacker.test:9090",
    "http://127.0.0.1:9999",
    "https://attacker.test:9090\t\n",
    "\thttps://attacker.test:9090/\r\n",
  ];

  assert.equal(readScopedSessionSecret(localBootStored, ""), "LOCAL_EPHEMERAL_SECRET_256BIT");
  assert.equal(readScopedSessionSecret(localBootStored, "  ///  "), "LOCAL_EPHEMERAL_SECRET_256BIT");

  for (const remoteBase of remoteBases) {
    assert.equal(
      readScopedSessionSecret(localBootStored, remoteBase),
      "",
      `local boot secret must not leak to remote baseUrl ${JSON.stringify(remoteBase)}`,
    );
  }
});

test("readScopedSessionSecret isolates Controller A secret from Controller B and local, while accepting equivalent Controller A forms", () => {
  const storedA = serializeScopedSessionSecret(
    "CONTROLLER_A_SECRET",
    "https://controller-a.test:9090/",
  );

  // Accepted for whitespace / trailing-slash equivalent Controller A URLs.
  for (const equivalentA of [
    "https://controller-a.test:9090",
    "https://controller-a.test:9090/",
    "  https://controller-a.test:9090///  ",
    "\thttps://controller-a.test:9090/\r\n",
  ]) {
    assert.equal(
      readScopedSessionSecret(storedA, equivalentA),
      "CONTROLLER_A_SECRET",
    );
  }

  // Rejected for Controller B, different ports/paths, and local ("").
  for (const otherBase of [
    "",
    "   ",
    "///",
    "https://controller-b.test:9090",
    "https://controller-a.test:9091",
    "http://controller-a.test:9090",
    "https://controller-a.test:9090/api",
  ]) {
    assert.equal(
      readScopedSessionSecret(storedA, otherBase),
      "",
      `Controller A secret must not leak to ${JSON.stringify(otherBase)}`,
    );
  }
});

test("readScopedSessionSecret handles malformed/future scoped JSON and empty values safely", () => {
  assert.equal(readScopedSessionSecret(null, ""), "");
  assert.equal(readScopedSessionSecret(undefined, ""), "");
  assert.equal(readScopedSessionSecret("", ""), "");
  assert.equal(readScopedSessionSecret("   ", ""), "");

  // Unnormalized valid v1 JSON still normalizes both baseUrl and secret.
  const rawUnnormalized = JSON.stringify({
    v: 1,
    baseUrl: "  https://controller-a.test:9090///  ",
    secret: "  trimmed-secret  ",
  });
  assert.equal(
    readScopedSessionSecret(rawUnnormalized, "https://controller-a.test:9090"),
    "trimmed-secret",
  );
  assert.equal(readScopedSessionSecret(rawUnnormalized, ""), "");

  // Unsupported version or non-string fields never leak raw JSON even for local "".
  for (const invalidScoped of [
    JSON.stringify({ v: 2, baseUrl: "", secret: "future-secret" }),
    JSON.stringify({ v: 1, baseUrl: null, secret: "bad-base" }),
    JSON.stringify({ v: 1, baseUrl: "", secret: 12345 }),
    JSON.stringify({ v: 1, baseUrl: "", secret: "   " }),
  ]) {
    assert.equal(readScopedSessionSecret(invalidScoped, ""), "");
    assert.equal(
      readScopedSessionSecret(invalidScoped, "https://controller-a.test:9090"),
      "",
    );
  }
});
