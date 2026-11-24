// Pure, dependency-free controller URL normalization and secret resolution helpers.
// Prevents leaking local Tauri desktop secrets or stale session secrets to
// user-configured remote controllers when no explicit remote secret is provided.

/**
 * Normalizes a controller base URL by trimming surrounding whitespace and
 * stripping trailing slashes. Returns `""` for local/same-origin/embedded
 * desktop defaults.
 *
 * @param {string | null | undefined} baseUrl
 * @returns {string}
 */
export function normalizeControllerBaseUrl(baseUrl) {
  return String(baseUrl ?? "").trim().replace(/\/+$/, "");
}

/**
 * Resolves the effective Bearer/WebSocket secret for a controller request:
 * - Always honors a non-empty explicit `settings.secret` (trimmed).
 * - Falls back to `sessionSecret`, then `desktopSecret` ONLY when
 *   `settings.baseUrl` normalizes to `""` (local/same-origin/embedded desktop).
 * - Returns `""` whenever a remote `baseUrl` is configured with an empty secret,
 *   guaranteeing neither `desktopSecret` nor a stale `sessionSecret` is leaked.
 *
 * @param {{ baseUrl?: string | null; secret?: string | null } | null | undefined} settings
 * @param {string | null | undefined} [sessionSecret]
 * @param {string | null | undefined} [desktopSecret]
 * @returns {string}
 */
export function resolveEffectiveSecret(
  settings,
  sessionSecret = "",
  desktopSecret = "",
) {
  const cleanBase = normalizeControllerBaseUrl(settings?.baseUrl);
  const explicitSecret = String(settings?.secret ?? "").trim();
  if (explicitSecret) {
    return explicitSecret;
  }
  if (!cleanBase) {
    return (
      String(sessionSecret ?? "").trim() ||
      String(desktopSecret ?? "").trim() ||
      ""
    );
  }
  return "";
}

/**
 * Serializes a controller session secret bound to its normalized `baseUrl`
 * scope so a local/boot secret or one remote controller's secret can never be
 * replayed against a different controller target.
 *
 * Returns `""` when `secret` trims to empty.
 *
 * @param {string | null | undefined} secret
 * @param {string | null | undefined} [baseUrl]
 * @returns {string}
 */
export function serializeScopedSessionSecret(secret, baseUrl = "") {
  const trimmedSecret = String(secret ?? "").trim();
  if (!trimmedSecret) {
    return "";
  }
  return JSON.stringify({
    v: 1,
    baseUrl: normalizeControllerBaseUrl(baseUrl),
    secret: trimmedSecret,
  });
}

/**
 * Reads a stored session secret ONLY when its recorded `baseUrl` scope matches
 * `normalizeControllerBaseUrl(targetBaseUrl)`.
 *
 * - Scoped JSON records (`{ v: 1, baseUrl, secret }`) return `secret.trim()`
 *   strictly when `normalizeControllerBaseUrl(record.baseUrl) === target`, and
 *   `""` otherwise.
 * - Legacy pre-fix bare-string values (non-scoped `sessionStorage` strings) are
 *   treated strictly as local (`""`) scope ONLY and return `""` for every
 *   non-empty remote `targetBaseUrl`.
 *
 * @param {string | null | undefined} rawStoredValue
 * @param {string | null | undefined} [targetBaseUrl]
 * @returns {string}
 */
export function readScopedSessionSecret(rawStoredValue, targetBaseUrl = "") {
  if (typeof rawStoredValue !== "string") {
    return "";
  }
  const trimmedRaw = rawStoredValue.trim();
  if (!trimmedRaw) {
    return "";
  }
  const target = normalizeControllerBaseUrl(targetBaseUrl);
  try {
    const parsed = JSON.parse(trimmedRaw);
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      Object.prototype.hasOwnProperty.call(parsed, "v") &&
      Object.prototype.hasOwnProperty.call(parsed, "baseUrl") &&
      Object.prototype.hasOwnProperty.call(parsed, "secret")
    ) {
      if (
        parsed.v === 1 &&
        typeof parsed.baseUrl === "string" &&
        typeof parsed.secret === "string" &&
        normalizeControllerBaseUrl(parsed.baseUrl) === target
      ) {
        return parsed.secret.trim();
      }
      return "";
    }
  } catch {
    // Non-JSON legacy bare string — handled below.
  }
  return target === "" ? trimmedRaw : "";
}
