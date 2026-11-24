// Pure verify-before-save helper for controller Bearer Secret updates.
// Ensures an invalid secret (HTTP 401) or transient network failure never overwrites
// a previously persisted valid controller secret.

/**
 * Probes `{ ...currentSettings, secret: candidateSecret }` via `probeSettings`
 * BEFORE calling `saveSettings`. Only commits the new secret after probing succeeds.
 *
 * @template TVersion
 * @param {{
 *   loadSettings: () => { baseUrl: string; secret: string };
 *   probeSettings: (candidate: { baseUrl: string; secret: string }) => Promise<TVersion>;
 *   saveSettings: (next: { baseUrl: string; secret: string }) => void;
 *   candidateSecret: string;
 * }} params
 * @returns {Promise<{ settings: { baseUrl: string; secret: string }; version: TVersion }>}
 */
export async function verifyAndCommitControllerSecret({
  loadSettings,
  probeSettings,
  saveSettings,
  candidateSecret,
}) {
  const current = loadSettings();
  const candidate = {
    ...current,
    secret: candidateSecret,
  };
  const version = await probeSettings(candidate);
  saveSettings(candidate);
  return { settings: candidate, version };
}
