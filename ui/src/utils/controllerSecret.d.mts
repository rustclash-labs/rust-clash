export interface ControllerSecretSettings {
  baseUrl?: string | null;
  secret?: string | null;
}

export function normalizeControllerBaseUrl(
  baseUrl?: string | null,
): string;

export function resolveEffectiveSecret(
  settings: ControllerSecretSettings | null | undefined,
  sessionSecret?: string | null,
  desktopSecret?: string | null,
): string;

export function serializeScopedSessionSecret(
  secret?: string | null,
  baseUrl?: string | null,
): string;

export function readScopedSessionSecret(
  rawStoredValue?: string | null,
  targetBaseUrl?: string | null,
): string;
