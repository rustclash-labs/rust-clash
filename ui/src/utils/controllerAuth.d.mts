export interface ControllerAuthSettings {
  baseUrl: string;
  secret: string;
}

export function verifyAndCommitControllerSecret<TVersion>(params: {
  loadSettings: () => ControllerAuthSettings;
  probeSettings: (candidate: ControllerAuthSettings) => Promise<TVersion>;
  saveSettings: (next: ControllerAuthSettings) => void;
  candidateSecret: string;
}): Promise<{ settings: ControllerAuthSettings; version: TVersion }>;
