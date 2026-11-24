export function requiresVlessTcpTransport(
  vlessReality: boolean,
  vlessFlow: string | null | undefined,
): boolean;

export function resolveVlessTransportPayload<TWsOpts>(params: {
  vlessReality: boolean;
  flowTrimmed: string;
  buildWsTransport: () => { network: string; wsOpts: TWsOpts | undefined };
}): { network: string; wsOpts: TWsOpts | undefined };

export function resolveTransportOnVlessFlowChange(
  nextFlow: string | null | undefined,
  currentTransport: "tcp" | "ws",
): "tcp" | "ws";
