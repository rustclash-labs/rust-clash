// Pure VLESS transport selection helpers.
// XTLS Vision (any non-empty flow) and REALITY only support raw TCP transport,
// so WebSocket (`network: "ws"` / `ws-opts`) must be reset/omitted whenever
// either REALITY or an XTLS flow is active.

/**
 * Returns `true` when VLESS configuration requires raw TCP transport
 * (REALITY enabled OR any non-empty trimmed XTLS flow).
 *
 * @param {boolean} vlessReality
 * @param {string | null | undefined} vlessFlow
 * @returns {boolean}
 */
export function requiresVlessTcpTransport(vlessReality, vlessFlow) {
  return Boolean(vlessReality) || Boolean(String(vlessFlow ?? "").trim());
}

/**
 * Resolves the effective transport payload (`{ network, wsOpts }`) for a VLESS node.
 * Forces `{ network: "tcp", wsOpts: undefined }` whenever `vlessReality` is true
 * OR `flowTrimmed` is non-empty, skipping `buildWsTransport` so hidden WS state
 * can never leak into the submitted payload.
 *
 * @template TWsOpts
 * @param {{
 *   vlessReality: boolean;
 *   flowTrimmed: string;
 *   buildWsTransport: () => { network: string; wsOpts: TWsOpts | undefined };
 * }} params
 * @returns {{ network: string; wsOpts: TWsOpts | undefined }}
 */
export function resolveVlessTransportPayload({
  vlessReality,
  flowTrimmed,
  buildWsTransport,
}) {
  if (requiresVlessTcpTransport(vlessReality, flowTrimmed)) {
    return { network: "tcp", wsOpts: undefined };
  }
  return buildWsTransport();
}

/**
 * Computes the next UI transport selector value (`"tcp" | "ws"`) when the VLESS
 * Flow dropdown changes. Choosing any non-empty flow resets transport to `"tcp"`
 * so the UI remains consistent if flow is later cleared back to empty.
 *
 * @param {string | null | undefined} nextFlow
 * @param {"tcp" | "ws"} currentTransport
 * @returns {"tcp" | "ws"}
 */
export function resolveTransportOnVlessFlowChange(nextFlow, currentTransport) {
  if (String(nextFlow ?? "").trim().length > 0) {
    return "tcp";
  }
  return currentTransport;
}
