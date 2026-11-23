import type { ConnectionItem, ConnectionsResponse } from "../types";

export const EMPTY_CONNECTIONS: readonly ConnectionItem[];

export interface ConnectionsPauseState {
  paused: boolean;
  frozenItems: readonly ConnectionItem[];
}

export function resolveLiveConnections(
  connections: ConnectionsResponse | null | undefined,
): readonly ConnectionItem[];

export function resolveDisplayedConnections(
  paused: boolean,
  liveItems: readonly ConnectionItem[],
  frozenItems: readonly ConnectionItem[],
): readonly ConnectionItem[];

export function transitionConnectionsPauseState(
  state: ConnectionsPauseState,
  liveItems: readonly ConnectionItem[],
): ConnectionsPauseState;
