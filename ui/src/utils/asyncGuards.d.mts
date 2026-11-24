export const DEFAULT_PROBE_CONCURRENCY: number;

export function runWithConcurrency<T, R>(
  items: Iterable<T> | null | undefined,
  limit: number | undefined,
  worker: (item: T, index: number) => Promise<R> | R,
): Promise<Array<PromiseSettledResult<R>>>;

export function collectUniqueProbeTargets(
  members: Iterable<string> | null | undefined,
  seen?: Set<string>,
): string[];

export interface GuardedPollerOptions<T, TTimer = number> {
  intervalMs: number;
  poll: () => Promise<T>;
  onSuccess?: (value: T) => void;
  onError?: (err: unknown) => void;
  isHidden?: () => boolean;
  setIntervalFn?: (fn: () => void, ms: number) => TTimer;
  clearIntervalFn?: (id: TTimer) => void;
}

export interface GuardedPoller {
  start(): void;
  stop(): void;
  dispose(): void;
  triggerTick(): void;
  isRunning(): boolean;
  isInFlight(): boolean;
  isDisposed(): boolean;
}

export function createGuardedPoller<T, TTimer = number>(
  options: GuardedPollerOptions<T, TTimer>,
): GuardedPoller;
