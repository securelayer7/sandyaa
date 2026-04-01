/**
 * ScanState — shared state interface for the Sandyaa dashboard UI.
 *
 * The orchestrator pushes partial updates into the singleton ScanStateStore,
 * and the Ink dashboard (or the console-log fallback) reads from it.
 */

// ── Types ────────────────────────────────────────────────────────────

export type ScanPhase =
  | 'initializing'
  | 'mapping'
  | 'chunking'
  | 'vulnerability-detection'
  | 'validation'
  | 'poc-generation'
  | 'reporting'
  | 'done';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface FindingsCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  rejected: number;
}

export interface ScanProgress {
  current: number;
  total: number;
}

export interface ActivityItem {
  timestamp: number;
  message: string;
}

export interface ScanState {
  /** Target codebase path being scanned */
  targetPath: string;

  /** Current scan phase */
  phase: ScanPhase;

  /** Whether the scan is actively running */
  running: boolean;

  /** Chunk-level progress */
  progress: ScanProgress;

  /** Tokens consumed so far and budget ceiling */
  tokensUsed: number;
  tokenBudget: number;

  /** Scan start time (epoch ms) — used to compute elapsed */
  startTime: number;

  /** File currently being analyzed */
  currentFile: string;

  /** Aggregated finding counts by severity */
  findings: FindingsCounts;

  /** Rolling activity log (most recent last) */
  activityLog: ActivityItem[];
}

// ── Helpers ──────────────────────────────────────────────────────────

const MAX_ACTIVITY_ITEMS = 5;

function defaultState(): ScanState {
  return {
    targetPath: '',
    phase: 'initializing',
    running: false,
    progress: { current: 0, total: 0 },
    tokensUsed: 0,
    tokenBudget: 200_000,
    startTime: Date.now(),
    currentFile: '',
    findings: { critical: 0, high: 0, medium: 0, low: 0, rejected: 0 },
    activityLog: [],
  };
}

// ── Listener type ────────────────────────────────────────────────────

export type ScanStateListener = (state: ScanState) => void;

// ── Singleton store ──────────────────────────────────────────────────

export class ScanStateStore {
  private static instance: ScanStateStore | null = null;

  private state: ScanState;
  private listeners: Set<ScanStateListener> = new Set();

  private constructor() {
    this.state = defaultState();
  }

  static getInstance(): ScanStateStore {
    if (!ScanStateStore.instance) {
      ScanStateStore.instance = new ScanStateStore();
    }
    return ScanStateStore.instance;
  }

  /** Reset to default state (useful between runs / tests). */
  reset(): void {
    this.state = defaultState();
    this.notify();
  }

  /** Return a shallow-frozen snapshot of the current state. */
  getState(): Readonly<ScanState> {
    return this.state;
  }

  /** Merge a partial update into the state and notify listeners. */
  update(partial: Partial<ScanState>): void {
    this.state = { ...this.state, ...partial };
    this.notify();
  }

  /** Append an activity log entry (keeps last N). */
  addActivity(message: string): void {
    const entry: ActivityItem = { timestamp: Date.now(), message };
    const log = [...this.state.activityLog, entry].slice(-MAX_ACTIVITY_ITEMS);
    this.state = { ...this.state, activityLog: log };
    this.notify();
  }

  /** Increment a findings counter and optionally log the finding. */
  addFinding(severity: FindingSeverity | 'rejected', description?: string): void {
    const findings = { ...this.state.findings };
    findings[severity] += 1;

    const patches: Partial<ScanState> = { findings };
    this.state = { ...this.state, ...patches };

    if (description) {
      this.addActivity(`Found: ${description}`);
    } else {
      this.notify();
    }
  }

  // ── Subscriptions ────────────────────────────────────────────────

  subscribe(listener: ScanStateListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) {
      listener(this.state);
    }
  }
}
