/**
 * Dashboard.tsx — Terminal UI dashboard for Sandyaa using Ink (React for CLI).
 *
 * Provides a real-time progress display while scans run.  Falls back to plain
 * console.log output when Ink is unavailable or the --no-ui flag is set.
 *
 * Usage (from the orchestrator):
 *
 *   const renderer = new DashboardRenderer({ useInk: true });
 *   renderer.start('/path/to/target');
 *   renderer.update({ phase: 'vulnerability-detection', progress: { current: 3, total: 12 } });
 *   renderer.addActivity('Analyzed auth/login.ts');
 *   renderer.addFinding('critical', 'SQL injection in db/query.ts');
 *   renderer.stop();
 */

import React, { useState, useEffect } from 'react';
import type { Instance as InkInstance } from 'ink';
import {
  ScanStateStore,
  type ScanState,
  type ScanPhase,
  type FindingSeverity,
} from './ScanState.js';

// ── Ink component (lazy-loaded) ──────────────────────────────────────

// We keep the Ink component in a function so the heavy imports are only
// resolved when Ink mode is actually used.

function buildProgressBar(current: number, total: number, width: number = 20): string {
  if (total === 0) return '\u2591'.repeat(width) + '  0%';
  const pct = Math.min(current / total, 1);
  const filled = Math.round(pct * width);
  const empty = width - filled;
  const bar = '\u2588'.repeat(filled) + '\u2591'.repeat(empty);
  const label = `${Math.round(pct * 100)}%`;
  return `${bar} ${label} (${current}/${total} chunks)`;
}

function formatElapsed(startTime: number): string {
  const elapsed = Math.max(0, Math.floor((Date.now() - startTime) / 1000));
  const m = Math.floor(elapsed / 60);
  const s = elapsed % 60;
  return `${m}m ${s.toString().padStart(2, '0')}s`;
}

function formatTokens(used: number, budget: number): string {
  const fmt = (n: number) => n.toLocaleString('en-US');
  return `${fmt(used)} / ${fmt(budget)}`;
}

function phaseLabel(phase: ScanPhase): string {
  const labels: Record<ScanPhase, string> = {
    initializing: 'Initializing',
    mapping: 'Codebase Mapping',
    chunking: 'Chunking Files',
    'vulnerability-detection': 'Vulnerability Detection',
    validation: 'Validation',
    'poc-generation': 'PoC Generation',
    reporting: 'Reporting',
    done: 'Complete',
  };
  return labels[phase] ?? phase;
}

function statusLabel(state: ScanState): string {
  if (!state.running) return 'Idle';
  if (state.phase === 'done') return 'Complete';
  return 'Scanning...';
}

// ── Ink React component ──────────────────────────────────────────────

function DashboardApp(): React.ReactElement {
  const store = ScanStateStore.getInstance();
  const [state, setState] = useState<ScanState>({ ...store.getState() } as ScanState);

  // re-render every 500 ms to keep the elapsed-time clock ticking, and
  // also subscribe to store pushes for immediate updates.
  useEffect(() => {
    const unsub = store.subscribe((s) => setState({ ...s }));
    const timer = setInterval(() => setState({ ...store.getState() } as ScanState), 500);
    return () => {
      unsub();
      clearInterval(timer);
    };
  }, []);

  // Dynamic imports already resolved by the time we render — the
  // caller ensures loadInk() succeeded before mounting this component.
  // We use require-style access since they were loaded dynamically.
  // Actually, since this module is imported dynamically by the renderer,
  // we can import statically at the top (the file is only loaded when
  // Ink mode is active).

  // We need ink components — they are imported at module level since
  // this file is only loaded when Ink is available.
  const { Box, Text } = require('ink') as typeof import('ink');

  let SpinnerComponent: React.ComponentType<{ type?: string }> | null = null;
  try {
    SpinnerComponent = (require('ink-spinner') as { default: React.ComponentType<{ type?: string }> }).default;
  } catch {
    // spinner not available, skip
  }

  let GradientComponent: React.ComponentType<{ name?: string; children: React.ReactNode }> | null = null;
  try {
    GradientComponent = (require('ink-gradient') as { default: React.ComponentType<{ name?: string; children: React.ReactNode }> }).default;
  } catch {
    // gradient not available, skip
  }

  const headerTitle = GradientComponent ? (
    <GradientComponent name="vice">SANDYAA</GradientComponent>
  ) : (
    <Text bold color="cyan">SANDYAA</Text>
  );

  const spinner = state.running && state.phase !== 'done' && SpinnerComponent ? (
    <SpinnerComponent type="dots" />
  ) : null;

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
      {/* Header */}
      <Box flexDirection="column">
        <Box>
          <Text>  </Text>
          {headerTitle}
          <Text bold> — Security Bug Hunter</Text>
        </Box>
        <Text>  Target: {state.targetPath || '(none)'}</Text>
        <Box>
          <Text>  Status: {statusLabel(state)} </Text>
          {spinner}
        </Box>
      </Box>

      {/* Divider */}
      <Box marginY={0}>
        <Text dimColor>{'─'.repeat(45)}</Text>
      </Box>

      {/* Progress section */}
      <Box flexDirection="column">
        <Text>  Phase: {phaseLabel(state.phase)}</Text>
        <Text>  Progress: {buildProgressBar(state.progress.current, state.progress.total)}</Text>
        <Text>  Tokens: {formatTokens(state.tokensUsed, state.tokenBudget)}</Text>
        <Text>  Time: {formatElapsed(state.startTime)}</Text>
        {state.currentFile ? <Text>  File: {state.currentFile}</Text> : null}
      </Box>

      {/* Divider */}
      <Box marginY={0}>
        <Text dimColor>{'─'.repeat(45)}</Text>
      </Box>

      {/* Findings */}
      <Box flexDirection="column">
        <Text>  Findings:</Text>
        <Text color="red">    {'\u{1F534}'} Critical: {state.findings.critical}</Text>
        <Text color="yellow">    {'\u{1F7E0}'} High: {state.findings.high}</Text>
        <Text color="yellowBright">    {'\u{1F7E1}'} Medium: {state.findings.medium}</Text>
        <Text>    {'\u26AA'} Low: {state.findings.low}</Text>
        <Text>    {'\u274C'} Rejected: {state.findings.rejected}</Text>
      </Box>

      {/* Divider */}
      <Box marginY={0}>
        <Text dimColor>{'─'.repeat(45)}</Text>
      </Box>

      {/* Activity log */}
      <Box flexDirection="column">
        <Text>  Recent Activity:</Text>
        {state.activityLog.length === 0 ? (
          <Text dimColor>    (none yet)</Text>
        ) : (
          state.activityLog.map((item, i) => (
            <Text key={i}>    {item.message}</Text>
          ))
        )}
      </Box>
    </Box>
  );
}

// ── Console-log fallback renderer ────────────────────────────────────

class ConsoleFallbackRenderer {
  private store: ScanStateStore;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastPrintedPhase: ScanPhase | null = null;

  constructor() {
    this.store = ScanStateStore.getInstance();
  }

  start(targetPath: string): void {
    this.store.update({ targetPath, running: true, startTime: Date.now() });
    console.log(`\n=== SANDYAA — Security Bug Hunter ===`);
    console.log(`Target: ${targetPath}`);
    console.log(`Status: Scanning...\n`);

    // Subscribe for live updates
    this.store.subscribe((s) => {
      if (s.phase !== this.lastPrintedPhase) {
        this.lastPrintedPhase = s.phase;
        console.log(`[phase] ${phaseLabel(s.phase)}`);
      }
    });
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const s = this.store.getState();
    console.log(`\n=== Scan Complete ===`);
    console.log(
      `Findings: Critical=${s.findings.critical}  High=${s.findings.high}  ` +
      `Medium=${s.findings.medium}  Low=${s.findings.low}  Rejected=${s.findings.rejected}`
    );
    console.log(`Tokens used: ${s.tokensUsed.toLocaleString('en-US')}`);
    console.log(`Elapsed: ${formatElapsed(s.startTime)}\n`);
  }
}

// ── DashboardRenderer (public API) ───────────────────────────────────

export interface DashboardRendererOptions {
  /**
   * If true, attempt to use the Ink-based TUI.
   * Falls back to console output if Ink is unavailable.
   * Default: false (console fallback).
   */
  useInk?: boolean;
}

export class DashboardRenderer {
  private store: ScanStateStore;
  private inkInstance: InkInstance | null = null;
  private fallback: ConsoleFallbackRenderer | null = null;
  private useInk: boolean;
  private inkAvailable: boolean | null = null; // lazy-checked

  constructor(options: DashboardRendererOptions = {}) {
    this.useInk = options.useInk ?? false;
    this.store = ScanStateStore.getInstance();
  }

  // ── Public API ───────────────────────────────────────────────────

  /** Render the dashboard for the given target path. */
  async start(targetPath: string): Promise<void> {
    this.store.reset();
    this.store.update({
      targetPath,
      running: true,
      startTime: Date.now(),
    });

    if (this.useInk) {
      const ok = await this.tryStartInk();
      if (ok) return;
      // Ink failed — fall through to console
    }

    this.fallback = new ConsoleFallbackRenderer();
    this.fallback.start(targetPath);
  }

  /** Merge a partial state update into the dashboard. */
  update(partial: Partial<ScanState>): void {
    this.store.update(partial);
  }

  /** Append a message to the activity log. */
  addActivity(message: string): void {
    this.store.addActivity(message);
    // In fallback mode, also print directly
    if (this.fallback) {
      console.log(`  ${message}`);
    }
  }

  /** Record a finding and optionally log it. */
  addFinding(severity: FindingSeverity | 'rejected', description: string): void {
    this.store.addFinding(severity, description);
    if (this.fallback) {
      const tag = severity === 'rejected' ? 'REJECTED' : severity.toUpperCase();
      console.log(`  [${tag}] ${description}`);
    }
  }

  /** Stop the dashboard and print a final summary. */
  stop(): void {
    this.store.update({ running: false, phase: 'done' });

    if (this.inkInstance) {
      // Give Ink a moment to render the final state, then unmount
      setTimeout(() => {
        this.inkInstance?.unmount();
        this.inkInstance = null;
        this.printFinalSummary();
      }, 300);
    } else if (this.fallback) {
      this.fallback.stop();
      this.fallback = null;
    }
  }

  // ── Internals ────────────────────────────────────────────────────

  private async tryStartInk(): Promise<boolean> {
    try {
      // Dynamic import so the module works even if Ink is not installed
      const { render: renderFn } = await import('ink');
      const element = React.createElement(DashboardApp);
      this.inkInstance = renderFn(element);
      return true;
    } catch {
      this.inkAvailable = false;
      return false;
    }
  }

  private printFinalSummary(): void {
    const s = this.store.getState();
    console.log(`\n=== Scan Complete ===`);
    console.log(
      `Findings: Critical=${s.findings.critical}  High=${s.findings.high}  ` +
      `Medium=${s.findings.medium}  Low=${s.findings.low}  Rejected=${s.findings.rejected}`
    );
    console.log(`Tokens used: ${s.tokensUsed.toLocaleString('en-US')}`);
    console.log(`Elapsed: ${formatElapsed(s.startTime)}\n`);
  }
}

export { DashboardApp };
