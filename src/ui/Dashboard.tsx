/**
 * Dashboard.tsx — Terminal UI dashboard for Sandyaa using Ink (React for CLI).
 *
 * Inspired by Claude Code's terminal UI patterns:
 * - Animated spinner glyphs (·, ✢, ✳, ✶, ✻, ✽) with shimmer
 * - Sub-eighth-block progress bar (▏▎▍▌▋▊▉█)
 * - Themed RGB colors for severity and status
 * - Bordered panels with status line at bottom
 * - Activity log with timestamps
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

import React, { useState, useEffect, useRef } from 'react';
import type { Instance as InkInstance } from 'ink';
import {
  ScanStateStore,
  type ScanState,
  type ScanPhase,
  type FindingSeverity,
} from './ScanState.js';

// ── Theme colors (RGB strings, matching Claude Code's dark theme style) ──

const COLORS = {
  // Brand
  sandyaa:     'rgb(215,119,87)',   // Claude orange — brand identity
  shimmer:     'rgb(245,149,117)',  // Lighter orange for shimmer
  // Severity
  critical:    'rgb(220,38,38)',    // Red 600
  high:        'rgb(234,88,12)',    // Orange 600
  medium:      'rgb(202,138,4)',    // Yellow 600
  low:         'rgb(153,153,153)',  // Gray
  // Status
  success:     'rgb(44,122,57)',    // Green
  error:       'rgb(171,43,63)',    // Red
  warning:     'rgb(200,158,80)',   // Amber
  // UI
  border:      'rgb(153,153,153)',  // Medium gray
  text:        'rgb(255,255,255)',  // White
  dimText:     'rgb(102,102,102)',  // Dark gray
  subtle:      'rgb(175,175,175)',  // Light gray
  // Progress bar
  barFill:     'rgb(87,105,247)',   // Medium blue
  barEmpty:    'rgb(39,47,111)',    // Dark blue
} as const;

// ── Spinner animation (Claude Code style: ·✢✳✶✻✽✻✶✳✢·) ──

const SPINNER_CHARS = process.platform === 'darwin'
  ? ['·', '✢', '✳', '✶', '✻', '✽']
  : ['·', '✢', '*', '✶', '✻', '✽'];

const SPINNER_FRAMES = [...SPINNER_CHARS, ...[...SPINNER_CHARS].reverse()];
const SPINNER_INTERVAL_MS = 80;

// ── Sub-eighth-block progress bar (Claude Code style) ──

const BLOCKS = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];

function buildProgressBar(current: number, total: number, width: number = 30): string {
  if (total === 0) return BLOCKS[0].repeat(width) + '  0%';
  const ratio = Math.min(current / total, 1);
  const whole = Math.floor(ratio * width);
  const segments = [BLOCKS[BLOCKS.length - 1].repeat(whole)];

  if (whole < width) {
    const remainder = ratio * width - whole;
    const middle = Math.floor(remainder * BLOCKS.length);
    segments.push(BLOCKS[middle]);
    const empty = width - whole - 1;
    if (empty > 0) {
      segments.push(BLOCKS[0].repeat(empty));
    }
  }

  const pct = `${Math.round(ratio * 100)}%`;
  return `${segments.join('')} ${pct} (${current}/${total})`;
}

function formatElapsed(startTime: number): string {
  const elapsed = Math.max(0, Math.floor((Date.now() - startTime) / 1000));
  const m = Math.floor(elapsed / 60);
  const s = elapsed % 60;
  return `${m}m ${s.toString().padStart(2, '0')}s`;
}

function formatTokens(used: number, budget: number): string {
  const fmt = (n: number) => n.toLocaleString('en-US');
  const pct = budget > 0 ? ` (${Math.round((used / budget) * 100)}%)` : '';
  return `${fmt(used)} / ${fmt(budget)}${pct}`;
}

function phaseLabel(phase: ScanPhase): string {
  const labels: Record<ScanPhase, string> = {
    initializing: 'Initializing',
    mapping: 'Codebase Mapping',
    chunking: 'Chunking Files',
    'vulnerability-detection': 'Vulnerability Detection',
    validation: 'Recursive Verification',
    'poc-generation': 'PoC Generation',
    reporting: 'Reporting',
    done: 'Complete',
  };
  return labels[phase] ?? phase;
}

function phaseIcon(phase: ScanPhase): string {
  const icons: Record<ScanPhase, string> = {
    initializing: '...',
    mapping: '...',
    chunking: '...',
    'vulnerability-detection': '...',
    validation: '...',
    'poc-generation': '...',
    reporting: '...',
    done: '...',
  };
  return icons[phase] ?? '...';
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return COLORS.critical;
    case 'high': return COLORS.high;
    case 'medium': return COLORS.medium;
    default: return COLORS.low;
  }
}

// ── Ink React component ──────────────────────────────────────────────

function DashboardApp(): React.ReactElement {
  const store = ScanStateStore.getInstance();
  const [state, setState] = useState<ScanState>({ ...store.getState() } as ScanState);
  const [frame, setFrame] = useState(0);

  // Subscribe to store + tick animation
  useEffect(() => {
    const unsub = store.subscribe((s) => setState({ ...s }));
    const timer = setInterval(() => {
      setState({ ...store.getState() } as ScanState);
      setFrame((f) => (f + 1) % SPINNER_FRAMES.length);
    }, SPINNER_INTERVAL_MS);
    return () => {
      unsub();
      clearInterval(timer);
    };
  }, []);

  const { Box, Text } = require('ink') as typeof import('ink');

  const spinnerChar = state.running && state.phase !== 'done'
    ? SPINNER_FRAMES[frame]
    : state.phase === 'done' ? '✓' : '·';

  const spinnerColor = state.phase === 'done' ? COLORS.success : COLORS.sandyaa;
  const termWidth = process.stdout.columns || 80;
  const innerWidth = Math.max(40, Math.min(termWidth - 4, 76));
  const divider = '─'.repeat(innerWidth);

  return (
    <Box flexDirection="column" borderStyle="round" borderColor={COLORS.border} paddingX={1} width={innerWidth + 4}>
      {/* ── Header ── */}
      <Box flexDirection="row" justifyContent="space-between">
        <Box>
          <Text color={spinnerColor} bold>{spinnerChar} </Text>
          <Text color={COLORS.sandyaa} bold>SANDYAA</Text>
          <Text color={COLORS.subtle}> — Security Bug Hunter</Text>
        </Box>
        <Text color={COLORS.dimText}>{formatElapsed(state.startTime)}</Text>
      </Box>

      {/* ── Target ── */}
      <Box>
        <Text color={COLORS.dimText}>Target: </Text>
        <Text color={COLORS.text}>{state.targetPath || '(none)'}</Text>
      </Box>

      <Text color={COLORS.dimText}>{divider}</Text>

      {/* ── Phase + Progress ── */}
      <Box flexDirection="column">
        <Box>
          <Text color={COLORS.subtle}>Phase   </Text>
          <Text color={COLORS.text} bold>{phaseLabel(state.phase)}</Text>
        </Box>
        <Box>
          <Text color={COLORS.subtle}>Progress</Text>
          <Text color={COLORS.barFill}> {buildProgressBar(state.progress.current, state.progress.total, Math.min(30, innerWidth - 20))}</Text>
        </Box>
        <Box>
          <Text color={COLORS.subtle}>Tokens  </Text>
          <Text color={COLORS.text}> {formatTokens(state.tokensUsed, state.tokenBudget)}</Text>
        </Box>
        {state.currentFile ? (
          <Box>
            <Text color={COLORS.subtle}>File    </Text>
            <Text color={COLORS.dimText}> {state.currentFile}</Text>
          </Box>
        ) : null}
      </Box>

      <Text color={COLORS.dimText}>{divider}</Text>

      {/* ── Findings ── */}
      <Box flexDirection="column">
        <Text color={COLORS.subtle} bold>Findings</Text>
        <Box flexDirection="row" gap={2}>
          <Text color={COLORS.critical}> Critical {state.findings.critical}</Text>
          <Text color={COLORS.high}> High {state.findings.high}</Text>
          <Text color={COLORS.medium}> Medium {state.findings.medium}</Text>
          <Text color={COLORS.low}> Low {state.findings.low}</Text>
        </Box>
        {state.findings.rejected > 0 && (
          <Text color={COLORS.dimText}> Rejected: {state.findings.rejected}</Text>
        )}
      </Box>

      <Text color={COLORS.dimText}>{divider}</Text>

      {/* ── Activity Log ── */}
      <Box flexDirection="column">
        <Text color={COLORS.subtle} bold>Activity</Text>
        {state.activityLog.length === 0 ? (
          <Text color={COLORS.dimText}> Waiting...</Text>
        ) : (
          state.activityLog.map((item, i) => {
            const ts = new Date(item.timestamp);
            const timeStr = `${ts.getHours().toString().padStart(2, '0')}:${ts.getMinutes().toString().padStart(2, '0')}:${ts.getSeconds().toString().padStart(2, '0')}`;
            return (
              <Box key={i}>
                <Text color={COLORS.dimText}> {timeStr} </Text>
                <Text color={COLORS.subtle}>{item.message}</Text>
              </Box>
            );
          })
        )}
      </Box>

      {/* ── Status Line (bottom) ── */}
      <Text color={COLORS.dimText}>{divider}</Text>
      <Box flexDirection="row" justifyContent="space-between">
        <Text color={COLORS.dimText}>
          sandyaa v1.0
        </Text>
        <Text color={COLORS.dimText}>
          {state.running ? `${phaseLabel(state.phase)}...` : state.phase === 'done' ? 'Scan complete' : 'Idle'}
        </Text>
      </Box>
    </Box>
  );
}

// ── Console-log fallback renderer (Claude Code style: minimal, colored) ──

class ConsoleFallbackRenderer {
  private store: ScanStateStore;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastPrintedPhase: ScanPhase | null = null;
  private spinnerFrame: number = 0;
  private spinnerTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.store = ScanStateStore.getInstance();
  }

  start(targetPath: string): void {
    this.store.update({ targetPath, running: true, startTime: Date.now() });

    // Print header with spinner character
    const chalk = this.getChalk();
    if (chalk) {
      console.log('');
      console.log(chalk.rgb(215, 119, 87).bold('  ✽ SANDYAA') + chalk.gray(' — Security Bug Hunter'));
      console.log(chalk.gray(`  Target: ${targetPath}`));
      console.log(chalk.gray(`  ${'─'.repeat(50)}`));
      console.log('');
    } else {
      console.log(`\n  ✽ SANDYAA — Security Bug Hunter`);
      console.log(`  Target: ${targetPath}`);
      console.log(`  ${'─'.repeat(50)}\n`);
    }

    // Subscribe for live updates
    this.store.subscribe((s) => {
      if (s.phase !== this.lastPrintedPhase) {
        this.lastPrintedPhase = s.phase;
        const icon = SPINNER_FRAMES[this.spinnerFrame % SPINNER_FRAMES.length];
        if (chalk) {
          console.log(chalk.rgb(215, 119, 87)(`  ${icon} `) + chalk.white.bold(phaseLabel(s.phase)));
        } else {
          console.log(`  ${icon} ${phaseLabel(s.phase)}`);
        }
      }
    });
  }

  stop(): void {
    if (this.spinnerTimer) {
      clearInterval(this.spinnerTimer);
      this.spinnerTimer = null;
    }
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const s = this.store.getState();
    const chalk = this.getChalk();

    if (chalk) {
      console.log('');
      console.log(chalk.gray(`  ${'─'.repeat(50)}`));
      console.log(chalk.rgb(44, 122, 57).bold('  ✓ Scan Complete'));
      console.log('');
      console.log(
        chalk.red(`    Critical: ${s.findings.critical}`) + '  ' +
        chalk.rgb(234, 88, 12)(`High: ${s.findings.high}`) + '  ' +
        chalk.yellow(`Medium: ${s.findings.medium}`) + '  ' +
        chalk.gray(`Low: ${s.findings.low}`)
      );
      if (s.findings.rejected > 0) {
        console.log(chalk.gray(`    Rejected: ${s.findings.rejected}`));
      }
      console.log('');
      console.log(chalk.gray(`    Tokens: ${s.tokensUsed.toLocaleString('en-US')}`));
      console.log(chalk.gray(`    Elapsed: ${formatElapsed(s.startTime)}`));
      console.log('');
    } else {
      console.log(`\n  ${'─'.repeat(50)}`);
      console.log(`  ✓ Scan Complete`);
      console.log(`    Critical: ${s.findings.critical}  High: ${s.findings.high}  Medium: ${s.findings.medium}  Low: ${s.findings.low}`);
      console.log(`    Tokens: ${s.tokensUsed.toLocaleString('en-US')}`);
      console.log(`    Elapsed: ${formatElapsed(s.startTime)}\n`);
    }
  }

  private getChalk(): typeof import('chalk').default | null {
    try {
      return require('chalk').default || require('chalk');
    } catch {
      return null;
    }
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
  private inkAvailable: boolean | null = null;

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
    if (this.fallback) {
      const ts = new Date();
      const timeStr = `${ts.getHours().toString().padStart(2, '0')}:${ts.getMinutes().toString().padStart(2, '0')}:${ts.getSeconds().toString().padStart(2, '0')}`;
      try {
        const chalk = require('chalk').default || require('chalk');
        console.log(chalk.gray(`    ${timeStr}`) + ` ${message}`);
      } catch {
        console.log(`    ${timeStr} ${message}`);
      }
    }
  }

  /** Record a finding and optionally log it. */
  addFinding(severity: FindingSeverity | 'rejected', description: string): void {
    this.store.addFinding(severity, description);
    if (this.fallback) {
      const tag = severity === 'rejected' ? 'REJECTED' : severity.toUpperCase();
      try {
        const chalk = require('chalk').default || require('chalk');
        const color = severity === 'critical' ? chalk.red
          : severity === 'high' ? chalk.rgb(234, 88, 12)
          : severity === 'medium' ? chalk.yellow
          : chalk.gray;
        console.log(color(`    [${tag}] ${description}`));
      } catch {
        console.log(`    [${tag}] ${description}`);
      }
    }
  }

  /** Stop the dashboard and print a final summary. */
  stop(): void {
    this.store.update({ running: false, phase: 'done' });

    if (this.inkInstance) {
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
    try {
      const chalk = require('chalk').default || require('chalk');
      console.log('');
      console.log(chalk.gray(`  ${'─'.repeat(50)}`));
      console.log(chalk.rgb(44, 122, 57).bold('  ✓ Scan Complete'));
      console.log('');
      console.log(
        chalk.red(`    Critical: ${s.findings.critical}`) + '  ' +
        chalk.rgb(234, 88, 12)(`High: ${s.findings.high}`) + '  ' +
        chalk.yellow(`Medium: ${s.findings.medium}`) + '  ' +
        chalk.gray(`Low: ${s.findings.low}`)
      );
      console.log('');
      console.log(chalk.gray(`    Tokens: ${s.tokensUsed.toLocaleString('en-US')}`));
      console.log(chalk.gray(`    Elapsed: ${formatElapsed(s.startTime)}`));
      console.log('');
    } catch {
      console.log(`\n  ✓ Scan Complete`);
      console.log(`    Critical: ${s.findings.critical}  High: ${s.findings.high}  Medium: ${s.findings.medium}  Low: ${s.findings.low}`);
      console.log(`    Tokens: ${s.tokensUsed.toLocaleString('en-US')}`);
      console.log(`    Elapsed: ${formatElapsed(s.startTime)}\n`);
    }
  }
}

export { DashboardApp };
