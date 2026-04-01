import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Hook types for the Sandyaa scanning lifecycle.
 * Inspired by Claude Code's hooks system — lets users attach callbacks
 * or shell scripts to key events in the scanning pipeline.
 */
export enum HookType {
  /** Before scanning begins. Receives { targetPath, config }. */
  ScanStart = 'ScanStart',
  /** After scanning completes. Receives { totalBugs, filesAnalyzed, duration, findingsDir }. */
  ScanComplete = 'ScanComplete',
  /** When a vulnerability is found. Receives the vulnerability object. */
  FindingDetected = 'FindingDetected',
  /** When a finding passes recursive verification. Receives the verified vulnerability. */
  FindingVerified = 'FindingVerified',
  /** When a finding is contradicted during verification. Receives the rejected vulnerability. */
  FindingRejected = 'FindingRejected',
  /** Before analyzing a chunk of files. Receives { chunkIndex, files, totalFiles }. */
  ChunkStart = 'ChunkStart',
  /** After chunk analysis completes. Receives { chunkIndex, files, vulnerabilitiesFound, tokensUsed }. */
  ChunkComplete = 'ChunkComplete',
  /** On errors. Receives { error, phase, context }. */
  Error = 'Error',
}

export type HookHandler = (data: any) => void | Promise<void>;

/** Maps shell script filenames in .sandyaa/hooks/ to their hook types. */
const SHELL_HOOK_MAP: Record<string, HookType> = {
  'on-scan-start.sh': HookType.ScanStart,
  'on-scan-complete.sh': HookType.ScanComplete,
  'on-complete.sh': HookType.ScanComplete,
  'on-finding.sh': HookType.FindingDetected,
  'on-finding-detected.sh': HookType.FindingDetected,
  'on-finding-verified.sh': HookType.FindingVerified,
  'on-finding-rejected.sh': HookType.FindingRejected,
  'on-chunk-start.sh': HookType.ChunkStart,
  'on-chunk-complete.sh': HookType.ChunkComplete,
  'on-error.sh': HookType.Error,
};

/**
 * Manages lifecycle hooks for the scanning pipeline.
 *
 * Supports two kinds of handlers:
 *   1. Programmatic callbacks registered via `register()`.
 *   2. Shell scripts loaded from `.sandyaa/hooks/` via `registerFromConfig()`.
 *      Scripts receive JSON data on stdin.
 */
export class HookManager {
  private handlers: Map<HookType, HookHandler[]> = new Map();

  /**
   * Register a callback for a given hook type.
   * Returns an unregister function.
   */
  register(hookType: HookType, handler: HookHandler): () => void {
    if (!this.handlers.has(hookType)) {
      this.handlers.set(hookType, []);
    }
    this.handlers.get(hookType)!.push(handler);

    // Return unsubscribe function
    return () => {
      const list = this.handlers.get(hookType);
      if (list) {
        const idx = list.indexOf(handler);
        if (idx !== -1) {
          list.splice(idx, 1);
        }
      }
    };
  }

  /**
   * Load shell-script hooks from the `.sandyaa/hooks/` directory
   * relative to the given config/project root.
   *
   * Each executable `.sh` file whose name matches SHELL_HOOK_MAP
   * is wrapped in a handler that spawns the script and pipes JSON
   * data on stdin.
   */
  async registerFromConfig(projectRoot: string): Promise<void> {
    const hooksDir = path.join(projectRoot, '.sandyaa', 'hooks');

    let entries: string[];
    try {
      entries = await fs.readdir(hooksDir);
    } catch {
      // No hooks directory — nothing to load
      return;
    }

    for (const entry of entries) {
      const hookType = SHELL_HOOK_MAP[entry];
      if (!hookType) {
        continue;
      }

      const scriptPath = path.join(hooksDir, entry);

      // Verify the file is executable (or at least exists)
      try {
        await fs.access(scriptPath, fs.constants.X_OK);
      } catch {
        // Not executable — try to make it so, but skip if that fails
        try {
          await fs.chmod(scriptPath, 0o755);
        } catch {
          continue;
        }
      }

      this.register(hookType, (data: any) => {
        return this.executeShellHook(scriptPath, data);
      });
    }
  }

  /**
   * Fire all registered handlers for a hook type synchronously
   * (fire-and-forget for async handlers).
   */
  emit(hookType: HookType, data: any): void {
    const list = this.handlers.get(hookType);
    if (!list || list.length === 0) {
      return;
    }

    for (const handler of list) {
      try {
        const result = handler(data);
        // If it returns a promise, catch errors but don't await
        if (result && typeof (result as any).catch === 'function') {
          (result as any).catch((err: Error) => {
            console.error(`[hooks] Error in ${hookType} handler:`, err.message);
          });
        }
      } catch (err: any) {
        console.error(`[hooks] Error in ${hookType} handler:`, err.message);
      }
    }
  }

  /**
   * Fire all registered handlers for a hook type and wait for
   * all of them (including async ones) to complete.
   */
  async emitAsync(hookType: HookType, data: any): Promise<void> {
    const list = this.handlers.get(hookType);
    if (!list || list.length === 0) {
      return;
    }

    const results: Promise<void>[] = [];
    for (const handler of list) {
      try {
        const result = handler(data);
        if (result && typeof (result as any).then === 'function') {
          results.push(result as Promise<void>);
        }
      } catch (err: any) {
        console.error(`[hooks] Error in ${hookType} handler:`, err.message);
      }
    }

    if (results.length > 0) {
      const settled = await Promise.allSettled(results);
      for (const outcome of settled) {
        if (outcome.status === 'rejected') {
          console.error(`[hooks] Async handler error in ${hookType}:`, outcome.reason?.message ?? outcome.reason);
        }
      }
    }
  }

  /**
   * Remove all handlers for a specific hook type, or all hooks
   * if no type is provided.
   */
  clear(hookType?: HookType): void {
    if (hookType) {
      this.handlers.delete(hookType);
    } else {
      this.handlers.clear();
    }
  }

  /**
   * Spawn a shell script and pipe JSON-serialized data to its stdin.
   * Times out after 30 seconds.
   */
  private executeShellHook(scriptPath: string, data: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = 30_000;
      const child = spawn(scriptPath, [], {
        stdio: ['pipe', 'inherit', 'inherit'],
        env: {
          ...process.env,
          SANDYAA_HOOK: '1',
        },
      });

      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error(`Shell hook timed out after ${timeout / 1000}s: ${scriptPath}`));
      }, timeout);

      child.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Shell hook exited with code ${code}: ${scriptPath}`));
        }
      });

      // Write JSON data to stdin and close
      const jsonData = JSON.stringify(data, null, 2);
      child.stdin.write(jsonData);
      child.stdin.end();
    });
  }
}

/** Singleton hooks instance for the scanning pipeline. */
export const hooks = new HookManager();
