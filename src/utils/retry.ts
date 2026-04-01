/**
 * Retry with exponential backoff utility.
 *
 * Inspired by Claude Code's withRetry pattern. Designed for wrapping
 * Claude CLI and Gemini API calls that can hit rate limits or
 * transient network errors.
 */

import { spawn, type SpawnOptionsWithoutStdio, type ChildProcess } from 'child_process';

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/** Errors whose `.code` indicates a connection-level problem. */
const CONNECTION_ERROR_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'ETIMEDOUT',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'EAI_AGAIN',      // DNS resolution transient failure
]);

/** HTTP-style status codes that signal rate limiting. */
const RATE_LIMIT_CODES = new Set([429, 529]);

export type RetryErrorKind = 'rate_limit' | 'connection' | 'timeout' | 'unknown';

/**
 * Classify an error so the retry loop can decide on delay strategy.
 */
export function classifyError(error: unknown): RetryErrorKind {
  if (error instanceof Error) {
    const msg = error.message.toLowerCase();
    const code = (error as NodeJS.ErrnoException).code;

    // Connection-level errors
    if (code && CONNECTION_ERROR_CODES.has(code)) {
      return 'connection';
    }

    // Rate limit detection — status code in message or dedicated field
    for (const rc of RATE_LIMIT_CODES) {
      if (msg.includes(String(rc))) return 'rate_limit';
    }
    if (msg.includes('rate limit') || msg.includes('rate_limit') || msg.includes('overloaded')) {
      return 'rate_limit';
    }

    // Timeout
    if (msg.includes('timeout') || msg.includes('timed out') || code === 'ETIMEDOUT') {
      return 'timeout';
    }
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// RetryOptions & withRetry
// ---------------------------------------------------------------------------

export interface RetryOptions {
  /** Maximum number of retry attempts (not counting the first try). Default 3. */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff. Default 1000. */
  baseDelay?: number;
  /** Ceiling for the computed delay. Default 30000. */
  maxDelay?: number;
  /** Called before each retry. Return `false` to abort. */
  onRetry?: (error: unknown, attempt: number, delay: number, kind: RetryErrorKind) => void | boolean;
}

/**
 * Sleep for `ms` milliseconds, adding uniform jitter of up to `jitter` ms.
 */
function sleep(ms: number, jitter = 0): Promise<void> {
  const actual = ms + Math.random() * jitter;
  return new Promise((resolve) => setTimeout(resolve, actual));
}

/**
 * Compute the delay for a given attempt number and error kind.
 *
 * - **rate_limit**: full exponential backoff with jitter (back off hard).
 * - **connection**: immediate retry (0 ms on first attempt, small delay after).
 * - **timeout**: moderate linear increase so the next try has more room.
 * - **unknown**: standard exponential backoff.
 */
function computeDelay(
  attempt: number,
  kind: RetryErrorKind,
  baseDelay: number,
  maxDelay: number,
): number {
  switch (kind) {
    case 'rate_limit': {
      // Exponential: base * 2^attempt, capped at maxDelay
      const exp = baseDelay * Math.pow(2, attempt);
      return Math.min(exp, maxDelay);
    }
    case 'connection': {
      // First retry is immediate; subsequent ones grow slowly
      if (attempt === 0) return 0;
      return Math.min(baseDelay * attempt, maxDelay);
    }
    case 'timeout': {
      // Moderate linear backoff
      return Math.min(baseDelay * (attempt + 1), maxDelay);
    }
    default: {
      const exp = baseDelay * Math.pow(2, attempt);
      return Math.min(exp, maxDelay);
    }
  }
}

/**
 * Generic retry wrapper with exponential backoff.
 *
 * ```ts
 * const result = await withRetry(() => callSomeAPI(), { maxRetries: 5 });
 * ```
 *
 * The return type is preserved from the wrapped function.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 30_000,
    onRetry,
  } = options;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      // Exhausted all retries — rethrow
      if (attempt === maxRetries) {
        throw error;
      }

      const kind = classifyError(error);
      const delay = computeDelay(attempt, kind, baseDelay, maxDelay);
      // Add jitter: up to 25% of the computed delay
      const jitter = delay * 0.25;

      // Notify caller (they can abort by returning false)
      if (onRetry) {
        const shouldContinue = onRetry(error, attempt + 1, delay, kind);
        if (shouldContinue === false) {
          throw error;
        }
      }

      if (delay > 0 || jitter > 0) {
        await sleep(delay, jitter);
      }
    }
  }

  // Should be unreachable, but satisfy the compiler
  throw lastError;
}

// ---------------------------------------------------------------------------
// retryableSpawn — retry-aware child_process.spawn wrapper
// ---------------------------------------------------------------------------

/** Exit codes that CLI tools commonly use to signal rate limiting / overload. */
const RETRYABLE_EXIT_CODES = new Set([
  2,   // Some CLIs use exit-code 2 for transient / rate-limit errors
  75,  // EX_TEMPFAIL (sysexits.h)
]);

export interface SpawnResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export interface RetryableSpawnOptions extends RetryOptions {
  /** Additional exit codes (beyond the built-in set) to treat as retryable. */
  retryableExitCodes?: number[];
  /**
   * A predicate evaluated against stderr/stdout when the process exits
   * with a non-zero code. Return `true` to allow a retry.
   * This lets callers detect rate-limit messages in the output even when
   * the exit code is generic (e.g., 1).
   */
  isRetryableOutput?: (result: SpawnResult) => boolean;
}

/**
 * Spawn a CLI process with automatic retry on transient failures.
 *
 * Accepts the same positional arguments as `child_process.spawn`, plus
 * an optional `input` string to write to stdin and retry options.
 *
 * ```ts
 * const result = await retryableSpawn('claude', ['--print', ...args], {
 *   cwd: '/some/path',
 * }, {
 *   input: prompt,
 *   maxRetries: 3,
 * });
 * ```
 */
export async function retryableSpawn(
  command: string,
  args: readonly string[],
  spawnOptions?: SpawnOptionsWithoutStdio,
  retryOptions?: RetryableSpawnOptions & { input?: string },
): Promise<SpawnResult> {
  const {
    input,
    retryableExitCodes = [],
    isRetryableOutput,
    ...retryOpts
  } = retryOptions ?? {};

  const allRetryableCodes = new Set([...RETRYABLE_EXIT_CODES, ...retryableExitCodes]);

  return withRetry<SpawnResult>(
    () =>
      new Promise<SpawnResult>((resolve, reject) => {
        const proc: ChildProcess = spawn(command, args, {
          ...spawnOptions,
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        if (input && proc.stdin) {
          proc.stdin.write(input);
          proc.stdin.end();
        }

        let stdout = '';
        let stderr = '';

        proc.stdout?.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        proc.stderr?.on('data', (data: Buffer) => {
          stderr += data.toString();
        });

        proc.on('error', (err) => {
          // Spawn-level errors (ENOENT, etc.) — let classifyError decide
          reject(err);
        });

        proc.on('close', (exitCode) => {
          const result: SpawnResult = { exitCode, stdout, stderr };

          if (exitCode === 0) {
            resolve(result);
            return;
          }

          // Check if this failure is retryable
          const outputLower = (stderr + stdout).toLowerCase();
          const isRateLimited =
            outputLower.includes('rate limit') ||
            outputLower.includes('rate_limit') ||
            outputLower.includes('429') ||
            outputLower.includes('529') ||
            outputLower.includes('overloaded');

          const exitRetryable = exitCode !== null && allRetryableCodes.has(exitCode);
          const outputRetryable = isRetryableOutput?.(result) ?? false;

          if (isRateLimited || exitRetryable || outputRetryable) {
            // Reject so withRetry can catch and retry
            const err = new Error(
              `Process exited with code ${exitCode}: ${(stderr || stdout).substring(0, 300)}`,
            );
            (err as any).exitCode = exitCode;
            (err as any).spawnResult = result;
            // Tag the message so classifyError picks it up
            if (isRateLimited) {
              (err as any).message = `rate limit: ${err.message}`;
            }
            reject(err);
            return;
          }

          // Non-retryable failure — resolve (not reject) so the caller
          // can inspect the result without triggering a retry.
          resolve(result);
        });
      }),
    retryOpts,
  );
}
