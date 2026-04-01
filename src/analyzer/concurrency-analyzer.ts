import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import * as fs from 'fs/promises';
import chalk from 'chalk';

export interface ConcurrencyIssue {
  type: string;
  location: {
    file: string;
    line: number;
  };
  description: string;
  scenario: string;
  exploitability: number;
  impact: string;
  evidence: string[];
}

export interface ConcurrencyContext {
  concurrencyIssues: ConcurrencyIssue[];
  sharedState: SharedStateInfo[];
  synchronizationPrimitives: SyncPrimitive[];
}

export interface SharedStateInfo {
  variable: string;
  accessedBy: string[];
  synchronized: boolean;
  syncMechanism: string | null;
}

export interface SyncPrimitive {
  type: 'lock' | 'mutex' | 'semaphore' | 'atomic' | 'channel';
  location: string;
  protects: string[];
}

export class ConcurrencyAnalyzer {
  private executor: ModelExecutor;

  constructor(providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  async analyze(files: string[]): Promise<ConcurrencyContext> {
    // Quick check: do any files suggest concurrency patterns?
    const hasConcurrency = await this.quickCheckConcurrency(files);

    if (!hasConcurrency) {
      return {
        concurrencyIssues: [],
        sharedState: [],
        synchronizationPrimitives: []
      };
    }

    // Let Claude decide what to analyze - provide file list and let it read what it needs
    process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Concurrency analysis running...`));
    const result = await this.executor.execute({
      type: 'concurrency-analysis',
      input: {
        files,
        instruction: 'Analyze these files for concurrency issues. YOU decide which files to focus on based on risk.'
      },
      maxTokens: 8000
    });

    process.stdout.write('\r' + ' '.repeat(80) + '\r');

    if (!result.success || !result.output) {
      console.log(chalk.yellow(`      ⚠ Concurrency analysis failed: ${result.error}`));
      return {
        concurrencyIssues: [],
        sharedState: [],
        synchronizationPrimitives: []
      };
    }

    const concurrencyIssues = result.output.concurrencyIssues || [];

    if (concurrencyIssues.length > 0) {
      console.log(chalk.gray(`      Found ${concurrencyIssues.length} concurrency issue${concurrencyIssues.length !== 1 ? 's' : ''}:`));

      // Show first 2 issues
      const samplesToShow = Math.min(2, concurrencyIssues.length);
      for (let i = 0; i < samplesToShow; i++) {
        const issue = concurrencyIssues[i];
        console.log(chalk.gray(`        • ${issue.type} at ${issue.location || 'unknown'}`));
      }

      if (concurrencyIssues.length > 2) {
        console.log(chalk.gray(`        ... and ${concurrencyIssues.length - 2} more`));
      }
    }

    return {
      concurrencyIssues,
      sharedState: [],
      synchronizationPrimitives: []
    };
  }

  private async quickCheckConcurrency(files: string[]): Promise<boolean> {
    // Quick check: are any files likely to have concurrency?
    const concurrencyKeywords = [
      'thread', 'Thread', 'pthread', 'async', 'await',
      'goroutine', 'channel', 'mutex', 'lock',
      'synchronized', 'atomic', 'volatile',
      'Promise', 'Future', 'Task'
    ];

    for (const file of files) {
      try {
        // Just read first 5000 chars for quick check
        const handle = await fs.open(file, 'r');
        const buffer = Buffer.alloc(5000);
        await handle.read(buffer, 0, 5000, 0);
        await handle.close();

        const snippet = buffer.toString('utf-8');
        if (concurrencyKeywords.some(kw => snippet.includes(kw))) {
          return true;
        }
      } catch {
        // Skip files we can't read
      }
    }

    return false;
  }
}
