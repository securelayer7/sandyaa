import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import * as fs from 'fs/promises';
import chalk from 'chalk';

export interface MemoryIssue {
  type: string;
  location: {
    file: string;
    line: number;
  };
  description: string;
  rootCause: string;
  exploitability: number;
  impact: string;
  evidence: string[];
}

export interface MemorySafetyContext {
  memoryIssues: MemoryIssue[];
  objectLifetimes: Map<string, LifetimeInfo>;
  pointerRelationships: PointerGraph;
}

export interface LifetimeInfo {
  object: string;
  creationLocation: string;
  destructionLocation: string | null;
  references: string[];
  canBeAccessedAfterDestruction: boolean;
}

export interface PointerGraph {
  nodes: Array<{
    object: string;
    type: string;
  }>;
  edges: Array<{
    from: string;
    to: string;
    relationship: 'points-to' | 'owns' | 'references';
  }>;
}

export class MemorySafetyAnalyzer {
  private executor: ModelExecutor;

  constructor(providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  async analyze(files: string[]): Promise<MemorySafetyContext> {
    // Only analyze if files contain languages that have manual memory management
    const needsAnalysis = await this.quickCheck(files);

    if (!needsAnalysis) {
      return {
        memoryIssues: [],
        objectLifetimes: new Map(),
        pointerRelationships: { nodes: [], edges: [] }
      };
    }

    // Let Claude decide what to analyze - provide file list and let it read what it needs
    process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Memory safety analysis running...`));
    const result = await this.executor.execute({
      type: 'memory-safety-analysis',
      input: {
        files,
        instruction: 'Analyze these files for memory safety issues. YOU decide which files to focus on based on risk.'
      },
      maxTokens: 8000
    });

    process.stdout.write('\r' + ' '.repeat(80) + '\r');

    if (!result.success || !result.output) {
      console.log(chalk.yellow(`      ⚠ Memory safety analysis failed: ${result.error}`));
      return {
        memoryIssues: [],
        objectLifetimes: new Map(),
        pointerRelationships: { nodes: [], edges: [] }
      };
    }

    // Parse the response
    const memoryIssues = result.output.memoryIssues || [];

    if (memoryIssues.length > 0) {
      console.log(chalk.gray(`      Found ${memoryIssues.length} memory issue${memoryIssues.length !== 1 ? 's' : ''}:`));

      // Show first 2 issues
      const samplesToShow = Math.min(2, memoryIssues.length);
      for (let i = 0; i < samplesToShow; i++) {
        const issue = memoryIssues[i];
        console.log(chalk.gray(`        • ${issue.type} at ${issue.location || 'unknown'}`));
      }

      if (memoryIssues.length > 2) {
        console.log(chalk.gray(`        ... and ${memoryIssues.length - 2} more`));
      }
    }

    return {
      memoryIssues,
      objectLifetimes: new Map(), // TODO: Extract from response
      pointerRelationships: { nodes: [], edges: [] } // TODO: Extract from response
    };
  }

  private async quickCheck(files: string[]): Promise<boolean> {
    // Quick check: are any files in languages with memory management?
    for (const file of files) {
      const ext = file.substring(file.lastIndexOf('.'));
      if (['.c', '.cpp', '.cc', '.h', '.hpp', '.rs', '.go'].includes(ext)) {
        return true;
      }
    }
    return false;
  }
}
