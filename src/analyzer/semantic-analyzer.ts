import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import * as fs from 'fs/promises';
import chalk from 'chalk';

export interface SemanticIssue {
  type: string;
  location: {
    file: string;
    line: number;
  };
  description: string;
  invariantViolated: string;
  attackScenario: string;
  exploitability: number;
  impact: string;
  fiveWhys: string[];
  fiveHows: string[];
}

export interface SemanticContext {
  semanticIssues: SemanticIssue[];
  businessLogic: BusinessLogicInfo[];
  stateMachines: StateMachine[];
  securityCriticalOperations: SecurityOperation[];
}

export interface BusinessLogicInfo {
  operation: string;
  purpose: string;
  invariants: string[];
  constraints: string[];
}

export interface StateMachine {
  name: string;
  states: string[];
  transitions: Array<{
    from: string;
    to: string;
    trigger: string;
  }>;
  invalidTransitions: string[];
}

export interface SecurityOperation {
  type: 'authentication' | 'authorization' | 'crypto' | 'data-access' | 'state-transition';
  location: string;
  description: string;
  risks: string[];
}

export class SemanticAnalyzer {
  private executor: ModelExecutor;

  constructor(providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  async analyze(files: string[]): Promise<SemanticContext> {
    // Direct semantic analysis without spawning agents
    process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Semantic & logic bug analysis running...`));
    const result = await this.executor.execute({
      type: 'semantic-analysis',
      input: {
        files,
        instruction: 'Analyze these files for semantic vulnerabilities and logic bugs. Focus on authentication, authorization, state machines, and trust boundaries.'
      },
      maxTokens: 8000
    });

    process.stdout.write('\r' + ' '.repeat(80) + '\r');

    if (!result.success || !result.output) {
      console.log(chalk.yellow(`      ⚠ Semantic analysis failed: ${result.error}`));
      return {
        semanticIssues: [],
        businessLogic: [],
        stateMachines: [],
        securityCriticalOperations: []
      };
    }

    const semanticIssues = result.output.semanticIssues || [];

    if (semanticIssues.length > 0) {
      console.log(chalk.gray(`      Found ${semanticIssues.length} semantic issue${semanticIssues.length !== 1 ? 's' : ''}:`));

      // Show first 2 issues
      const samplesToShow = Math.min(2, semanticIssues.length);
      for (let i = 0; i < samplesToShow; i++) {
        const issue = semanticIssues[i];
        console.log(chalk.gray(`        • ${issue.type} at ${issue.location || 'unknown'}`));
      }

      if (semanticIssues.length > 2) {
        console.log(chalk.gray(`        ... and ${semanticIssues.length - 2} more`));
      }
    }

    return {
      semanticIssues,
      businessLogic: result.output.businessLogic || [],
      stateMachines: result.output.stateMachines || [],
      securityCriticalOperations: result.output.securityCriticalOperations || []
    };
  }
}
