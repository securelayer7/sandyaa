import { RLMConfig, RLMTokenBreakdown, CostReport, RLMExecutionRecord, StandardExecutionRecord } from './rlm-types.js';
import * as fs from 'fs/promises';

/**
 * Tracks and compares RLM vs standard execution costs
 * Validates the 3× cost reduction claim from the paper
 */
export class RLMCostTracker {
  private rlmExecutions: RLMExecutionRecord[] = [];
  private standardExecutions: StandardExecutionRecord[] = [];
  private config: RLMConfig;

  constructor(config?: RLMConfig) {
    this.config = config || {
      enabled: false,
      activationThreshold: { minContextSize: 100, minFileCount: 20 },
      repl: { pythonPath: 'python3', timeout: 60000, maxMemory: 512 * 1024 * 1024 },
      multiTurn: { maxTurns: 20, turnTimeout: 120000 },
      subQueries: { maxConcurrent: 3, maxChunkSize: 500000, model: 'haiku' },
      costTracking: { enabled: true, logFile: '.sandyaa/rlm-cost-report.json' }
    };
  }

  /**
   * Record RLM execution
   */
  recordRLMExecution(taskType: string, tokenBreakdown: RLMTokenBreakdown): void {
    this.rlmExecutions.push({
      taskType,
      environmentSetup: tokenBreakdown.environmentSetup,
      turnInteractions: tokenBreakdown.turnInteractions,
      subLLMQueries: tokenBreakdown.subLLMQueries,
      total: tokenBreakdown.total,
      timestamp: Date.now()
    });

    this.saveToFile();
  }

  /**
   * Record standard execution
   */
  recordStandardExecution(taskType: string, tokens: number): void {
    this.standardExecutions.push({
      taskType,
      tokens,
      timestamp: Date.now()
    });

    this.saveToFile();
  }

  /**
   * Get cost comparison report
   */
  getCostComparison(): CostReport {
    const rlmTotal = this.rlmExecutions.reduce((sum, e) => sum + e.total, 0);
    const standardTotal = this.standardExecutions.reduce((sum, e) => sum + e.tokens, 0);

    // Calculate cost reduction factor
    const costReductionFactor = standardTotal > 0 ? standardTotal / rlmTotal : 0;

    // Estimate savings (using Sonnet pricing: $3/1M input + $15/1M output)
    // Simplified: assume 70% input, 30% output tokens
    const costPerToken = (0.7 * 3 + 0.3 * 15) / 1_000_000;
    const rlmCost = rlmTotal * costPerToken;
    const standardCost = standardTotal * costPerToken;
    const estimatedSavings = standardCost - rlmCost;

    return {
      rlmExecutions: this.rlmExecutions.length,
      standardExecutions: this.standardExecutions.length,
      rlmTotalTokens: rlmTotal,
      standardTotalTokens: standardTotal,
      costReductionFactor,
      estimatedSavings
    };
  }

  /**
   * Get detailed breakdown by task type
   */
  getBreakdownByTaskType(): { [taskType: string]: { rlm: number; standard: number; reduction: number } } {
    const breakdown: { [taskType: string]: { rlm: number; standard: number; reduction: number } } = {};

    // Aggregate by task type
    for (const exec of this.rlmExecutions) {
      if (!breakdown[exec.taskType]) {
        breakdown[exec.taskType] = { rlm: 0, standard: 0, reduction: 0 };
      }
      breakdown[exec.taskType].rlm += exec.total;
    }

    for (const exec of this.standardExecutions) {
      if (!breakdown[exec.taskType]) {
        breakdown[exec.taskType] = { rlm: 0, standard: 0, reduction: 0 };
      }
      breakdown[exec.taskType].standard += exec.tokens;
    }

    // Calculate reduction factors
    for (const taskType in breakdown) {
      const { rlm, standard } = breakdown[taskType];
      breakdown[taskType].reduction = standard > 0 ? standard / rlm : 0;
    }

    return breakdown;
  }

  /**
   * Save tracking data to file
   */
  private async saveToFile(): Promise<void> {
    if (!this.config.costTracking.enabled) {
      return;
    }

    try {
      const data = {
        rlmExecutions: this.rlmExecutions,
        standardExecutions: this.standardExecutions,
        report: this.getCostComparison(),
        breakdown: this.getBreakdownByTaskType(),
        timestamp: new Date().toISOString()
      };

      await fs.writeFile(
        this.config.costTracking.logFile,
        JSON.stringify(data, null, 2)
      );
    } catch (error) {
      // Silently fail - cost tracking is not critical
    }
  }

  /**
   * Load tracking data from file
   */
  async loadFromFile(): Promise<void> {
    if (!this.config.costTracking.enabled) {
      return;
    }

    try {
      const content = await fs.readFile(this.config.costTracking.logFile, 'utf-8');
      const data = JSON.parse(content);

      this.rlmExecutions = data.rlmExecutions || [];
      this.standardExecutions = data.standardExecutions || [];
    } catch (error) {
      // File doesn't exist yet - that's okay
    }
  }

  /**
   * Reset all tracking data
   */
  reset(): void {
    this.rlmExecutions = [];
    this.standardExecutions = [];
    this.saveToFile();
  }
}
