import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import chalk from 'chalk';

export interface AnalysisPlan {
  analyses: AnalysisStrategy[];
  reasoning: string;
  focusAreas: string[];
}

export interface AnalysisStrategy {
  name: string;              // Custom strategy name (Claude decides)
  description: string;       // What this analysis will look for
  justification: string;     // Why this is needed for THIS code
  targetFiles?: string[];    // Specific files to analyze (optional)
}

export interface LearningContext {
  previousFindings?: Array<{
    type: string;
    severity: string;
    location: string;
    pattern: string;
  }>;
  gitHistoryPatterns?: string[];
  highRiskAreas?: string[];
  commonVulnerabilityTypes?: string[];
  successfulStrategies?: string[];
}

/**
 * Intelligent analysis planner - examines code and decides what analyses to run
 * LEARNS from previous findings and adapts strategies dynamically
 */
export class AnalysisPlanner {
  private executor: ModelExecutor;
  private learningContext: LearningContext;

  constructor(providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
    this.learningContext = {};
  }

  /**
   * Update the planner with learnings from previous chunks
   * TOKEN-EFFICIENT: Only keeps essential compressed information
   */
  updateLearning(context: LearningContext): void {
    // Merge new learnings with existing context - keep only essentials to save tokens
    this.learningContext = {
      // Keep last 10 findings only (was 20) - each ~50 tokens = 500 tokens max
      previousFindings: [
        ...(this.learningContext.previousFindings || []),
        ...(context.previousFindings || [])
      ].slice(-10),

      // Git history patterns - keep top 10 only (set once, don't duplicate)
      gitHistoryPatterns: context.gitHistoryPatterns || this.learningContext.gitHistoryPatterns,

      // High-risk areas - deduplicate and keep top 5
      highRiskAreas: Array.from(new Set([
        ...(this.learningContext.highRiskAreas || []),
        ...(context.highRiskAreas || [])
      ])).slice(0, 5),

      // Common types - aggregate counts (compressed)
      commonVulnerabilityTypes: context.commonVulnerabilityTypes || this.learningContext.commonVulnerabilityTypes,

      // Successful strategies - deduplicate and keep top 5
      successfulStrategies: Array.from(new Set([
        ...(this.learningContext.successfulStrategies || []),
        ...(context.successfulStrategies || [])
      ])).slice(0, 5)
    };
  }

  /**
   * Get compressed summary of learnings (for token-efficient prompting)
   */
  getLearningsSummary(): string {
    if (!this.learningContext.previousFindings || this.learningContext.previousFindings.length === 0) {
      return 'No previous learnings yet (first chunk).';
    }

    // Aggregate vulnerability types for compression
    const typeCounts = new Map<string, number>();
    for (const finding of this.learningContext.previousFindings) {
      typeCounts.set(finding.type, (typeCounts.get(finding.type) || 0) + 1);
    }

    const topTypes = Array.from(typeCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type, count]) => `${type} (${count}x)`)
      .join(', ');

    return `Found ${this.learningContext.previousFindings.length} bugs: ${topTypes}`;
  }

  async planAnalysis(files: string[]): Promise<AnalysisPlan> {
    const hasLearnings = this.learningContext.previousFindings && this.learningContext.previousFindings.length > 0;

    if (hasLearnings) {
      process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Planning with ${this.learningContext.previousFindings!.length} previous findings...`));
    } else {
      process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Planning analyses (examining ${files.length} file${files.length !== 1 ? 's' : ''})...`));
    }

    const result = await this.executor.execute({
      type: 'analysis-planning',
      input: {
        files,
        learningContext: this.learningContext // Pass learning context to Claude
      },
      maxTokens: 4000,
      model: 'haiku' // Fast planning with Haiku
    });

    process.stdout.write('\r' + ' '.repeat(100) + '\r');

    // Validate that Claude didn't hallucinate and analyze Sandyaa instead of target
    if (result.success && result.output && result.output.reasoning) {
      const reasoning = result.output.reasoning.toLowerCase();
      const hallucinations = [
        'sandyaa', 'security tool', 'vulnerability discovery tool', 'analysis tool',
        'scanner', 'detection tool', 'poc generator', 'agent executor'
      ];

      const foundHallucination = hallucinations.find(h => reasoning.includes(h));
      if (foundHallucination) {
        console.log(chalk.red(`      ⚠ REJECTED: Claude analyzed wrong codebase (mentioned "${foundHallucination}")`));
        console.log(chalk.red(`      Claude must analyze the TARGET codebase, not Sandyaa itself!`));
        result.output = null; // Force fallback
      }
    }

    if (!result.success || !result.output || !result.output.analyses || !Array.isArray(result.output.analyses)) {
      // Fallback: analyze everything BUT use accumulated learnings
      if (result.output) {
        console.log(chalk.yellow(`      ⚠ Planning response malformed (missing analyses array), using fallback`));

        // Check if this is CLI metadata instead of actual response
        if (result.output.type && (result.output.type === 'result' || result.output.type === 'system')) {
          console.log(chalk.red(`        ERROR: Got CLI metadata instead of Claude's response!`));
          console.log(chalk.red(`        This means the response parser failed to extract the actual content.`));
        } else {
          console.log(chalk.gray(`        Response keys: ${Object.keys(result.output).join(', ')}`));
          console.log(chalk.gray(`        Response preview: ${JSON.stringify(result.output).substring(0, 200)}...`));
        }
      } else if (result.error) {
        console.log(chalk.yellow(`      ⚠ Planning failed: ${result.error}`));
      } else {
        console.log(chalk.yellow(`      ⚠ Planning failed, analyzing all aspects`));
      }

      // Build smart fallback description using learnings
      let fallbackDescription = 'Full security analysis covering all vulnerability classes';
      let fallbackJustification = 'Planning failed - analyzing all security aspects to ensure nothing is missed';

      // Enhance with learnings if available
      if (this.learningContext.previousFindings && this.learningContext.previousFindings.length > 0) {
        const bugTypes = [...new Set(this.learningContext.previousFindings.map(f => f.type))];
        fallbackDescription += `. FOCUS on patterns similar to previously found bugs: ${bugTypes.slice(0, 3).join(', ')}`;
        fallbackJustification += `. Previous research found: ${this.learningContext.previousFindings.length} bugs`;
      }

      if (this.learningContext.gitHistoryPatterns && this.learningContext.gitHistoryPatterns.length > 0) {
        fallbackDescription += `. CHECK for regressions of: ${this.learningContext.gitHistoryPatterns.slice(0, 2).join(', ')}`;
        fallbackJustification += `. Git history shows: ${this.learningContext.gitHistoryPatterns.length} vulnerability patterns`;
      }

      if (this.learningContext.successfulStrategies && this.learningContext.successfulStrategies.length > 0) {
        fallbackDescription += `. APPLY techniques from successful strategies: ${this.learningContext.successfulStrategies.slice(0, 2).join(', ')}`;
      }

      return {
        analyses: [
          {
            name: 'comprehensive-security-analysis-with-learnings',
            description: fallbackDescription,
            justification: fallbackJustification
          }
        ],
        reasoning: 'Comprehensive analysis with accumulated learnings (planning failed but using research data)',
        focusAreas: this.learningContext.highRiskAreas || []
      };
    }

    console.log(chalk.gray(`      Plan: ${result.output.analyses.length} analyses recommended`));
    return result.output;
  }
}
