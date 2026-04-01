/**
 * Intelligent Provider Selector
 *
 * Automatically chooses between Claude and Gemini based on:
 * - Task type and complexity
 * - Provider strengths/weaknesses
 * - Cost optimization
 * - Performance history
 */

import { getClaudeCostMap, getGeminiCostMap, getClaudeContextWindowMap, getGeminiContextWindowMap } from './model-registry.js';

export type Provider = 'claude' | 'gemini';

export interface TaskCharacteristics {
  type: string;
  complexity: 'low' | 'medium' | 'high';
  requiresDeepReasoning: boolean;
  requiresCodeGeneration: boolean;
  requiresLongContext: boolean;
  estimatedTokens: number;
  isCostSensitive: boolean;
}

export interface ProviderRecommendation {
  provider: Provider;
  model: string;
  reasoning: string;
  confidence: number; // 0-1
  fallbackProvider?: Provider;
}

export interface ProviderPerformance {
  successRate: number;
  avgTokensUsed: number;
  avgCostUSD: number;
  taskCount: number;
}

export class IntelligentProviderSelector {
  private performanceHistory: Map<string, Map<Provider, ProviderPerformance>> = new Map();

  /**
   * Provider strengths based on empirical testing
   */
  private readonly PROVIDER_STRENGTHS = {
    claude: {
      // Claude excels at:
      strengths: [
        'deep-reasoning',
        'code-analysis',
        'security-review',
        'complex-logic',
        'long-context',
        'instruction-following'
      ],
      weaknesses: [
        'simple-tasks', // Overkill for simple tasks
        'high-volume'   // More expensive for bulk operations
      ],
      costPerMToken: getClaudeCostMap(),
      contextWindow: getClaudeContextWindowMap()
    },
    gemini: {
      // Gemini excels at:
      strengths: [
        'fast-iteration',
        'simple-tasks',
        'high-volume',
        'cost-efficiency',
        'code-completion'
      ],
      weaknesses: [
        'complex-reasoning', // Sometimes misses edge cases
        'security-edge-cases' // May not catch subtle vulnerabilities
      ],
      costPerMToken: getGeminiCostMap(),
      contextWindow: getGeminiContextWindowMap()
    }
  };

  /**
   * Task type to provider mapping
   */
  private readonly TASK_RECOMMENDATIONS = {
    // Security-critical tasks → Claude (better at finding edge cases)
    'vulnerability-detection': { provider: 'claude', model: 'sonnet', reasoning: 'Critical security analysis requires deep reasoning' },
    'memory-safety-analysis': { provider: 'claude', model: 'sonnet', reasoning: 'Complex memory patterns need careful analysis' },
    'concurrency-analysis': { provider: 'claude', model: 'sonnet', reasoning: 'Race conditions require deep reasoning' },
    'poc-generation': { provider: 'claude', model: 'sonnet', reasoning: 'Exploit code needs precision and creativity' },
    'semantic-analysis': { provider: 'claude', model: 'sonnet', reasoning: 'Deep semantic understanding required' },

    // Context building → Gemini (faster, cheaper for large volumes)
    'context-building': { provider: 'gemini', model: 'flash', reasoning: 'Fast data extraction, high volume' },
    'file-prioritization': { provider: 'gemini', model: 'flash', reasoning: 'Simple ranking task' },
    'analysis-planning': { provider: 'gemini', model: 'pro', reasoning: 'Strategic planning benefits from broad knowledge' },

    // Pattern extraction → Mix (Gemini for extraction, Claude for validation)
    'vulnerability-pattern-extraction': { provider: 'gemini', model: 'pro', reasoning: 'Pattern recognition, moderate complexity' },
    'regression-detection': { provider: 'gemini', model: 'flash', reasoning: 'Fast comparison task' },

    // Custom analysis → Adaptive (depends on complexity)
    'custom-security-analysis': { provider: 'auto', model: 'auto', reasoning: 'Adaptive based on complexity' },
    'blast-radius-analysis': { provider: 'claude', model: 'haiku', reasoning: 'Impact analysis needs precision but not deep reasoning' }
  } as const;

  /**
   * Select best provider for a task
   */
  selectProvider(characteristics: TaskCharacteristics): ProviderRecommendation {
    // Get base recommendation for task type
    const baseRec = this.TASK_RECOMMENDATIONS[characteristics.type as keyof typeof this.TASK_RECOMMENDATIONS];

    // If task type not in map, use adaptive selection
    if (!baseRec || baseRec.provider === 'auto') {
      return this.adaptiveSelection(characteristics);
    }

    // Check if we should override based on characteristics
    const override = this.checkOverrideConditions(baseRec.provider as Provider, characteristics);
    if (override) {
      return override;
    }

    // Use base recommendation
    return {
      provider: baseRec.provider as Provider,
      model: baseRec.model,
      reasoning: baseRec.reasoning,
      confidence: 0.85,
      fallbackProvider: baseRec.provider === 'claude' ? 'gemini' : 'claude'
    };
  }

  /**
   * Adaptive selection based on task characteristics
   */
  private adaptiveSelection(characteristics: TaskCharacteristics): ProviderRecommendation {
    let score = {
      claude: 0,
      gemini: 0
    };

    // Deep reasoning favors Claude
    if (characteristics.requiresDeepReasoning) {
      score.claude += 3;
      score.gemini += 1;
    }

    // Code generation is neutral (both good)
    if (characteristics.requiresCodeGeneration) {
      score.claude += 2;
      score.gemini += 2;
    }

    // Long context favors Gemini (larger context window)
    if (characteristics.requiresLongContext) {
      score.claude += 1;
      score.gemini += 3;
    }

    // Complexity favors Claude
    const complexityScore = { low: 0, medium: 1, high: 3 }[characteristics.complexity];
    score.claude += complexityScore;
    score.gemini += Math.max(0, complexityScore - 1);

    // Cost sensitivity favors Gemini
    if (characteristics.isCostSensitive) {
      score.gemini += 2;
    } else {
      score.claude += 1; // Better quality when cost doesn't matter
    }

    // Large token estimates favor Gemini (cheaper)
    if (characteristics.estimatedTokens > 50000) {
      score.gemini += 2;
    }

    // Check performance history
    const perfBonus = this.getPerformanceBonus(characteristics.type);
    score.claude += perfBonus.claude;
    score.gemini += perfBonus.gemini;

    // Select winner
    const provider = score.claude > score.gemini ? 'claude' : 'gemini';
    const confidence = Math.abs(score.claude - score.gemini) / Math.max(score.claude, score.gemini);

    return {
      provider,
      model: this.selectModelForProvider(provider, characteristics),
      reasoning: `Adaptive selection: complexity=${characteristics.complexity}, deepReasoning=${characteristics.requiresDeepReasoning}, tokens=${characteristics.estimatedTokens}`,
      confidence,
      fallbackProvider: provider === 'claude' ? 'gemini' : 'claude'
    };
  }

  /**
   * Check if we should override base recommendation
   */
  private checkOverrideConditions(baseProvider: Provider, characteristics: TaskCharacteristics): ProviderRecommendation | null {
    // Override Claude with Gemini for very simple tasks (cost optimization)
    if (baseProvider === 'claude' && characteristics.complexity === 'low' && !characteristics.requiresDeepReasoning) {
      return {
        provider: 'gemini',
        model: 'flash',
        reasoning: 'Cost optimization: Task too simple for Claude',
        confidence: 0.9,
        fallbackProvider: 'claude'
      };
    }

    // Override Gemini with Claude for security-critical tasks
    if (baseProvider === 'gemini' && characteristics.type.includes('security') && characteristics.complexity === 'high') {
      return {
        provider: 'claude',
        model: 'sonnet',
        reasoning: 'Security-critical: Upgrading to Claude for better edge case detection',
        confidence: 0.85,
        fallbackProvider: 'gemini'
      };
    }

    // Large context override
    if (characteristics.estimatedTokens > 150000) {
      return {
        provider: 'gemini',
        model: 'pro',
        reasoning: 'Large context: Gemini has larger context window and is more cost-effective',
        confidence: 0.9,
        fallbackProvider: 'claude'
      };
    }

    return null;
  }

  /**
   * Select model tier for provider
   */
  private selectModelForProvider(provider: Provider, characteristics: TaskCharacteristics): string {
    if (provider === 'claude') {
      // Claude model selection
      if (characteristics.complexity === 'high' || characteristics.requiresDeepReasoning) {
        return 'sonnet'; // Best balance of performance and cost
      } else if (characteristics.complexity === 'low') {
        return 'haiku'; // Fast and cheap for simple tasks
      } else {
        return 'sonnet'; // Default to sonnet
      }
    } else {
      // Gemini model selection
      if (characteristics.complexity === 'high') {
        return 'pro'; // Better reasoning for complex tasks
      } else {
        return 'flash'; // Fast and cheap for simple/medium tasks
      }
    }
  }

  /**
   * Get performance bonus based on historical success
   */
  private getPerformanceBonus(taskType: string): { claude: number; gemini: number } {
    const history = this.performanceHistory.get(taskType);
    if (!history) {
      return { claude: 0, gemini: 0 };
    }

    const claudePerf = history.get('claude');
    const geminiPerf = history.get('gemini');

    if (!claudePerf || !geminiPerf) {
      return { claude: 0, gemini: 0 };
    }

    // Give bonus to provider with better success rate
    const claudeBonus = claudePerf.successRate > geminiPerf.successRate ? 1 : 0;
    const geminiBonus = geminiPerf.successRate > claudePerf.successRate ? 1 : 0;

    return { claude: claudeBonus, gemini: geminiBonus };
  }

  /**
   * Record task result for learning
   */
  recordTaskResult(taskType: string, provider: Provider, success: boolean, tokensUsed: number, costUSD: number) {
    if (!this.performanceHistory.has(taskType)) {
      this.performanceHistory.set(taskType, new Map());
    }

    const taskHistory = this.performanceHistory.get(taskType)!;
    const currentPerf = taskHistory.get(provider) || {
      successRate: 0,
      avgTokensUsed: 0,
      avgCostUSD: 0,
      taskCount: 0
    };

    // Update running averages
    const newCount = currentPerf.taskCount + 1;
    taskHistory.set(provider, {
      successRate: (currentPerf.successRate * currentPerf.taskCount + (success ? 1 : 0)) / newCount,
      avgTokensUsed: (currentPerf.avgTokensUsed * currentPerf.taskCount + tokensUsed) / newCount,
      avgCostUSD: (currentPerf.avgCostUSD * currentPerf.taskCount + costUSD) / newCount,
      taskCount: newCount
    });
  }

  /**
   * Get provider statistics
   */
  getStats(): { [provider: string]: { totalTasks: number; successRate: number; totalCost: number } } {
    const stats: any = {
      claude: { totalTasks: 0, successRate: 0, totalCost: 0 },
      gemini: { totalTasks: 0, successRate: 0, totalCost: 0 }
    };

    for (const [taskType, providers] of this.performanceHistory.entries()) {
      for (const [provider, perf] of providers.entries()) {
        stats[provider].totalTasks += perf.taskCount;
        stats[provider].successRate = (stats[provider].successRate * stats[provider].totalTasks + perf.successRate * perf.taskCount) / (stats[provider].totalTasks + perf.taskCount);
        stats[provider].totalCost += perf.avgCostUSD * perf.taskCount;
      }
    }

    return stats;
  }
}
