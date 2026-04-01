/**
 * Multi-Provider Model Executor
 *
 * Automatically switches between Claude and Gemini:
 * - Primary provider (Claude or Gemini)
 * - Automatic fallback on rate limits
 * - Model selection per provider
 */

import { ClaudeExecutor, AgentTask as ClaudeTask, AgentResult as ClaudeResult } from './agent-executor.js';
import { GeminiExecutor, AgentTask as GeminiTask, AgentResult as GeminiResult } from './gemini-executor.js';
import { IntelligentProviderSelector, TaskCharacteristics } from '../utils/intelligent-provider-selector.js';
import chalk from 'chalk';

export type Provider = 'claude' | 'gemini';
export type ClaudeModel = 'haiku' | 'sonnet' | 'opus';
export type GeminiModel = 'flash' | 'pro' | 'ultra';

export interface ProviderConfig {
  primary: Provider | 'auto';
  fallback: Provider | 'none';
  autoSwitch: boolean;
  intelligentSelection?: boolean; // NEW: Enable intelligent provider selection (optional, defaults to true)
  models?: {
    claude?: ClaudeModel;
    gemini?: GeminiModel;
  };
}

export interface AgentTask {
  id?: string;
  type: string;
  input: any;
  maxTokens?: number;
  model?: string;
}

export interface AgentResult {
  success: boolean;
  output: any;
  error?: string;
  tokensUsed?: number;
  model?: string;
  provider?: Provider;
}

export class ModelExecutor {
  private claudeExecutor: ClaudeExecutor;
  private geminiExecutor: GeminiExecutor;
  private config: ProviderConfig;
  private currentProvider: Provider;
  private rateLimitTracker: Map<Provider, number> = new Map();
  private intelligentSelector: IntelligentProviderSelector;

  constructor(config?: ProviderConfig) {
    this.config = config || {
      primary: 'auto',
      fallback: 'gemini',
      autoSwitch: true,
      intelligentSelection: true // Enable by default
    };
    this.claudeExecutor = new ClaudeExecutor();
    this.geminiExecutor = new GeminiExecutor();
    this.intelligentSelector = new IntelligentProviderSelector();

    // Determine initial provider
    if (this.config.primary === 'auto') {
      // Intelligent selection will choose per-task
      this.currentProvider = 'claude';
    } else {
      this.currentProvider = this.config.primary as Provider;
    }

    console.log(chalk.cyan(`\n🤖 [PROVIDER CONFIG]`));
    console.log(chalk.cyan(`   Mode:       ${this.config.intelligentSelection ? 'INTELLIGENT AUTO-SELECT' : 'STATIC'}`));
    console.log(chalk.cyan(`   Primary:    ${this.currentProvider.toUpperCase()}`));
    console.log(chalk.cyan(`   Fallback:   ${this.config.fallback.toUpperCase()}`));
    console.log(chalk.cyan(`   Auto-Switch: ${this.config.autoSwitch ? 'ENABLED' : 'DISABLED'}`));
    if (this.config.models?.claude) {
      console.log(chalk.cyan(`   Claude Model: ${this.config.models.claude}`));
    }
    if (this.config.models?.gemini) {
      console.log(chalk.cyan(`   Gemini Model: ${this.config.models.gemini}`));
    }
    console.log('');
  }

  /**
   * Set target path so Claude CLI runs in the target directory (prevents self-scanning)
   */
  setTargetPath(targetPath: string): void {
    this.claudeExecutor.setTargetPath(targetPath);
  }

  /**
   * Execute task with automatic provider switching
   */
  async execute(task: AgentTask): Promise<AgentResult> {
    // Use intelligent provider selection if enabled
    let selectedProvider = this.currentProvider;
    let selectedModel: string | undefined;
    let selectionReasoning = 'Using configured provider';

    if (this.config.intelligentSelection && this.config.primary === 'auto') {
      // Determine task characteristics
      const characteristics: TaskCharacteristics = {
        type: task.type,
        complexity: this.estimateComplexity(task),
        requiresDeepReasoning: this.requiresDeepReasoning(task.type),
        requiresCodeGeneration: task.type.includes('poc') || task.type.includes('generation'),
        requiresLongContext: (task.input?.files?.length || 0) > 10,
        estimatedTokens: this.estimateTokens(task),
        isCostSensitive: false // Could be made configurable
      };

      // Get intelligent recommendation
      const recommendation = this.intelligentSelector.selectProvider(characteristics);
      selectedProvider = recommendation.provider;
      selectedModel = recommendation.model;
      selectionReasoning = recommendation.reasoning;

      console.log(chalk.magenta(`🧠 [INTELLIGENT SELECT] ${selectedProvider.toUpperCase()} (${selectedModel})`));
      console.log(chalk.gray(`   Reason: ${selectionReasoning}`));
    }

    const modelName = selectedModel || (selectedProvider === 'claude'
      ? (this.config.models?.claude || 'default')
      : (this.config.models?.gemini || 'default'));

    console.log(chalk.blue(`🚀 [EXECUTING] ${selectedProvider.toUpperCase()} (${modelName})...`));

    // Execute with selected provider
    const result = await this.executeWithProvider(selectedProvider, task, selectedModel);

    // Check if rate limited
    if (!result.success && this.isRateLimitError(result.error)) {
      console.log(chalk.yellow(`\n⚠️  [RATE LIMIT] ${this.currentProvider.toUpperCase()} rate limit reached!`));

      // Try fallback provider if auto-switch enabled
      if (this.config.autoSwitch && this.config.fallback !== 'none') {
        console.log(chalk.green(`\n🔄 [AUTO-SWITCHING] Switching to ${this.config.fallback.toUpperCase()}...`));

        const fallbackResult = await this.executeWithProvider(this.config.fallback as Provider, task);

        if (fallbackResult.success) {
          // Update current provider to fallback
          this.currentProvider = this.config.fallback as Provider;
          console.log(chalk.green(`✅ [PROVIDER SWITCHED] Now using ${this.currentProvider.toUpperCase()}\n`));
        } else {
          console.log(chalk.red(`❌ [FALLBACK FAILED] ${this.config.fallback.toUpperCase()} also failed\n`));
        }

        return fallbackResult;
      } else {
        console.log(chalk.yellow(`   Auto-switch disabled or no fallback configured\n`));
      }
    }

    return result;
  }

  /**
   * Execute with specific provider
   */
  private async executeWithProvider(provider: Provider, task: AgentTask, model?: string): Promise<AgentResult> {
    try {
      if (provider === 'claude') {
        return await this.executeWithClaude(task, model);
      } else {
        return await this.executeWithGemini(task, model);
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        output: null,
        provider
      };
    }
  }

  /**
   * Execute with Claude
   */
  private async executeWithClaude(task: AgentTask, selectedModel?: string): Promise<AgentResult> {
    // Map model if specified
    let model: ClaudeModel | undefined;
    if (selectedModel) {
      model = selectedModel as ClaudeModel;
    } else if (task.model) {
      model = task.model as ClaudeModel;
    } else if (this.config.models?.claude) {
      model = this.config.models.claude;
    }

    const claudeTask = {
      ...task,
      model: model as 'haiku' | 'sonnet' | 'opus'
    } as ClaudeTask;

    const result = await this.claudeExecutor.execute(claudeTask);

    return {
      ...result,
      provider: 'claude'
    };
  }

  /**
   * Execute with Gemini
   */
  private async executeWithGemini(task: AgentTask, selectedModel?: string): Promise<AgentResult> {
    // Map model if specified
    let model: GeminiModel | undefined;
    if (selectedModel) {
      model = selectedModel as GeminiModel;
    } else if (task.model) {
      model = task.model as GeminiModel;
    } else if (this.config.models?.gemini) {
      model = this.config.models.gemini;
    }

    const geminiTask = {
      ...task,
      model: model as 'flash' | 'pro' | 'ultra'
    } as GeminiTask;

    const result = await this.geminiExecutor.execute(geminiTask);

    return {
      ...result,
      provider: 'gemini'
    };
  }

  /**
   * Check if error is a rate limit error
   */
  private isRateLimitError(error?: string): boolean {
    if (!error) return false;

    const rateLimitKeywords = [
      'rate limit',
      'too many requests',
      '429',
      'quota exceeded',
      'rate_limit_error',
      'overloaded'
    ];

    return rateLimitKeywords.some(keyword =>
      error.toLowerCase().includes(keyword)
    );
  }

  /**
   * Manually switch provider
   */
  switchProvider(provider: Provider): void {
    this.currentProvider = provider;
    console.log(`[PROVIDER] Manually switched to ${provider}`);
  }

  /**
   * Get current provider
   */
  getCurrentProvider(): Provider {
    return this.currentProvider;
  }

  /**
   * Estimate task complexity based on type and input
   */
  private estimateComplexity(task: AgentTask): 'low' | 'medium' | 'high' {
    // High complexity tasks
    const highComplexityTasks = [
      'vulnerability-detection',
      'memory-safety-analysis',
      'concurrency-analysis',
      'semantic-analysis',
      'custom-security-analysis'
    ];

    // Low complexity tasks
    const lowComplexityTasks = [
      'file-prioritization',
      'regression-detection'
    ];

    if (highComplexityTasks.includes(task.type)) {
      return 'high';
    } else if (lowComplexityTasks.includes(task.type)) {
      return 'low';
    } else {
      return 'medium';
    }
  }

  /**
   * Determine if task requires deep reasoning
   */
  private requiresDeepReasoning(taskType: string): boolean {
    const deepReasoningTasks = [
      'vulnerability-detection',
      'memory-safety-analysis',
      'concurrency-analysis',
      'semantic-analysis',
      'poc-generation',
      'custom-security-analysis',
      'blast-radius-analysis'
    ];

    return deepReasoningTasks.includes(taskType);
  }

  /**
   * Estimate token count for task
   */
  private estimateTokens(task: AgentTask): number {
    let estimate = 1000; // Base estimate

    // Add tokens for files
    if (task.input?.files) {
      estimate += task.input.files.length * 500;
    }

    // Add tokens for file contents
    if (task.input?.fileContents) {
      const contentLength = JSON.stringify(task.input.fileContents).length;
      estimate += Math.floor(contentLength / 4); // Rough token estimate (4 chars per token)
    }

    // Add tokens for max tokens setting
    if (task.maxTokens) {
      estimate += task.maxTokens;
    }

    return estimate;
  }
}
