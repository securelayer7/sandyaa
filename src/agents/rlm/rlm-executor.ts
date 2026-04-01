import { RLMConfig, RLMResult, REPLContext } from './rlm-types.js';
import { PythonREPLManager } from './python-repl-manager.js';
import { RLMOrchestrator } from './rlm-orchestrator.js';
import { RLMPromptBuilder } from './rlm-prompt-builder.js';
import { RLMCostTracker } from './rlm-cost-tracker.js';
import { AgentTask, AgentResult } from '../agent-executor.js';
import { ClaudeExecutor } from '../agent-executor.js';

/**
 * Main RLM executor that coordinates all RLM components
 * This is the entry point for RLM-powered analysis
 */
export class RLMExecutor {
  private config: RLMConfig;
  private replManager: PythonREPLManager;
  private orchestrator: RLMOrchestrator;
  private promptBuilder: RLMPromptBuilder;
  private costTracker: RLMCostTracker;
  private claudeExecutor: ClaudeExecutor;

  constructor(config: RLMConfig, costTracker: RLMCostTracker, claudeExecutor: ClaudeExecutor) {
    this.config = config;
    this.costTracker = costTracker;
    this.claudeExecutor = claudeExecutor;

    // Initialize components
    this.replManager = new PythonREPLManager(config);
    this.promptBuilder = new RLMPromptBuilder();

    // Initialize orchestrator (uses ClaudeExecutor for API calls, no direct client needed)
    this.orchestrator = new RLMOrchestrator(config, claudeExecutor);
  }

  /**
   * Execute task using RLM approach
   */
  async execute(taskId: string, task: AgentTask, originalPrompt: string): Promise<AgentResult> {
    try {
      // Step 1: Start Python REPL
      console.log('      Starting Python REPL...');
      await this.replManager.startREPL();

      // Step 2: Load codebase into REPL
      console.log('      Loading codebase into REPL...');
      await this.replManager.loadCodebase(task.input.context);

      // Step 3: Register tool functions
      console.log('      Registering tool functions...');
      await this.replManager.registerTools();

      // Step 4: Build RLM prompt
      const replContext: REPLContext = {
        totalFiles: task.input.context.files.length,
        languages: Array.from(new Set(task.input.context.files.map((f: any) => f.language as string))) as string[],
        metadata: task.input.context
      };

      const rlmPrompt = this.promptBuilder.buildREPLPrompt(task, replContext);

      // Step 5: Execute multi-turn RLM loop
      console.log('      Starting RLM multi-turn analysis...');
      const result = await this.orchestrator.multiTurnLoop(
        taskId,
        rlmPrompt,
        this.replManager,
        'sonnet'  // Use Sonnet for main analysis
      );

      // Step 6: Cleanup REPL
      await this.replManager.cleanup();

      // Step 7: Format result
      if (result.success) {
        console.log(`      ✓ RLM complete: ${result.turnsUsed} turns, ${result.subQueriesUsed} sub-queries`);
        console.log(`      Tokens: ${result.tokenBreakdown.total.toLocaleString()}`);

        return {
          success: true,
          output: result.output,
          tokensUsed: result.tokenBreakdown.total,
          model: 'rlm-sonnet'
        };
      } else {
        console.error(`      RLM failed: ${result.error}`);

        return {
          success: false,
          output: null,
          error: result.error,
          tokensUsed: result.tokenBreakdown.total,
          model: 'rlm-sonnet'
        };
      }

    } catch (error) {
      // Cleanup on error
      await this.replManager.cleanup();

      return {
        success: false,
        output: null,
        error: String(error),
        tokensUsed: 0,
        model: 'rlm-sonnet'
      };
    }
  }

  /**
   * Estimate cost savings for a task
   */
  estimateCostSavings(task: AgentTask, promptSize: number): {
    standardTokens: number;
    rlmTokens: number;
    savingsPercent: number;
  } {
    // Estimate standard approach tokens
    const standardTokens = Math.ceil(promptSize / 4);  // ~4 chars per token

    // Estimate RLM approach tokens (based on paper's 3× reduction)
    const rlmTokens = Math.ceil(standardTokens / 3);

    const savingsPercent = ((standardTokens - rlmTokens) / standardTokens) * 100;

    return {
      standardTokens,
      rlmTokens,
      savingsPercent
    };
  }
}
