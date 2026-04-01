/**
 * Gemini CLI Executor - Uses gemini CLI (no API keys)
 *
 * Works exactly like ClaudeExecutor but uses `gemini` command:
 * - gemini -p "prompt" --output-format json
 * - No API keys needed (uses gemini CLI authentication)
 * - Same task/file structure as ClaudeExecutor
 */

import { execSync } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import { getGeminiModelMap } from '../utils/model-registry.js';

export interface AgentTask {
  type: 'context-building' | 'vulnerability-detection' | 'poc-generation' |
        'recursive-verification' | 'regression-analysis' | 'contradiction-detection' |
        'memory-safety-analysis' | 'concurrency-analysis' | 'semantic-analysis' |
        'blast-radius-analysis' | 'file-prioritization' | 'analysis-planning' |
        'custom-security-analysis';
  input: any;
  maxTokens?: number;
  model?: 'flash' | 'pro' | 'ultra';  // Gemini model tiers
}

export interface AgentResult {
  success: boolean;
  output: any;
  error?: string;
  tokensUsed?: number;
  model?: string;
}

export class GeminiExecutor {
  private tasksDir: string;
  private tasksInProgress = new Set<string>();

  constructor(tasksDir: string = './.sandyaa/tasks') {
    this.tasksDir = tasksDir;
  }

  /**
   * Check if gemini CLI is available
   */
  private isGeminiCLIAvailable(): boolean {
    try {
      execSync('which gemini', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Execute a task using Gemini CLI
   */
  async execute(task: AgentTask): Promise<AgentResult> {
    if (!this.isGeminiCLIAvailable()) {
      return {
        success: false,
        error: 'Gemini CLI not found. Install with: npm install -g @google/gemini-cli\n' +
               'Then authenticate: gemini auth',
        output: null
      };
    }

    const taskId = this.generateTaskId();

    if (this.tasksInProgress.has(taskId)) {
      return {
        success: false,
        error: `Task ${taskId} already in progress`,
        output: null
      };
    }

    this.tasksInProgress.add(taskId);

    try {
      return await this.executeViaFiles(taskId, task);
    } finally {
      this.tasksInProgress.delete(taskId);
    }
  }

  /**
   * Execute task by writing prompt to file and using gemini CLI
   */
  private async executeViaFiles(taskId: string, task: AgentTask): Promise<AgentResult> {
    await fs.mkdir(this.tasksDir, { recursive: true });

    // Determine model (default to pro)
    const model = task.model || 'pro';
    const modelMap = getGeminiModelMap();
    const geminiModel = modelMap[model as keyof typeof modelMap];

    // Build prompt
    const prompt = this.buildPrompt(task);

    // Write prompt to file
    const promptFile = path.join(this.tasksDir, `${taskId}-prompt.txt`);
    const rawOutputFile = path.join(this.tasksDir, `${taskId}-raw.txt`);

    await fs.writeFile(promptFile, prompt, 'utf-8');

    // Execute gemini CLI in headless mode with JSON output
    try {
      console.log(`    Running gemini CLI (model: ${geminiModel})...`);

      // Use positional prompt instead of -p flag (preferred in newer versions)
      const command = `gemini "$(cat "${promptFile}")" --output-format json --model ${geminiModel}`;

      const output = execSync(command, {
        encoding: 'utf-8',
        maxBuffer: 50 * 1024 * 1024,  // 50MB buffer
        timeout: 300000,  // 5 minute timeout
        env: {
          ...process.env,
        }
      });

      // Save raw output
      await fs.writeFile(rawOutputFile, output, 'utf-8');

      // Parse JSON response
      const parsedOutput = this.parseGeminiResponse(output);

      if (!parsedOutput) {
        return {
          success: false,
          error: 'Failed to parse Gemini CLI response',
          output: null
        };
      }

      return {
        success: true,
        output: parsedOutput,
        model: geminiModel
      };

    } catch (error: any) {
      console.error(`Gemini CLI execution failed:`, error.message);

      return {
        success: false,
        error: error.message,
        output: null
      };
    }
  }

  /**
   * Parse Gemini CLI JSON response
   */
  private parseGeminiResponse(output: string): any {
    try {
      // Gemini CLI with --output-format json returns structured JSON
      const parsed = JSON.parse(output);

      // Extract the actual response text from Gemini's structure
      // Gemini CLI typically returns: { response: "text", metadata: {...} }
      if (parsed.response) {
        // Try to parse the response text as JSON (for structured outputs)
        try {
          return JSON.parse(parsed.response);
        } catch {
          // If not JSON, return as-is
          return { text: parsed.response };
        }
      }

      return parsed;
    } catch (e) {
      // Fallback: try to extract JSON from text
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          return JSON.parse(jsonMatch[0]);
        } catch {
          return null;
        }
      }
      return null;
    }
  }

  /**
   * Build prompt based on task type (same structure as ClaudeExecutor)
   */
  private buildPrompt(task: AgentTask): string {
    // For now, just forward the input as prompt
    // In production, you'd use the same prompt builders as ClaudeExecutor
    // buildDetectionPrompt, buildPOCPrompt, etc.

    switch (task.type) {
      case 'vulnerability-detection':
        return this.buildDetectionPrompt(task.input);

      case 'context-building':
        return this.buildContextPrompt(task.input);

      default:
        return JSON.stringify(task.input, null, 2);
    }
  }

  /**
   * Build vulnerability detection prompt (simplified version)
   */
  private buildDetectionPrompt(input: any): string {
    const { context } = input;

    return `# Security Vulnerability Analysis

Analyze the following codebase for security vulnerabilities.

## Code Context
${JSON.stringify(context, null, 2)}

## Instructions
1. Find real, exploitable security vulnerabilities
2. Trace attacker control paths from external input
3. Provide concrete evidence with file:line references

## Output Format

Respond with ONLY a JSON object:

\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "type": "vulnerability-type",
      "severity": "critical|high|medium|low",
      "location": {
        "file": "path/to/file",
        "line": 123,
        "function": "functionName"
      },
      "description": "What is wrong",
      "attackVector": "How to exploit",
      "impact": "What attacker achieves"
    }
  ]
}
\`\`\`

START YOUR RESPONSE WITH THE JSON OBJECT NOW.`;
  }

  /**
   * Build context building prompt
   */
  private buildContextPrompt(input: any): string {
    return `Analyze this codebase and build security context.

${JSON.stringify(input, null, 2)}

Return JSON with: { components: [], dataFlows: [], trustBoundaries: [] }`;
  }

  /**
   * Generate unique task ID
   */
  private generateTaskId(): string {
    return `gemini-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  }
}
