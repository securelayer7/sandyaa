import { RLMConfig, TurnResult, CompletionStatus, RLMResult } from './rlm-types.js';
import { PythonREPLManager } from './python-repl-manager.js';
import { ClaudeExecutor } from '../agent-executor.js';
import { ContextCompactor } from '../../utils/context-compactor.js';

/**
 * Orchestrates multi-turn RLM interaction between Claude and Python REPL
 * Implements the core RLM loop from the arXiv paper
 */
export class RLMOrchestrator {
  private config: RLMConfig;
  private executor: ClaudeExecutor;
  private compactor: ContextCompactor;

  constructor(config: RLMConfig, executor: ClaudeExecutor) {
    this.config = config;
    this.executor = executor;
    this.compactor = new ContextCompactor();
  }

  /**
   * Execute multi-turn RLM loop
   */
  async multiTurnLoop(
    taskId: string,
    initialPrompt: string,
    replManager: PythonREPLManager,
    model: 'haiku' | 'sonnet' = 'sonnet'
  ): Promise<RLMResult> {
    let turn = 0;
    const maxTurns = this.config.multiTurn.maxTurns;

    // Build conversation as a single prompt with turn markers
    let conversationHistory = initialPrompt;

    const tokenBreakdown = {
      environmentSetup: this.estimatePromptTokens(initialPrompt),
      turnInteractions: [] as number[],
      subLLMQueries: [] as number[],
      total: 0
    };

    let finalAnswer: any = null;

    while (turn < maxTurns) {
      turn++;
      console.log(`    Turn ${turn}/${maxTurns}...`);

      // Call Claude via ClaudeExecutor (uses Claude Code CLI)
      const turnStart = Date.now();
      const result = await this.executor.executeRLMTurn(
        taskId,
        conversationHistory,
        model,
        turn
      );

      if (!result.success) {
        // Execution failed
        tokenBreakdown.total = tokenBreakdown.environmentSetup +
          tokenBreakdown.turnInteractions.reduce((a, b) => a + b, 0) +
          tokenBreakdown.subLLMQueries.reduce((a, b) => a + b, 0);

        return {
          success: false,
          output: null,
          error: result.error || 'Claude execution failed',
          tokenBreakdown,
          turnsUsed: turn,
          subQueriesUsed: tokenBreakdown.subLLMQueries.length
        };
      }

      const turnTokens = result.tokensUsed || 0;
      tokenBreakdown.turnInteractions.push(turnTokens);

      const assistantText = result.output || '';

      // Add assistant response to conversation history
      conversationHistory += `\n\n<assistant_response>\n${assistantText}\n</assistant_response>\n`;

      // Extract Python code blocks
      const pythonCode = replManager.extractPythonCode(assistantText);

      if (pythonCode.length > 0) {
        console.log(`      Executing ${pythonCode.length} Python code blocks...`);

        let executionResults: string[] = [];

        // Execute each code block sequentially
        for (const code of pythonCode) {
          const result = await replManager.executeCode(code);

          if (!result.success) {
            // Execution error - send error back to Claude
            conversationHistory += `\n<execution_error>\n${result.error}\n\nPlease fix the code and try again.\n</execution_error>\n`;
            break;  // Stop executing remaining blocks on error
          }

          executionResults.push(result.output);

          // Check for tool calls in output
          const toolCall = replManager.parseToolCall(result.output);

          if (toolCall) {
            if (toolCall.type === 'FINAL') {
              // Analysis complete!
              finalAnswer = toolCall.params;
              tokenBreakdown.total = tokenBreakdown.environmentSetup +
                tokenBreakdown.turnInteractions.reduce((a, b) => a + b, 0) +
                tokenBreakdown.subLLMQueries.reduce((a, b) => a + b, 0);

              return {
                success: true,
                output: finalAnswer,
                tokenBreakdown,
                turnsUsed: turn,
                subQueriesUsed: tokenBreakdown.subLLMQueries.length
              };
            } else if (toolCall.type === 'llm_query') {
              // Handle recursive sub-query
              console.log(`        → Sub-query: ${toolCall.params.question.substring(0, 50)}...`);
              const subResult = await this.handleLLMQuery(
                toolCall.params.context,
                toolCall.params.question
              );

              tokenBreakdown.subLLMQueries.push(subResult.tokens);

              // Inject result as Python variable
              await replManager.executeCode(
                `_last_llm_result = ${JSON.stringify(subResult.result)}`,
                false
              );

              executionResults.push(`llm_query() returned: ${subResult.result.substring(0, 100)}...`);

            } else if (toolCall.type === 'read_file_range') {
              // Execute read_file_range tool
              console.log(`        → Reading ${toolCall.params.path}:${toolCall.params.start}-${toolCall.params.end}`);
              const fileContent = await replManager.executeReadFileRange(
                toolCall.params.path,
                toolCall.params.start,
                toolCall.params.end
              );

              // Inject result as Python variable
              await replManager.executeCode(
                `_last_read_result = ${fileContent}`,
                false
              );

              const parsed = JSON.parse(fileContent);
              if (parsed.error) {
                executionResults.push(`read_file_range() error: ${parsed.error}`);
              } else {
                executionResults.push(`read_file_range() returned ${parsed.content.split('\n').length} lines from ${parsed.path}`);
              }

            } else if (toolCall.type === 'search_pattern') {
              // Execute search_pattern tool
              console.log(`        → Searching pattern: ${toolCall.params.pattern}`);
              const searchResults = await replManager.executeSearchPattern(
                toolCall.params.pattern,
                toolCall.params.files
              );

              // Inject result as Python variable
              await replManager.executeCode(
                `_last_search_result = ${searchResults}`,
                false
              );

              const parsed = JSON.parse(searchResults);
              if (parsed.error) {
                executionResults.push(`search_pattern() error: ${parsed.error}`);
              } else {
                executionResults.push(`search_pattern() found ${parsed.matches} matches (showing ${parsed.results.length})`);
              }
            }
          }
        }

        // Add execution results to conversation history
        if (executionResults.length > 0) {
          conversationHistory += `\n<execution_results>\n\`\`\`\n${executionResults.join('\n\n')}\n\`\`\`\n</execution_results>\n`;
        }
      } else {
        // No Python code in response - Claude might be explaining or asking
        conversationHistory += `\n<system_reminder>\nPlease write Python code to continue the analysis. Remember to call FINAL() when done.\n</system_reminder>\n`;
      }

      // Smart context compaction — apply micro-compact first, then escalate
      const maxHistoryTokens = 100_000; // ~400K chars
      const currentTokens = this.compactor.estimateTokens(conversationHistory);
      if (currentTokens > maxHistoryTokens) {
        const { text, strategy } = this.compactor.compactConversation(conversationHistory, maxHistoryTokens);
        const newTokens = this.compactor.estimateTokens(text);
        conversationHistory = text;
        console.log(`      (context compacted via "${strategy}": ${currentTokens} → ${newTokens} tokens)`);
      }

      // Check for timeout
      if (turn >= maxTurns) {
        console.log(`      Max turns reached without FINAL() call`);
        break;
      }
    }

    // Timeout or error - return partial results
    tokenBreakdown.total = tokenBreakdown.environmentSetup +
      tokenBreakdown.turnInteractions.reduce((a, b) => a + b, 0) +
      tokenBreakdown.subLLMQueries.reduce((a, b) => a + b, 0);

    return {
      success: false,
      output: null,
      error: `RLM loop terminated after ${turn} turns without calling FINAL()`,
      tokenBreakdown,
      turnsUsed: turn,
      subQueriesUsed: tokenBreakdown.subLLMQueries.length
    };
  }

  /**
   * Handle llm_query() recursive sub-call
   */
  private async handleLLMQuery(
    contextChunk: string,
    question: string
  ): Promise<{ result: string; tokens: number }> {
    console.log(`      Sub-query: "${question.substring(0, 60)}..."`);

    try {
      // Parse context if it's JSON
      let parsedContext;
      try {
        parsedContext = JSON.parse(contextChunk);
      } catch {
        parsedContext = { rawContext: contextChunk };
      }

      // Use cheaper model (Haiku) for sub-queries (cost optimization from paper)
      const subModel = this.config.subQueries.model || 'haiku';

      const subPrompt = `# Security Sub-Analysis Task

You are a security researcher analyzing a code chunk for vulnerabilities.

## Context
${JSON.stringify(parsedContext, null, 2)}

## Question
${question}

## Instructions
- Analyze ONLY the provided context for security issues
- Trace data flows from user inputs to dangerous sinks
- Report ONLY proven vulnerabilities with concrete evidence
- Include exact file paths and line numbers
- Be concise - you are one of many parallel analyses

## Required Output Format
Return JSON only (wrap in \`\`\`json blocks):
\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "vuln-N",
      "type": "specific-type",
      "severity": "critical|high|medium|low",
      "location": { "file": "path", "line": 123, "function": "name" },
      "description": "what is wrong",
      "attackVector": "how to exploit",
      "dataFlow": ["source", "transform", "sink"],
      "impact": "what attacker achieves"
    }
  ],
  "observations": "any security-relevant notes"
}
\`\`\``;

      const response = await this.executor.executeRLMSubQuery(
        `rlm-subquery-${Date.now()}`,
        subPrompt,
        subModel
      );

      if (!response.success) {
        return {
          result: JSON.stringify({ error: response.error || 'Sub-query failed' }),
          tokens: response.tokensUsed || 0
        };
      }

      const text = response.output || '';

      // Extract JSON from response
      const jsonMatch = text.match(/```json\n([\s\S]*?)```/);
      const result = jsonMatch ? jsonMatch[1] : text;

      return { result, tokens: response.tokensUsed || 0 };

    } catch (error) {
      console.error(`      Sub-query error: ${error}`);
      return {
        result: JSON.stringify({ error: String(error) }),
        tokens: 0
      };
    }
  }

  /**
   * Estimate token count for prompt (rough approximation)
   */
  private estimatePromptTokens(prompt: string): number {
    // Rough estimate: ~4 chars per token
    return Math.ceil(prompt.length / 4);
  }
}
