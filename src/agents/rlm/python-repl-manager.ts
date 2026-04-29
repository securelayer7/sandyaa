import { spawn, ChildProcess } from 'child_process';
import { RLMConfig, REPLResult, REPLContext } from './rlm-types.js';
import { CodeContext } from '../../analyzer/context-analyzer.js';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Manages persistent Python REPL subprocess for RLM execution
 * Handles tool function registration and code execution
 */
export class PythonREPLManager {
  private pythonProcess: ChildProcess | null = null;
  private replReady: boolean = false;
  private config: RLMConfig;
  private outputBuffer: string = '';
  private errorBuffer: string = '';
  private pendingOutput: Promise<string> | null = null;
  private resolveOutput: ((value: string) => void) | null = null;
  private codebaseContext: CodeContext | null = null;

  constructor(config: RLMConfig) {
    this.config = config;
  }

  /**
   * Start Python REPL in interactive mode
   */
  async startREPL(): Promise<void> {
    if (this.pythonProcess) {
      throw new Error('REPL already started');
    }

    this.pythonProcess = spawn(this.config.repl.pythonPath, ['-u', '-i'], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Handle stdout
    this.pythonProcess.stdout?.on('data', (data) => {
      const text = data.toString();
      this.outputBuffer += text;

      // Check for completion markers
      if (this.resolveOutput && (
        text.includes('>>>') ||
        text.includes('<<</FINAL_ANSWER>>>') ||
        text.includes('<<</LLM_QUERY_REQUEST>>>')
      )) {
        const output = this.outputBuffer;
        this.outputBuffer = '';
        this.resolveOutput(output);
        this.resolveOutput = null;
      }
    });

    // Handle stderr
    this.pythonProcess.stderr?.on('data', (data) => {
      this.errorBuffer += data.toString();
    });

    // Wait for Python to be ready
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Suppress Python banner and set up clean output
    await this.executeCode('import sys; sys.ps1 = ""; sys.ps2 = ""', false);

    this.replReady = true;
  }

  /**
   * Load codebase into REPL as variables
   */
  async loadCodebase(context: CodeContext): Promise<void> {
    if (!this.replReady) {
      throw new Error('REPL not started');
    }

    // Prepare metadata
    const metadata = {
      total_files: context.files.length,
      languages: [...new Set(context.files.map(f => f.language))],
      file_paths: context.files.map(f => f.path),
      total_functions: context.files.reduce((sum, f) => sum + f.functions.length, 0),
      entry_points: context.entryPoints,
      data_flows: context.dataFlows.length
    };

    // Load context as JSON — include security-relevant function metadata
    const contextData = {
      files: context.files.map(f => ({
        path: f.path,
        language: f.language,
        functions: f.functions.map(fn => ({
          name: fn.name,
          line: fn.line,
          params: fn.params,
          userInputs: fn.userInputs || [],
          sensitiveSinks: fn.sensitiveSinks || [],
          dataFlow: fn.dataFlow || [],
        }))
      })),
      entryPoints: context.entryPoints,
      trustBoundaries: context.trustBoundaries,
      dataFlows: context.dataFlows || [],
    };

    // Store full context for tool functions to access
    this.codebaseContext = context;

    // Use Base64 encoding to safely pass JSON without injection risk
    const contextJson = JSON.stringify(contextData);
    const contextBase64 = Buffer.from(contextJson).toString('base64');

    await this.executeCode(`
import json
import re
import base64

# Load context safely via Base64 (prevents injection attacks)
context = json.loads(base64.b64decode('${contextBase64}').decode('utf-8'))

# Metadata for quick inspection
metadata = ${JSON.stringify(metadata)}

print("✓ Context loaded: " + str(metadata['total_files']) + " files, " + str(metadata['total_functions']) + " functions")
`, false);
  }

  /**
   * Register tool functions available to Claude
   */
  async registerTools(): Promise<void> {
    if (!this.replReady) {
      throw new Error('REPL not started');
    }

    await this.executeCode(`
# Global variables for tool results
_last_read_result = None
_last_search_result = None
_last_llm_result = None

def read_file_range(path, start_line, end_line):
    """Read specific lines from a file (tool function - handled by TypeScript)"""
    global _last_read_result
    print("<<<TOOL_CALL:read_file_range>>>")
    print(json.dumps({"path": path, "start": start_line, "end": end_line}))
    print("<<</TOOL_CALL>>>")
    # Result will be injected by TypeScript into _last_read_result
    # For now, return placeholder that will be replaced
    return _last_read_result

def search_pattern(regex_pattern, files=None):
    """Search codebase with regex (tool function - handled by TypeScript)"""
    global _last_search_result
    print("<<<TOOL_CALL:search_pattern>>>")
    print(json.dumps({"pattern": regex_pattern, "files": files}))
    print("<<</TOOL_CALL>>>")
    # Result will be injected by TypeScript into _last_search_result
    return _last_search_result

def llm_query(context_chunk, question):
    """Recursive sub-LM call for semantic analysis (tool function - handled by TypeScript)"""
    global _last_llm_result
    print("<<<LLM_QUERY_REQUEST>>>")
    print(json.dumps({"context": context_chunk, "question": question}))
    print("<<</LLM_QUERY_REQUEST>>>")
    # Result will be injected by TypeScript into _last_llm_result
    return _last_llm_result

def FINAL(answer):
    """Mark analysis complete and return final answer"""
    print("<<<FINAL_ANSWER>>>")
    print(json.dumps(answer))
    print("<<</FINAL_ANSWER>>>")
    return answer

print("✓ Tool functions registered: read_file_range, search_pattern, llm_query, FINAL")
`, false);
  }

  /**
   * Execute Python code in REPL
   */
  async executeCode(code: string, waitForOutput: boolean = true): Promise<REPLResult> {
    if (!this.replReady || !this.pythonProcess || !this.pythonProcess.stdin) {
      throw new Error('REPL not ready');
    }

    const startTime = Date.now();

    // Create promise for output
    if (waitForOutput) {
      this.pendingOutput = new Promise((resolve) => {
        this.resolveOutput = resolve;
      });
    }

    // Clear buffers
    this.outputBuffer = '';
    this.errorBuffer = '';

    // Write code to stdin
    this.pythonProcess.stdin.write(code + '\n');

    if (waitForOutput) {
      // Wait for output with timeout
      const timeout = this.config.repl.timeout;
      const output = await Promise.race([
        this.pendingOutput!,
        new Promise<string>((_, reject) =>
          setTimeout(() => reject(new Error('Execution timeout')), timeout)
        )
      ]);

      const executionTime = Date.now() - startTime;

      // Check for errors
      if (this.errorBuffer) {
        return {
          success: false,
          output: output,
          error: this.errorBuffer,
          executionTime
        };
      }

      return {
        success: true,
        output: output.replace(/>>>\s*/g, '').trim(),
        executionTime
      };
    }

    return {
      success: true,
      output: '',
      executionTime: Date.now() - startTime
    };
  }

  /**
   * Extract Python code blocks from Claude's response
   */
  extractPythonCode(text: string): string[] {
    const codeBlocks: string[] = [];
    const pythonBlockRegex = /```python\n([\s\S]*?)```/g;

    let match;
    while ((match = pythonBlockRegex.exec(text)) !== null) {
      codeBlocks.push(match[1].trim());
    }

    return codeBlocks;
  }

  /**
   * Check if output contains tool call request
   */
  hasToolCall(output: string): boolean {
    return output.includes('<<<TOOL_CALL:') ||
           output.includes('<<<LLM_QUERY_REQUEST>>>') ||
           output.includes('<<<FINAL_ANSWER>>>');
  }

  /**
   * Parse tool call from output
   */
  parseToolCall(output: string): { type: string; params: any } | null {
    // Check for FINAL answer
    const finalMatch = output.match(/<<<FINAL_ANSWER>>>([\s\S]*?)<<<\/FINAL_ANSWER>>>/);
    if (finalMatch) {
      try {
        return {
          type: 'FINAL',
          params: JSON.parse(finalMatch[1].trim())
        };
      } catch {
        return {
          type: 'FINAL',
          params: finalMatch[1].trim()
        };
      }
    }

    // Check for LLM query
    const llmMatch = output.match(/<<<LLM_QUERY_REQUEST>>>([\s\S]*?)<<<\/LLM_QUERY_REQUEST>>>/);
    if (llmMatch) {
      try {
        return {
          type: 'llm_query',
          params: JSON.parse(llmMatch[1].trim())
        };
      } catch {
        return null;
      }
    }

    // Check for other tool calls
    const toolMatch = output.match(/<<<TOOL_CALL:(\w+)>>>([\s\S]*?)<<<\/TOOL_CALL>>>/);
    if (toolMatch) {
      try {
        return {
          type: toolMatch[1],
          params: JSON.parse(toolMatch[2].trim())
        };
      } catch {
        return null;
      }
    }

    return null;
  }

  /**
   * Execute read_file_range tool
   */
  async executeReadFileRange(path: string, startLine: number, endLine: number): Promise<string> {
    if (!this.codebaseContext) {
      return JSON.stringify({ error: 'Codebase not loaded' });
    }

    // Find file in context
    const file = this.codebaseContext.files.find(f =>
      f.path === path || f.path.endsWith(path)
    );

    if (!file) {
      return JSON.stringify({ error: `File not found: ${path}` });
    }

    // Read actual file content from disk
    try {
      const content = await fs.readFile(file.path, 'utf-8');
      const lines = content.split('\n');

      // Validate line range
      const start = Math.max(0, startLine - 1);  // Convert to 0-indexed
      const end = Math.min(lines.length, endLine);

      const selectedLines = lines.slice(start, end);

      return JSON.stringify({
        path: file.path,
        startLine,
        endLine,
        totalLines: lines.length,
        content: selectedLines.join('\n'),
        lineNumbers: Array.from({ length: selectedLines.length }, (_, i) => start + i + 1)
      });
    } catch (error) {
      return JSON.stringify({ error: `Failed to read file: ${error}` });
    }
  }

  /**
   * Execute search_pattern tool
   */
  async executeSearchPattern(pattern: string, files?: string[]): Promise<string> {
    if (!this.codebaseContext) {
      return JSON.stringify({ error: 'Codebase not loaded' });
    }

    // Bounds against catastrophic backtracking. JavaScript's RegExp is not
    // interruptible, so a pattern like `(a+)+b` against a long input line
    // can stall the event loop for an unbounded time. Until/unless we adopt
    // a linear-time engine (e.g. re2), apply soft caps:
    //
    //   - reject lines longer than MAX_LINE_BYTES so a 10MB minified file
    //     doesn't become a single super-long line that amplifies a bad
    //     pattern,
    //   - check a wall-clock deadline between lines so a runaway match on
    //     one file cannot keep the loop pinned forever.
    //
    // These are best-effort: a single line under MAX_LINE_BYTES with a
    // nested-quantifier pattern can still hang `regex.test()` for that one
    // call. The deadline check stops us from compounding the damage.
    const MAX_LINE_BYTES = 64 * 1024;     // 64KB
    const DEADLINE_MS = 10_000;            // 10s total wall budget
    const startedAt = Date.now();

    try {
      const regex = new RegExp(pattern, 'gm');
      const results: any[] = [];

      // Determine which files to search
      const filesToSearch = files
        ? this.codebaseContext.files.filter(f => files.includes(f.path))
        : this.codebaseContext.files;

      let timedOut = false;
      let skippedLongLines = 0;

      outer:
      for (const file of filesToSearch) {
        try {
          const content = await fs.readFile(file.path, 'utf-8');
          const lines = content.split('\n');

          for (let index = 0; index < lines.length; index++) {
            const line = lines[index];
            if (line.length > MAX_LINE_BYTES) {
              skippedLongLines++;
              continue;
            }
            // Reset lastIndex defensively — `g` flag carries state across
            // `test()` calls on the same regex instance.
            regex.lastIndex = 0;
            if (regex.test(line)) {
              results.push({
                file: file.path,
                line: index + 1,
                content: line.trim(),
                language: file.language
              });
            }
            // Cheap deadline check (every 256 lines) keeps overhead low
            // while still bounding total wall time.
            if ((index & 0xff) === 0 && Date.now() - startedAt > DEADLINE_MS) {
              timedOut = true;
              break outer;
            }
          }
        } catch (error) {
          // Skip files that can't be read
          continue;
        }
      }

      return JSON.stringify({
        pattern,
        matches: results.length,
        results: results.slice(0, 100),  // Limit to 100 matches to prevent overwhelming output
        truncated: results.length > 100,
        timedOut,
        skippedLongLines
      });
    } catch (error) {
      return JSON.stringify({ error: `Invalid regex pattern: ${error}` });
    }
  }

  /**
   * Inject tool result back into REPL
   */
  async injectToolResult(result: string): Promise<void> {
    // Python will be waiting for result - just write it
    await this.executeCode(`_tool_result = ${JSON.stringify(result)}`, false);
  }

  /**
   * Cleanup REPL process
   */
  async cleanup(): Promise<void> {
    if (this.pythonProcess) {
      this.pythonProcess.kill();
      this.pythonProcess = null;
      this.replReady = false;
    }
  }

  /**
   * Check if REPL is ready
   */
  isReady(): boolean {
    return this.replReady;
  }
}
