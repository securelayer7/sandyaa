/**
 * RLM (Recursive Language Model) Type Definitions
 * Based on arXiv paper: https://arxiv.org/html/2512.24601v1
 */

export interface RLMConfig {
  enabled: boolean;
  activationThreshold: {
    minContextSize: number;  // KB
    minFileCount: number;
  };
  repl: {
    pythonPath: string;
    timeout: number;  // ms per code execution
    maxMemory: number;  // bytes
  };
  multiTurn: {
    maxTurns: number;
    turnTimeout: number;  // ms
  };
  subQueries: {
    maxConcurrent: number;
    maxChunkSize: number;  // chars
    model: 'haiku' | 'sonnet';
  };
  costTracking: {
    enabled: boolean;
    logFile: string;
  };
}

export interface RLMActivation {
  shouldActivate: boolean;
  reason: string;
}

export interface REPLContext {
  totalFiles: number;
  languages: string[];
  metadata: any;
}

export interface REPLResult {
  success: boolean;
  output: string;
  error?: string;
  executionTime: number;
}

export interface RLMTokenBreakdown {
  environmentSetup: number;
  turnInteractions: number[];
  subLLMQueries: number[];
  total: number;
}

export interface RLMResult {
  success: boolean;
  output: any;
  error?: string;
  tokenBreakdown: RLMTokenBreakdown;
  turnsUsed: number;
  subQueriesUsed: number;
}

export interface TurnResult {
  assistantResponse: string;
  pythonCodeExecuted: string[];
  executionResults: REPLResult[];
  tokenCost: number;
}

export interface CompletionStatus {
  complete: boolean;
  answer?: any;
  timeout?: boolean;
}

export interface CostReport {
  rlmExecutions: number;
  standardExecutions: number;
  rlmTotalTokens: number;
  standardTotalTokens: number;
  costReductionFactor: number;
  estimatedSavings: number;
}

export interface RLMExecutionRecord {
  taskType: string;
  environmentSetup: number;
  turnInteractions: number[];
  subLLMQueries: number[];
  total: number;
  timestamp: number;
}

export interface StandardExecutionRecord {
  taskType: string;
  tokens: number;
  timestamp: number;
}
