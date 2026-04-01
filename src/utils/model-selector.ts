import * as fs from 'fs/promises';
import * as path from 'path';

export type ModelTier = 'haiku' | 'sonnet' | 'opus';

export interface ComplexityMetrics {
  avgFileSize: number;
  avgNestingDepth: number;
  language: string;
  hasUnsafeCode: boolean;
  hasConcurrency: boolean;
  hasIPC: boolean;
  linesOfCode: number;
  cyclomaticComplexity: number;
}

export interface ModelRecommendation {
  model: ModelTier;
  reasoning: string;
  confidence: number;
}

export class DynamicModelSelector {
  private taskHistory: Map<string, { model: ModelTier; success: boolean; tokensUsed: number }> = new Map();
  private complexityCache: Map<string, ComplexityMetrics> = new Map();

  /**
   * Dynamically select model based on code complexity and task type
   */
  async selectModel(
    taskType: string,
    files: string[],
    previousFindings?: any[]
  ): Promise<ModelRecommendation> {
    // Step 1: Analyze code complexity
    const complexity = await this.analyzeComplexity(files);

    // Step 2: Check if previous attempts needed escalation
    const needsEscalation = this.checkEscalationNeeded(taskType, previousFindings);

    // Step 3: Apply decision logic
    return this.decideModel(taskType, complexity, needsEscalation);
  }

  /**
   * Analyze code complexity to determine model requirements
   */
  private async analyzeComplexity(files: string[]): Promise<ComplexityMetrics> {
    let totalLines = 0;
    let totalSize = 0;
    let maxNestingDepth = 0;
    let hasUnsafeCode = false;
    let hasConcurrency = false;
    let hasIPC = false;

    for (const file of files) {
      // Check cache first
      const cached = this.complexityCache.get(file);
      if (cached) {
        totalLines += cached.linesOfCode;
        totalSize += cached.avgFileSize;
        maxNestingDepth = Math.max(maxNestingDepth, cached.avgNestingDepth);
        hasUnsafeCode = hasUnsafeCode || cached.hasUnsafeCode;
        hasConcurrency = hasConcurrency || cached.hasConcurrency;
        hasIPC = hasIPC || cached.hasIPC;
        continue;
      }

      try {
        const content = await fs.readFile(file, 'utf-8');
        const stats = await fs.stat(file);

        // Calculate metrics
        const lines = content.split('\n').length;
        totalLines += lines;
        totalSize += stats.size;

        // Detect complexity indicators
        const nestingDepth = this.calculateNestingDepth(content);
        maxNestingDepth = Math.max(maxNestingDepth, nestingDepth);

        // Check for high-risk patterns
        if (this.hasUnsafePatterns(content)) hasUnsafeCode = true;
        if (this.hasConcurrencyPatterns(content)) hasConcurrency = true;
        if (this.hasIPCPatterns(content)) hasIPC = true;

        // Cache metrics
        this.complexityCache.set(file, {
          avgFileSize: stats.size,
          avgNestingDepth: nestingDepth,
          language: this.detectLanguage(file),
          hasUnsafeCode: this.hasUnsafePatterns(content),
          hasConcurrency: this.hasConcurrencyPatterns(content),
          hasIPC: this.hasIPCPatterns(content),
          linesOfCode: lines,
          cyclomaticComplexity: this.estimateCyclomaticComplexity(content)
        });
      } catch (error) {
        // Skip files that can't be read
        continue;
      }
    }

    const avgFileSize = files.length > 0 ? totalSize / files.length : 0;
    const avgNestingDepth = maxNestingDepth;
    const language = files.length > 0 ? this.detectLanguage(files[0]) : 'unknown';

    return {
      avgFileSize,
      avgNestingDepth,
      language,
      hasUnsafeCode,
      hasConcurrency,
      hasIPC,
      linesOfCode: totalLines,
      cyclomaticComplexity: this.estimateOverallComplexity(files.length, totalLines, maxNestingDepth)
    };
  }

  /**
   * Decide which model to use based on complexity and task type
   */
  private decideModel(
    taskType: string,
    complexity: ComplexityMetrics,
    needsEscalation: boolean
  ): ModelRecommendation {
    const reasons: string[] = [];
    let score = 0; // 0-10 scale, higher = need more powerful model

    // Task-based baseline
    if (['analysis-planning', 'file-prioritization'].includes(taskType)) {
      score = 1; // Simple tasks always Haiku
      reasons.push('simple planning task');
    } else if (['context-building', 'memory-safety-analysis', 'concurrency-analysis'].includes(taskType)) {
      score = 5; // Medium tasks start at Sonnet
      reasons.push('analysis task');
    } else if (['vulnerability-detection', 'poc-generation'].includes(taskType)) {
      score = 6; // Detection starts at Sonnet, may escalate to Opus
      reasons.push('critical detection task');
    }

    // Complexity adjustments
    if (complexity.linesOfCode > 5000) {
      score += 2;
      reasons.push(`large codebase (${complexity.linesOfCode} LOC)`);
    }

    if (complexity.avgNestingDepth > 6) {
      score += 1;
      reasons.push(`deep nesting (${complexity.avgNestingDepth} levels)`);
    }

    if (complexity.cyclomaticComplexity > 50) {
      score += 2;
      reasons.push(`high cyclomatic complexity (${complexity.cyclomaticComplexity})`);
    }

    // High-risk pattern adjustments
    if (complexity.hasUnsafeCode) {
      score += 2;
      reasons.push('unsafe code patterns detected');
    }

    if (complexity.hasConcurrency) {
      score += 2;
      reasons.push('concurrency detected (race conditions possible)');
    }

    if (complexity.hasIPC) {
      score += 2;
      reasons.push('IPC detected (trust boundary)');
    }

    // Language-specific adjustments
    if (['c', 'cpp', 'rust'].includes(complexity.language)) {
      score += 1;
      reasons.push(`memory-unsafe language (${complexity.language})`);
    }

    // Escalation from previous attempts
    if (needsEscalation) {
      score += 3;
      reasons.push('previous model found complex issues requiring deeper analysis');
    }

    // Map score to model tier
    let model: ModelTier;
    let confidence: number;

    if (score <= 3) {
      model = 'haiku';
      confidence = 0.9;
      reasons.unshift('Low complexity');
    } else if (score <= 7) {
      model = 'sonnet';
      confidence = 0.8;
      reasons.unshift('Medium complexity');
    } else {
      model = 'opus';
      confidence = 0.7;
      reasons.unshift('High complexity');
    }

    return {
      model,
      reasoning: reasons.join(', '),
      confidence
    };
  }

  /**
   * Check if previous findings suggest we need a more powerful model
   */
  private checkEscalationNeeded(taskType: string, previousFindings?: any[]): boolean {
    if (!previousFindings || previousFindings.length === 0) {
      return false;
    }

    // Check if findings mention complexity or uncertainty
    for (const finding of previousFindings) {
      if (finding.complexity && finding.complexity > 7) {
        return true;
      }

      if (finding.selfVerification &&
          (finding.selfVerification.includes('uncertain') ||
           finding.selfVerification.includes('needs deeper analysis'))) {
        return true;
      }

      // Check if exploitability is borderline (suggests complexity)
      if (finding.exploitability > 0.6 && finding.exploitability < 0.8) {
        return true; // Borderline cases need better reasoning
      }
    }

    return false;
  }

  /**
   * Record task result for learning
   */
  recordTaskResult(taskType: string, model: ModelTier, success: boolean, tokensUsed: number): void {
    const key = `${taskType}-${model}`;
    this.taskHistory.set(key, { model, success, tokensUsed });
  }

  /**
   * Get explanation of model choice
   */
  explainChoice(recommendation: ModelRecommendation): string {
    const costs = {
      'haiku': '$0.80/M input, $4/M output',
      'sonnet': '$3/M input, $15/M output',
      'opus': '$15/M input, $75/M output'
    };

    return `Selected ${recommendation.model.toUpperCase()} (${costs[recommendation.model]}) - ${recommendation.reasoning}`;
  }

  // Helper methods for pattern detection

  private calculateNestingDepth(content: string): number {
    let maxDepth = 0;
    let currentDepth = 0;

    for (const char of content) {
      if (char === '{' || char === '(') {
        currentDepth++;
        maxDepth = Math.max(maxDepth, currentDepth);
      } else if (char === '}' || char === ')') {
        currentDepth--;
      }
    }

    return maxDepth;
  }

  private hasUnsafePatterns(content: string): boolean {
    const unsafePatterns = [
      /\bunsafe\b/,           // Rust unsafe blocks
      /reinterpret_cast/,     // C++ unsafe casts
      /\*\s*\(/,              // Pointer dereference
      /strcpy|strcat|gets/,   // Unsafe C functions
      /malloc|free/,          // Manual memory management
      /memcpy|memmove/        // Memory operations
    ];

    return unsafePatterns.some(pattern => pattern.test(content));
  }

  private hasConcurrencyPatterns(content: string): boolean {
    const concurrencyPatterns = [
      /\bmutex\b/i,
      /\block\b/i,
      /\batomic\b/i,
      /\bthread\b/i,
      /pthread_/,
      /std::thread/,
      /async\s+fn/,
      /\.await/
    ];

    return concurrencyPatterns.some(pattern => pattern.test(content));
  }

  private hasIPCPatterns(content: string): boolean {
    const ipcPatterns = [
      /\bIPC\b/,
      /ReadParam|WriteParam/,
      /ParamTraits/,
      /SendMessage|PostMessage/,
      /MessagePort/,
      /__IPC__/
    ];

    return ipcPatterns.some(pattern => pattern.test(content));
  }

  private estimateCyclomaticComplexity(content: string): number {
    // Simplified McCabe complexity: count decision points
    const decisionPoints = [
      /\bif\b/g,
      /\belse\b/g,
      /\bwhile\b/g,
      /\bfor\b/g,
      /\bcase\b/g,
      /\bcatch\b/g,
      /\&\&/g,
      /\|\|/g
    ];

    let complexity = 1; // Base complexity
    for (const pattern of decisionPoints) {
      const matches = content.match(pattern);
      complexity += matches ? matches.length : 0;
    }

    return complexity;
  }

  private estimateOverallComplexity(fileCount: number, totalLines: number, maxNesting: number): number {
    // Weighted formula for overall complexity
    return Math.min(100,
      (fileCount * 2) +
      (totalLines / 100) +
      (maxNesting * 5)
    );
  }

  private detectLanguage(file: string): string {
    const ext = path.extname(file);
    const map: { [key: string]: string } = {
      '.js': 'javascript',
      '.ts': 'typescript',
      '.py': 'python',
      '.go': 'go',
      '.rs': 'rust',
      '.c': 'c',
      '.cpp': 'cpp',
      '.cc': 'cpp',
      '.h': 'c',
      '.hpp': 'cpp',
      '.java': 'java'
    };
    return map[ext] || 'unknown';
  }
}
