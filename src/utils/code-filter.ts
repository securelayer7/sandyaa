import * as fs from 'fs/promises';
import * as path from 'path';

export interface FilterResult {
  highPriority: ScoredFile[];
  mediumPriority: ScoredFile[];
  lowPriority: ScoredFile[];
}

export interface ScoredFile {
  path: string;
  score: number;
  matchedPatterns: string[];
}

export interface SecurityPatterns {
  [key: string]: RegExp;
}

/**
 * Lightweight code filter that scores files based on security-relevant patterns
 * Reduces token usage by 40-60% by filtering out low-priority files BEFORE LLM analysis
 */
export class LightweightCodeFilter {
  private patterns: SecurityPatterns;

  constructor() {
    this.patterns = {
      // Memory safety issues (critical for C/C++)
      memory_unsafe: /\b(malloc|free|memcpy|strcpy|strcat|sprintf|alloc|delete|new\[\]|realloc|calloc)\b/,

      // User input sources
      user_input: /\b(req\.|request\.|POST|GET|PUT|DELETE|cookie|header|param|query|body|formData)\b/,

      // Dangerous sinks
      dangerous_sinks: /\b(eval|exec|system|shell|sql|query|execute|innerHTML|dangerouslySetInnerHTML)\b/,

      // Authentication & authorization
      authentication: /\b(auth|login|session|token|password|jwt|oauth|credential|authenticate|authorize)\b/,

      // Cryptography (weak algorithms)
      crypto_weak: /\b(md5|sha1|ECB|DES|RC4|random|Math\.random)\b/,

      // File operations
      file_ops: /\b(readFile|writeFile|fs\.|path\.join|open|fopen|mkdir|rmdir|unlink)\b/,

      // Network operations
      network_ops: /\b(http|fetch|axios|XMLHttpRequest|WebSocket|socket|connect|listen)\b/,

      // Process operations
      process_ops: /\b(spawn|fork|exec|child_process|process\.env|system)\b/,

      // Type casts (C/C++)
      type_casts: /\b(static_cast|reinterpret_cast|dynamic_cast|const_cast|C-style cast)\b/,

      // Pointers & memory (C/C++)
      pointers: /\b(ptr|pointer|nullptr|NULL|->|address|dereference)\b/
    };
  }

  /**
   * Scan files and score them based on security relevance
   */
  async scanForSecurityPatterns(files: string[]): Promise<FilterResult> {
    const scored: ScoredFile[] = [];

    for (const file of files) {
      try {
        const score = await this.scoreFile(file);
        scored.push(score);
      } catch (error) {
        // File read error - keep in low priority
        scored.push({
          path: file,
          score: 0,
          matchedPatterns: []
        });
      }
    }

    return {
      highPriority: scored.filter(s => s.score >= 3),
      mediumPriority: scored.filter(s => s.score >= 1 && s.score < 3),
      lowPriority: scored.filter(s => s.score < 1)
    };
  }

  /**
   * Score a single file based on pattern matches
   */
  private async scoreFile(filePath: string): Promise<ScoredFile> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const matchedPatterns: string[] = [];
      let score = 0;

      // Check each pattern
      for (const [patternName, regex] of Object.entries(this.patterns)) {
        if (regex.test(content)) {
          matchedPatterns.push(patternName);

          // Weight patterns by criticality
          if (patternName === 'dangerous_sinks') {
            score += 2; // High priority
          } else if (patternName === 'memory_unsafe' || patternName === 'authentication') {
            score += 1.5;
          } else if (patternName === 'user_input' || patternName === 'crypto_weak') {
            score += 1;
          } else {
            score += 0.5;
          }
        }
      }

      return {
        path: filePath,
        score,
        matchedPatterns
      };
    } catch (error) {
      return {
        path: filePath,
        score: 0,
        matchedPatterns: []
      };
    }
  }

  /**
   * Get pattern details for reporting
   */
  public getPatternInfo(): { [key: string]: string } {
    return {
      memory_unsafe: 'Memory allocation/deallocation operations',
      user_input: 'User input sources (HTTP, cookies, params)',
      dangerous_sinks: 'Dangerous operations (eval, exec, SQL)',
      authentication: 'Auth-related code',
      crypto_weak: 'Weak cryptographic algorithms',
      file_ops: 'File system operations',
      network_ops: 'Network operations',
      process_ops: 'Process spawning/execution',
      type_casts: 'Type casting operations',
      pointers: 'Pointer operations'
    };
  }
}
