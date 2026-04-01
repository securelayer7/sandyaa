/**
 * Language-Agnostic Attacker Control Analysis
 *
 * Validates whether a vulnerability is actually attacker-controlled by:
 * 1. Tracing execution path FROM external input to vulnerable code
 * 2. Identifying trust boundaries (external vs internal APIs)
 * 3. Understanding execution context (compiler vs runtime vs startup)
 * 4. Distinguishing trusted vs untrusted input
 *
 * Works across all languages: C/C++, JavaScript, Python, Go, Rust, Java, etc.
 *
 * This prevents false positives like:
 * - Compiler code reported as runtime bugs
 * - Internal APIs reported as externally exploitable
 * - Startup code reported as runtime exploitable
 * - Output functions reported as input parsing bugs
 */

import * as fs from 'fs/promises';
import { Language, LanguagePatterns, LANGUAGE_PATTERNS, detectLanguage } from './language-patterns.js';

export interface AttackerControlResult {
  isControlled: boolean;
  confidence: 'high' | 'medium' | 'low' | 'none';
  reason: string;
  issues: string[];
  executionContext?: 'runtime' | 'compiler' | 'startup' | 'internal-api' | 'unknown';
  trustBoundary?: 'untrusted' | 'trusted' | 'mixed';
  externallyReachable?: boolean;
  detectedLanguage?: Language;
}

export interface ContextHints {
  // File path/function patterns
  isCompilerCode: boolean;
  isRuntimeCode: boolean;
  isStartupCode: boolean;
  isInternalAPI: boolean;
  isTestCode: boolean;

  // Function types
  isOutputFunction: boolean;  // WRITE/GENERATE
  isInputFunction: boolean;   // READ/PARSE
  isValidationFunction: boolean;

  // Call chain indicators
  calledFromExternal?: boolean;
  calledFromInternal?: boolean;
}

export class AttackerControlAnalyzer {
  private language: Language = 'unknown';
  private patterns: LanguagePatterns;

  constructor(language?: Language, files?: Array<{ path: string; language?: string }>) {
    if (language) {
      // Normalize language string to canonical type
      const normalized = this.normalizeLanguage(language);
      this.language = normalized;
    } else if (files) {
      this.language = detectLanguage(files);
    }

    this.patterns = LANGUAGE_PATTERNS[this.language];

    // Fallback if patterns is still undefined
    if (!this.patterns) {
      console.warn(`    [LANGUAGE WARNING] No patterns for language: ${this.language}, using 'unknown' patterns`);
      this.language = 'unknown';
      this.patterns = LANGUAGE_PATTERNS['unknown'];
    }

    console.log(`    [LANGUAGE DETECTION] Detected language: ${this.language.toUpperCase()}`);
  }

  private normalizeLanguage(lang: string): Language {
    const normalized = (lang as string).toLowerCase().trim();

    const langMap: Record<string, Language> = {
      'c++': 'cpp',
      'cpp': 'cpp',
      'c': 'c',
      'javascript': 'javascript',
      'js': 'javascript',
      'typescript': 'typescript',
      'ts': 'typescript',
      'python': 'python',
      'py': 'python',
      'go': 'go',
      'golang': 'go',
      'rust': 'rust',
      'rs': 'rust',
      'java': 'java',
      'c#': 'csharp',
      'csharp': 'csharp',
      'cs': 'csharp',
      'php': 'php',
      'ruby': 'ruby',
      'rb': 'ruby'
    };

    return langMap[normalized] || 'unknown';
  }

  /**
   * Analyze if vulnerability is attacker-controlled (language-agnostic)
   */
  async analyze(vulnerability: any, fileContent?: string): Promise<AttackerControlResult> {
    const issues: string[] = [];

    // Get execution context hints using language patterns
    const hints = this.analyzeContext(vulnerability);

    // P0-3: EXECUTION CONTEXT VALIDATION
    const contextResult = this.validateExecutionContext(vulnerability, hints, issues);

    // P0-4: TRUST BOUNDARY VALIDATION
    const boundaryResult = this.validateTrustBoundary(vulnerability, hints, issues);

    // P0-2: EXTERNAL REACHABILITY VALIDATION
    const reachabilityResult = await this.validateExternalReachability(vulnerability, hints, issues);

    // P0-5: VALIDATION CHAIN CHECK
    if (fileContent) {
      await this.checkValidationChain(vulnerability, fileContent, issues);
    }

    // P1-6: THREADING MODEL VALIDATION
    this.validateThreadingModel(vulnerability, issues);

    // P1-7: SEMANTIC UNDERSTANDING
    if (fileContent) {
      this.validateSemanticPatterns(vulnerability, fileContent, issues);
    }

    // Determine overall result
    const isControlled = this.determineOverallControl(
      contextResult,
      boundaryResult,
      reachabilityResult,
      issues
    );

    return {
      isControlled: isControlled.controlled,
      confidence: isControlled.confidence as 'high' | 'medium' | 'low' | 'none',
      reason: isControlled.reason,
      issues,
      executionContext: contextResult.context as 'runtime' | 'compiler' | 'startup' | 'internal-api' | 'unknown' | undefined,
      trustBoundary: boundaryResult.boundary as 'untrusted' | 'trusted' | 'mixed' | undefined,
      externallyReachable: reachabilityResult.reachable,
      detectedLanguage: this.language
    };
  }

  /**
   * P0-3: Analyze execution context using language-specific patterns
   */
  private analyzeContext(vulnerability: any): ContextHints {
    const filePath = vulnerability.location?.file || '';
    const functionName = vulnerability.location?.function || '';
    const description = vulnerability.description || '';

    const matchAny = (patterns: RegExp[], text: string): boolean => {
      return patterns.some(p => p.test(text));
    };

    // File path + function name analysis
    const isCompilerCode =
      matchAny(this.patterns.compilerCode, filePath) ||
      matchAny(this.patterns.compilerCode, functionName);

    const isRuntimeCode =
      matchAny(this.patterns.runtimeCode, filePath) ||
      matchAny(this.patterns.runtimeCode, functionName);

    const isStartupCode =
      matchAny(this.patterns.startupCode, filePath) ||
      matchAny(this.patterns.startupCode, functionName);

    const isInternalAPI =
      matchAny(this.patterns.embedderAPIs, filePath) ||
      matchAny(this.patterns.embedderAPIs, functionName);

    const isTestCode = matchAny(this.patterns.testCode, filePath);

    // Function type analysis
    const isOutputFunction = matchAny(this.patterns.outputFunctions, functionName);
    const isInputFunction = matchAny(this.patterns.inputFunctions, functionName);
    const isValidationFunction = matchAny(this.patterns.validationFunctions, functionName);

    return {
      isCompilerCode,
      isRuntimeCode,
      isStartupCode,
      isInternalAPI,
      isTestCode,
      isOutputFunction,
      isInputFunction,
      isValidationFunction
    };
  }

  /**
   * P0-3: Validate execution context (language-agnostic)
   * Prevents reporting compile-time code as runtime bugs
   */
  private validateExecutionContext(
    vulnerability: any,
    hints: ContextHints,
    issues: string[]
  ): { valid: boolean; context: string } {
    let context = 'unknown';

    // CRITICAL: Compiler code is NOT runtime exploitable
    if (hints.isCompilerCode) {
      context = 'compiler';
      issues.push(`❌ COMPILER CODE: Runs during compilation (${this.language.toUpperCase()}), not at runtime`);
      issues.push('   → External input cannot trigger this during execution');
      issues.push('   → Only affects build process, not production runtime');
      return { valid: false, context };
    }

    // CRITICAL: Startup code runs once at initialization
    if (hints.isStartupCode) {
      context = 'startup';
      issues.push('❌ STARTUP CODE: Runs once during initialization');
      issues.push('   → External input cannot trigger this after startup');
      issues.push('   → Requires pre-compromised environment');
      return { valid: false, context };
    }

    // CRITICAL: Internal APIs are not externally accessible
    if (hints.isInternalAPI) {
      context = 'internal-api';
      issues.push('❌ INTERNAL API: Not exposed to external callers');
      issues.push('   → Only accessible from trusted internal code');
      issues.push('   → Requires compromising the application first');
      return { valid: false, context };
    }

    // Test code is not production
    if (hints.isTestCode) {
      context = 'test';
      issues.push('❌ TEST CODE: Found in test directory');
      issues.push('   → Not part of production build');
      return { valid: false, context };
    }

    // Runtime code is potentially exploitable
    if (hints.isRuntimeCode) {
      context = 'runtime';
      return { valid: true, context };
    }

    return { valid: true, context };
  }

  /**
   * P0-4: Validate trust boundary (language-agnostic)
   * Distinguishes trusted (internal) from untrusted (external) input
   */
  private validateTrustBoundary(
    vulnerability: any,
    hints: ContextHints,
    issues: string[]
  ): { valid: boolean; boundary: string } {
    const attackerControlled = vulnerability.attackerControlled || {};
    const entryPoint = attackerControlled.entryPoint || '';
    const dataFlow = attackerControlled.dataFlow || [];

    // Check if internal/trusted API
    const internalKeywords = ['internal', 'private', 'trusted', 'admin', 'system'];
    const isInternalEntry = internalKeywords.some(kw =>
      entryPoint.toLowerCase().includes(kw)
    );

    if (isInternalEntry || hints.isInternalAPI) {
      issues.push('❌ TRUSTED INPUT: Entry point is internal/trusted');
      issues.push('   → Internal APIs are TRUSTED - not attacker-controlled');
      issues.push('   → External input cannot reach this code path');
      return { valid: false, boundary: 'trusted' };
    }

    // Check data flow for external → trusted boundary crossing
    const hasTrustedStep = dataFlow.some((step: string) =>
      /deserialize|snapshot|startup|build|compile-time|internal/i.test(step)
    );

    if (hasTrustedStep) {
      issues.push('⚠️ MIXED BOUNDARY: Data flow crosses trusted boundary');
      issues.push('   → Requires internal cooperation to exploit');
      return { valid: false, boundary: 'mixed' };
    }

    return { valid: true, boundary: 'untrusted' };
  }

  /**
   * P0-2: Validate external reachability (language-agnostic)
   * Traces execution path FROM external input sources
   */
  private async validateExternalReachability(
    vulnerability: any,
    hints: ContextHints,
    issues: string[]
  ): Promise<{ valid: boolean; reachable: boolean }> {
    const attackerControlled = vulnerability.attackerControlled || {};
    const entryPoint = attackerControlled.entryPoint || '';
    const dataFlow = attackerControlled.dataFlow || [];

    // Must have entry point
    if (!entryPoint || entryPoint === 'N/A' || entryPoint.toLowerCase().includes('unknown')) {
      issues.push('❌ NO ENTRY POINT: Cannot prove external reachability');
      issues.push('   → Must specify HOW external input reaches this code');
      return { valid: false, reachable: false };
    }

    // Must have data flow
    if (dataFlow.length === 0) {
      issues.push('❌ NO DATA FLOW: Cannot trace attacker control path');
      issues.push('   → Must show step-by-step path from input → vulnerability');
      return { valid: false, reachable: false };
    }

    // Check for external input APIs using language patterns
    const matchAny = (patterns: RegExp[], text: string): boolean => {
      return patterns.some(p => p.test(text));
    };

    const hasUserInputAPI = matchAny(this.patterns.userInputAPIs, entryPoint) ||
                            dataFlow.some((step: string) => matchAny(this.patterns.userInputAPIs, step));

    const hasDeserializationAPI = matchAny(this.patterns.deserializationAPIs, entryPoint) ||
                                   dataFlow.some((step: string) => matchAny(this.patterns.deserializationAPIs, step));

    const hasExternalAPI = matchAny(this.patterns.externalAPIs, entryPoint) ||
                           dataFlow.some((step: string) => matchAny(this.patterns.externalAPIs, step));

    if (!hasUserInputAPI && !hasDeserializationAPI && !hasExternalAPI) {
      issues.push('⚠️ NO EXTERNAL INPUT API: Entry point doesn\'t mention external input sources');
      issues.push(`   → Expected: HTTP request, socket, file input, deserialization (${this.language})`);
      issues.push('   → Suggest verifying external reachability with concrete API');
      return { valid: false, reachable: false };
    }

    // CRITICAL: Output functions are WRITE/GENERATE, not input parsing
    if (hints.isOutputFunction) {
      issues.push('❌ OUTPUT FUNCTION: This function WRITES/GENERATES output');
      issues.push('   → Output functions don\'t PARSE external input');
      issues.push('   → Cannot be exploited by malicious input');
      return { valid: false, reachable: false };
    }

    return { valid: true, reachable: true };
  }

  /**
   * P0-5: Check for validation chain
   * Prevents "missing validation" false positives
   */
  private async checkValidationChain(
    vulnerability: any,
    fileContent: string,
    issues: string[]
  ): Promise<void> {
    const functionName = vulnerability.location?.function || '';
    const description = vulnerability.description || '';

    // Check if vulnerability claims "missing validation"
    const claimsMissingValidation = /missing.*validation|no.*check|unchecked|unvalidated/i.test(description);

    if (claimsMissingValidation && functionName) {
      // Look for validation in the code
      const validationPatterns = [
        /CHECK\s*\(/g,           // V8 CHECK macros
        /DCHECK\s*\(/g,          // Debug checks
        /Verify|Validate|Assert/gi,
        /if\s*\([^)]*<\s*0\)/g,  // Bounds checks
        /if\s*\([^)]*>\s*\w+\)/g // Bounds checks
      ];

      const foundValidation: string[] = [];
      for (const pattern of validationPatterns) {
        const matches = fileContent.match(pattern);
        if (matches) {
          foundValidation.push(...matches.slice(0, 3)); // First 3 matches
        }
      }

      if (foundValidation.length > 0) {
        issues.push('⚠️ VALIDATION EXISTS: Found validation in the code:');
        foundValidation.forEach(v => {
          issues.push(`   → ${v.trim()}`);
        });
        issues.push('   → May have multi-layer validation (parser + compiler + runtime)');
        issues.push('   → Suggest deeper validation chain analysis');
      }
    }
  }

  /**
   * P1-6: Validate threading model (language-aware)
   * Prevents false positives about race conditions in single-threaded languages
   */
  private validateThreadingModel(
    vulnerability: any,
    issues: string[]
  ): void {
    const type = vulnerability.type || '';
    const description = vulnerability.description || '';
    const category = vulnerability.category || '';

    // Check if vulnerability claims race condition or concurrency issue
    const raceConditionKeywords = [
      'race condition',
      'data race',
      'concurrent access',
      'thread safety',
      'race window',
      'toctou',
      'time-of-check',
      'concurrent modification'
    ];

    const claimsRaceCondition = raceConditionKeywords.some(kw =>
      type.toLowerCase().includes(kw) ||
      description.toLowerCase().includes(kw) ||
      category.toLowerCase().includes(kw)
    );

    if (claimsRaceCondition) {
      // Check for actual concurrency primitives
      const matchAny = (patterns: RegExp[], text: string): boolean => {
        return patterns.some(p => p.test(text));
      };

      const hasConcurrency = matchAny(this.patterns.concurrencyKeywords, description);

      if (this.patterns.singleThreaded && !hasConcurrency) {
        // Language is single-threaded by default
        issues.push(`❌ THREADING MODEL: ${this.language.toUpperCase()} is single-threaded by default`);
        issues.push('   → Race conditions impossible without explicit concurrency primitives');
        issues.push('   → Verify code actually uses threading/async features');
      } else if (!hasConcurrency) {
        // Multi-threaded language but no concurrency keywords found
        issues.push('⚠️ NO CONCURRENCY PRIMITIVES: Claims race condition but no threading keywords found');
        issues.push(`   → Expected: ${this.patterns.concurrencyKeywords.map(p => p.source).slice(0, 3).join(', ')}`);
        issues.push('   → Verify concurrent access is actually possible');
      }
    }
  }

  /**
   * P1-7: Validate semantic patterns (language-aware)
   * Prevents pattern-matching false positives by understanding language-specific safety guarantees
   */
  private validateSemanticPatterns(
    vulnerability: any,
    fileContent: string,
    issues: string[]
  ): void {
    const type = vulnerability.type || '';
    const description = vulnerability.description || '';

    const matchAny = (patterns: RegExp[], text: string): boolean => {
      return patterns.some(p => p.test(text));
    };

    // Memory safety checks (only for memory-unsafe languages)
    if (this.patterns.memoryUnsafe) {
      // Check for use-after-free, buffer overflow, null pointer
      if (/use.*after.*free|buffer.*overflow|null.*pointer/i.test(type + description)) {
        const hasSafetyCheck = matchAny(this.patterns.safetyChecks, fileContent);

        if (hasSafetyCheck) {
          issues.push(`⚠️ MEMORY SAFETY: ${this.language.toUpperCase()} has safety mechanisms present`);
          issues.push(`   → Found: ${this.patterns.safetyChecks.map(p => p.source).slice(0, 2).join(', ')}`);
          issues.push('   → Verify vulnerability can bypass safety checks');
        }
      }
    } else {
      // Memory-safe language
      if (/use.*after.*free|buffer.*overflow|dangling.*pointer/i.test(type + description)) {
        issues.push(`⚠️ MEMORY SAFETY: ${this.language.toUpperCase()} is memory-safe by default`);
        issues.push('   → Use-after-free/buffer overflow typically prevented by runtime');
        issues.push('   → Verify claimed vulnerability is actually possible');
      }
    }

    // Check for unsafe operations in safe languages
    if (!this.patterns.memoryUnsafe) {
      const hasUnsafeOp = matchAny(this.patterns.unsafeOperations, fileContent);
      if (hasUnsafeOp) {
        issues.push(`⚠️ UNSAFE OPERATION: Code uses unsafe primitives in ${this.language.toUpperCase()}`);
        issues.push('   → May bypass language safety guarantees');
      }
    }

    // Integer overflow checks
    if (/integer.*overflow|arithmetic.*overflow/i.test(type) || /overflow/i.test(description)) {
      // Check for bounds/length validation
      const hasLengthCheck = /length|size|capacity|count|len\(\)/i.test(fileContent);
      const hasRangeCheck = /if\s*\([^)]*[<>]=?/i.test(fileContent);

      if (hasLengthCheck || hasRangeCheck) {
        issues.push('⚠️ OVERFLOW CLAIMED: Code has length/range validation');
        issues.push('   → Verify overflow is reachable after validation');
      }
    }

    // Type confusion checks
    if (/type.*confusion|type.*safety/i.test(type) || /type/i.test(description)) {
      const hasTypeCheck = /typeof|instanceof|is_a\?|type\(|isinstance/i.test(fileContent);

      if (hasTypeCheck) {
        issues.push('⚠️ TYPE CONFUSION: Code has runtime type checks');
        issues.push('   → Verify type confusion can bypass these checks');
      }
    }

    // Bounds checking
    if (/bounds|out.*of.*bounds/i.test(type) || /bounds/i.test(description)) {
      const hasBoundsCheck = /length|size|capacity|bounds/i.test(fileContent);

      if (hasBoundsCheck) {
        issues.push('⚠️ BOUNDS CHECK: Code validates bounds/length');
        issues.push('   → Verify bounds check can be bypassed');
      }
    }
  }

  /**
   * Determine overall attacker control based on all checks
   */
  private determineOverallControl(
    contextResult: { valid: boolean; context: string },
    boundaryResult: { valid: boolean; boundary: string },
    reachabilityResult: { valid: boolean; reachable: boolean },
    issues: string[]
  ): { controlled: boolean; confidence: string; reason: string } {
    // If ANY critical check fails, not attacker-controlled
    const criticalFailures = issues.filter(i => i.startsWith('❌')).length;
    const warnings = issues.filter(i => i.startsWith('⚠️')).length;

    if (criticalFailures > 0) {
      return {
        controlled: false,
        confidence: 'none',
        reason: `Failed ${criticalFailures} critical checks: ${issues.filter(i => i.startsWith('❌'))[0]}`
      };
    }

    if (warnings > 0) {
      return {
        controlled: false,
        confidence: 'low',
        reason: `${warnings} warnings suggest incomplete analysis`
      };
    }

    if (!contextResult.valid || !boundaryResult.valid || !reachabilityResult.valid) {
      return {
        controlled: false,
        confidence: 'low',
        reason: 'Context, boundary, or reachability validation failed'
      };
    }

    // All checks passed
    return {
      controlled: true,
      confidence: 'high',
      reason: 'All validation checks passed'
    };
  }
}
