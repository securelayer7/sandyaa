import { Config } from '../orchestrator/orchestrator.js';
import { ModelExecutor } from '../agents/model-executor.js';
import { MemorySafetyAnalyzer, MemorySafetyContext } from './memory-safety-analyzer.js';
import { ConcurrencyAnalyzer, ConcurrencyContext } from './concurrency-analyzer.js';
import { SemanticAnalyzer, SemanticContext } from './semantic-analyzer.js';
import { GitHistoryAnalyzer, GitHistoryContext } from './git-history-analyzer.js';
import { AnalysisPlanner } from './analysis-planner.js';
import { PathResolver } from '../utils/path-resolver.js';
import { LightweightCodeFilter } from '../utils/code-filter.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface CodeContext {
  files: FileContext[];
  entryPoints: string[];
  dataFlows: DataFlow[];
  trustBoundaries: TrustBoundary[];
  assumptions: string[];
  facts: string[];
  // Extended context from specialized analyzers
  memorySafety?: MemorySafetyContext;
  concurrency?: ConcurrencyContext;
  semantic?: SemanticContext;
  gitHistory?: GitHistoryContext;
  customStrategies?: any[]; // Results from custom analysis strategies
}

export interface FileContext {
  path: string;
  language: string;
  functions: FunctionContext[];
  imports: string[];
  exports: string[];
}

export interface FunctionContext {
  name: string;
  params: string[];
  returnType: string;
  line: number;
  dataFlow: DataFlow[];
  controlFlow: string[];
  userInputs: string[];
  sensitiveSinks: string[];
}

export interface DataFlow {
  source: string;
  sink: string;
  taintPath: string[];
  isTainted: boolean;
}

export interface TrustBoundary {
  location: string;
  type: string;
  validation: string[];
}

export class ContextAnalyzer {
  private config: Config;
  private executor: ModelExecutor;
  private planner: AnalysisPlanner;
  private memorySafetyAnalyzer: MemorySafetyAnalyzer;
  private concurrencyAnalyzer: ConcurrencyAnalyzer;
  private semanticAnalyzer: SemanticAnalyzer;
  private gitHistoryAnalyzer: GitHistoryAnalyzer;
  private gitHistoryContext?: any; // Store git history for future reference
  private pathResolver: PathResolver;
  private targetPathResolved: string;
  private sandyaaPath: string;
  private codeFilter: LightweightCodeFilter;

  constructor(config: Config) {
    this.config = config;
    this.executor = new ModelExecutor(config.provider);
    this.planner = new AnalysisPlanner(config.provider);
    this.memorySafetyAnalyzer = new MemorySafetyAnalyzer(config.provider);
    this.concurrencyAnalyzer = new ConcurrencyAnalyzer(config.provider);
    this.semanticAnalyzer = new SemanticAnalyzer(config.provider);
    this.gitHistoryAnalyzer = new GitHistoryAnalyzer('.sandyaa/git-history', config.provider);
    this.pathResolver = new PathResolver(config.target.path);
    this.codeFilter = new LightweightCodeFilter();

    // Cache boundary paths for fast validation
    this.targetPathResolved = path.resolve(config.target.path);
    this.sandyaaPath = path.resolve(__dirname, '../..');
  }

  /**
   * CRITICAL: Validate file is within target boundaries
   * Prevent analyzing Sandyaa's own code, generated POCs, findings, etc.
   */
  private isWithinTargetBoundary(filePath: string): boolean {
    const resolved = path.resolve(filePath);

    // Must be within target
    if (!resolved.startsWith(this.targetPathResolved)) {
      return false;
    }

    // Must NOT be Sandyaa framework source code
    if (resolved.startsWith(this.sandyaaPath)) {
      return false;
    }

    // CRITICAL: Exclude Sandyaa's working directories
    // These can be created INSIDE the target during analysis
    const sandyaaWorkingDirs = [
      '/.sandyaa/',           // POC validation, tasks, checkpoints
      '/findings/',           // Generated vulnerability reports
      '/node_modules/',       // Dependencies
      '/dist/',               // Build output
      '/build/',              // Build output
      '/.git/',               // Git internals
      '/poc-validation/',     // POC test files
      '/test-cases/',         // Test files
    ];

    for (const dir of sandyaaWorkingDirs) {
      if (resolved.includes(dir)) {
        return false;
      }
    }

    // CRITICAL: Exclude Sandyaa-generated POC files by pattern
    const basename = path.basename(filePath);
    const sandyaaPOCPatterns = [
      /^poc[-_].*\.(cpp|c|js|ts|py)$/i,      // poc-test.cpp, poc_exploit.js
      /^test[-_]exploit/i,                    // test-exploit.js
      /^vulnerable[-_]/i,                     // vulnerable-test.cpp
      /^exploit[-_]/i,                        // exploit-demo.py
    ];

    for (const pattern of sandyaaPOCPatterns) {
      if (pattern.test(basename)) {
        return false;
      }
    }

    // CRITICAL: Exclude files with "VulnerableRead" or similar test function names
    // (These are deliberately vulnerable for POC demonstration)
    const knownPOCIndicators = [
      'poc.cpp', 'poc.c', 'poc.js', 'poc.py',
      'exploit.cpp', 'exploit.c', 'exploit.js',
      'test-vuln.cpp', 'vulnerable-demo.cpp'
    ];

    if (knownPOCIndicators.includes(basename.toLowerCase())) {
      return false;
    }

    return true;
  }

  /**
   * Update planner with learnings from previous chunks
   */
  updateLearnings(learnings: {
    vulnerabilities?: any[];
    successfulStrategies?: string[];
  }): void {
    const previousFindings = learnings.vulnerabilities?.map(v => ({
      type: v.type,
      severity: v.severity,
      location: `${v.location.file}:${v.location.line}`,
      pattern: v.description?.substring(0, 100) || ''
    })) || [];

    const gitHistoryPatterns = this.gitHistoryContext?.commonPatterns || [];
    const highRiskAreas = this.gitHistoryContext?.riskAreas || [];

    this.planner.updateLearning({
      previousFindings,
      gitHistoryPatterns,
      highRiskAreas,
      successfulStrategies: learnings.successfulStrategies
    });
  }

  async analyze(files: string[]): Promise<{ context: CodeContext; tokensUsed: number }> {
    let totalTokens = 0;

    // DEBUG: Check what we received
    console.log(chalk.gray(`    DEBUG: First input file: ${files[0]}`));
    console.log(chalk.gray(`    DEBUG: Base path: ${this.config.target.path}`));

    // UNIVERSAL PATH NORMALIZATION: Ensure all paths are absolute
    const absoluteFiles = this.pathResolver.resolveAll(files);
    console.log(chalk.gray(`    DEBUG: First absolute file: ${absoluteFiles[0]}`));

    // CRITICAL: Enforce boundary BEFORE reading any files
    const boundaryViolations = absoluteFiles.filter(f => !this.isWithinTargetBoundary(f));
    if (boundaryViolations.length > 0) {
      console.log(chalk.red(`    [BOUNDARY VIOLATION] Rejected ${boundaryViolations.length} files outside target:`));
      boundaryViolations.slice(0, 3).forEach(f => {
        console.log(chalk.red(`      - ${f}`));
      });
      if (boundaryViolations.length > 3) {
        console.log(chalk.red(`      ... and ${boundaryViolations.length - 3} more`));
      }
    }

    // Filter to only files within target boundary
    const safeFiles = absoluteFiles.filter(f => this.isWithinTargetBoundary(f));

    if (safeFiles.length === 0) {
      console.log(chalk.red(`    [ERROR] No valid files within target boundary!`));
      return {
        context: {
          files: [],
          entryPoints: [],
          dataFlows: [],
          trustBoundaries: [],
          assumptions: [],
          facts: []
        },
        tokensUsed: 0
      };
    }

    // For planning, send relative paths (cleaner for Claude to work with)
    const relativeFiles = safeFiles.map(f => this.pathResolver.toRelative(f));
    console.log(chalk.gray(`    DEBUG: First relative file: ${relativeFiles[0]}`));

    // Validate files exist before processing
    if (safeFiles.length > 20) {
      process.stdout.write(chalk.hex('#FF8C00')(`    ⚡ Validating ${safeFiles.length} files...`));
    }

    // Filter out files that don't actually exist (might be from wrong base path)
    const validFiles: string[] = [];
    const validRelativeFiles: string[] = [];

    for (let i = 0; i < safeFiles.length; i++) {
      const absolutePath = safeFiles[i];
      const relativePath = relativeFiles[i];

      if (await this.pathResolver.exists(absolutePath)) {
        validFiles.push(absolutePath);
        validRelativeFiles.push(relativePath);
      } else {
        // File doesn't exist at this path - skip it silently
        // This can happen with monorepos where files are at different levels
        if (safeFiles.length <= 20) {
          console.log(chalk.gray(`    Skipping ${relativePath} (not found at target path)`));
        }
      }
    }

    if (safeFiles.length > 20) {
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
    }

    if (validFiles.length < safeFiles.length) {
      const skipped = safeFiles.length - validFiles.length;
      console.log(chalk.gray(`    ✓ Validated ${validFiles.length} files (${skipped} skipped - not at target path)`));
    }

    // Phase 0.5: Code filtering (RLM Phase 1 - Pattern-based reduction)
    // Filter security-relevant files BEFORE sending to planner (40-60% token savings)
    let filesToAnalyze = validFiles;
    let relativeFilesToAnalyze = validRelativeFiles;

    if (this.config.analysis.code_filtering?.enabled && validFiles.length >= 10) {
      console.log(chalk.hex('#FF8C00')(`    🎯 Filtering ${validFiles.length} files for security relevance...`));
      const filterResult = await this.codeFilter.scanForSecurityPatterns(validFiles);

      // Combine high and medium priority based on min_pattern_score
      const minScore = this.config.analysis.code_filtering.min_pattern_score || 1;
      const filtered = [
        ...filterResult.highPriority,
        ...(minScore <= 1 ? filterResult.mediumPriority : [])
      ];

      if (filtered.length < validFiles.length) {
        // Map back to absolute paths and relative paths
        const filteredPaths = new Set(filtered.map(f => f.path));
        const indices = validFiles
          .map((file, idx) => filteredPaths.has(file) ? idx : -1)
          .filter(idx => idx !== -1);

        filesToAnalyze = indices.map(idx => validFiles[idx]);
        relativeFilesToAnalyze = indices.map(idx => validRelativeFiles[idx]);

        const reduction = ((1 - filtered.length / validFiles.length) * 100).toFixed(0);
        console.log(chalk.green(
          `    ✓ Filtered to ${filtered.length}/${validFiles.length} security-relevant files (${reduction}% reduction)`
        ));

        // Show top patterns found
        const patternCounts: { [key: string]: number } = {};
        filtered.forEach(f => {
          f.matchedPatterns.forEach(p => {
            patternCounts[p] = (patternCounts[p] || 0) + 1;
          });
        });

        const topPatterns = Object.entries(patternCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([pattern, count]) => `${pattern}(${count})`)
          .join(', ');

        if (topPatterns) {
          console.log(chalk.gray(`    Patterns: ${topPatterns}`));
        }
      } else {
        console.log(chalk.gray(`    All files appear security-relevant (no filtering needed)`));
      }
    }

    // Phase 1: Let Claude decide what analyses are needed for this chunk
    console.log(chalk.gray(`  → Planning: examining ${filesToAnalyze.length} files to determine needed analyses...`));
    const plan = await this.planner.planAnalysis(relativeFilesToAnalyze);

    // Show plan and reasoning
    if (plan.analyses.length > 0) {
      console.log(chalk.cyan(`    Plan: ${plan.analyses.map(a => a.name).join(', ')}`));
      if (plan.reasoning) {
        console.log(chalk.gray(`    Reasoning: ${plan.reasoning.substring(0, 120)}${plan.reasoning.length > 120 ? '...' : ''}`));
      }
      if (plan.focusAreas && plan.focusAreas.length > 0) {
        console.log(chalk.gray(`    Focus: ${plan.focusAreas.slice(0, 3).join(', ')}${plan.focusAreas.length > 3 ? '...' : ''}`));
      }
    }

    // Read file contents for files to analyze (after filtering)
    // Store with relative paths as keys (matches what Claude sees)
    const fileContents: { [path: string]: string } = {};

    if (filesToAnalyze.length > 20) {
      process.stdout.write(chalk.hex('#FF8C00')(`    ⚡ Reading ${filesToAnalyze.length} files...`));
    }

    for (let i = 0; i < filesToAnalyze.length; i++) {
      const absolutePath = filesToAnalyze[i];
      const relativePath = relativeFilesToAnalyze[i];

      if (filesToAnalyze.length > 20 && i % 10 === 0) {
        // Update progress every 10 files
        process.stdout.write(chalk.hex('#FF8C00')(`\r    ⚡ Reading files ${i + 1}/${filesToAnalyze.length}...`));
      }
      try {
        // Read using absolute path, store with relative path key
        fileContents[relativePath] = await this.pathResolver.readFile(absolutePath);
      } catch (error) {
        // Shouldn't happen since we checked exists(), but handle anyway
        fileContents[relativePath] = '';
      }
    }

    if (filesToAnalyze.length > 20) {
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      console.log(chalk.gray(`    ✓ Read ${filesToAnalyze.length} files`));
    }

    // Phase 2: Base context building (always needed)
    console.log(chalk.gray(`\n  → Reading files and mapping data flows...`));
    const baseContext = await this.executor.execute({
      type: 'context-building',
      input: {
        files: validRelativeFiles, // Send relative paths to Claude for readability (only valid files)
        targetPath: this.config.target.path,
        fileContents,
        focusAreas: plan.focusAreas
      },
      maxTokens: 8000
    });

    if (!baseContext.success || !baseContext.output) {
      throw new Error(`Context analysis failed: ${baseContext.error}`);
    }

    totalTokens += baseContext.tokensUsed || 0;

    // Show what was found
    const fileCount = baseContext.output.files?.length || 0;
    const entryPoints = baseContext.output.entryPoints?.length || 0;
    const dataFlows = baseContext.output.files?.reduce((sum: number, f: any) =>
      sum + (f.functions?.reduce((s2: number, fn: any) => s2 + (fn.dataFlow?.length || 0), 0) || 0), 0) || 0;
    console.log(chalk.gray(`    Found: ${fileCount} files, ${entryPoints} entry points, ${dataFlows} data flows`));

    // Phase 3: Execute custom analysis strategies SEQUENTIALLY
    const results: any[] = [];
    const analysisTypes: string[] = [];

    // Execute each custom strategy designed by Claude
    for (const strategy of plan.analyses) {
      console.log(chalk.gray(`  → ${strategy.name}`));
      console.log(chalk.gray(`    ${strategy.description.substring(0, 80)}...`));

      // Resolve target files using PathResolver (handles both absolute and relative paths)
      let strategyFiles = validFiles;
      let strategyFilesRelative = validRelativeFiles;

      if (strategy.targetFiles && strategy.targetFiles.length > 0) {
        // Filter out hallucinated Sandyaa paths (Claude sometimes analyzes the tool instead of target)
        const sandyaaPatterns = [
          'src/agents/', 'src/utils/', 'src/poc-gen/', 'src/recursive/',
          'src/analyzer/', 'src/detector/', 'src/reporter/', 'src/orchestrator/',
          'agent-executor', 'git-helper', 'poc-generator', 'recursive-strategy',
          'context-analyzer', 'vulnerability-detector'
        ];

        const validTargetFiles = strategy.targetFiles.filter(tf => {
          // Check if it's a Sandyaa path
          const isSandyaaPath = sandyaaPatterns.some(pattern => tf.includes(pattern)) ||
                               (tf.startsWith('src/') && tf.includes('.ts'));

          if (isSandyaaPath) {
            console.log(chalk.red(`    [REJECTED] hallucinated path: ${tf}`));
            console.log(chalk.red(`       This is Sandyaa's own code, NOT the target application!`));
            return false;
          }
          return true;
        });

        if (validTargetFiles.length === 0) {
          console.log(chalk.red(`    [ERROR] ALL target files were Sandyaa paths - Claude analyzed wrong codebase!`));
          console.log(chalk.yellow(`    [WARNING] Using original file list from target application`));
        }

        // Claude often returns paths without full prefixes (e.g., "airflow/models/dagbag.py" instead of "airflow-core/src/airflow/models/dagbag.py")
        // Match intelligently: if target file doesn't exist as-is, find files that end with it
        const matchedFiles: string[] = [];

        for (const targetFile of validTargetFiles) {
          // Try exact match first
          const absoluteTarget = this.pathResolver.toAbsolute(targetFile);
          if (await this.pathResolver.exists(absoluteTarget)) {
            matchedFiles.push(absoluteTarget);
            continue;
          }

          // Try suffix match: find files from validFiles that end with the target path
          const normalized = targetFile.replace(/^\/+/, ''); // Remove leading slashes
          const match = validFiles.find(f => {
            const relativePath = this.pathResolver.toRelative(f);
            return relativePath.endsWith(normalized) || relativePath === normalized;
          });

          if (match) {
            matchedFiles.push(match);
          }
        }

        if (matchedFiles.length > 0) {
          strategyFiles = matchedFiles;
          strategyFilesRelative = matchedFiles.map(f => this.pathResolver.toRelative(f));
        } else {
          console.log(chalk.yellow(`    ⚠ Target files don't exist, using original file list instead`));
        }
      }

      // Pass the custom strategy to Claude for autonomous execution (send relative paths)
      const strategyResult = await this.executor.execute({
        type: 'custom-security-analysis',
        input: {
          strategy: strategy,
          files: strategyFilesRelative,
          targetPath: this.config.target.path
        },
        maxTokens: 8000
      });

      if (strategyResult.success && strategyResult.output) {
        results.push(strategyResult.output);
        analysisTypes.push(strategy.name);

        // Show what was found
        const issues = strategyResult.output.issues || strategyResult.output.vulnerabilities || [];
        if (issues.length > 0) {
          console.log(chalk.yellow(`    Found ${issues.length} issue${issues.length !== 1 ? 's' : ''}:`));

          // Show first 3 issues with type and location
          const samplesToShow = Math.min(3, issues.length);
          for (let i = 0; i < samplesToShow; i++) {
            const issue = issues[i];
            const issueType = issue.type || issue.category || 'unknown';
            const location = issue.location
              ? `${issue.location.file?.split('/').pop() || issue.location.file || 'unknown'}:${issue.location.line || '?'}`
              : 'unknown location';
            const severity = issue.severity ? `[${issue.severity.toUpperCase()}]` : '';

            console.log(chalk.gray(`      ${severity} ${issueType} at ${location}`));
          }

          if (issues.length > 3) {
            console.log(chalk.gray(`      ... and ${issues.length - 3} more`));
          }
        } else {
          console.log(chalk.gray(`    No issues detected`));
        }
      } else {
        console.log(chalk.yellow(`    Analysis failed: ${strategyResult.error}`));
      }

      totalTokens += strategyResult.tokensUsed || 0;
    }

    // Still run git history analysis if it's a git repo (universal)
    // BUT skip for large repos (>5000 files) to avoid timeout issues
    const shouldSkipGitHistory = validFiles.length > 5000;

    if (await this.isGitRepository(this.config.target.path)) {
      if (shouldSkipGitHistory) {
        console.log(chalk.gray(`  → Git history: skipped (large repo with ${validFiles.length} files - would timeout)`));
      } else {
        console.log(chalk.gray(`  → Git history: analyzing past vulnerabilities and patterns...`));
        const gitResult = await this.gitHistoryAnalyzer.analyzeHistory(this.config.target.path);
        results.push(gitResult);
        analysisTypes.push('git-history');
        const fixes = gitResult.securityFixes?.length || 0;
        const patterns = gitResult.commonPatterns?.length || 0;
        if (fixes > 0 || patterns > 0) {
          console.log(chalk.gray(`    Found ${fixes} past security fixes, ${patterns} common patterns`));
        }

        // Store git history context for future learning
        this.gitHistoryContext = gitResult;

        // Immediately feed git history patterns to planner as knowledge base
        if (gitResult.commonPatterns && gitResult.commonPatterns.length > 0) {
          this.planner.updateLearning({
            gitHistoryPatterns: gitResult.commonPatterns.slice(0, 10), // Top 10 patterns only (token-efficient)
            highRiskAreas: gitResult.riskAreas?.slice(0, 5) || [] // Top 5 risk areas only
          });
          console.log(chalk.cyan(`    → Planner updated with ${gitResult.commonPatterns.length} historical patterns`));
        }
      }
    }

    // Map results to their types
    const specializedContexts: any = {
      memorySafety: { memoryIssues: [], criticalFunctions: [], pointerFlows: [] },
      concurrency: { concurrencyIssues: [], locks: [], threads: [], atomics: [] },
      semantic: { semanticIssues: [], businessLogic: [], stateMachines: [], securityCriticalOperations: [] },
      gitHistory: { vulnerabilityPatterns: [], recentChanges: [] },
      customStrategies: [] // Store custom strategy results
    };

    for (let i = 0; i < results.length; i++) {
      const type = analysisTypes[i];
      const result = results[i];

      if (type === 'memory-safety') {
        specializedContexts.memorySafety = result;
      } else if (type === 'concurrency') {
        specializedContexts.concurrency = result;
      } else if (type === 'semantic') {
        specializedContexts.semantic = result;
      } else if (type === 'git-history') {
        specializedContexts.gitHistory = result;
      } else {
        // Custom strategy result - store it
        specializedContexts.customStrategies.push({
          name: type,
          result: result,
          issues: result.issues || result.vulnerabilities || []
        });
      }
    }

    // Merge all contexts
    const context = await this.enhanceContext(baseContext.output, files, specializedContexts);

    return { context, tokensUsed: totalTokens };
  }

  private async enhanceContext(
    context: any,
    files: string[],
    specializedContexts: {
      memorySafety: MemorySafetyContext;
      concurrency: ConcurrencyContext;
      semantic: SemanticContext;
      gitHistory: GitHistoryContext;
      customStrategies: any[];
    }
  ): Promise<CodeContext> {
    // Ensure all required fields exist
    const enhanced: CodeContext = {
      files: context.files || [],
      entryPoints: context.entryPoints || [],
      dataFlows: this.extractDataFlows(context.files || []),
      trustBoundaries: context.trustBoundaries || [],
      assumptions: context.assumptions || [],
      facts: context.facts || [],
      // Add specialized context
      memorySafety: specializedContexts.memorySafety,
      concurrency: specializedContexts.concurrency,
      semantic: specializedContexts.semantic,
      gitHistory: specializedContexts.gitHistory,
      customStrategies: specializedContexts.customStrategies || []
    };

    return enhanced;
  }

  private extractDataFlows(files: FileContext[]): DataFlow[] {
    const dataFlows: DataFlow[] = [];

    for (const file of files) {
      for (const func of file.functions || []) {
        if (func.dataFlow) {
          dataFlows.push(...func.dataFlow);
        }
      }
    }

    return dataFlows;
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
      '.java': 'java',
      '.rb': 'ruby',
      '.php': 'php'
    };
    return map[ext] || 'unknown';
  }

  private async isGitRepository(targetPath: string): Promise<boolean> {
    try {
      const { execSync } = await import('child_process');
      execSync('git rev-parse --git-dir', {
        cwd: targetPath,
        stdio: 'pipe'
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the executor (for RLM cost tracking)
   */
  public getExecutor(): any {
    return this.executor;
  }
}
