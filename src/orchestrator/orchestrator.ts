import { ContextAnalyzer } from '../analyzer/context-analyzer.js';
import { VulnerabilityDetector } from '../detector/vulnerability-detector.js';
import { POCGenerator } from '../poc-gen/poc-generator.js';
import { Reporter } from '../reporter/reporter.js';
import { Checkpoint } from '../utils/checkpoint.js';
import { FileScanner } from '../utils/file-scanner.js';
import { RecursiveStrategyEngine } from '../recursive/recursive-strategy.js';
import { GitHelper } from '../utils/git-helper.js';
import { RegressionDetector } from '../analyzer/regression-detector.js';
import { BlastRadiusCalculator } from '../analyzer/blast-radius.js';
import { FilePrioritizer } from '../utils/file-prioritizer.js';
import { DynamicChunker } from '../utils/dynamic-chunker.js';
import { getDefaultContextWindow, autoResolveGeminiModels } from '../utils/model-registry.js';
import { hooks, HookType } from '../utils/hooks.js';
import { DashboardRenderer } from '../ui/Dashboard.js';
import chalk from 'chalk';
import ora from 'ora';
import * as path from 'path';
import * as crypto from 'crypto';

export interface Config {
  target: {
    path: string;
    language: string;
    exclude_patterns: string[];
  };
  git: {
    auto_install: boolean;
    clone_depth: number;
    cleanup: boolean;
  };
  // AI Provider Configuration - Auto-switching between Claude/Gemini
  provider?: {
    primary: 'claude' | 'gemini' | 'auto';  // Primary provider
    fallback: 'claude' | 'gemini' | 'none'; // Fallback on rate limit
    autoSwitch: boolean;  // Enable automatic switching
    models?: {
      claude?: 'haiku' | 'sonnet' | 'opus';
      gemini?: 'flash' | 'pro' | 'ultra';
    };
  };
  analysis: {
    depth: string;
    chunk_size: number;
    incremental: boolean;
    focus_areas: string[];
    code_filtering?: {
      enabled: boolean;
      strategy: string;
      min_pattern_score: number;
    };
  };
  rlm?: {
    enabled: boolean;
    activationThreshold: {
      minContextSize: number;
      minFileCount: number;
    };
    repl: {
      pythonPath: string;
      timeout: number;
      maxMemory: number;
    };
    multiTurn: {
      maxTurns: number;
      turnTimeout: number;
    };
    subQueries: {
      maxConcurrent: number;
      maxChunkSize: number;
      model: 'haiku' | 'sonnet';
    };
    costTracking: {
      enabled: boolean;
      logFile: string;
    };
  };
  detection: {
    min_severity: string;
    exploitability_threshold: number;
    validate_findings: boolean;
  };
  recursive: {
    enabled: boolean;
    max_depth: number;
    refinement_iterations: number;
    strategies: string[];
  };
  loop: {
    mode: string;
    max_iterations: number | string;
    save_checkpoint_every: number;
  };
  poc: {
    generate: boolean;
    validate: boolean;
    max_poc_runtime: number;
  };
  output: {
    findings_dir: string;
    checkpoint_file: string;
    verbose: boolean;
  };
}

export class Orchestrator {
  private config: Config;
  private checkpoint: Checkpoint;
  private analyzer: ContextAnalyzer;
  private detector: VulnerabilityDetector;
  private pocGen: POCGenerator;
  private reporter: Reporter;
  private scanner: FileScanner;
  private recursiveEngine: RecursiveStrategyEngine;
  private gitHelper: GitHelper;
  private regressionDetector: RegressionDetector;
  private blastRadiusCalc: BlastRadiusCalculator;
  private clonedRepoPath?: string;
  private totalTokensUsed: number = 0;
  private tokensByPhase: Map<string, number> = new Map();
  private filePrioritizer?: FilePrioritizer;
  private dynamicChunker: DynamicChunker;
  private executor: any;  // Will hold ClaudeExecutor reference for RLM summary
  private dashboard: DashboardRenderer;

  constructor(config: Config) {
    this.config = config;
    // Checkpoint, Reporter, and Detector will be initialized in run() with target-specific path
    this.checkpoint = null as any; // Temporary, will be set in run()
    this.reporter = null as any; // Temporary, will be set in run()
    this.detector = null as any; // Temporary, will be set in run()
    this.analyzer = new ContextAnalyzer(config);
    this.dynamicChunker = new DynamicChunker(config.analysis.chunk_size);
    this.pocGen = new POCGenerator(config);
    this.scanner = new FileScanner(config);
    this.regressionDetector = new RegressionDetector(config.provider);
    this.blastRadiusCalc = new BlastRadiusCalculator(config.provider);

    // Store executor reference for RLM cost tracking
    this.executor = this.analyzer.getExecutor();

    // Map snake_case config to camelCase for RecursiveConfig
    const recursiveConfig = {
      enabled: config.recursive.enabled,
      maxDepth: config.recursive.max_depth,
      refinementIterations: config.recursive.refinement_iterations,
      strategies: config.recursive.strategies as any[],
      providerConfig: config.provider
    };
    this.recursiveEngine = new RecursiveStrategyEngine(recursiveConfig);
    this.gitHelper = new GitHelper();
    this.dashboard = new DashboardRenderer();
  }

  private getCheckpointFile(targetPath: string): string {
    // Create unique checkpoint file for each project (based on absolute path hash)
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 12);
    const checkpointDir = path.dirname(this.config.output.checkpoint_file);
    return path.join(checkpointDir, `checkpoint-${hash}.json`);
  }

  async run(startFresh: boolean = false): Promise<void> {
    const startTime = Date.now();
    let totalBugsFound = 0;

    // Auto-resolve Gemini models from API (picks latest stable per tier)
    await autoResolveGeminiModels();

    // Check if target is a git URL
    let targetPath = this.config.target.path;
    if (this.gitHelper.isGitURL(targetPath)) {
      console.log(chalk.cyan('Git URL detected'));

      // Clone repository (use config for depth)
      const depth = this.config.git.clone_depth || 1;
      const cloneResult = await this.gitHelper.cloneWithProgress(targetPath, depth);

      if (!cloneResult.success) {
        console.error(chalk.red('Failed to clone repository:'), cloneResult.error);
        process.exit(1);
      }

      targetPath = cloneResult.localPath;
      this.clonedRepoPath = cloneResult.localPath;
      console.log(chalk.green(`Repository: ${cloneResult.repoName}`));
    }

    console.log(chalk.cyan('Target:'), targetPath);
    console.log(chalk.cyan('Mode:'), this.config.loop.mode);
    console.log();

    // Emit ScanStart hook
    hooks.emit(HookType.ScanStart, { targetPath, config: this.config });

    // Set target path on all executors so Claude CLI runs in the target directory
    // This prevents Claude from seeing/analyzing Sandyaa's own source code
    const resolvedTarget = path.resolve(targetPath);
    const executor = this.analyzer.getExecutor();
    if (executor && typeof executor.setTargetPath === 'function') {
      executor.setTargetPath(resolvedTarget);
    }

    // Initialize project-specific checkpoint, reporter, and detector (after we know final target path)
    const checkpointFile = this.getCheckpointFile(targetPath);
    this.checkpoint = new Checkpoint(checkpointFile);
    this.reporter = new Reporter(this.config, targetPath);
    this.detector = new VulnerabilityDetector(this.config, targetPath);

    console.log(chalk.gray(`Findings will be saved to: ${path.join(this.config.output.findings_dir, path.basename(targetPath))}-<hash>`));
    console.log(chalk.gray(`Target boundary: ${path.resolve(targetPath)}`));

    // Scan target codebase (fast git-based scan)
    process.stdout.write(chalk.hex('#FF8C00')('⚡ Scanning codebase...'));
    const files = await this.scanner.scan(targetPath);
    process.stdout.write('\r' + ' '.repeat(50) + '\r');
    console.log(chalk.green(`✓ Found ${files.length.toLocaleString()} files`));

    // Initialize intelligent file prioritizer
    this.filePrioritizer = new FilePrioritizer(targetPath, this.config.provider);

    // Check for existing checkpoint and ask user
    let processedFiles = new Set<string>();
    const checkpointData = await this.checkpoint.loadForTarget(targetPath);

    if (startFresh) {
      // User explicitly wants fresh start
      if (checkpointData && checkpointData.processedFiles.length > 0) {
        await this.checkpoint.clear();
        console.log(chalk.green('Starting fresh analysis (checkpoint cleared)...\n'));
      }
    } else if (checkpointData && checkpointData.processedFiles.length > 0) {
      const filesProcessed = checkpointData.processedFiles.length;
      const bugsFound = checkpointData.totalBugsFound;
      const timestamp = new Date(checkpointData.timestamp).toLocaleString();

      console.log(chalk.yellow(`\nFound existing checkpoint from ${timestamp}:`));
      console.log(chalk.yellow(`  - ${filesProcessed} files already analyzed`));
      console.log(chalk.yellow(`  - ${bugsFound} bugs found so far`));
      console.log();

      // Ask user whether to resume or start fresh
      const readline = await import('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      const shouldResume = await new Promise<boolean>((resolve) => {
        rl.question(chalk.cyan('Resume from checkpoint? (y/n): '), (answer) => {
          rl.close();
          resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
        });
      });

      if (shouldResume) {
        processedFiles = new Set(checkpointData.processedFiles);
        totalBugsFound = checkpointData.totalBugsFound;
        console.log(chalk.green('Resuming from checkpoint...\n'));
      } else {
        await this.checkpoint.clear();
        console.log(chalk.green('Starting fresh analysis...\n'));
      }
    }

    // Filter unprocessed files
    // Note: Files in attack paths can be re-analyzed via recursive strategies
    // (call-chain-tracing, data-flow-expansion) even if marked as processed
    let filesToProcess = files.filter(f => !processedFiles.has(f));

    if (filesToProcess.length < files.length) {
      const skipped = files.length - filesToProcess.length;
      console.log(chalk.gray(`    Skipping ${skipped} already analyzed files`));
      console.log(chalk.gray(`    (Files can be re-analyzed if part of attack path in recursive analysis)`));
    }

    console.log(chalk.cyan(`Files to process: ${filesToProcess.length}\n`));

    // Start the dashboard UI (console fallback — Ink is opt-in)
    await this.dashboard.start(targetPath);
    this.dashboard.update({
      phase: 'mapping',
      progress: { current: 0, total: Math.ceil(filesToProcess.length / (this.config.analysis.chunk_size || 15)) },
      tokenBudget: getDefaultContextWindow(),
    });

    // Smart target selection for large codebases
    let prioritizedFiles: string[] = [];
    let phase = 'high-priority';
    let phaseStart = 0;

    if (filesToProcess.length > 1000 && processedFiles.size === 0) {
      const prioritizer = new FilePrioritizer(targetPath, this.config.provider);
      const prioritized = await prioritizer.prioritize(filesToProcess, {
        phase: 'high-value',
        samplingRate: 0.1,
        focusAreas: []
      });

      prioritizedFiles = prioritized
        .sort((a: any, b: any) => b.priority - a.priority)
        .map((p: any) => p.path);

      // Phase 1: Analyze prioritized targets only
      filesToProcess = prioritizedFiles;
      console.log(chalk.cyan(`Phase 1: High-priority targets (${filesToProcess.length} files)\n`));
    } else {
      phase = 'systematic';
      console.log(chalk.cyan(`Phase 2: Systematic coverage (${filesToProcess.length} files remaining)\n`));
    }

    // Process files in dynamic chunks (adapts based on complexity)
    let iteration = 0;
    let i = 0;

    while (i < filesToProcess.length) {
      iteration++;

      // Get dynamic chunk size based on learned metrics
      const chunkSize = this.dynamicChunker.getChunkSize();
      const chunk = filesToProcess.slice(i, i + chunkSize);
      const remainingFiles = filesToProcess.length - i;
      const estimatedChunksRemaining = Math.ceil(remainingFiles / chunkSize);

      console.log(chalk.bold(`\n[${phase}] Chunk ${iteration} (${chunk.length} files | ~${estimatedChunksRemaining} chunks remaining)`));
      console.log(chalk.gray(`  ${this.dynamicChunker.getExplanation()}`));

      // Update dashboard
      this.dashboard.update({
        phase: 'chunking',
        progress: { current: iteration, total: Math.ceil(filesToProcess.length / chunkSize) },
        currentFile: chunk[0] ? path.basename(chunk[0]) : '',
      });
      this.dashboard.addActivity(`Chunk ${iteration}: analyzing ${chunk.length} files`);

      const chunkStartTime = Date.now();

      // Phase 1: Deep Context Building with intelligent planning
      process.stdout.write(chalk.cyan(`  Planning: examining ${chunk.length} files... `));

      const contextResult = await this.analyzer.analyze(chunk);
      const context = contextResult.context || contextResult;
      const contextTokens = contextResult.tokensUsed || 0;
      this.totalTokensUsed += contextTokens;
      this.tokensByPhase.set('context-building', (this.tokensByPhase.get('context-building') || 0) + contextTokens);

      const contextWindowPercent = ((this.totalTokensUsed / getDefaultContextWindow()) * 100).toFixed(1);

      // Clear line and show completion
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      console.log(chalk.green(
        `✓ Analysis planned & context built: ${context.files.length} components | ` +
        `${contextTokens.toLocaleString()} tokens (${contextWindowPercent}% of ${(getDefaultContextWindow() / 1000).toFixed(0)}k)`
      ));

      // Phase 2: Vulnerability Detection
      console.log(chalk.cyan(`\n  → Vulnerability detection: correlating findings and analyzing exploitability...`));
      const detectionStartTokens = this.totalTokensUsed;
      let vulnerabilities = await this.detector.detect(context);
      const detectionTokens = this.totalTokensUsed - detectionStartTokens;

      // Update dashboard with detection results
      this.dashboard.update({
        phase: 'vulnerability-detection',
        tokensUsed: this.totalTokensUsed,
      });

      if (vulnerabilities.length > 0) {
        console.log(chalk.green(`    ✓ Found ${vulnerabilities.length} potential vulnerabilities | ${detectionTokens.toLocaleString()} tokens`));

        // Feed findings to dashboard
        for (const v of vulnerabilities) {
          const sev = (v.severity?.toLowerCase() || 'low') as 'critical' | 'high' | 'medium' | 'low';
          this.dashboard.addFinding(sev, `${v.type} at ${v.location?.file?.split('/').pop() || 'unknown'}`);
        }

        // Show sample of what was found (Claude decides what's important)
        const sample = vulnerabilities.slice(0, 3);
        for (const vuln of sample) {
          const severity = vuln.severity?.toUpperCase() || 'UNKNOWN';
          const severityColor = ['critical', 'high'].includes(vuln.severity?.toLowerCase() || '') ? chalk.red : chalk.yellow;
          const attackerNote = vuln.attackerControlled?.isControlled ? 'VERIFIED ' : '';
          console.log(severityColor(`      ${attackerNote}[${severity}] ${vuln.type} at ${vuln.location.file.split('/').pop()}:${vuln.location.line}`));
        }
        if (vulnerabilities.length > 3) {
          console.log(chalk.gray(`      ... and ${vulnerabilities.length - 3} more`));
        }
      } else {
        console.log(chalk.gray(`    ✓ No vulnerabilities in this chunk | ${detectionTokens.toLocaleString()} tokens`));
      }

      // Phase 2.5: Recursive Analysis (if enabled)
      if (this.config.recursive.enabled && vulnerabilities.length > 0) {
        this.dashboard.update({ phase: 'validation' });
        console.log(chalk.cyan(`\n  → Recursive verification: tracing call chains, checking contradictions...`));
        const recursiveStartTokens = this.totalTokensUsed;
        const enhanced = await this.recursiveEngine.apply(vulnerabilities, context);
        const recursiveTokens = this.totalTokensUsed - recursiveStartTokens;

        // Count verification statuses instead of filtering
        const verified = enhanced.filter(v => v.verificationStatus === 'verified' || !v.verificationStatus).length;
        const uncertain = enhanced.filter(v => v.verificationStatus === 'uncertain').length;
        const contradicted = enhanced.filter(v => v.verificationStatus === 'contradicted').length;
        const needsReview = enhanced.filter(v => v.needsManualReview).length;

        vulnerabilities = enhanced; // Keep ALL findings

        // Show verification breakdown
        if (verified === enhanced.length) {
          console.log(chalk.green(`    ✓ All ${enhanced.length} findings verified as exploitable | ${recursiveTokens.toLocaleString()} tokens`));
        } else {
          console.log(chalk.yellow(`    ✓ Verification complete: ${verified} verified, ${uncertain} uncertain, ${contradicted} contradicted | ${recursiveTokens.toLocaleString()} tokens`));
          if (needsReview > 0) {
            console.log(chalk.cyan(`      → ${needsReview} finding${needsReview > 1 ? 's' : ''} flagged for manual review`));
          }
        }
      }

      // Phase 2.6: Regression Detection
      if (vulnerabilities.length > 0) {
        process.stdout.write(chalk.cyan(`  Checking git history... `));
        const regressions = await this.regressionDetector.detectRegressions(
          targetPath,
          vulnerabilities
        );

        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        if (regressions.length > 0) {
          console.log(chalk.yellow(`⚠ Found ${regressions.length} regressions (previously fixed bugs)`));

          // Attach regression info to vulnerabilities
          for (const regression of regressions) {
            regression.vulnerability.regression = {
              originalFix: regression.originalFix.commit,
              similarity: regression.similarity,
              type: regression.type
            };
          }
        } else {
          console.log(chalk.gray(`✓ No regressions found`));
        }
      }

      // Phase 2.7: Blast Radius Calculation
      if (vulnerabilities.length > 0) {
        console.log(chalk.cyan(`  Mapping blast radius for ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'}...`));

        for (let i = 0; i < vulnerabilities.length; i++) {
          const vuln = vulnerabilities[i];
          process.stdout.write(chalk.hex('#FF8C00')(`\r    ⚡ Analyzing impact ${i + 1}/${vulnerabilities.length}: ${vuln.id}...`));

          const blastRadius = await this.blastRadiusCalc.calculateBlastRadius(
            vuln,
            context,
            targetPath
          );

          vuln.blastRadius = blastRadius;

          // Show result for this vulnerability
          process.stdout.write('\r' + ' '.repeat(100) + '\r');
          console.log(chalk.gray(`      ${vuln.id}: ${blastRadius.callSiteCount} call site${blastRadius.callSiteCount !== 1 ? 's' : ''}`));
        }

        const totalCallSites = vulnerabilities.reduce((sum, v) => sum + (v.blastRadius?.callSiteCount || 0), 0);
        console.log(chalk.gray(`    ✓ Impact mapped: ${totalCallSites} total call sites affected`));
      }

      if (vulnerabilities.length > 0) {
        // Phase 3: POC Generation + Validation
        this.dashboard.update({ phase: 'poc-generation' });
        console.log(chalk.cyan(`  Generating and validating POCs for ${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'}...`));
        const allFindings: any[] = [];  // KEEP EVERYTHING

        for (let i = 0; i < vulnerabilities.length; i++) {
          const vuln = vulnerabilities[i];

          if (this.config.poc.generate) {
            try {
              process.stdout.write(chalk.hex('#FF8C00')(`\r    ⚡ POC ${i + 1}/${vulnerabilities.length}: Generating for ${vuln.id}...`));
              const poc = await this.pocGen.generate(vuln, context);

              // Anti-hallucination: Validate POC actually works
              if (this.config.poc.validate) {
                process.stdout.write(chalk.hex('#FF8C00')(`\r    ⚡ POC ${i + 1}/${vulnerabilities.length}: Validating ${vuln.id}...          `));
                const isValid = await this.pocGen.validate(poc);
                if (isValid) {
                  vuln.poc = poc;
                  vuln.poc.validated = true;
                  process.stdout.write('\r' + ' '.repeat(100) + '\r');
                  console.log(chalk.green(`      ✓ ${vuln.id}: POC validated`));
                } else {
                  // POC didn't work - KEEP THE FINDING but mark it
                  vuln.poc = poc;
                  vuln.poc.validated = false;
                  vuln.needsManualReview = true;
                  if (!vuln.verificationStatus) {
                    vuln.verificationStatus = 'unverified';
                  }
                  process.stdout.write('\r' + ' '.repeat(100) + '\r');
                  console.log(chalk.yellow(`      ⚠ ${vuln.id}: POC validation failed - marked for manual review`));
                }
              } else {
                // Validation skipped
                vuln.poc = poc;
                vuln.poc.validated = false;
                process.stdout.write('\r' + ' '.repeat(100) + '\r');
                console.log(chalk.gray(`      ${vuln.id}: POC generated (validation skipped)`));
              }
            } catch (error) {
              // POC generation failed - STILL KEEP THE FINDING
              process.stdout.write('\r' + ' '.repeat(100) + '\r');
              console.log(chalk.yellow(`      ⚠ ${vuln.id}: POC generation failed, reported without POC`));
              vuln.needsManualReview = true;
            }
          }

          // ALWAYS add to findings list - NEVER discard
          allFindings.push(vuln);
          hooks.emit(HookType.FindingDetected, vuln);
        }

        // Count findings by status
        const validated = allFindings.filter(v => v.poc?.validated === true).length;
        const unvalidated = allFindings.filter(v => v.poc && v.poc.validated === false).length;
        const noPOC = allFindings.filter(v => !v.poc).length;
        const highSeverity = allFindings.filter(v => v.severity === 'critical' || v.severity === 'high').length;

        if (highSeverity > 0) {
          console.log(chalk.red(`    ✓ Collected ${allFindings.length} findings (${highSeverity} HIGH/CRITICAL) - ${validated} validated, ${unvalidated} unvalidated, ${noPOC} no POC`));
        } else {
          console.log(chalk.green(`    ✓ Collected ${allFindings.length} findings - ${validated} validated, ${unvalidated} unvalidated, ${noPOC} no POC`));
        }
        totalBugsFound += allFindings.length;

        // Phase 4: Report Generation - REPORT EVERYTHING
        if (allFindings.length > 0) {
          await this.reporter.report(allFindings);

          // Show breakdown
          const verifiedCount = allFindings.filter(v =>
            v.verificationStatus === 'verified' ||
            (!v.verificationStatus && v.poc?.validated === true)
          ).length;
          const uncertainCount = allFindings.filter(v =>
            v.verificationStatus === 'uncertain' ||
            v.poc?.validated === false
          ).length;
          const contradictedCount = allFindings.filter(v =>
            v.verificationStatus === 'contradicted'
          ).length;

          console.log(chalk.green.bold(`\n${allFindings.length} findings documented:`));
          console.log(chalk.green(`  ✓ ${verifiedCount} verified`));
          console.log(chalk.yellow(`  ⚠ ${uncertainCount} uncertain/unvalidated`));
          console.log(chalk.red(`  ✗ ${contradictedCount} contradicted`));
          console.log();

          // IMMEDIATE CHECKPOINT: Save findings count right after writing to disk
          // This prevents loss if process crashes before main checkpoint
          chunk.forEach(f => processedFiles.add(f));

          // Mark files in attack paths (tracks for metrics/debugging)
          // Note: Recursive strategies can already read these files as needed
          // This tracking helps identify which files are frequently part of attack chains
          for (const finding of allFindings) {
            const attackPathFiles = this.extractAttackPathFiles(finding);
            for (const file of attackPathFiles) {
              await this.checkpoint.markAttackPathFile(file, finding.id);
            }
          }

          await this.checkpoint.save({
            targetPath,
            processedFiles: Array.from(processedFiles),
            totalBugsFound,
            timestamp: Date.now()
          });
          console.log(chalk.gray(`    → Checkpoint saved (${allFindings.length} findings secured)`));

          // Update planner with learnings from validated bugs (for next chunk's planning)
          const successfulStrategies = context.files
            .filter((f: any) => allFindings.some((v: any) => v.location.file.includes(f.path)))
            .map((f: any) => f.analysisStrategy)
            .filter(Boolean);

          this.analyzer.updateLearnings({
            vulnerabilities: allFindings,
            successfulStrategies: successfulStrategies.length > 0 ? successfulStrategies : undefined
          });

          console.log(chalk.cyan(`    → Planner updated with ${allFindings.length} new finding${allFindings.length !== 1 ? 's' : ''} for next chunk`));
        }
      } else {
        // No vulnerabilities found, still mark files as processed
        chunk.forEach(f => processedFiles.add(f));

        // Save checkpoint even when no bugs found
        await this.checkpoint.save({
          targetPath,
          processedFiles: Array.from(processedFiles),
          totalBugsFound,
          timestamp: Date.now()
        });
      }

      // Update dynamic chunker metrics
      const chunkTime = Date.now() - chunkStartTime;
      await this.dynamicChunker.updateMetrics(
        chunk,
        contextTokens + (detectionTokens || 0),
        this.totalTokensUsed,
        chunkTime
      );

      // Show chunk summary with cumulative stats
      const contextPercent = ((this.totalTokensUsed / getDefaultContextWindow()) * 100).toFixed(1);
      const chunkTimeMin = (chunkTime / 60000).toFixed(1);
      const bugsThisChunk = vulnerabilities.filter(v => v.poc?.validated).length;

      console.log(chalk.bold.cyan(
        `\n━━━ Chunk ${iteration} Summary ━━━`
      ));
      console.log(chalk.gray(
        `  Time: ${chunkTimeMin} min | ` +
        `Files analyzed: ${chunk.length} | ` +
        `Bugs found: ${bugsThisChunk}`
      ));
      console.log(chalk.gray(
        `  Progress: ${processedFiles.size}/${files.length} files (${((processedFiles.size/files.length)*100).toFixed(1)}%) | ` +
        `Total bugs: ${totalBugsFound} | ` +
        `Context: ${contextPercent}% of 200k`
      ));

      // Show next chunk size reasoning
      const nextSize = this.dynamicChunker.getChunkSize();
      console.log(chalk.gray(
        `  Next chunk: ${nextSize} files (${this.dynamicChunker.getExplanation()})`
      ));

      // Move to next chunk
      i += chunk.length;
    }

    // After phase 1 completes, check if we should do phase 2
    if (phase === 'high-priority' && prioritizedFiles.length < files.length) {
      const remaining = files.filter(f => !processedFiles.has(f));

      if (remaining.length > 0) {
        console.log(chalk.yellow(`\nPhase 1 complete. ${totalBugsFound} bugs found in priority targets.`));
        console.log(chalk.yellow(`${remaining.length.toLocaleString()} files remaining for systematic coverage.\n`));

        // Ask user if they want to continue
        const readline = await import('readline');
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        });

        const shouldContinue = await new Promise<boolean>((resolve) => {
          rl.question(chalk.cyan('Continue with full codebase scan? (y/n): '), (answer) => {
            rl.close();
            resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
          });
        });

        if (shouldContinue) {
          // Restart loop with remaining files
          filesToProcess = remaining;
          phase = 'systematic';
          console.log(chalk.green('Starting systematic coverage...\n'));

          // Continue analysis with dynamic chunking
          let j = 0;
          while (j < remaining.length) {
            iteration++;
            const chunkSize = this.dynamicChunker.getChunkSize();
            const chunk = remaining.slice(j, j + chunkSize);
            const remainingFiles = remaining.length - j;
            const estimatedChunksRemaining = Math.ceil(remainingFiles / chunkSize);

            console.log(chalk.bold(`\n[systematic] Chunk ${iteration} (${chunk.length} files | ~${estimatedChunksRemaining} chunks remaining)`));
            console.log(chalk.gray(`  ${this.dynamicChunker.getExplanation()}`));

            const chunkStartTime = Date.now();

            // Same analysis pipeline as before...
            process.stdout.write(chalk.hex('#FF8C00')(`⚡ Analyzing ${chunk.length} files...`));
            const contextResult = await this.analyzer.analyze(chunk);
            const context = contextResult.context || contextResult;
            const contextTokens = contextResult.tokensUsed || 0;
            this.totalTokensUsed += contextTokens;
            this.tokensByPhase.set('context-building', (this.tokensByPhase.get('context-building') || 0) + contextTokens);

            const contextWindowPercent = ((this.totalTokensUsed / getDefaultContextWindow()) * 100).toFixed(1);
            process.stdout.write('\r' + ' '.repeat(80) + '\r');
            console.log(chalk.green(`✓ Analyzed ${chunk.length} files, mapped ${context.files.length} components [${contextTokens.toLocaleString()} tokens | ${contextWindowPercent}% context]`));

            // Continue with detection, recursive, etc... (copy from above)
            console.log(chalk.hex('#FF8C00')(`⚡ Detecting vulnerabilities...`));
            const detectionStartTokens = this.totalTokensUsed;
            let vulnerabilities = await this.detector.detect(context);
            const detectionTokens = this.totalTokensUsed - detectionStartTokens;

            if (vulnerabilities.length > 0) {
              console.log(chalk.green(`  ✓ Found ${vulnerabilities.length} potential vulnerabilities [${detectionTokens.toLocaleString()} tokens]`));
            } else {
              console.log(chalk.gray(`  ✓ No vulnerabilities in this chunk [${detectionTokens.toLocaleString()} tokens]`));
            }

            // Update processed files
            chunk.forEach(f => processedFiles.add(f));

            // Update dynamic chunker metrics
            const systematicChunkTime = Date.now() - chunkStartTime;
            await this.dynamicChunker.updateMetrics(
              chunk,
              contextTokens + detectionTokens,
              this.totalTokensUsed,
              systematicChunkTime
            );

            // Show chunk summary
            const contextPercent = ((this.totalTokensUsed / getDefaultContextWindow()) * 100).toFixed(1);
            const chunkTimeMin = (systematicChunkTime / 60000).toFixed(1);
            console.log(chalk.cyan(
              `\nChunk ${iteration} complete (${chunkTimeMin} min) | ` +
              `Files: ${processedFiles.size}/${files.length} | ` +
              `Bugs: ${totalBugsFound} | ` +
              `Tokens: ${this.totalTokensUsed.toLocaleString()} (${contextPercent}% of ${(getDefaultContextWindow() / 1000).toFixed(0)}k)`
            ));

            // Save checkpoint
            await this.checkpoint.save({
              targetPath,
              processedFiles: Array.from(processedFiles),
              totalBugsFound,
              timestamp: Date.now()
            });

            // Move to next chunk
            j += chunk.length;
          }
        } else {
          console.log(chalk.yellow('Stopping after high-priority analysis.'));
        }
      }
    }

    // Stop dashboard
    this.dashboard.update({ phase: 'reporting', tokensUsed: this.totalTokensUsed });
    this.dashboard.addActivity(`Scan complete: ${totalBugsFound} findings`);
    this.dashboard.stop();

    // Final summary
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.log(chalk.bold.green('\nAnalysis Complete'));
    console.log(chalk.cyan('Total files analyzed:'), files.length);
    console.log(chalk.cyan('Total bugs found:'), totalBugsFound);
    console.log(chalk.cyan('Duration:'), `${duration} minutes`);
    console.log(chalk.cyan('Findings:'), this.config.output.findings_dir);

    // Token usage summary
    const { ClaudeExecutor } = await import('../agents/agent-executor.js');
    const tokenStats = ClaudeExecutor.formatTokenUsage();
    if (tokenStats) {
      console.log(chalk.cyan('\nToken Usage:'));
      console.log(chalk.gray(tokenStats));
    }

    // Generate summary report
    await this.reporter.generateSummary(totalBugsFound, files.length, duration);

    // Emit ScanComplete hook
    hooks.emit(HookType.ScanComplete, {
      totalBugs: totalBugsFound,
      filesAnalyzed: files.length,
      duration,
      findingsDir: this.config.output.findings_dir,
    });

    // Cleanup cloned repository if configured
    if (this.clonedRepoPath && this.config.git.cleanup) {
      console.log(chalk.gray('\nCleaning up cloned repository...'));
      await this.gitHelper.cleanup(this.clonedRepoPath);
    } else if (this.clonedRepoPath) {
      console.log(chalk.gray(`\nCloned repository kept at: ${this.clonedRepoPath}`));
    }
  }

  /**
   * Extract all files that are part of attack path from vulnerability
   * These files should be re-analyzed even if processed before
   */
  private extractAttackPathFiles(vulnerability: any): string[] {
    const files = new Set<string>();

    // Add main vulnerability location
    if (vulnerability.location?.file) {
      files.add(vulnerability.location.file);
    }

    // Add files from evidence chain
    if (vulnerability.evidenceChain) {
      for (const evidence of vulnerability.evidenceChain) {
        if (evidence.location) {
          // Extract file path from location (format: "file.js:123" or just "file.js")
          const filePath = evidence.location.split(':')[0];
          if (filePath) {
            files.add(filePath);
          }
        }
      }
    }

    // Add files from data flow (attacker-controlled analysis)
    if (vulnerability.attackerControlled?.dataFlow) {
      for (const flowStep of vulnerability.attackerControlled.dataFlow) {
        // Flow steps might be "file.js:functionName" format
        const filePath = flowStep.split(':')[0];
        if (filePath && filePath.includes('.')) {
          files.add(filePath);
        }
      }
    }

    // Add entry point file
    if (vulnerability.attackerControlled?.entryPoint) {
      const entryFile = vulnerability.attackerControlled.entryPoint.split(':')[0];
      if (entryFile && entryFile.includes('.')) {
        files.add(entryFile);
      }
    }

    return Array.from(files);
  }
}
