import { execSync } from 'child_process';
import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';

export interface SecurityFix {
  commit: string;
  date: string;
  author: string;
  message: string;
  changedFiles: string[];
  diff: string;
  vulnerabilityPattern: VulnerabilityPattern | null;
}

export interface VulnerabilityPattern {
  type: string;
  pattern: string;
  location: {
    file: string;
    linesBefore: string[];
    linesAfter: string[];
  };
  rootCause: string;
  fixApplied: string;
}

export interface GitHistoryContext {
  securityFixes: SecurityFix[];
  commonPatterns: string[];
  riskAreas: string[];
}

export interface GitHistoryCheckpoint {
  analyzedCommits: string[];
  securityFixes: SecurityFix[];
  timestamp: string;
}

export class GitHistoryAnalyzer {
  private executor: ModelExecutor;
  private checkpointDir: string;

  constructor(checkpointDir: string = '.sandyaa/git-history', providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
    this.checkpointDir = checkpointDir;
  }

  async analyzeHistory(targetPath: string): Promise<GitHistoryContext> {
    // Check if path is a git repository
    if (!await this.isGitRepository(targetPath)) {
      console.warn('Target is not a git repository, skipping git history analysis');
      return {
        securityFixes: [],
        commonPatterns: [],
        riskAreas: []
      };
    }

    // Get all commits with security-related keywords
    const securityCommits = await this.findSecurityCommits(targetPath);

    if (securityCommits.length === 0) {
      console.log(chalk.gray(`    No security-related commits found in last year`));
      return {
        securityFixes: [],
        commonPatterns: [],
        riskAreas: []
      };
    }

    console.log(chalk.cyan(`    Found ${securityCommits.length} security-related commits to analyze`));

    // Load checkpoint to resume from where we left off
    const checkpoint = await this.loadCheckpoint(targetPath);
    const analyzedCommits = new Set(checkpoint.analyzedCommits);
    const securityFixes: SecurityFix[] = [...checkpoint.securityFixes];

    // Filter out already-analyzed commits
    const remainingCommits = securityCommits.filter(c => !analyzedCommits.has(c));

    if (remainingCommits.length === 0) {
      console.log(chalk.green(`    ✓ All ${securityCommits.length} commits already analyzed (resumed from checkpoint)`));
    } else if (analyzedCommits.size > 0) {
      console.log(chalk.cyan(`    Resuming: ${analyzedCommits.size} already done, ${remainingCommits.length} remaining`));
    }

    // Analyze remaining commits
    let analyzed = analyzedCommits.size;

    for (const commit of remainingCommits) {
      analyzed++;

      // Show progress with model selection info
      process.stdout.write(chalk.hex('#FF8C00')(`\r    ⚡ Analyzing commit ${analyzed}/${securityCommits.length}...`));

      const fix = await this.analyzeSecurityFix(targetPath, commit);
      if (fix) {
        securityFixes.push(fix);

        // Show what pattern was found
        const commitShort = commit.substring(0, 7);
        const patternType = fix.vulnerabilityPattern?.type || 'no-pattern';
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        console.log(chalk.gray(`      ${commitShort}: ${patternType}`));
      } else {
        // Clear the progress line
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
      }

      // Save checkpoint after each commit (so we can resume)
      analyzedCommits.add(commit);
      await this.saveCheckpoint(targetPath, {
        analyzedCommits: Array.from(analyzedCommits),
        securityFixes,
        timestamp: new Date().toISOString()
      });
    }

    // Clear progress line
    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    console.log(chalk.green(`    ✓ Analyzed ${analyzed} commits, found ${securityFixes.length} vulnerability patterns`));

    // Extract common vulnerability patterns
    console.log(chalk.gray(`\n    → Extracting common patterns from ${securityFixes.length} fixes...`));
    const commonPatterns = await this.extractCommonPatterns(securityFixes);
    if (commonPatterns.length > 0) {
      console.log(chalk.gray(`      Found ${commonPatterns.length} recurring patterns:`));
      commonPatterns.slice(0, 3).forEach(pattern => {
        console.log(chalk.gray(`        - ${pattern.substring(0, 60)}${pattern.length > 60 ? '...' : ''}`));
      });
      if (commonPatterns.length > 3) {
        console.log(chalk.gray(`        ... and ${commonPatterns.length - 3} more`));
      }
    }

    // Identify high-risk areas (files frequently involved in security fixes)
    console.log(chalk.gray(`\n    → Identifying high-risk code areas...`));
    const riskAreas = this.identifyRiskAreas(securityFixes);
    if (riskAreas.length > 0) {
      console.log(chalk.yellow(`      ${riskAreas.length} high-risk areas identified:`));
      riskAreas.slice(0, 3).forEach(area => {
        console.log(chalk.yellow(`        - ${area}`));
      });
      if (riskAreas.length > 3) {
        console.log(chalk.gray(`        ... and ${riskAreas.length - 3} more`));
      }
    }

    return {
      securityFixes,
      commonPatterns,
      riskAreas
    };
  }

  private async isGitRepository(targetPath: string): Promise<boolean> {
    try {
      execSync('git rev-parse --git-dir', {
        cwd: targetPath,
        stdio: 'pipe'
      });
      return true;
    } catch {
      return false;
    }
  }

  private async findSecurityCommits(targetPath: string): Promise<string[]> {
    try {
      // Search for commits with security-related keywords
      const keywords = [
        'CVE-',
        'security',
        'vulnerability',
        'exploit',
        'bypass',
        'injection',
        'XSS',
        'CSRF',
        'sanitize',
        'validate',
        'fix.*bug',
        'patch',
        'unsafe',
        'attack',
        'malicious'
      ];

      const grepPattern = keywords.join('\\|');

      // Limit to recent commits (last year) to avoid buffer overflow on large repos
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
      const sinceDate = oneYearAgo.toISOString().split('T')[0];

      const log = execSync(
        `git log --since="${sinceDate}" --grep="${grepPattern}" --pretty=format:"%H" -i --max-count=100`,
        {
          cwd: targetPath,
          encoding: 'utf-8',
          stdio: 'pipe',
          maxBuffer: 1024 * 1024 * 10 // 10MB buffer
        }
      );

      const commits = log.trim().split('\n').filter(c => c.length > 0);

      // Limit to last 100 security commits for performance
      return commits.slice(0, 100);
    } catch (error) {
      console.warn('Error searching git history:', error);
      return [];
    }
  }

  private async analyzeSecurityFix(
    targetPath: string,
    commitHash: string
  ): Promise<SecurityFix | null> {
    try {
      // Get commit details
      const details = execSync(
        `git show ${commitHash} --pretty=format:"%H%n%aI%n%an%n%B" --name-only`,
        {
          cwd: targetPath,
          encoding: 'utf-8',
          stdio: 'pipe'
        }
      );

      const lines = details.split('\n');
      const commit = lines[0];
      const date = lines[1];
      const author = lines[2];

      // Extract commit message (everything until file list)
      let messageEndIndex = 3;
      while (messageEndIndex < lines.length && lines[messageEndIndex].trim() !== '') {
        messageEndIndex++;
      }
      const message = lines.slice(3, messageEndIndex).join('\n');

      // Get changed files
      const changedFiles = lines.slice(messageEndIndex + 1).filter(f => f.trim().length > 0);

      // Get full diff
      const diff = execSync(`git show ${commitHash}`, {
        cwd: targetPath,
        encoding: 'utf-8',
        stdio: 'pipe',
        maxBuffer: 10 * 1024 * 1024 // 10MB max
      });

      // Analyze the vulnerability pattern using Claude
      const vulnerabilityPattern = await this.extractVulnerabilityPattern(
        message,
        diff,
        changedFiles
      );

      return {
        commit,
        date,
        author,
        message,
        changedFiles,
        diff: diff.substring(0, 50000), // Limit diff size
        vulnerabilityPattern
      };
    } catch (error) {
      console.warn(`Error analyzing commit ${commitHash}:`, error);
      return null;
    }
  }

  private async extractVulnerabilityPattern(
    message: string,
    diff: string,
    changedFiles: string[]
  ): Promise<VulnerabilityPattern | null> {
    try {
      const result = await this.executor.execute({
        type: 'vulnerability-pattern-extraction',
        input: { message, diff, changedFiles },
        maxTokens: 4000
      });

      if (result.success && result.output) {
        return result.output as VulnerabilityPattern;
      }

      return null;
    } catch (error) {
      console.warn('Error extracting vulnerability pattern:', error);
      return null;
    }
  }

  private async extractCommonPatterns(fixes: SecurityFix[]): Promise<string[]> {
    if (fixes.length === 0) {
      return [];
    }

    // Group by vulnerability types
    const patternsByType = new Map<string, VulnerabilityPattern[]>();

    for (const fix of fixes) {
      if (fix.vulnerabilityPattern) {
        const type = fix.vulnerabilityPattern.type;
        if (!patternsByType.has(type)) {
          patternsByType.set(type, []);
        }
        patternsByType.get(type)!.push(fix.vulnerabilityPattern);
      }
    }

    // Extract common patterns for each type
    const commonPatterns: string[] = [];

    for (const [type, patterns] of patternsByType.entries()) {
      if (patterns.length >= 2) {
        // If we have multiple fixes of the same type, there's a pattern
        commonPatterns.push(
          `${type}: ${patterns.length} occurrences found. ` +
          `Common fix: ${patterns[0].fixApplied}`
        );
      }
    }

    return commonPatterns;
  }

  private identifyRiskAreas(fixes: SecurityFix[]): string[] {
    // Count how many times each file was involved in security fixes
    const fileFrequency = new Map<string, number>();

    for (const fix of fixes) {
      for (const file of fix.changedFiles) {
        fileFrequency.set(file, (fileFrequency.get(file) || 0) + 1);
      }
    }

    // Files with 3+ security fixes are high-risk areas
    const riskAreas: string[] = [];
    for (const [file, count] of fileFrequency.entries()) {
      if (count >= 3) {
        riskAreas.push(`${file} (${count} security fixes)`);
      }
    }

    return riskAreas.sort((a, b) => {
      const aCount = parseInt(a.match(/\((\d+) security fixes\)/)![1]);
      const bCount = parseInt(b.match(/\((\d+) security fixes\)/)![1]);
      return bCount - aCount;
    });
  }

  async findSimilarBugs(
    targetPath: string,
    pattern: VulnerabilityPattern
  ): Promise<string[]> {
    // Search codebase for similar patterns using git grep
    const similarLocations: string[] = [];

    try {
      // Extract key code patterns from the vulnerability
      const searchTerms = this.extractSearchTerms(pattern);

      for (const term of searchTerms) {
        try {
          const results = execSync(
            `git grep -n "${term}"`,
            {
              cwd: targetPath,
              encoding: 'utf-8',
              stdio: 'pipe'
            }
          );

          const matches = results.trim().split('\n');
          similarLocations.push(...matches);
        } catch {
          // No matches for this term
        }
      }

      return [...new Set(similarLocations)]; // Remove duplicates
    } catch (error) {
      console.warn('Error searching for similar bugs:', error);
      return [];
    }
  }

  private extractSearchTerms(pattern: VulnerabilityPattern): string[] {
    const terms: string[] = [];

    // Extract function names, variable names from the pattern
    const codePattern = pattern.pattern;

    // Simple heuristic: extract identifiers
    const identifiers = codePattern.match(/\b[a-zA-Z_][a-zA-Z0-9_]{3,}\b/g);

    if (identifiers) {
      terms.push(...identifiers.slice(0, 5)); // Top 5 identifiers
    }

    return terms;
  }

  private getCheckpointFile(targetPath: string): string {
    // Use absolute path hash for unique checkpoint per project
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 12);
    return path.join(this.checkpointDir, `git-history-${hash}.json`);
  }

  private async loadCheckpoint(targetPath: string): Promise<GitHistoryCheckpoint> {
    const checkpointFile = this.getCheckpointFile(targetPath);

    try {
      const content = await fs.readFile(checkpointFile, 'utf-8');
      const checkpoint = JSON.parse(content);
      return checkpoint;
    } catch {
      // No checkpoint found, start fresh
      return {
        analyzedCommits: [],
        securityFixes: [],
        timestamp: new Date().toISOString()
      };
    }
  }

  private async saveCheckpoint(
    targetPath: string,
    checkpoint: GitHistoryCheckpoint
  ): Promise<void> {
    const checkpointFile = this.getCheckpointFile(targetPath);

    try {
      // Ensure checkpoint directory exists
      await fs.mkdir(this.checkpointDir, { recursive: true });

      // Save checkpoint
      await fs.writeFile(
        checkpointFile,
        JSON.stringify(checkpoint, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.warn('Failed to save git history checkpoint:', error);
    }
  }

  async detectRegressions(
    targetPath: string,
    securityFixes: SecurityFix[]
  ): Promise<Array<{ fix: SecurityFix; isRegressed: boolean; reason: string }>> {
    const regressions = [];

    for (const fix of securityFixes) {
      // Check if the fix is still present
      const isRegressed = await this.checkIfRegressed(targetPath, fix);

      regressions.push({
        fix,
        isRegressed: isRegressed.regressed,
        reason: isRegressed.reason
      });
    }

    return regressions;
  }

  private async checkIfRegressed(
    targetPath: string,
    fix: SecurityFix
  ): Promise<{ regressed: boolean; reason: string }> {
    try {
      // Get current state of changed files
      const currentState: { [file: string]: string } = {};

      for (const file of fix.changedFiles) {
        try {
          const content = await fs.readFile(
            path.join(targetPath, file),
            'utf-8'
          );
          currentState[file] = content;
        } catch {
          // File might have been deleted
          continue;
        }
      }

      // Use Claude to check if the fix is still present
      const result = await this.executor.execute({
        type: 'regression-detection',
        input: {
          fix,
          currentState
        },
        maxTokens: 2000
      });

      if (result.success && result.output) {
        return result.output as { regressed: boolean; reason: string };
      }

      return { regressed: false, reason: 'Unable to analyze' };
    } catch (error) {
      return { regressed: false, reason: `Error: ${error}` };
    }
  }
}
