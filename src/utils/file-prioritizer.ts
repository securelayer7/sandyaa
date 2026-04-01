import * as fs from 'fs/promises';
import * as path from 'path';
import { execSync } from 'child_process';
import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import chalk from 'chalk';

export interface PrioritizedFile {
  path: string;
  priority: number;
  reason: string;
}

export interface PrioritizationStrategy {
  phase: 'high-value' | 'systematic' | 'adaptive';
  samplingRate: number;
  focusAreas: string[];
}

export class FilePrioritizer {
  private executor: ModelExecutor;
  private targetPath: string;
  private analyzedFiles: Set<string> = new Set();
  private bugsFoundByPath: Map<string, number> = new Map();

  constructor(targetPath: string, providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
    this.targetPath = targetPath;
  }

  async prioritize(
    allFiles: string[],
    strategy: PrioritizationStrategy
  ): Promise<PrioritizedFile[]> {
    switch (strategy.phase) {
      case 'high-value':
        return this.selectHighValueTargets(allFiles);
      case 'systematic':
        return this.systematicCoverage(allFiles);
      case 'adaptive':
        return this.adaptiveSelection(allFiles);
      default:
        return allFiles.map(f => ({ path: f, priority: 1, reason: 'sequential' }));
    }
  }

  private async selectHighValueTargets(allFiles: string[]): Promise<PrioritizedFile[]> {
    const fileStats = await this.gatherFileMetadata(allFiles);

    // Use heuristics for large codebases (faster)
    if (allFiles.length > 50000) {
      return this.heuristicPrioritization(allFiles, fileStats);
    }

    // Sample files to show Claude the actual structure
    const sampleSize = Math.min(200, allFiles.length);
    const sampleFiles = this.stratifiedSample(allFiles, sampleSize)
      .map(f => path.relative(this.targetPath, f)); // Convert to relative paths

    // Let Claude decide which files are most interesting
    process.stdout.write(chalk.hex('#FF8C00')(`    ⚡ AI-powered file prioritization (analyzing ${allFiles.length} files)...`));
    const result = await this.executor.execute({
      type: 'file-prioritization',
      input: {
        totalFiles: allFiles.length,
        fileStats,
        targetPath: this.targetPath,
        sampleFiles // Show Claude actual file structure
      },
      maxTokens: 8000
    });

    process.stdout.write('\r' + ' '.repeat(100) + '\r');

    if (!result.success || !result.output) {
      const errorMsg = result.error ? `: ${result.error.substring(0, 200)}` : '';
      console.log(chalk.yellow(`    ⚠ AI prioritization failed${errorMsg}`));
      console.log(chalk.gray(`    → Using heuristic prioritization instead`));
      return this.heuristicPrioritization(allFiles, fileStats);
    }

    const prioritized = result.output.prioritizedFiles || [];

    if (prioritized.length === 0) {
      console.log(chalk.yellow(`    ⚠ AI returned 0 prioritized files, using heuristics`));
      return this.heuristicPrioritization(allFiles, fileStats);
    }

    // Convert Claude's relative paths to absolute paths to match scanner output
    const withAbsolutePaths = prioritized.map((p: PrioritizedFile) => ({
      ...p,
      path: path.isAbsolute(p.path) ? p.path : path.join(this.targetPath, p.path)
    }));

    console.log(chalk.gray(`    ✓ Prioritized ${withAbsolutePaths.length} high-value targets\n`));

    return withAbsolutePaths;
  }

  private async gatherFileMetadata(allFiles: string[]): Promise<any> {
    // Fast metadata gathering - no file I/O
    const stats = {
      totalFiles: allFiles.length,
      languages: this.detectLanguages(allFiles),
      directories: this.analyzeDirectoryStructure(allFiles),
      securityCriticalPaths: this.findSecurityCriticalPaths(allFiles),
      recentChanges: await this.findRecentChanges(100)
    };

    return stats;
  }

  private stratifiedSample(files: string[], sampleSize: number): string[] {
    // Group by directory
    const byDir = new Map<string, string[]>();
    for (const file of files) {
      const dir = path.dirname(file);
      if (!byDir.has(dir)) byDir.set(dir, []);
      byDir.get(dir)!.push(file);
    }

    // Sample proportionally from each directory
    const sample: string[] = [];
    const dirs = Array.from(byDir.keys());
    const perDir = Math.ceil(sampleSize / dirs.length);

    for (const dir of dirs) {
      const dirFiles = byDir.get(dir)!;
      const toTake = Math.min(perDir, dirFiles.length);
      sample.push(...dirFiles.slice(0, toTake));
      if (sample.length >= sampleSize) break;
    }

    return sample.slice(0, sampleSize);
  }

  private detectLanguages(files: string[]): Record<string, number> {
    const langs: Record<string, number> = {};
    for (const file of files) {
      const ext = path.extname(file);
      langs[ext] = (langs[ext] || 0) + 1;
    }
    return langs;
  }

  private analyzeDirectoryStructure(files: string[]): any[] {
    const dirs = new Map<string, number>();
    for (const file of files) {
      // Convert to relative path from targetPath to get meaningful directory structure
      const relativePath = path.relative(this.targetPath, file);
      const dir = relativePath.split('/')[0]; // First directory in relative path
      if (dir && dir !== '..') { // Skip if outside targetPath
        dirs.set(dir, (dirs.get(dir) || 0) + 1);
      }
    }

    return Array.from(dirs.entries())
      .map(([dir, count]) => ({ dir, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
  }

  private findSecurityCriticalPaths(files: string[]): string[] {
    const keywords = [
      'security', 'crypto', 'auth', 'login', 'password', 'token',
      'network', 'http', 'fetch', 'request', 'socket',
      'parser', 'xml', 'json', 'html', 'css',
      'sandbox', 'permission', 'privilege', 'capability',
      'ipc', 'message', 'channel', 'process',
      'memory', 'allocat', 'buffer', 'pointer',
      'jit', 'compile', 'interpret', 'vm'
    ];

    return files.filter(f => {
      const lower = f.toLowerCase();
      return keywords.some(kw => lower.includes(kw));
    });
  }

  private async findRecentChanges(limit: number): Promise<string[]> {
    try {
      process.stdout.write(chalk.hex('#FF8C00')(`      ⚡ Analyzing git history for recent changes...`));

      // Find git repo root (git returns paths relative to this, not to cwd)
      const gitRoot = execSync('git rev-parse --show-toplevel', {
        cwd: this.targetPath,
        encoding: 'utf-8'
      }).trim();

      const output = execSync(
        `git log --name-only --pretty=format: --since="6 months ago" | sort | uniq -c | sort -rn | head -${limit}`,
        { cwd: this.targetPath, encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024, timeout: 10000 }
      );

      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      const files = output.trim().split('\n')
        .map(line => line.trim().split(/\s+/)[1])
        .filter(f => f && f.length > 0)
        .map(f => path.join(gitRoot, f)); // Join with git repo root, not targetPath

      if (files.length > 0) {
        console.log(chalk.gray(`      Found ${files.length} frequently changed files from git history`));
      }

      return files;
    } catch {
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      return [];
    }
  }

  private async findOldestFiles(limit: number): Promise<string[]> {
    // This is too slow for large repos, skip it
    return [];
  }

  private async findLargeFiles(limit: number): Promise<string[]> {
    // Skip for large repos, too slow
    return [];
  }

  // Removed - too slow for large repos

  private heuristicPrioritization(allFiles: string[], fileStats: any): PrioritizedFile[] {
    const prioritized: PrioritizedFile[] = [];

    // Security-critical paths (highest priority)
    for (const file of fileStats.securityCriticalPaths.slice(0, 1000)) {
      prioritized.push({
        path: file,
        priority: 10,
        reason: 'Security-critical'
      });
    }

    // Recent changes (might have new bugs)
    for (const file of fileStats.recentChanges.slice(0, 500)) {
      if (!prioritized.some(p => p.path === file)) {
        prioritized.push({
          path: file,
          priority: 8,
          reason: 'Recent changes'
        });
      }
    }

    console.log(`Prioritized ${prioritized.length} targets\n`);

    return prioritized;
  }

  private systematicCoverage(allFiles: string[]): PrioritizedFile[] {
    // After high-value targets, ensure we cover everything
    const unanalyzed = allFiles.filter(f => !this.analyzedFiles.has(f));

    return unanalyzed.map(f => ({
      path: f,
      priority: 5,
      reason: 'Systematic coverage'
    }));
  }

  private adaptiveSelection(allFiles: string[]): PrioritizedFile[] {
    // Learn from findings and focus on similar areas
    const hotspots: PrioritizedFile[] = [];

    // Find directories with most bugs
    const dirBugCount = new Map<string, number>();
    for (const [file, bugs] of this.bugsFoundByPath.entries()) {
      const dir = path.dirname(file);
      dirBugCount.set(dir, (dirBugCount.get(dir) || 0) + bugs);
    }

    const hotDirs = Array.from(dirBugCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([dir]) => dir);

    // Prioritize files in hot directories
    for (const file of allFiles) {
      if (this.analyzedFiles.has(file)) continue;

      const dir = path.dirname(file);
      if (hotDirs.includes(dir)) {
        hotspots.push({
          path: file,
          priority: 9,
          reason: `High bug density area (${dirBugCount.get(dir)} bugs found nearby)`
        });
      }
    }

    return hotspots;
  }

  markAnalyzed(file: string, bugsFound: number): void {
    this.analyzedFiles.add(file);
    if (bugsFound > 0) {
      this.bugsFoundByPath.set(file, bugsFound);
    }
  }

  getProgress(): { analyzed: number; remaining: number; coverage: number } {
    const analyzed = this.analyzedFiles.size;
    const total = analyzed + this.getUnanalyzedCount();
    const coverage = total > 0 ? (analyzed / total) * 100 : 0;

    return {
      analyzed,
      remaining: this.getUnanalyzedCount(),
      coverage
    };
  }

  private getUnanalyzedCount(): number {
    // This would be tracked from the original file list
    return 0;
  }
}
