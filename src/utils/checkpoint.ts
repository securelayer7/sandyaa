import * as fs from 'fs/promises';
import * as path from 'path';

export interface CheckpointData {
  targetPath: string;  // Full path to the codebase being analyzed
  processedFiles: string[];  // Files that completed standalone analysis
  totalBugsFound: number;
  timestamp: number;
  // Track files analyzed as part of attack paths
  // These files can be re-read by recursive strategies (call-chain-tracing, etc.)
  // even if they're in processedFiles
  attackPathFiles?: {
    [filePath: string]: {
      analysisCount: number;  // How many times analyzed in attack paths
      lastAnalyzed: number;   // Timestamp
      vulnerabilityIds: string[];  // Which vulns referenced this file
    }
  };
}

export class Checkpoint {
  private checkpointFile: string;

  constructor(checkpointFile: string) {
    this.checkpointFile = checkpointFile;
  }

  async save(data: CheckpointData): Promise<void> {
    try {
      const dir = path.dirname(this.checkpointFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.checkpointFile, JSON.stringify(data, null, 2));
    } catch (error) {
      console.warn('Failed to save checkpoint:', error);
    }
  }

  async load(): Promise<CheckpointData | null> {
    try {
      const content = await fs.readFile(this.checkpointFile, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  /**
   * Load checkpoint and verify it matches the target path
   * Returns null if checkpoint is for a different project
   */
  async loadForTarget(targetPath: string): Promise<CheckpointData | null> {
    const data = await this.load();
    if (!data) return null;

    // Normalize paths for comparison (resolve to absolute paths)
    const normalizedTarget = path.resolve(targetPath);
    const normalizedCheckpoint = path.resolve(data.targetPath);

    if (normalizedTarget !== normalizedCheckpoint) {
      console.log(`Checkpoint is for different project (${data.targetPath}), starting fresh`);
      return null;
    }

    return data;
  }

  async clear(): Promise<void> {
    try {
      await fs.unlink(this.checkpointFile);
    } catch (error) {
      // Ignore
    }
  }

  /**
   * Check if file should be re-analyzed
   * Returns true if:
   * 1. File was never analyzed, OR
   * 2. File is part of an attack path (needs re-analysis in context)
   */
  shouldAnalyzeFile(filePath: string, data: CheckpointData | null, isAttackPath: boolean = false): boolean {
    if (!data) return true;  // No checkpoint, analyze everything

    const isProcessed = data.processedFiles.includes(filePath);

    // If never processed, always analyze
    if (!isProcessed) return true;

    // If part of attack path, re-analyze even if processed before
    if (isAttackPath) {
      console.log(`    [ATTACK PATH] Re-analyzing ${path.basename(filePath)} as part of vulnerability chain`);
      return true;
    }

    // Already processed and not in attack path, skip
    return false;
  }

  /**
   * Mark file as part of attack path (allows re-analysis)
   */
  async markAttackPathFile(filePath: string, vulnerabilityId: string): Promise<void> {
    const data = await this.load();
    if (!data) return;

    if (!data.attackPathFiles) {
      data.attackPathFiles = {};
    }

    if (!data.attackPathFiles[filePath]) {
      data.attackPathFiles[filePath] = {
        analysisCount: 0,
        lastAnalyzed: Date.now(),
        vulnerabilityIds: []
      };
    }

    data.attackPathFiles[filePath].analysisCount++;
    data.attackPathFiles[filePath].lastAnalyzed = Date.now();
    if (!data.attackPathFiles[filePath].vulnerabilityIds.includes(vulnerabilityId)) {
      data.attackPathFiles[filePath].vulnerabilityIds.push(vulnerabilityId);
    }

    await this.save(data);
  }
}
