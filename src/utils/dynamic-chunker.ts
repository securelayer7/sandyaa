import * as fs from 'fs/promises';
import * as path from 'path';
import { getDefaultContextWindow } from './model-registry.js';

export interface ChunkMetrics {
  avgFileSize: number;
  avgTokensPerFile: number;
  contextWindowUsage: number;
  analysisTimeMs: number;
}

export class DynamicChunker {
  private metrics: ChunkMetrics = {
    avgFileSize: 0,
    avgTokensPerFile: 0,
    contextWindowUsage: 0,
    analysisTimeMs: 0
  };

  private readonly CONTEXT_WINDOW = getDefaultContextWindow();
  private readonly MIN_CHUNK_SIZE = 5;
  private readonly MAX_CHUNK_SIZE = 50;
  private startingSize: number;

  constructor(baselineSize: number = 10) {
    this.startingSize = baselineSize;
  }

  /**
   * Calculate optimal chunk size based on learned metrics
   */
  getChunkSize(): number {
    // Start with baseline from config
    if (this.metrics.avgTokensPerFile === 0) {
      return this.startingSize;
    }

    // Factor 1: Token budget per chunk (target ~30k tokens per chunk max)
    const targetTokensPerChunk = 30_000;
    let sizeByTokens = Math.floor(targetTokensPerChunk / this.metrics.avgTokensPerFile);

    // Factor 2: Context window pressure (if using >50% context, be conservative)
    const contextPressure = this.metrics.contextWindowUsage / this.CONTEXT_WINDOW;
    if (contextPressure > 0.5) {
      sizeByTokens = Math.floor(sizeByTokens * 0.7); // Reduce by 30%
    }
    if (contextPressure > 0.7) {
      sizeByTokens = Math.floor(sizeByTokens * 0.5); // Reduce by 50%
    }

    // Factor 3: Analysis speed (if chunks take >5 minutes, reduce size)
    const fiveMinutes = 5 * 60 * 1000;
    if (this.metrics.analysisTimeMs > fiveMinutes) {
      sizeByTokens = Math.floor(sizeByTokens * 0.8); // Reduce by 20%
    }

    // Factor 4: File size (if files are huge, use smaller chunks)
    const avgFileSizeMB = this.metrics.avgFileSize / (1024 * 1024);
    if (avgFileSizeMB > 0.5) {
      sizeByTokens = Math.floor(sizeByTokens * 0.8); // Big files need smaller chunks
    }

    // Clamp to reasonable bounds
    const chunkSize = Math.max(
      this.MIN_CHUNK_SIZE,
      Math.min(this.MAX_CHUNK_SIZE, sizeByTokens)
    );

    return chunkSize;
  }

  /**
   * Update metrics after processing a chunk
   */
  async updateMetrics(
    files: string[],
    tokensUsed: number,
    totalContextUsed: number,
    timeMs: number
  ): Promise<void> {
    // Calculate average file size for this chunk
    let totalSize = 0;
    for (const file of files) {
      try {
        const stats = await fs.stat(file);
        totalSize += stats.size;
      } catch {
        // Skip if file doesn't exist
      }
    }

    const avgFileSizeThisChunk = files.length > 0 ? totalSize / files.length : 0;
    const tokensPerFileThisChunk = files.length > 0 ? tokensUsed / files.length : 0;

    // Exponential moving average (weight recent chunks more heavily)
    const alpha = 0.3; // Weight for new data
    this.metrics.avgFileSize =
      this.metrics.avgFileSize === 0
        ? avgFileSizeThisChunk
        : alpha * avgFileSizeThisChunk + (1 - alpha) * this.metrics.avgFileSize;

    this.metrics.avgTokensPerFile =
      this.metrics.avgTokensPerFile === 0
        ? tokensPerFileThisChunk
        : alpha * tokensPerFileThisChunk + (1 - alpha) * this.metrics.avgTokensPerFile;

    this.metrics.contextWindowUsage = totalContextUsed;
    this.metrics.analysisTimeMs =
      this.metrics.analysisTimeMs === 0
        ? timeMs
        : alpha * timeMs + (1 - alpha) * this.metrics.analysisTimeMs;
  }

  /**
   * Get explanation for current chunk size
   */
  getExplanation(): string {
    const size = this.getChunkSize();
    const reasons: string[] = [];

    if (this.metrics.avgTokensPerFile === 0) {
      return `Starting with ${size} files/chunk (baseline from config, will adapt)`;
    }

    const contextPressure = this.metrics.contextWindowUsage / this.CONTEXT_WINDOW;
    if (contextPressure > 0.7) {
      reasons.push('high context usage');
    } else if (contextPressure > 0.5) {
      reasons.push('moderate context usage');
    }

    const fiveMinutes = 5 * 60 * 1000;
    if (this.metrics.analysisTimeMs > fiveMinutes) {
      reasons.push('slow analysis speed');
    }

    const avgFileSizeKB = this.metrics.avgFileSize / 1024;
    if (avgFileSizeKB > 500) {
      reasons.push('large files');
    }

    const tokensPerFile = Math.floor(this.metrics.avgTokensPerFile);
    reasons.push(`~${tokensPerFile} tokens/file`);

    return reasons.length > 1
      ? `${size} files/chunk (adjusted for ${reasons.join(', ')})`
      : `${size} files/chunk (${reasons[0]})`;
  }

  /**
   * Get current metrics
   */
  getMetrics(): ChunkMetrics {
    return { ...this.metrics };
  }
}
