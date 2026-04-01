import * as fs from 'fs/promises';
import * as crypto from 'crypto';

interface CacheEntry {
  content: string;
  hash: string;
  timestamp: number;
}

export class FileCache {
  private cache: Map<string, CacheEntry> = new Map();
  private maxSize: number = 1000; // Cache up to 1000 files
  private ttl: number = 5 * 60 * 1000; // 5 minutes

  async read(filePath: string): Promise<string> {
    const cached = this.cache.get(filePath);

    if (cached && Date.now() - cached.timestamp < this.ttl) {
      return cached.content;
    }

    // Read from disk
    const content = await fs.readFile(filePath, 'utf-8');
    const hash = crypto.createHash('md5').update(content).digest('hex');

    // Store in cache
    this.cache.set(filePath, {
      content,
      hash,
      timestamp: Date.now()
    });

    // Evict old entries if cache is full
    if (this.cache.size > this.maxSize) {
      const entries = Array.from(this.cache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);

      // Remove oldest 10%
      const toRemove = Math.floor(this.maxSize * 0.1);
      for (let i = 0; i < toRemove; i++) {
        this.cache.delete(entries[i][0]);
      }
    }

    return content;
  }

  async readBatch(filePaths: string[]): Promise<Map<string, string>> {
    const results = new Map<string, string>();

    // Read in parallel batches
    const batchSize = 50;
    for (let i = 0; i < filePaths.length; i += batchSize) {
      const batch = filePaths.slice(i, i + batchSize);

      const contents = await Promise.all(
        batch.map(async (path) => {
          try {
            const content = await this.read(path);
            return { path, content };
          } catch {
            return { path, content: '' };
          }
        })
      );

      for (const { path, content } of contents) {
        results.set(path, content);
      }
    }

    return results;
  }

  clear(): void {
    this.cache.clear();
  }

  getStats(): { size: number; maxSize: number; hitRate: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      hitRate: 0 // TODO: Track hits/misses
    };
  }
}

// Singleton instance
export const fileCache = new FileCache();
