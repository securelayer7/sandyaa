import * as path from 'path';
import * as fs from 'fs/promises';

/**
 * Universal path resolver - ensures all paths are absolute and exist
 * Handles the confusion between:
 * - Absolute paths from scanner: /full/path/to/file.py
 * - Relative paths from Claude: airflow/models/file.py
 * - Relative paths from git: src/file.py
 */
export class PathResolver {
  private basePath: string;

  constructor(basePath: string) {
    // Ensure base path is absolute
    this.basePath = path.resolve(basePath);
  }

  /**
   * Convert any path (absolute or relative) to absolute
   * If relative, resolves against basePath
   */
  toAbsolute(filePath: string): string {
    if (path.isAbsolute(filePath)) {
      return filePath;
    }

    return path.join(this.basePath, filePath);
  }

  /**
   * Convert absolute path to relative (for display/logging)
   */
  toRelative(filePath: string): string {
    const absolutePath = this.toAbsolute(filePath);
    return path.relative(this.basePath, absolutePath);
  }

  /**
   * Check if a file exists (handles both absolute and relative paths)
   */
  async exists(filePath: string): Promise<boolean> {
    try {
      const absolutePath = this.toAbsolute(filePath);
      await fs.access(absolutePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Read file contents (handles both absolute and relative paths)
   */
  async readFile(filePath: string): Promise<string> {
    const absolutePath = this.toAbsolute(filePath);
    return await fs.readFile(absolutePath, 'utf-8');
  }

  /**
   * Resolve an array of paths to absolute
   */
  resolveAll(filePaths: string[]): string[] {
    return filePaths.map(f => this.toAbsolute(f));
  }

  /**
   * Filter paths to only those that exist
   * Always returns absolute paths for consistency
   */
  async filterExisting(filePaths: string[]): Promise<string[]> {
    const results = await Promise.all(
      filePaths.map(async (f) => ({
        path: this.toAbsolute(f), // Convert to absolute
        exists: await this.exists(f)
      }))
    );

    return results
      .filter(r => r.exists)
      .map(r => r.path); // Returns absolute paths
  }

  getBasePath(): string {
    return this.basePath;
  }
}
