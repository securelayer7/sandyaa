import { Config } from '../orchestrator/orchestrator.js';
import { glob } from 'glob';
import * as path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';

// Resolve Sandyaa's own install directory to exclude from scans
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SANDYAA_ROOT = path.resolve(__dirname, '../..');

export class FileScanner {
  private config: Config;

  constructor(config: Config) {
    this.config = config;
  }

  async scan(targetPath: string): Promise<string[]> {
    // If focus areas specified, only scan those
    if (this.config.analysis.focus_areas.length > 0) {
      return await this.scanFocusAreas(targetPath);
    }

    // Otherwise scan everything except excluded patterns
    return await this.scanAll(targetPath);
  }

  private async scanFocusAreas(targetPath: string): Promise<string[]> {
    const files: string[] = [];

    console.log(chalk.gray(`    Scanning ${this.config.analysis.focus_areas.length} focus area${this.config.analysis.focus_areas.length !== 1 ? 's' : ''}...`));

    for (let i = 0; i < this.config.analysis.focus_areas.length; i++) {
      const area = this.config.analysis.focus_areas[i];
      if (this.config.analysis.focus_areas.length > 3) {
        process.stdout.write(chalk.hex('#FF8C00')(`\r      ⚡ Scanning area ${i + 1}/${this.config.analysis.focus_areas.length}: ${area}...`));
      }
      const pattern = path.join(targetPath, area, '**/*');
      const matches = await glob(pattern, {
        ignore: this.config.target.exclude_patterns,
        nodir: true
      });
      files.push(...matches);
    }

    if (this.config.analysis.focus_areas.length > 3) {
      process.stdout.write('\r' + ' '.repeat(100) + '\r');
    }

    return this.filterSourceFiles(files);
  }

  private async scanAll(targetPath: string): Promise<string[]> {
    process.stdout.write(chalk.hex('#FF8C00')(`    ⚡ Scanning codebase...`));
    const pattern = path.join(targetPath, '**/*');
    const files = await glob(pattern, {
      ignore: this.config.target.exclude_patterns,
      nodir: true
    });

    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    console.log(chalk.gray(`    Found ${files.length} files`));

    return this.filterSourceFiles(files);
  }

  private filterSourceFiles(files: string[]): string[] {
    // Only include source code files
    const sourceExtensions = [
      '.js', '.ts', '.jsx', '.tsx',
      '.py', '.rb', '.php',
      '.go', '.rs', '.c', '.cpp', '.h', '.hpp',
      '.java', '.kt', '.scala',
      '.swift', '.m',
      '.sh', '.bash',
      '.sql',
      '.vue', '.svelte'
    ];

    return files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      if (!sourceExtensions.includes(ext)) return false;

      // Exclude Sandyaa's own source files (prevents self-scanning)
      const resolved = path.resolve(file);
      if (resolved.startsWith(SANDYAA_ROOT + path.sep)) return false;

      return true;
    });
  }
}
