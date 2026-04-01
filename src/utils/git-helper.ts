import { execSync, exec } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import chalk from 'chalk';

export interface GitCloneResult {
  success: boolean;
  localPath: string;
  repoName: string;
  error?: string;
}

export class GitHelper {
  private cloneDir: string;

  constructor(cloneDir: string = '.sandyaa/clones') {
    this.cloneDir = cloneDir;
  }

  /**
   * Check if git is installed
   */
  isGitInstalled(): boolean {
    try {
      execSync('git --version', { stdio: 'pipe' });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Install git (platform-specific)
   */
  async installGit(): Promise<boolean> {
    console.log(chalk.yellow('\nGit is not installed. Attempting to install...'));

    const platform = process.platform;

    try {
      if (platform === 'darwin') {
        // macOS - use Homebrew if available, otherwise Xcode tools
        console.log('Installing git via Xcode Command Line Tools...');
        execSync('xcode-select --install', { stdio: 'inherit' });
        return true;

      } else if (platform === 'linux') {
        // Linux - try common package managers
        console.log('Detecting package manager...');

        // Try apt (Debian/Ubuntu)
        try {
          execSync('which apt-get', { stdio: 'pipe' });
          console.log('Installing git via apt...');
          execSync('sudo apt-get update && sudo apt-get install -y git', { stdio: 'inherit' });
          return true;
        } catch (e) {}

        // Try yum (RedHat/CentOS)
        try {
          execSync('which yum', { stdio: 'pipe' });
          console.log('Installing git via yum...');
          execSync('sudo yum install -y git', { stdio: 'inherit' });
          return true;
        } catch (e) {}

        // Try dnf (Fedora)
        try {
          execSync('which dnf', { stdio: 'pipe' });
          console.log('Installing git via dnf...');
          execSync('sudo dnf install -y git', { stdio: 'inherit' });
          return true;
        } catch (e) {}

        console.log(chalk.red('Could not detect package manager. Please install git manually.'));
        return false;

      } else if (platform === 'win32') {
        console.log(chalk.yellow('Please install git from: https://git-scm.com/download/win'));
        return false;

      } else {
        console.log(chalk.yellow('Unsupported platform. Please install git manually.'));
        return false;
      }

    } catch (error) {
      console.error(chalk.red('Failed to install git:'), error);
      return false;
    }
  }

  /**
   * Detect if a string is a git URL
   */
  isGitURL(input: string): boolean {
    // GitHub, GitLab, Bitbucket, etc.
    const gitPatterns = [
      /^https?:\/\/github\.com\/.+\/.+/,
      /^https?:\/\/gitlab\.com\/.+\/.+/,
      /^https?:\/\/bitbucket\.org\/.+\/.+/,
      /^git@github\.com:.+\/.+\.git$/,
      /^git@gitlab\.com:.+\/.+\.git$/,
      /^https?:\/\/.+\.git$/,
      /^git:\/\/.+/
    ];

    return gitPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Extract repository name from URL
   */
  getRepoName(url: string): string {
    // https://github.com/user/repo.git -> repo
    // https://github.com/user/repo -> repo
    const match = url.match(/\/([^\/]+?)(\.git)?$/);
    return match ? match[1] : 'repository';
  }

  /**
   * Clone a git repository
   */
  async clone(url: string, depth?: number): Promise<GitCloneResult> {
    // Ensure git is installed
    if (!this.isGitInstalled()) {
      const installed = await this.installGit();
      if (!installed) {
        return {
          success: false,
          localPath: '',
          repoName: '',
          error: 'Git is not installed and auto-install failed'
        };
      }
    }

    const repoName = this.getRepoName(url);
    const timestamp = Date.now();
    const localPath = path.join(this.cloneDir, `${repoName}-${timestamp}`);

    try {
      // Create clone directory
      await fs.mkdir(this.cloneDir, { recursive: true });

      console.log(chalk.cyan(`\nCloning repository: ${url}`));
      console.log(chalk.gray(`Destination: ${localPath}`));

      // Build git clone command
      let cmd = `git clone`;

      // Shallow clone for speed (if depth specified)
      if (depth) {
        cmd += ` --depth ${depth}`;
      }

      cmd += ` "${url}" "${localPath}"`;

      // Execute clone
      execSync(cmd, { stdio: 'inherit' });

      console.log(chalk.green(`Repository cloned successfully\n`));

      return {
        success: true,
        localPath,
        repoName
      };

    } catch (error) {
      return {
        success: false,
        localPath: '',
        repoName,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Clone with progress reporting
   */
  async cloneWithProgress(url: string, depth?: number): Promise<GitCloneResult> {
    const repoName = this.getRepoName(url);
    const timestamp = Date.now();
    const localPath = path.join(this.cloneDir, `${repoName}-${timestamp}`);

    try {
      await fs.mkdir(this.cloneDir, { recursive: true });

      console.log(chalk.cyan(`\nCloning: ${repoName}`));

      return new Promise((resolve) => {
        let cmd = `git clone`;
        if (depth) {
          cmd += ` --depth ${depth}`;
        }
        cmd += ` --progress "${url}" "${localPath}"`;

        const proc = exec(cmd);

        proc.stderr?.on('data', (data) => {
          // Git outputs progress to stderr
          process.stderr.write(chalk.gray(data));
        });

        proc.on('close', (code) => {
          if (code === 0) {
            console.log(chalk.green(`\nClone complete\n`));
            resolve({
              success: true,
              localPath,
              repoName
            });
          } else {
            resolve({
              success: false,
              localPath: '',
              repoName,
              error: `Clone failed with exit code ${code}`
            });
          }
        });

        proc.on('error', (error) => {
          resolve({
            success: false,
            localPath: '',
            repoName,
            error: error.message
          });
        });
      });

    } catch (error) {
      return {
        success: false,
        localPath: '',
        repoName,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Cleanup cloned repositories
   */
  async cleanup(repoPath?: string): Promise<void> {
    try {
      if (repoPath) {
        // Clean specific repo
        await fs.rm(repoPath, { recursive: true, force: true });
        console.log(chalk.gray(`Cleaned up: ${repoPath}`));
      } else {
        // Clean all clones
        await fs.rm(this.cloneDir, { recursive: true, force: true });
        console.log(chalk.gray(`Cleaned up all clones`));
      }
    } catch (error) {
      console.warn('Cleanup warning:', error);
    }
  }

  /**
   * List cloned repositories
   */
  async listClones(): Promise<string[]> {
    try {
      const entries = await fs.readdir(this.cloneDir, { withFileTypes: true });
      return entries
        .filter(e => e.isDirectory())
        .map(e => path.join(this.cloneDir, e.name));
    } catch (error) {
      return [];
    }
  }
}
