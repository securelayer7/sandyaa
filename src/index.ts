#!/usr/bin/env node
import { Command } from 'commander';
import { Orchestrator } from './orchestrator/orchestrator.js';
import { loadConfig } from './utils/config.js';
import chalk from 'chalk';
import { fileURLToPath } from 'url';
import { dirname, resolve, sep } from 'path';
import { ClaudeExecutor } from './agents/agent-executor.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const program = new Command();

program
  .name('sandyaa')
  .description('Autonomous security bug hunter - real exploits, no hallucination')
  .version('1.0.0')
  .argument('<target>', 'Path to target codebase or git URL')
  .option('-c, --config <path>', 'Path to config file', '.sandyaa/config.yaml')
  .option('--fresh', 'Start fresh analysis, ignore existing checkpoint')
  .action(async (target: string, options) => {
    try {
      console.log(chalk.bold.cyan('\nSandyaa - Autonomous Bug Hunter\n'));

      // Validate target is provided
      if (!target || target.trim() === '') {
        console.error(chalk.red('Error: Target path or git URL is required'));
        console.log(chalk.yellow('\nUsage: sandyaa <target>'));
        console.log(chalk.gray('Examples:'));
        console.log(chalk.gray('  sandyaa /path/to/project'));
        console.log(chalk.gray('  sandyaa https://github.com/user/repo.git'));
        process.exit(1);
      }

      const config = await loadConfig(options.config);
      config.target.path = target;

      // Prevent scanning Sandyaa's own directory
      const sandyaaDir = resolve(__dirname, '..');
      const targetResolved = resolve(target);

      if (targetResolved === sandyaaDir || targetResolved.startsWith(sandyaaDir + sep)) {
        console.error(chalk.red('Error: Cannot analyze Sandyaa\'s own directory'));
        console.log(chalk.yellow('Please specify a different target project to analyze.'));
        process.exit(1);
      }

      // Set target path globally BEFORE any executors are created
      // This ensures ALL Claude CLI calls run in the target directory
      ClaudeExecutor.setGlobalTargetPath(targetResolved);

      const orchestrator = new Orchestrator(config);
      await orchestrator.run(options.fresh);

    } catch (error) {
      console.error(chalk.red('Error:'), error);
      process.exit(1);
    }
  });

program.parse();
