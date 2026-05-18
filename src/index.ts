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

const BRAND = '#FF8C00';
const VERSION = '1.0.0';

function printBanner(target: string): void {
  const orange = chalk.hex(BRAND);
  const dim = chalk.gray;
  const INNER = 52;

  const pad = (s: string): string => {
    const max = INNER - 2;
    const visible = s.length > max ? '…' + s.slice(-(max - 1)) : s;
    return ' ' + visible + ' '.repeat(max - visible.length) + ' ';
  };

  const border = (ch: string) => orange(ch);
  const top = border('╭' + '─'.repeat(INNER) + '╮');
  const bot = border('╰' + '─'.repeat(INNER) + '╯');
  const blank = border('│') + ' '.repeat(INNER) + border('│');
  const row = (text: string, color: (s: string) => string = (s) => s) =>
    border('│') + color(pad(text)) + border('│');

  const wordmark = [
    '  ███████╗ █████╗ ███╗   ██╗██████╗ ██╗   ██╗ █████╗  █████╗ ',
    '  ██╔════╝██╔══██╗████╗  ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗',
    '  ███████╗███████║██╔██╗ ██║██║  ██║ ╚████╔╝ ███████║███████║',
    '  ╚════██║██╔══██║██║╚██╗██║██║  ██║  ╚██╔╝  ██╔══██║██╔══██║',
    '  ███████║██║  ██║██║ ╚████║██████╔╝   ██║   ██║  ██║██║  ██║',
    '  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝',
  ];

  console.log();
  for (const line of wordmark) console.log(orange(line));
  console.log();
  console.log(top);
  console.log(row('✵ Welcome to Sandyaa', orange));
  console.log(blank);
  console.log(row('  Autonomous security bug hunter', (s) => s));
  console.log(row('  no API key  ·  powered by Claude Code', dim));
  console.log(blank);
  console.log(row('  target: ' + target, dim));
  console.log(row('  v' + VERSION, dim));
  console.log(bot);
  console.log();
}

const program = new Command();

program
  .name('sandyaa')
  .description('Autonomous security bug hunter - real exploits, no hallucination')
  .version('1.0.0')
  .argument('<target>', 'Path to target codebase or git URL')
  .option('-c, --config <path>', 'Path to config file', '.sandyaa/config.yaml')
  .option('--fresh', 'Start fresh analysis, ignore existing checkpoint')
  .option(
    '-m, --model <tier>',
    'Pin every Claude task to a specific model (haiku|sonnet|opus). ' +
    'Overrides the dynamic complexity-based selector and config.provider.models.claude. ' +
    'Use `opus` to take advantage of the 1M context window.'
  )
  .action(async (target: string, options) => {
    try {
      printBanner(target);

      // Validate target is provided
      if (!target || target.trim() === '') {
        console.error(chalk.red('Error: Target path or git URL is required'));
        console.log(chalk.yellow('\nUsage: sandyaa <target>'));
        console.log(chalk.gray('Examples:'));
        console.log(chalk.gray('  sandyaa /path/to/project'));
        console.log(chalk.gray('  sandyaa https://github.com/user/repo.git'));
        process.exit(1);
      }

      // Validate --model early so a typo doesn't waste a setup pass.
      const VALID_MODELS = ['haiku', 'sonnet', 'opus'] as const;
      type ModelTier = typeof VALID_MODELS[number];
      let forcedModel: ModelTier | undefined;
      if (options.model) {
        const normalized = String(options.model).toLowerCase();
        if (!VALID_MODELS.includes(normalized as ModelTier)) {
          console.error(chalk.red(`Error: --model must be one of ${VALID_MODELS.join(', ')} (got "${options.model}")`));
          process.exit(1);
        }
        forcedModel = normalized as ModelTier;
      }

      const config = await loadConfig(options.config);
      config.target.path = target;

      // Resolve the effective forced model: CLI flag wins, then config's
      // `provider.models.claude`. Either way it gets pinned globally so
      // every task in every executor honors it.
      const effectiveForcedModel: ModelTier | undefined =
        forcedModel ?? (config.provider?.models?.claude as ModelTier | undefined);
      if (effectiveForcedModel) {
        ClaudeExecutor.setGlobalForcedModel(effectiveForcedModel);
        console.log(chalk.cyan(`→ Forcing all Claude tasks to: ${effectiveForcedModel.toUpperCase()}`));
        if (effectiveForcedModel === 'opus') {
          console.log(chalk.gray('  (1M context — chunks can be larger; cost is ~5× sonnet)'));
        }
      }

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
