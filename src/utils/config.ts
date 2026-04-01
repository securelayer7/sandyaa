import * as fs from 'fs/promises';
import YAML from 'yaml';
import { Config } from '../orchestrator/orchestrator.js';

const DEFAULT_CONFIG: Config = {
  target: {
    path: '',
    language: 'auto',
    exclude_patterns: [
      'node_modules/**',
      'vendor/**',
      'dist/**',
      'build/**',
      '*.min.js',
      '*.test.*',
      // CRITICAL: Exclude Sandyaa's own working directories
      '.sandyaa/**',
      'findings/**',
      'poc-validation/**',
      'test-cases/**',
      '.git/**'
    ]
  },
  git: {
    auto_install: true,
    clone_depth: 1,
    cleanup: true
  },
  provider: {
    primary: 'claude',
    fallback: 'gemini',
    autoSwitch: true,
    models: {
      claude: 'sonnet',
      gemini: 'pro'
    }
  },
  analysis: {
    depth: 'maximum',
    chunk_size: 50,
    incremental: true,
    focus_areas: [],
    code_filtering: {
      enabled: true,
      strategy: 'pattern-based',
      min_pattern_score: 1
    }
  },
  detection: {
    min_severity: 'medium',
    exploitability_threshold: 0.6,
    validate_findings: true
  },
  recursive: {
    enabled: true,
    max_depth: 5,
    refinement_iterations: 3,
    strategies: [
      'call-chain-tracing',
      'data-flow-expansion',
      'self-verification',
      'vulnerability-chaining',
      'poc-refinement',
      'contradiction-detection'
    ]
  },
  loop: {
    mode: 'complete',
    max_iterations: 'unlimited',
    save_checkpoint_every: 10
  },
  poc: {
    generate: true,
    validate: true,
    max_poc_runtime: 60
  },
  output: {
    findings_dir: './findings',
    checkpoint_file: '.sandyaa/checkpoint.json',
    verbose: true
  }
};

export async function loadConfig(configPath?: string): Promise<Config> {
  if (!configPath) {
    return DEFAULT_CONFIG;
  }

  try {
    const content = await fs.readFile(configPath, 'utf-8');
    const loaded = YAML.parse(content);

    // Merge with defaults
    return deepMerge(DEFAULT_CONFIG, loaded);
  } catch (error) {
    console.warn(`Failed to load config from ${configPath}, using defaults`);
    return DEFAULT_CONFIG;
  }
}

function deepMerge(target: any, source: any): any {
  const result = { ...target };

  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }

  return result;
}
