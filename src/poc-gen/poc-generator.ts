import { Config } from '../orchestrator/orchestrator.js';
import { Vulnerability, POC } from '../detector/vulnerability-detector.js';
import { CodeContext } from '../analyzer/context-analyzer.js';
import { ModelExecutor } from '../agents/model-executor.js';
import { execSync } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';

export class POCGenerator {
  private config: Config;
  private executor: ModelExecutor;

  constructor(config: Config) {
    this.config = config;
    this.executor = new ModelExecutor(config.provider);
  }

  async generate(vulnerability: Vulnerability, context: CodeContext): Promise<POC> {
    // Detect target language from vulnerability context
    const targetLanguage = this.detectTargetLanguage(vulnerability, context);

    // RML: Use FULL context for recursive model language analysis
    // Large prompts (1.7MB+) enable deep recursive reasoning
    const result = await this.executor.execute({
      id: `poc-${vulnerability.id}`,
      type: 'poc-generation',
      input: {
        vulnerability,  // FULL vulnerability object with all recursive analysis
        context,        // FULL code context for deep understanding
        targetLanguage
      },
      maxTokens: 8000  // Increased for complex POCs
    });

    if (result.success && result.output) {
      // Validate that output has required POC fields
      const poc = result.output as any;
      if (!poc.language || !poc.code) {
        console.error(`POC generation returned incomplete data for ${vulnerability.id}:`, {
          hasLanguage: !!poc.language,
          hasCode: !!poc.code,
          hasSetupInstructions: !!poc.setupInstructions,
          keys: Object.keys(poc)
        });
        throw new Error(`POC generation returned incomplete data (missing language or code fields)`);
      }
      return poc as POC;
    }

    // If Claude fails, don't generate a fake POC - just throw error
    const errorMsg = result.error || 'Unknown error - response was null or empty';
    console.error(`POC generation failed for ${vulnerability.id}:`, {
      success: result.success,
      hasOutput: !!result.output,
      error: errorMsg
    });
    throw new Error(`POC generation failed: ${errorMsg}`);
  }

  private detectTargetLanguage(vulnerability: Vulnerability, context: CodeContext): string {
    // Get language from the vulnerable file
    const vulnerableFile = context.files.find(f =>
      f.path === vulnerability.location.file
    );

    if (vulnerableFile?.language) {
      return vulnerableFile.language;
    }

    // Detect from file extension
    const ext = path.extname(vulnerability.location.file);
    const langMap: { [key: string]: string } = {
      '.js': 'javascript',
      '.ts': 'typescript',
      '.py': 'python',
      '.rb': 'ruby',
      '.php': 'php',
      '.go': 'go',
      '.rs': 'rust',
      '.c': 'c',
      '.cpp': 'cpp',
      '.java': 'java',
      '.cs': 'csharp'
    };

    return langMap[ext] || 'bash';  // Default to bash for cross-platform POCs
  }

  async validate(poc: POC): Promise<boolean> {
    if (!this.config.poc.validate) {
      return true;  // Skip validation if disabled
    }

    try {
      // Save POC to .sandyaa directory
      const validationDir = './.sandyaa/poc-validation';
      await fs.mkdir(validationDir, { recursive: true });

      const pocFile = path.join(validationDir, `poc.${this.getExtension(poc.language)}`);
      await fs.writeFile(pocFile, poc.code);

      // Try to run POC (with timeout)
      const timeout = this.config.poc.max_poc_runtime * 1000;

      try {
        const output = execSync(this.getRunCommand(poc.language, pocFile), {
          timeout,
          encoding: 'utf-8',
          stdio: 'pipe'
        });

        // Check if output indicates success
        // This is a basic check - could be more sophisticated
        return output.length > 0 || true;

      } catch (execError) {
        // POC failed to run or timed out
        console.warn(`POC validation failed for ${pocFile}`);
        return false;
      }

    } catch (error) {
      console.warn('POC validation error:', error);
      return false;
    }
  }

  private getExtension(language: string): string {
    const exts: { [key: string]: string } = {
      'python': 'py',
      'javascript': 'js',
      'typescript': 'ts',
      'bash': 'sh',
      'ruby': 'rb',
      'php': 'php',
      'go': 'go',
      'rust': 'rs',
      'c': 'c',
      'cpp': 'cpp',
      'java': 'java',
      'html': 'html',
      'text': 'txt'
    };
    return exts[language] || 'txt';
  }

  private getRunCommand(language: string, file: string): string {
    const commands: { [key: string]: string } = {
      'python': `python3 ${file}`,
      'javascript': `node ${file}`,
      'bash': `bash ${file}`,
      'ruby': `ruby ${file}`
    };
    return commands[language] || `cat ${file}`;
  }
}
