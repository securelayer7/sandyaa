import { GitHistoryAnalyzer, SecurityFix } from './git-history-analyzer.js';
import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';

export interface Regression {
  vulnerability: Vulnerability;
  originalFix: SecurityFix;
  similarity: number;
  type: 'exact' | 'similar' | 'mutation';
  explanation: string;
}

export class RegressionDetector {
  private gitAnalyzer: GitHistoryAnalyzer;
  private executor: ModelExecutor;

  constructor(providerConfig?: ProviderConfig) {
    this.gitAnalyzer = new GitHistoryAnalyzer('.sandyaa/git-history', providerConfig);
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  async detectRegressions(
    targetPath: string,
    vulnerabilities: Vulnerability[]
  ): Promise<Regression[]> {
    // Get git history
    const historyContext = await this.gitAnalyzer.analyzeHistory(targetPath);

    if (historyContext.securityFixes.length === 0) {
      console.log('No security fixes found in git history');
      return [];
    }

    const regressions: Regression[] = [];

    // Check each current vulnerability against historical fixes
    for (const vuln of vulnerabilities) {
      for (const fix of historyContext.securityFixes) {
        const regression = await this.checkForRegression(vuln, fix);

        if (regression) {
          regressions.push(regression);
        }
      }
    }

    return regressions;
  }

  private async checkForRegression(
    vuln: Vulnerability,
    fix: SecurityFix
  ): Promise<Regression | null> {
    // Check if vulnerability is in a file that was previously fixed
    const isInSameFile = fix.changedFiles.includes(vuln.location.file);

    if (!isInSameFile) {
      return null;
    }

    // Use Claude to determine if this is a regression
    const result = await this.executor.execute({
      type: 'regression-detection',
      input: {
        vulnerability: vuln,
        securityFix: fix
      },
      maxTokens: 2000
    });

    if (!result.success || !result.output) {
      return null;
    }

    const analysis = result.output;

    if (analysis.isRegression) {
      return {
        vulnerability: vuln,
        originalFix: fix,
        similarity: analysis.similarity || 0.9,
        type: analysis.type || 'similar',
        explanation: analysis.explanation || 'Similar vulnerability pattern detected'
      };
    }

    return null;
  }

  async findMutations(
    targetPath: string,
    pattern: any
  ): Promise<string[]> {
    // Find code locations that are mutations of a known vulnerability pattern
    return this.gitAnalyzer.findSimilarBugs(targetPath, pattern);
  }
}
