import { Vulnerability } from '../detector/vulnerability-detector.js';
import { CodeContext } from './context-analyzer.js';
import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import { execSync } from 'child_process';

export interface BlastRadius {
  callSiteCount: number;
  affectedDataPaths: number;
  estimatedUserImpact: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: {
    callers: string[];
    affectedSystems: string[];
    impactDescription: string;
  };
}

export class BlastRadiusCalculator {
  private executor: ModelExecutor;

  constructor(providerConfig?: ProviderConfig) {
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  async calculateBlastRadius(
    vuln: Vulnerability,
    context: CodeContext,
    targetPath: string
  ): Promise<BlastRadius> {
    // Count call sites using git grep
    const callSites = await this.findCallSites(
      vuln.location.function,
      targetPath
    );

    // Use Claude to analyze impact
    const impactAnalysis = await this.analyzeImpact(vuln, context, callSites);

    const severity = this.calculateSeverity(
      callSites.length,
      impactAnalysis.affectedDataPaths || 0,
      impactAnalysis.userImpact || 0
    );

    return {
      callSiteCount: callSites.length,
      affectedDataPaths: impactAnalysis.affectedDataPaths || 0,
      estimatedUserImpact: impactAnalysis.userImpact || 0,
      severity,
      details: {
        callers: callSites,
        affectedSystems: impactAnalysis.affectedSystems || [],
        impactDescription: impactAnalysis.description || 'Unknown impact'
      }
    };
  }

  private async findCallSites(
    functionName: string,
    targetPath: string
  ): Promise<string[]> {
    try {
      const results = execSync(
        `git grep -n "${functionName}("`,
        {
          cwd: targetPath,
          encoding: 'utf-8',
          stdio: 'pipe'
        }
      );

      return results.trim().split('\n').filter(line => line.length > 0);
    } catch {
      // No call sites found or not a git repo
      return [];
    }
  }

  private async analyzeImpact(
    vuln: Vulnerability,
    context: CodeContext,
    callSites: string[]
  ): Promise<any> {
    const result = await this.executor.execute({
      type: 'blast-radius-analysis',
      input: {
        vulnerability: vuln,
        context,
        callSites
      },
      maxTokens: 2000
    });

    if (result.success && result.output) {
      return result.output;
    }

    return {
      affectedDataPaths: callSites.length,
      userImpact: 0.5,
      affectedSystems: [],
      description: 'Impact analysis unavailable'
    };
  }

  private calculateSeverity(
    callSites: number,
    affectedDataPaths: number,
    userImpact: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    // More call sites = larger attack surface
    // More data paths = wider impact
    // Higher user impact = more severe

    const score = (callSites * 0.3) +
                  (affectedDataPaths * 0.3) +
                  (userImpact * 0.4);

    if (score > 0.8) return 'critical';
    if (score > 0.6) return 'high';
    if (score > 0.4) return 'medium';
    return 'low';
  }
}
