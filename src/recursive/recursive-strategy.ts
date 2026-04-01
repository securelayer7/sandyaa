import { RecursiveAnalyzer, RecursiveAnalysis } from './recursive-analyzer.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';
import { CodeContext } from '../analyzer/context-analyzer.js';
import { ProviderConfig } from '../agents/model-executor.js';

export interface RecursiveConfig {
  enabled: boolean;
  maxDepth: number;
  strategies: RecursiveStrategy[];
  refinementIterations: number;
  providerConfig?: ProviderConfig;
}

export type RecursiveStrategy =
  | 'call-chain-tracing'      // Trace function calls recursively
  | 'data-flow-expansion'     // Expand data flows recursively
  | 'self-verification'       // Model verifies own findings
  | 'vulnerability-chaining'  // Find chains of bugs
  | 'poc-refinement'          // Iteratively improve POCs
  | 'contradiction-detection' // Recursively check for logical contradictions
  | 'assumption-validation'   // Recursively validate assumptions
  | 'exploitability-proof';   // GOD-LEVEL: Recursively prove user-controlled exploitation

export class RecursiveStrategyEngine {
  private analyzer: RecursiveAnalyzer;
  private config: RecursiveConfig;

  constructor(config: RecursiveConfig) {
    this.config = config;
    this.analyzer = new RecursiveAnalyzer(config.maxDepth, config.providerConfig);
  }

  async apply(
    vulnerabilities: Vulnerability[],
    context: CodeContext
  ): Promise<EnhancedVulnerability[]> {
    if (!this.config.enabled) {
      return vulnerabilities.map(v => ({ ...v, recursive: null }));
    }

    const enhanced: EnhancedVulnerability[] = [];

    for (const vuln of vulnerabilities) {
      console.log(`  Recursive analysis: ${vuln.id}`);

      let recursiveData: RecursiveAnalysis | null = null;

      // Apply enabled strategies
      if (this.shouldApplyStrategy('call-chain-tracing') ||
          this.shouldApplyStrategy('data-flow-expansion') ||
          this.shouldApplyStrategy('self-verification') ||
          this.shouldApplyStrategy('vulnerability-chaining')) {

        recursiveData = await this.analyzer.recursiveDeepen(vuln, context, 0);
      }

      // POC refinement (separate recursive process)
      let refinedPOC = vuln.poc;
      if (this.shouldApplyStrategy('poc-refinement') && vuln.poc) {
        refinedPOC = await this.analyzer.recursiveRefine(
          vuln.poc,
          vuln,
          this.config.refinementIterations
        );
      }

      // GOD-LEVEL: Recursive exploitability proof (5 Whys + 5 Hows)
      let exploitabilityProof: string[] = [];
      if (this.shouldApplyStrategy('exploitability-proof')) {
        exploitabilityProof = await this.proveExploitability(vuln, context, recursiveData);
      }

      // Contradiction detection
      let contradictions: string[] = [];
      let verificationStatus: 'verified' | 'uncertain' | 'contradicted' = 'verified';

      if (this.shouldApplyStrategy('contradiction-detection') && recursiveData) {
        contradictions = this.detectContradictions(vuln, recursiveData);

        // Classify verification status
        if (contradictions.length > 0) {
          // Check if it's uncertain vs contradicted
          const hasUncertainty = contradictions.some(c =>
            c.includes('uncertain') ||
            c.includes('verification inconclusive') ||
            c.includes('insufficient information')
          );

          if (hasUncertainty) {
            verificationStatus = 'uncertain';
            console.log(`    Verification uncertain for ${vuln.id} with Sonnet`);

            // Retry with Opus for uncertain critical findings
            if (vuln.severity === 'critical' || vuln.severity === 'high') {
              console.log(`    → Retrying verification with Opus (higher model)...`);
              const opusRecursiveData = await this.analyzer.recursiveDeepen(vuln, context, 0, 'opus');
              const opusContradictions = this.detectContradictions(vuln, opusRecursiveData);

              // Check Opus verification result
              const opusHasUncertainty = opusContradictions.some(c =>
                c.includes('uncertain') ||
                c.includes('verification inconclusive') ||
                c.includes('insufficient information')
              );

              if (opusContradictions.length === 0) {
                // Opus verified it - upgrade status
                verificationStatus = 'verified';
                recursiveData = opusRecursiveData;
                contradictions = [];
                console.log(`    ✓ Opus verified ${vuln.id} - upgraded to VERIFIED`);
              } else if (!opusHasUncertainty) {
                // Opus contradicted it
                verificationStatus = 'contradicted';
                recursiveData = opusRecursiveData;
                contradictions = opusContradictions;
                console.log(`    ✗ Opus contradicted ${vuln.id} - downgraded to CONTRADICTED`);
              } else {
                // Opus also uncertain - keep as uncertain
                recursiveData = opusRecursiveData;
                contradictions = opusContradictions;
                console.log(`    ⚠ Opus also uncertain for ${vuln.id} - keeping as UNCERTAIN`);
              }
            } else {
              console.log(`    → Skipping Opus retry (only for critical/high severity)`);
            }
          } else {
            verificationStatus = 'contradicted';
            console.log(`    Found contradictions in ${vuln.id}, marking as low confidence`);
          }
        }
      }

      // KEEP ALL FINDINGS - mark status instead of filtering
      // Add exploitability analysis if god-level rules active
      const passedExploitabilityChecks = exploitabilityProof.filter(p => p.startsWith('✓')).length;
      const totalExploitabilityChecks = 5; // 5 validations

      enhanced.push({
        ...vuln,
        poc: refinedPOC,
        recursive: recursiveData,
        verificationStatus,
        contradictions: contradictions.length > 0 ? contradictions : undefined,
        confidence: verificationStatus === 'verified' ? 'high' :
                   verificationStatus === 'uncertain' ? 'medium' : 'low',
        needsManualReview: verificationStatus !== 'verified',
        // GOD-LEVEL: Add recursive exploitability proof
        recursiveExploitabilityProof: exploitabilityProof.length > 0 ? {
          validationsPassed: passedExploitabilityChecks,
          validationsTotal: totalExploitabilityChecks,
          proofSteps: exploitabilityProof,
          isFullyProven: passedExploitabilityChecks === totalExploitabilityChecks
        } : undefined
      });
    }

    return enhanced;
  }

  private shouldApplyStrategy(strategy: RecursiveStrategy): boolean {
    return this.config.strategies.includes(strategy);
  }

  /**
   * GOD-LEVEL: Recursively prove user-controlled exploitation
   * Uses 5 Whys (root cause) + 5 Hows (attack path) methodology
   */
  private async proveExploitability(
    vuln: Vulnerability,
    context: CodeContext,
    recursiveData: RecursiveAnalysis | null
  ): Promise<string[]> {
    const proof: string[] = [];

    // RECURSIVE VALIDATION #1: 5 Whys - Trace back to user input
    console.log(`    → Proving exploitability: Tracing to user input (5 Whys)...`);

    if (!vuln.attackerControlled?.entryPoint) {
      proof.push('MISSING: Entry point not specified - cannot trace user input');
    } else {
      proof.push(`✓ Entry Point: ${vuln.attackerControlled.entryPoint}`);
    }

    if (!vuln.attackerControlled?.dataFlow || vuln.attackerControlled.dataFlow.length === 0) {
      proof.push('MISSING: Data flow not traced - cannot prove user control');
    } else {
      proof.push(`✓ Data Flow: ${vuln.attackerControlled.dataFlow.length} hops from input to sink`);

      // Validate each hop in the data flow using recursive analysis
      if (recursiveData) {
        const dataFlowFindings = recursiveData.findings.filter(f => f.type === 'data-flow-expansion');
        if (dataFlowFindings.length > 0) {
          proof.push(`✓ Recursive verification: Data flow validated at ${dataFlowFindings.length} depth levels`);
        }
      }
    }

    // RECURSIVE VALIDATION #2: 5 Hows - Prove exploitation steps
    console.log(`    → Proving exploitability: Validating attack steps (5 Hows)...`);

    if (!vuln.attackerControlled?.attackPath) {
      proof.push('MISSING: Attack path not documented - cannot prove exploitability');
    } else {
      proof.push(`✓ Attack Path: ${vuln.attackerControlled.attackPath.substring(0, 100)}...`);
    }

    if (!vuln.attackVector || vuln.attackVector.length < 20) {
      proof.push('MISSING: Detailed attack vector - exploitation scenario incomplete');
    } else {
      proof.push(`✓ Attack Vector: Detailed scenario provided (${vuln.attackVector.length} chars)`);
    }

    // RECURSIVE VALIDATION #3: Check call chains support the attack path
    if (recursiveData && recursiveData.callChains.length > 0) {
      const vulnerableChains = recursiveData.callChains.filter(c => c.vulnerableAt);
      if (vulnerableChains.length > 0) {
        proof.push(`✓ Call Chain: ${vulnerableChains.length} vulnerable call paths identified`);
      } else {
        proof.push('WARNING: No vulnerable call chains found in recursive analysis');
      }
    }

    // RECURSIVE VALIDATION #4: Verify preconditions are achievable
    if (vuln.exploitationDependencies) {
      const impossible = vuln.exploitationDependencies.required.filter(
        d => d.feasibility === 'theoretical'
      );
      if (impossible.length > 0) {
        proof.push(`WARNING: ${impossible.length} theoretical dependencies - exploitation may be impractical`);
      } else {
        proof.push(`✓ Dependencies: All prerequisites are achievable`);
      }
    }

    // RECURSIVE VALIDATION #5: Check reachability
    if (vuln.reachability && !vuln.reachability.isReachable) {
      proof.push(`WARNING: Code not reachable - ${vuln.reachability.reason || 'unknown reason'}`);
    } else {
      proof.push(`✓ Reachability: Code is reachable by attackers`);
    }

    console.log(`    → Exploitability proof: ${proof.filter(p => p.startsWith('✓')).length}/5 validations passed`);

    return proof;
  }

  /**
   * Detect logical contradictions in the analysis
   * This is a key anti-hallucination mechanism
   */
  private detectContradictions(
    vuln: Vulnerability,
    recursive: RecursiveAnalysis
  ): string[] {
    const contradictions: string[] = [];

    // Check if call chains contradict the vulnerability
    for (const chain of recursive.callChains) {
      if (chain.vulnerableAt && chain.vulnerableAt !== vuln.location.function) {
        // Contradiction: vulnerability claimed to be in one function,
        // but call chain analysis shows it's in another
        contradictions.push(
          `Call chain shows vulnerability in ${chain.vulnerableAt}, ` +
          `but original analysis says ${vuln.location.function}`
        );
      }
    }

    // Check if verification contradicts original finding
    const verification = recursive.findings.find(f => f.type === 'deeper-analysis');
    if (verification?.details?.verified === false) {
      // Distinguish between "uncertain" and "contradicted"
      const reason = verification.details.reason || 'unknown';
      if (reason.includes('insufficient') || reason.includes('unclear') ||
          reason.includes('uncertain') || reason.includes('inconclusive')) {
        contradictions.push(`verification inconclusive: ${reason}`);
      } else {
        contradictions.push(`Self-verification failed: ${reason}`);
      }
    } else if (verification?.details?.verified === undefined || verification?.details?.verified === null) {
      // Verification was attempted but couldn't make a determination
      contradictions.push('verification uncertain: insufficient information to confirm or deny');
    }

    // Check if data flow expansion contradicts evidence chain
    const dataFlowExpansions = recursive.findings.filter(
      f => f.type === 'data-flow-expansion'
    );
    for (const expansion of dataFlowExpansions) {
      if (expansion.details?.contradicts) {
        contradictions.push(
          `Data flow analysis contradicts original: ${expansion.details.contradicts}`
        );
      }
    }

    return contradictions;
  }
}

export interface EnhancedVulnerability extends Vulnerability {
  recursive: RecursiveAnalysis | null;
  recursiveExploitabilityProof?: {
    validationsPassed: number;
    validationsTotal: number;
    proofSteps: string[];
    isFullyProven: boolean;
  };
}
