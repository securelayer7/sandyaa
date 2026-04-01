import { CodeContext, FunctionContext, DataFlow } from '../analyzer/context-analyzer.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';
import { ModelExecutor, ProviderConfig } from '../agents/model-executor.js';
import chalk from 'chalk';

export interface RecursiveAnalysis {
  depth: number;
  maxDepth: number;
  findings: RecursiveFinding[];
  callChains: CallChain[];
  vulnerabilityChains: VulnerabilityChain[];
}

export interface RecursiveFinding {
  type: 'deeper-analysis' | 'call-chain' | 'data-flow-expansion' | 'vulnerability-chain';
  depth: number;
  parent?: string;
  details: any;
}

export interface CallChain {
  path: string[];  // ['main', 'handleRequest', 'processData', 'executeQuery']
  depth: number;
  tainted: boolean;
  vulnerableAt?: string;  // Which function in chain has the bug
}

export interface VulnerabilityChain {
  bugs: Vulnerability[];
  combinedExploitability: number;
  attackPath: string;
  impact: string;
}

export class RecursiveAnalyzer {
  private maxDepth: number;
  private executor: ModelExecutor;

  constructor(maxDepth: number = 10, providerConfig?: ProviderConfig) {
    this.maxDepth = maxDepth;
    this.executor = new ModelExecutor(providerConfig || {
      primary: 'claude',
      fallback: 'gemini',
      autoSwitch: true
    });
  }

  /**
   * Recursively analyze a vulnerability to find deeper issues
   */
  async recursiveDeepen(
    vulnerability: Vulnerability,
    context: CodeContext,
    currentDepth: number = 0,
    model?: 'haiku' | 'sonnet' | 'opus'
  ): Promise<RecursiveAnalysis> {
    if (currentDepth >= this.maxDepth) {
      return {
        depth: currentDepth,
        maxDepth: this.maxDepth,
        findings: [],
        callChains: [],
        vulnerabilityChains: []
      };
    }

    const findings: RecursiveFinding[] = [];
    const callChains: CallChain[] = [];

    // 1. Recursively trace call chains
    console.log(chalk.gray(`      → Tracing call chains (depth ${currentDepth}/${this.maxDepth})...`));
    const chains = await this.traceCallChainRecursive(
      vulnerability.location.function,
      context,
      [],
      currentDepth
    );
    callChains.push(...chains);
    if (chains.length > 0) {
      console.log(chalk.gray(`        Found ${chains.length} call chain${chains.length !== 1 ? 's' : ''}`));
    }

    // 2. Recursively expand data flows
    console.log(chalk.gray(`      → Expanding data flows recursively...`));
    const dataFlowFindings = await this.expandDataFlowRecursive(
      vulnerability,
      context,
      currentDepth
    );
    findings.push(...dataFlowFindings);
    if (dataFlowFindings.length > 0) {
      console.log(chalk.gray(`        Found ${dataFlowFindings.length} data flow expansion${dataFlowFindings.length !== 1 ? 's' : ''}`));
    }

    // 3. Recursively verify the finding (self-validation)
    if (model) {
      console.log(chalk.gray(`      → Self-verification with ${model.toUpperCase()} (recursive depth ${currentDepth})...`));
    } else {
      console.log(chalk.gray(`      → Self-verification (recursive depth ${currentDepth})...`));
    }
    const verification = await this.recursiveVerification(
      vulnerability,
      context,
      currentDepth,
      model
    );
    findings.push(verification);
    if (verification.details?.verified) {
      console.log(chalk.green(`        ✓ Verified`));
    } else if (verification.details?.verified === false) {
      console.log(chalk.yellow(`        ⚠ Verification uncertain`));
    }

    // 4. Look for vulnerability chains (bugs that combine)
    console.log(chalk.gray(`      → Searching for vulnerability chains...`));
    const vulnChains = await this.findVulnerabilityChains(
      vulnerability,
      context,
      currentDepth
    );
    if (vulnChains.length > 0) {
      console.log(chalk.yellow(`        Found ${vulnChains.length} vulnerability chain${vulnChains.length !== 1 ? 's' : ''}!`));
    }

    return {
      depth: currentDepth,
      maxDepth: this.maxDepth,
      findings,
      callChains,
      vulnerabilityChains: vulnChains
    };
  }

  /**
   * Recursively trace call chains to find how functions are called
   */
  private async traceCallChainRecursive(
    functionName: string,
    context: CodeContext,
    currentChain: string[],
    depth: number
  ): Promise<CallChain[]> {
    if (depth >= this.maxDepth || currentChain.includes(functionName)) {
      // Prevent infinite recursion
      return [];
    }

    const newChain = [...currentChain, functionName];
    const chains: CallChain[] = [];

    // Find all functions that call this function
    const callers = this.findCallers(functionName, context);

    if (callers.length === 0) {
      // Base case: no more callers, this is a root
      chains.push({
        path: newChain.reverse(),
        depth: depth,
        tainted: this.isChainTainted(newChain, context)
      });
    } else {
      // Recursive case: trace each caller
      for (let i = 0; i < callers.length; i++) {
        const caller = callers[i];
        if (callers.length > 3) {
          // Only show progress for larger caller lists
          process.stdout.write(chalk.hex('#FF8C00')(`\r        ⚡ Tracing caller ${i + 1}/${callers.length} (depth ${depth + 1})...`));
        }
        const subChains = await this.traceCallChainRecursive(
          caller,
          context,
          newChain,
          depth + 1
        );
        chains.push(...subChains);
      }
      if (callers.length > 3) {
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
      }
    }

    return chains;
  }

  /**
   * Recursively expand data flows to find all transformation steps
   */
  private async expandDataFlowRecursive(
    vulnerability: Vulnerability,
    context: CodeContext,
    depth: number
  ): Promise<RecursiveFinding[]> {
    if (depth >= this.maxDepth) {
      return [];
    }

    const findings: RecursiveFinding[] = [];

    // TOKEN-EFFICIENT: Reduce token allocation for deeper recursion levels
    // Depth 0: 4000 tokens, Depth 1: 3000, Depth 2: 2000, etc.
    const tokensForDepth = Math.max(2000, 4000 - (depth * 1000));

    // TOKEN-EFFICIENT: Only pass minimal context (not full vulnerability object)
    const minimalContext = {
      file: vulnerability.location.file,
      function: vulnerability.location.function,
      line: vulnerability.location.line,
      type: vulnerability.type
    };

    // Use agent to recursively analyze data flow
    const result = await this.executor.execute({
      id: `recursive-dataflow-${vulnerability.id}-depth-${depth}`,
      type: 'context-building',
      input: {
        targetPath: '.',
        files: [vulnerability.location.file],
        recursiveTask: {
          type: 'expand-data-flow',
          startingPoint: minimalContext, // Minimal context only
          depth: depth,
          question: `Recursively trace data flow in ${minimalContext.function} at ${minimalContext.file}:${minimalContext.line}.
                     Find sources and sinks. Then trace those recursively.
                     Remaining depth: ${this.maxDepth - depth}`
        }
      },
      maxTokens: tokensForDepth,
      model: depth > 2 ? 'haiku' : 'sonnet' // Use cheaper model for deeper recursion
    });

    if (result.success && result.output) {
      findings.push({
        type: 'data-flow-expansion',
        depth: depth + 1,
        parent: vulnerability.id,
        details: result.output
      });

      // EARLY STOPPING: Only recurse if new sources found and worth exploring
      if (result.output.newSources && result.output.newSources.length > 0 && depth + 1 < this.maxDepth) {
        // TOKEN-EFFICIENT: Limit recursive branching (max 3 sources per level)
        const sourcesToExplore = result.output.newSources.slice(0, 3);

        if (sourcesToExplore.length < result.output.newSources.length) {
          console.log(chalk.gray(`        Recursively analyzing top ${sourcesToExplore.length}/${result.output.newSources.length} sources (token limit)...`));
        } else {
          console.log(chalk.gray(`        Recursively analyzing ${sourcesToExplore.length} data source${sourcesToExplore.length !== 1 ? 's' : ''} at depth ${depth + 1}...`));
        }

        for (let i = 0; i < sourcesToExplore.length; i++) {
          const source = sourcesToExplore[i];
          if (sourcesToExplore.length > 2) {
            process.stdout.write(chalk.hex('#FF8C00')(`\r          ⚡ Analyzing source ${i + 1}/${sourcesToExplore.length}...`));
          }
          const subFindings = await this.expandDataFlowRecursive(
            {
              ...vulnerability,
              location: { ...vulnerability.location, function: source }
            },
            context,
            depth + 1
          );
          findings.push(...subFindings);
        }
        if (result.output.newSources.length > 2) {
          process.stdout.write('\r' + ' '.repeat(80) + '\r');
        }
      }
    }

    return findings;
  }

  /**
   * Recursively verify findings (model checks its own work)
   */
  private async recursiveVerification(
    vulnerability: Vulnerability,
    context: CodeContext,
    depth: number,
    model?: 'haiku' | 'sonnet' | 'opus'
  ): Promise<RecursiveFinding> {
    // Ask the model to verify its own finding
    const result = await this.executor.execute({
      id: `recursive-verify-${vulnerability.id}-depth-${depth}`,
      type: 'vulnerability-detection',
      input: {
        context,
        verificationTask: {
          vulnerability,
          depth,
          instruction: `Verify this vulnerability by:
                       1. Re-analyzing the code independently
                       2. Checking if the data flow is correct
                       3. Confirming the exploit path exists
                       4. Looking for mitigations you might have missed

                       If you find any errors in the original analysis, explain what was wrong.
                       If you find additional context, include it.

                       Be critical - challenge the original finding.`
        }
      },
      maxTokens: 4000,
      model: model  // Pass model parameter for escalation
    });

    return {
      type: 'deeper-analysis',
      depth: depth + 1,
      parent: vulnerability.id,
      details: result.output || { verified: false, error: result.error }
    };
  }

  /**
   * Find chains of vulnerabilities that combine for bigger impact
   */
  private async findVulnerabilityChains(
    vulnerability: Vulnerability,
    context: CodeContext,
    depth: number
  ): Promise<VulnerabilityChain[]> {
    if (depth >= this.maxDepth) {
      return [];
    }

    const chains: VulnerabilityChain[] = [];

    // Use recursive agent to find vulnerability chains
    const result = await this.executor.execute({
      id: `vuln-chain-${vulnerability.id}-depth-${depth}`,
      type: 'vulnerability-detection',
      input: {
        context,
        chainTask: {
          startingVuln: vulnerability,
          depth,
          instruction: `Look for OTHER vulnerabilities that could chain with this one.

                       Examples:
                       - XSS + CSRF = account takeover
                       - SSRF + weak auth = cloud metadata theft
                       - Path traversal + code execution = RCE
                       - Info leak + SQL injection = data breach

                       Find vulnerabilities that:
                       1. Are reachable from this vulnerability
                       2. Combine to create higher impact
                       3. Form a complete attack chain

                       Maximum chain depth: ${this.maxDepth - depth}`
        }
      },
      maxTokens: 4000
    });

    if (result.success && result.output?.chains) {
      for (const chain of result.output.chains) {
        chains.push({
          bugs: [vulnerability, ...chain.additionalBugs],
          combinedExploitability: chain.exploitability,
          attackPath: chain.path,
          impact: chain.impact
        });
      }
    }

    return chains;
  }

  /**
   * Recursive refinement of POCs
   */
  async recursiveRefine(
    poc: any,
    vulnerability: Vulnerability,
    iterations: number = 3
  ): Promise<any> {
    let refined = poc;

    console.log(chalk.gray(`      → Recursive POC refinement (${iterations} iteration${iterations !== 1 ? 's' : ''})...`));

    for (let i = 0; i < iterations; i++) {
      process.stdout.write(chalk.hex('#FF8C00')(`\r        ⚡ Refinement iteration ${i + 1}/${iterations}...`));

      const result = await this.executor.execute({
        id: `refine-poc-${vulnerability.id}-iter-${i}`,
        type: 'poc-generation',
        input: {
          vulnerability,
          currentPOC: refined,
          refinementTask: {
            iteration: i,
            instruction: `Improve this POC by:
                         1. Making it more reliable
                         2. Adding error handling
                         3. Making it easier to run
                         4. Adding more detailed output
                         5. Fixing any issues from iteration ${i}

                         Previous POC:
                         ${JSON.stringify(refined, null, 2)}

                         Return an improved version.`
          }
        },
        maxTokens: 4000
      });

      if (result.success && result.output) {
        refined = result.output;
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        console.log(chalk.gray(`        Iteration ${i + 1}: Refined successfully`));
      } else {
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        console.log(chalk.yellow(`        Iteration ${i + 1}: Could not refine further`));
        break;  // Can't refine further
      }
    }

    console.log(chalk.green(`        ✓ POC refinement complete`));
    return refined;
  }

  /**
   * Helper: Find all functions that call a given function
   */
  private findCallers(functionName: string, context: CodeContext): string[] {
    const callers: string[] = [];

    for (const file of context.files) {
      for (const func of file.functions) {
        // Check if function calls the target
        if (func.controlFlow?.some(call => call.includes(functionName))) {
          callers.push(func.name);
        }
      }
    }

    return callers;
  }

  /**
   * Helper: Check if a call chain is tainted
   */
  private isChainTainted(chain: string[], context: CodeContext): boolean {
    // Check if any function in the chain has tainted data flow
    for (const funcName of chain) {
      for (const file of context.files) {
        const func = file.functions.find(f => f.name === funcName);
        if (func?.dataFlow?.some(df => df.isTainted)) {
          return true;
        }
      }
    }
    return false;
  }
}
