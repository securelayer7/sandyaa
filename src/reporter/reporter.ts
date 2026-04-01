import { Config } from '../orchestrator/orchestrator.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';

export class Reporter {
  private config: Config;
  private findingsDir: string;

  constructor(config: Config, targetPath?: string) {
    this.config = config;

    // Create scan-specific findings directory if target path provided
    if (targetPath) {
      const scanName = this.createScanName(targetPath);
      this.findingsDir = path.join(config.output.findings_dir, scanName);
    } else {
      this.findingsDir = config.output.findings_dir;
    }
  }

  private createScanName(targetPath: string): string {
    // Extract meaningful name from path
    const baseName = path.basename(targetPath);

    // Create hash for uniqueness (in case of same-named directories in different locations)
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 8);

    // Format: src-a1b2c3d4 (for /path/to/v8/src)
    return `${baseName}-${hash}`;
  }

  async report(vulnerabilities: Vulnerability[]): Promise<void> {
    // Create findings directory
    await fs.mkdir(this.findingsDir, { recursive: true });

    // Create manifest to track ALL findings
    const manifest: any[] = [];

    // Report all vulnerabilities (Claude decides priority through severity + attacker control)
    for (const vuln of vulnerabilities) {
      await this.reportVulnerability(vuln);

      // Add to manifest
      manifest.push({
        id: vuln.id,
        type: vuln.type,
        severity: vuln.severity,
        verificationStatus: vuln.verificationStatus || 'unverified',
        confidence: vuln.confidence || 'unknown',
        needsManualReview: vuln.needsManualReview || false,
        hasPOC: !!vuln.poc,
        pocValidated: vuln.poc?.validated || false,
        location: `${vuln.location.file}:${vuln.location.line}`,
        attackerControlled: vuln.attackerControlled?.isControlled || false,
        blindspot: vuln.blindspotCategory && vuln.blindspotCategory !== 'none',
        timestamp: new Date().toISOString()
      });
    }

    // Write manifest file
    const manifestPath = path.join(this.findingsDir, 'MANIFEST.json');
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(chalk.gray(`    Manifest saved: ${manifest.length} findings tracked`));
  }

  private async reportVulnerability(vuln: Vulnerability): Promise<void> {
    // Let Claude's output determine directory naming with text-based status prefixes
    let prefix = '';

    // Verification status prefix (highest priority for triage)
    if (vuln.verificationStatus === 'contradicted') {
      prefix = 'contradicted-'; // Contradicted - likely false positive
    } else if (vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      prefix = 'uncertain-'; // Needs manual review
    } else if (vuln.blindspotCategory && vuln.blindspotCategory !== 'none') {
      prefix = 'blindspot-'; // Blindspot bugs are high-value research findings
    } else if (vuln.attackerControlled?.isControlled) {
      prefix = 'verified-'; // Attacker-controlled standard bug
    }

    const bugDir = path.join(this.findingsDir, `${prefix}${vuln.id}-${vuln.type}`);
    await fs.mkdir(bugDir, { recursive: true });

    // Write analysis report
    const analysisPath = path.join(bugDir, 'analysis.md');
    const analysis = this.generateAnalysis(vuln);
    await fs.writeFile(analysisPath, analysis);

    // Write POC if available
    if (vuln.poc) {
      const pocPath = path.join(bugDir, `poc.${this.getExtension(vuln.poc.language)}`);
      await fs.writeFile(pocPath, vuln.poc.code);

      // Write POC setup instructions
      const setupPath = path.join(bugDir, 'SETUP.md');
      let setup = `# Proof of Concept Setup\n\n`;

      // Prerequisites handled
      if (vuln.poc.prerequisitesHandled) {
        setup += `## Prerequisites Analysis\n\n`;
        if (vuln.poc.prerequisitesHandled.exploitationDependencies) {
          setup += `**Exploitation Dependencies**: ${vuln.poc.prerequisitesHandled.exploitationDependencies}\n\n`;
        }
        if (vuln.poc.prerequisitesHandled.reachability) {
          setup += `**Reachability**: ${vuln.poc.prerequisitesHandled.reachability}\n\n`;
        }
        if (vuln.poc.prerequisitesHandled.attackChain) {
          setup += `**Attack Chain**: ${vuln.poc.prerequisitesHandled.attackChain}\n\n`;
        }
      }

      setup += `## Setup Instructions\n\n${vuln.poc.setupInstructions}\n\n`;

      // Test steps
      if (vuln.poc.testSteps && vuln.poc.testSteps.length > 0) {
        setup += `## Test Steps\n\n`;
        vuln.poc.testSteps.forEach((step, i) => {
          setup += `${i + 1}. ${step}\n`;
        });
        setup += `\n`;
      }

      setup += `## Expected Impact\n\n${vuln.poc.expectedImpact}\n\n`;

      // POC Validation Status
      setup += `## POC Validation Status\n\n`;
      if (vuln.poc.validated === true) {
        setup += `✅ **VALIDATED** - POC has been tested and confirmed working\n\n`;
      } else if (vuln.poc.validated === false) {
        setup += `⚠️ **UNVALIDATED** - POC failed validation testing\n\n`;
        setup += `**Possible reasons**:\n`;
        setup += `- POC code needs adjustment\n`;
        setup += `- Environment/dependency mismatch\n`;
        setup += `- Bug exists but POC demonstration is incorrect\n`;
        setup += `- Bug may be a false positive (manual review required)\n\n`;
        setup += `**Action Required**: Manual testing and verification needed\n\n`;
      } else {
        setup += `⚪ **NOT TESTED** - Validation was skipped\n\n`;
      }

      await fs.writeFile(setupPath, setup);
    }

    // Write evidence
    const evidencePath = path.join(bugDir, 'evidence.json');
    await fs.writeFile(evidencePath, JSON.stringify(vuln.evidenceChain, null, 2));

    // Show status based on Claude's assessment
    const severityColor = ['critical', 'high'].includes(vuln.severity?.toLowerCase() || '') ? chalk.red : chalk.green;
    let marker = '';
    if (vuln.verificationStatus === 'contradicted') {
      marker = '[CONTRADICTED] ';
    } else if (vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      marker = '[UNCERTAIN] ';
    } else if (vuln.blindspotCategory && vuln.blindspotCategory !== 'none') {
      marker = '[BLINDSPOT] ';
    } else if (vuln.attackerControlled?.isControlled) {
      marker = '[VERIFIED] ';
    }
    console.log(severityColor(`  ${marker}${vuln.id}: ${vuln.type} (${vuln.severity})`));
  }

  private generateAnalysis(vuln: any): string {
    // Verification status banner (highest priority for triage)
    let statusBanner = '';
    if (vuln.verificationStatus === 'contradicted' || vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      statusBanner = `> **VERIFICATION STATUS**: ${vuln.verificationStatus?.toUpperCase() || 'NEEDS REVIEW'}\n`;
      statusBanner += `> **Confidence**: ${vuln.confidence?.toUpperCase() || 'UNKNOWN'}\n`;
      if (vuln.contradictions && vuln.contradictions.length > 0) {
        statusBanner += `> **Issues Found**:\n`;
        for (const contradiction of vuln.contradictions) {
          statusBanner += `> - ${contradiction}\n`;
        }
      }
      statusBanner += `> **Action Required**: Manual review recommended before reporting\n\n`;
    }

    // Blindspot bugs get special priority banner
    let priorityBanner = '';
    if (vuln.blindspotCategory && vuln.blindspotCategory !== 'none') {
      priorityBanner = `> **COVERAGE BLINDSPOT**: This bug would be missed by humans/fuzzers/scanners!\n> **Category**: ${vuln.blindspotCategory}\n> **Why Missed**: ${vuln.blindspotExplanation || 'See analysis below'}\n\n`;
    } else if (vuln.attackerControlled?.isControlled) {
      priorityBanner = `> **RESEARCHER PRIORITY**: Attacker-controlled ${vuln.severity?.toUpperCase() || 'UNKNOWN'} severity vulnerability\n\n`;
    }

    // Attacker control analysis
    let attackerControlSection = '';
    if (vuln.attackerControlled) {
      attackerControlSection = `
## Attacker Control Analysis

**Is Attacker-Controlled**: ${vuln.attackerControlled.isControlled ? 'YES' : 'NO'}

${vuln.attackerControlled.entryPoint ? `**Entry Point**: ${vuln.attackerControlled.entryPoint}` : ''}

${vuln.attackerControlled.dataFlow && vuln.attackerControlled.dataFlow.length > 0 ? `
**Data Flow Path**:
${vuln.attackerControlled.dataFlow.map((step: string, i: number) => `${i + 1}. \`${step}\``).join('\n')}
` : ''}

${vuln.attackerControlled.attackPath ? `**Attack Path**: ${vuln.attackerControlled.attackPath}` : ''}

${vuln.exploitabilityNotes ? `
### Exploitability Analysis

${vuln.exploitabilityNotes.includes('documented')
  ? '✅ **Fully Documented** - User-controlled with complete attack path'
  : `⚠️ **Needs Review** - ${vuln.exploitabilityNotes}`}
` : ''}
`;
    } else if (vuln.exploitabilityNotes) {
      attackerControlSection = `
## Attacker Control Analysis

⚠️ **Analysis Incomplete**: ${vuln.exploitabilityNotes}

**Action Required**: Verify if this bug is remotely exploitable and document the attack path.
`;
    }

    // GOD-LEVEL: Recursive exploitability proof
    let exploitabilityProofSection = '';
    if ((vuln as any).recursiveExploitabilityProof) {
      const proof = (vuln as any).recursiveExploitabilityProof;
      const passRate = ((proof.validationsPassed / proof.validationsTotal) * 100).toFixed(0);

      exploitabilityProofSection = `
## 🎯 Recursive Exploitability Proof (God-Level Analysis)

**Validation Score**: ${proof.validationsPassed}/${proof.validationsTotal} checks passed (${passRate}%)

${proof.isFullyProven
  ? '✅ **FULLY PROVEN** - All recursive validations passed, attack path completely verified'
  : `⚠️ **INCOMPLETE** - Missing ${proof.validationsTotal - proof.validationsPassed} validations`}

### Proof Steps (5 Whys + 5 Hows Methodology):

${proof.proofSteps.map((step: string, i: number) => `${i + 1}. ${step}`).join('\n')}

${!proof.isFullyProven ? `
> **Manual Review Required**: This finding needs additional verification to prove
> remote exploitability. Review the missing validations above and document the
> complete attack path from user input to exploitation.
` : ''}
`;
    }

    let recursiveSection = '';

    // Add recursive analysis section if available
    if (vuln.recursive) {
      recursiveSection = `
## Recursive Analysis

### Call Chains (Depth: ${vuln.recursive.depth})
${vuln.recursive.callChains.length > 0 ? vuln.recursive.callChains.map((chain: any) => `
- **Path**: ${chain.path.join(' → ')}
- **Tainted**: ${chain.tainted ? 'Yes' : 'No'}
- **Depth**: ${chain.depth}
${chain.vulnerableAt ? `- **Vulnerable At**: ${chain.vulnerableAt}` : ''}
`).join('\n') : 'No call chains found'}

### Vulnerability Chains
${vuln.recursive.vulnerabilityChains.length > 0 ? vuln.recursive.vulnerabilityChains.map((vc: any) => `
- **Combined Exploitability**: ${(vc.combinedExploitability * 100).toFixed(0)}%
- **Attack Path**: ${vc.attackPath}
- **Enhanced Impact**: ${vc.impact}
- **Chained Bugs**: ${vc.bugs.map((b: any) => b.id).join(' + ')}
`).join('\n') : 'No vulnerability chains found'}

### Deep Findings
${vuln.recursive.findings.length > 0 ? vuln.recursive.findings.map((f: any, i: number) => `
#### Finding ${i + 1} (${f.type}, depth: ${f.depth})
${JSON.stringify(f.details, null, 2)}
`).join('\n') : 'No additional findings'}
`;
    }

    return `# ${vuln.type.toUpperCase()} - ${vuln.id}

${statusBanner}${priorityBanner}${attackerControlSection}${exploitabilityProofSection}
## Summary
${vuln.description}

## Severity
**${vuln.severity.toUpperCase()}** (Exploitability: ${(vuln.exploitability * 100).toFixed(0)}%)

## Location
- **File**: \`${vuln.location.file}\`
- **Line**: ${vuln.location.line}
- **Function**: \`${vuln.location.function}\`

## Attack Vector
\`\`\`
${vuln.attackVector}
\`\`\`

## Impact
${vuln.impact}

${this.generateExploitationDependencies(vuln)}
${this.generateReachabilityAnalysis(vuln)}

## Evidence Chain

${vuln.evidenceChain.map((e: any, i: number) => `
### Evidence ${i + 1}: ${e.type}
**Location**: \`${e.location}\`

**Code**:
\`\`\`
${e.code}
\`\`\`

**Reasoning**: ${e.reasoning}
`).join('\n')}
${recursiveSection}

## Proof of Concept
See \`poc.*\` and \`SETUP.md\` files in this directory.

## Remediation
${this.generateRemediation(vuln)}

---
*Generated by Sandyaa*
`;
  }

  private generateRemediation(vuln: Vulnerability): string {
    // No hardcoded templates - return placeholder
    // Remediation should be generated by Claude during POC validation phase
    // or added as a specific field in the vulnerability detection output
    if (vuln.poc && vuln.poc.setupInstructions) {
      return `
## Remediation

Based on the vulnerability analysis:

**Root Cause**: ${vuln.description}

**Recommended Fix**:
- Review the attack vector: ${vuln.attackVector}
- Implement appropriate validation and sanitization
- Apply defense-in-depth principles

**Specific to this vulnerability**:
${this.generateSpecificRemediation(vuln)}

For detailed remediation guidance, consult security best practices for ${vuln.type}.
`;
    }

    return `
## Remediation

**Root Cause**: ${vuln.description}

**Recommended Fix**:
- Address the root cause: ${vuln.attackVector}
- Implement proper validation at trust boundaries
- Apply least privilege principles
- Consider defense-in-depth strategies

Consult security best practices specific to: ${vuln.type}
`;
  }

  private generateSpecificRemediation(vuln: Vulnerability): string {
    // Generate context-aware remediation based on vulnerability details
    const parts: string[] = [];

    if (vuln.location) {
      parts.push(`- Fix the issue at ${vuln.location.file}:${vuln.location.line}`);
    }

    if (vuln.evidenceChain && vuln.evidenceChain.length > 0) {
      const evidence = vuln.evidenceChain[0];
      if (evidence.reasoning) {
        parts.push(`- ${evidence.reasoning}`);
      }
    }

    if (vuln.impact) {
      parts.push(`- Mitigate the impact: ${vuln.impact}`);
    }

    return parts.length > 0 ? parts.join('\n') : '- Review the code and apply appropriate security controls';
  }

  private generateExploitationDependencies(vuln: Vulnerability): string {
    if (!vuln.exploitationDependencies || vuln.exploitationDependencies.required.length === 0) {
      return '';
    }

    const deps = vuln.exploitationDependencies;
    let section = `## Exploitation Dependencies\n\n`;
    section += `**Complexity**: ${deps.complexity.toUpperCase()}\n`;
    section += `**Directly Exploitable**: ${deps.directlyExploitable ? 'YES' : 'NO'}\n\n`;

    if (deps.required.length > 0) {
      section += `**Required Prerequisites**:\n`;
      for (const dep of deps.required) {
        const icon = dep.required ? '🔴' : '🟡';
        section += `- [${dep.feasibility.toUpperCase()}] **${dep.type}**: ${dep.description}\n`;
      }
      section += '\n';
    }

    if (deps.notes) {
      section += `**Notes**: ${deps.notes}\n\n`;
    }

    if (!deps.directlyExploitable) {
      section += `> ⚠️  **NOT DIRECTLY EXPLOITABLE**: This bug exists but requires specific conditions to exploit.\n`;
      section += `> The bug should still be fixed, as conditions could change or be manipulated.\n\n`;
    }

    return section;
  }

  private generateReachabilityAnalysis(vuln: Vulnerability): string {
    if (!vuln.reachability) {
      return '';
    }

    const reach = vuln.reachability;
    let section = `## Code Reachability\n\n`;
    section += `**Currently Reachable**: ${reach.isReachable ? 'YES' : 'NO'}\n`;

    if (reach.reason) {
      section += `**Reason**: ${reach.reason}\n`;
    }

    if (!reach.isReachable && reach.couldBecomeReachable) {
      section += `**Could Become Reachable**: YES\n`;
      if (reach.conditions && reach.conditions.length > 0) {
        section += `**Conditions**:\n`;
        for (const condition of reach.conditions) {
          section += `- ${condition}\n`;
        }
      }
      section += `\n> ⚠️  **LATENT BUG**: Code is currently unreachable but bug exists.\n`;
      section += `> Should be fixed before code becomes reachable.\n\n`;
    } else if (!reach.isReachable && !reach.couldBecomeReachable) {
      section += `\n> ℹ️  **DEAD CODE**: This code appears to be unreachable and may be removed.\n`;
      section += `> Bug exists but cannot currently be exploited.\n\n`;
    }

    return section;
  }

  private getExtension(language: string): string {
    const exts: { [key: string]: string } = {
      'python': 'py',
      'javascript': 'js',
      'bash': 'sh',
      'ruby': 'rb',
      'html': 'html',
      'sql': 'sql',
      'http': 'http',
      'curl': 'sh',
      'text': 'txt'
    };
    return exts[language] || 'txt';
  }

  async generateSummary(totalBugs: number, totalFiles: number, duration: string): Promise<void> {
    const summaryPath = path.join(this.findingsDir, 'SUMMARY.md');

    // Read all bug directories to compile summary
    const entries = await fs.readdir(this.findingsDir, { withFileTypes: true });
    const bugDirs = entries.filter(e => e.isDirectory() && e.name.startsWith('bug-'));

    const bugsByType: { [key: string]: number } = {};
    const bugsBySeverity: { [key: string]: number } = {};

    for (const dir of bugDirs) {
      const parts = dir.name.split('-');
      const type = parts.slice(2).join('-');
      bugsByType[type] = (bugsByType[type] || 0) + 1;

      // Read analysis to get severity
      try {
        const analysisPath = path.join(this.findingsDir, dir.name, 'analysis.md');
        const content = await fs.readFile(analysisPath, 'utf-8');
        const severityMatch = content.match(/\*\*(\w+)\*\*/);
        if (severityMatch) {
          const severity = severityMatch[1].toLowerCase();
          bugsBySeverity[severity] = (bugsBySeverity[severity] || 0) + 1;
        }
      } catch (e) {
        // Skip
      }
    }

    const summary = `# Security Analysis Summary

## Overview
- **Total Files Analyzed**: ${totalFiles}
- **Total Vulnerabilities Found**: ${totalBugs}
- **Analysis Duration**: ${duration} minutes
- **Generated**: ${new Date().toISOString()}

## Vulnerabilities by Severity
${Object.entries(bugsBySeverity)
  .sort(([, a], [, b]) => b - a)
  .map(([severity, count]) => `- **${severity.toUpperCase()}**: ${count}`)
  .join('\n')}

## Vulnerabilities by Type
${Object.entries(bugsByType)
  .sort(([, a], [, b]) => b - a)
  .map(([type, count]) => `- ${type}: ${count}`)
  .join('\n')}

## Findings
${bugDirs.map(d => `- [\`${d.name}\`](./${d.name}/analysis.md)`).join('\n')}

---
*Generated by Sandyaa*
`;

    await fs.writeFile(summaryPath, summary);
    console.log(chalk.cyan('\nSummary report:'), summaryPath);
  }
}
