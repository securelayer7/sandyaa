/**
 * Smart context compaction inspired by Claude Code's multi-strategy approach.
 * Applies progressively aggressive compaction strategies while preserving
 * security-critical content (vulnerability descriptions, attack vectors,
 * data flow traces).
 */

/** Keywords that indicate security-relevant content — never compact these away */
const SECURITY_KEYWORDS: RegExp = /\b(vuln|exploit|inject|overflow|bypass|auth|XSS|SQL|SSRF|attack|CVE|CWE|RCE|LFI|RFI|IDOR|deserialization|privilege.escalation|path.traversal)\b/i;

/** Patterns considered low-value / repetitive and safe to snip */
const DEFAULT_SNIP_PATTERNS: string[] = [
  // Import / require boilerplate
  '^\\s*import\\s+.*from\\s+[\'"]',
  '^\\s*const\\s+\\w+\\s*=\\s*require\\(',
  '^\\s*#include\\s+[<"]',
  '^\\s*using\\s+\\w+',
  // Blank / comment-only lines
  '^\\s*\\/\\/[^!].*$',
  '^\\s*#[^!].*$',
  '^\\s*\\/\\*\\*?$',
  '^\\s*\\*\\/$',
  '^\\s*\\*\\s',
  // Test boilerplate
  '^\\s*(describe|it|test|beforeEach|afterEach|beforeAll|afterAll)\\(',
  '^\\s*(assert|expect)\\.',
  // Console / debug
  '^\\s*console\\.(log|debug|info|warn)\\(',
  // Empty lines (collapse multiples)
  '^\\s*$',
];

export interface CompactionResult {
  messages: string[];
  strategy: 'none' | 'micro' | 'snip' | 'trim' | 'aggressive';
  originalTokens: number;
  compactedTokens: number;
}

/**
 * Multi-strategy context compactor for security analysis conversations.
 *
 * Strategies are applied in order of increasing aggressiveness:
 *   1. Micro   — summarise large code blocks inline, keep security lines
 *   2. SNIP    — strip repeated / low-value patterns
 *   3. Trim    — drop oldest messages, keep system prompt + recent turns
 *   4. Aggressive — summarise everything except findings + current analysis
 */
export class ContextCompactor {
  // ──────────────────────────────────────────────
  // Token estimation
  // ──────────────────────────────────────────────

  /** Rough token estimate (~4 chars per token) */
  estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  // ──────────────────────────────────────────────
  // Top-level compact
  // ──────────────────────────────────────────────

  /**
   * Compact a conversation history (array of message strings) so the total
   * stays within `maxTokens`.  Applies strategies from least to most
   * aggressive until the budget is met.
   */
  compact(messages: string[], maxTokens: number): CompactionResult {
    const originalTokens = this.estimateTokens(messages.join('\n'));

    if (originalTokens <= maxTokens) {
      return { messages: [...messages], strategy: 'none', originalTokens, compactedTokens: originalTokens };
    }

    // --- Strategy 1: Micro-compact each message ---
    let compacted = messages.map(m => this.microCompact(m, Math.floor((maxTokens * 4) / messages.length)));
    let tokens = this.estimateTokens(compacted.join('\n'));
    if (tokens <= maxTokens) {
      return { messages: compacted, strategy: 'micro', originalTokens, compactedTokens: tokens };
    }

    // --- Strategy 2: SNIP low-value patterns ---
    compacted = compacted.map(m => this.snipCompact(m, DEFAULT_SNIP_PATTERNS));
    tokens = this.estimateTokens(compacted.join('\n'));
    if (tokens <= maxTokens) {
      return { messages: compacted, strategy: 'snip', originalTokens, compactedTokens: tokens };
    }

    // --- Strategy 3: Trim oldest messages, keep first (system) and recent ---
    compacted = this.trimMessages(compacted, maxTokens);
    tokens = this.estimateTokens(compacted.join('\n'));
    if (tokens <= maxTokens) {
      return { messages: compacted, strategy: 'trim', originalTokens, compactedTokens: tokens };
    }

    // --- Strategy 4: Aggressive — summarise everything except findings ---
    compacted = this.aggressiveCompact(compacted, maxTokens);
    tokens = this.estimateTokens(compacted.join('\n'));
    return { messages: compacted, strategy: 'aggressive', originalTokens, compactedTokens: tokens };
  }

  // ──────────────────────────────────────────────
  // Strategy 1 — Micro-compact
  // ──────────────────────────────────────────────

  /**
   * Inline summarisation of large text blocks.
   * - Replaces code fences longer than a threshold with a short summary
   *   that preserves any security-relevant lines.
   * - Leaves small blocks and security-heavy content untouched.
   */
  microCompact(text: string, maxChars: number): string {
    if (text.length <= maxChars) {
      return text;
    }

    // Shrink large fenced code blocks first
    const codeBlockRe = /```[\w]*\n([\s\S]*?)```/g;
    let result = text.replace(codeBlockRe, (_match, codeBody: string) => {
      const lines: string[] = codeBody.split('\n');
      if (lines.length <= 15) {
        return _match; // small block — keep as-is
      }

      // Preserve security-relevant lines
      const securityLines = lines.filter(l => SECURITY_KEYWORDS.test(l));
      const lang = _match.startsWith('```') ? _match.slice(3, _match.indexOf('\n')) : '';
      const summary = [
        `\`\`\`${lang}`,
        `// [COMPACTED: ${lines.length} lines → ${securityLines.length} security-relevant lines kept]`,
        ...securityLines,
        '```',
      ].join('\n');

      return summary;
    });

    // If still over budget, truncate non-security prose paragraphs
    if (result.length > maxChars) {
      const paragraphs = result.split('\n\n');
      const kept: string[] = [];
      let charBudget = maxChars;

      for (const para of paragraphs) {
        if (SECURITY_KEYWORDS.test(para)) {
          // Always keep security-relevant paragraphs
          kept.push(para);
          charBudget -= para.length;
        } else if (charBudget > 0) {
          kept.push(para);
          charBudget -= para.length;
        }
      }

      result = kept.join('\n\n');
    }

    return result;
  }

  // ──────────────────────────────────────────────
  // Strategy 2 — SNIP compact
  // ──────────────────────────────────────────────

  /**
   * Remove lines matching low-value / repetitive patterns.
   * Security-relevant lines are never removed, even if they match a pattern.
   */
  snipCompact(text: string, patterns: string[]): string {
    const regexes = patterns.map(p => new RegExp(p));
    const lines = text.split('\n');
    const kept: string[] = [];
    let snipped = 0;

    for (const line of lines) {
      // Never snip security-relevant lines
      if (SECURITY_KEYWORDS.test(line)) {
        kept.push(line);
        continue;
      }

      const shouldSnip = regexes.some(r => r.test(line));
      if (shouldSnip) {
        snipped++;
      } else {
        kept.push(line);
      }
    }

    if (snipped > 0) {
      kept.push(`\n// [SNIP: ${snipped} low-value lines removed]`);
    }

    // Collapse runs of multiple blank lines into one
    const collapsed = kept.join('\n').replace(/\n{3,}/g, '\n\n');
    return collapsed;
  }

  // ──────────────────────────────────────────────
  // Strategy 3 — Trim
  // ──────────────────────────────────────────────

  /**
   * Drop oldest messages while preserving:
   *  - The first message (system prompt / initial prompt)
   *  - The most recent messages (current analysis state)
   */
  private trimMessages(messages: string[], maxTokens: number): string[] {
    if (messages.length <= 2) {
      return messages;
    }

    const first = messages[0];
    const firstTokens = this.estimateTokens(first);
    const remainingBudget = maxTokens - firstTokens;

    // Walk backwards from end, keeping messages until budget exhausted
    const recentKept: string[] = [];
    let usedTokens = 0;

    for (let i = messages.length - 1; i >= 1; i--) {
      const msgTokens = this.estimateTokens(messages[i]);
      if (usedTokens + msgTokens <= remainingBudget) {
        recentKept.unshift(messages[i]);
        usedTokens += msgTokens;
      } else {
        break;
      }
    }

    const droppedCount = messages.length - 1 - recentKept.length;
    const note = droppedCount > 0
      ? `\n\n<system_note>${droppedCount} earlier turns trimmed to fit context window.</system_note>\n\n`
      : '';

    return [first, note, ...recentKept].filter(s => s.length > 0);
  }

  // ──────────────────────────────────────────────
  // Strategy 4 — Aggressive
  // ──────────────────────────────────────────────

  /**
   * Last-resort compaction: summarise everything except vulnerability
   * findings and the current analysis turn.
   */
  private aggressiveCompact(messages: string[], maxTokens: number): string[] {
    if (messages.length === 0) {
      return messages;
    }

    const first = messages[0];
    const last = messages[messages.length - 1];

    // Extract all security-relevant lines from middle messages
    const securityFindings: string[] = [];
    for (let i = 1; i < messages.length - 1; i++) {
      const lines = messages[i].split('\n');
      for (const line of lines) {
        if (SECURITY_KEYWORDS.test(line)) {
          securityFindings.push(line.trim());
        }
      }
    }

    // Deduplicate findings
    const uniqueFindings = [...new Set(securityFindings)];

    const findingSummary = uniqueFindings.length > 0
      ? `\n<security_findings_summary>\n${uniqueFindings.join('\n')}\n</security_findings_summary>\n`
      : '';

    const note = '<system_note>Conversation aggressively compacted. Only security findings and current turn preserved.</system_note>';

    const result = [first, note, findingSummary, last].filter(s => s.length > 0);

    // If STILL too large, micro-compact the remaining pieces
    let tokens = this.estimateTokens(result.join('\n'));
    if (tokens > maxTokens) {
      const perMessage = Math.floor((maxTokens * 4) / result.length);
      return result.map(m => this.microCompact(m, perMessage));
    }

    return result;
  }

  // ──────────────────────────────────────────────
  // Convenience: compact a single conversation string
  // ──────────────────────────────────────────────

  /**
   * Compact a monolithic conversation string (used by RLMOrchestrator).
   * Splits on turn boundaries, compacts, and re-joins.
   */
  compactConversation(conversation: string, maxTokens: number): { text: string; strategy: string } {
    // Split on XML turn markers used by the orchestrator
    const turnBoundary = /(?=<(?:assistant_response|execution_results|execution_error|system_reminder|system_note)>)/;
    const segments = conversation.split(turnBoundary).filter(s => s.trim().length > 0);

    if (segments.length <= 1) {
      // Single segment — apply micro + snip directly
      let compacted = this.microCompact(conversation, maxTokens * 4);
      compacted = this.snipCompact(compacted, DEFAULT_SNIP_PATTERNS);
      return { text: compacted, strategy: 'micro+snip' };
    }

    const result = this.compact(segments, maxTokens);
    return { text: result.messages.join('\n'), strategy: result.strategy };
  }
}
