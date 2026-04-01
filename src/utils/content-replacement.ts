import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

/**
 * ContentReplacer implements a content replacement pattern for large tool results.
 *
 * When tool outputs exceed a character threshold, the full content is persisted
 * to disk and replaced in context with a compact summary that preserves
 * security-relevant lines, the leading portion, and the trailing portion.
 */
export class ContentReplacer {
  private storageDir: string;

  /** Security-related patterns to extract when summarizing large content. */
  private static readonly SECURITY_PATTERNS: RegExp = new RegExp(
    '(' +
    [
      'vulnerab',
      'exploit',
      'injection',
      'xss',
      'cross.site',
      'sql\\s*inject',
      'auth(?:entication|orization)?\\s*(?:bypass|fail|miss|lack|broken)',
      'bypass',
      'overflow',
      'buffer\\s*over',
      'heap\\s*over',
      'stack\\s*over',
      'integer\\s*over',
      'use.after.free',
      'double.free',
      'race\\s*condition',
      'toctou',
      'path\\s*traversal',
      'directory\\s*traversal',
      'command\\s*inject',
      'code\\s*inject',
      'remote\\s*code\\s*exec',
      'rce',
      'ssrf',
      'csrf',
      'xxe',
      'deserializ',
      'insecure',
      'hardcoded\\s*(?:password|secret|key|credential)',
      'privilege\\s*escalat',
      'sensitive\\s*data',
      'unvalidated',
      'unsanitized',
      'untrusted',
      'tainted',
      'cve-\\d{4}',
      'cwe-\\d+',
      'owasp',
      'severity:\\s*(?:critical|high|medium)',
      'cvss',
    ].join('|') +
    ')',
    'i',
  );

  constructor(storageDir: string = '.sandyaa/content-cache') {
    this.storageDir = storageDir;
    fs.mkdirSync(this.storageDir, { recursive: true });
  }

  /**
   * If `content` exceeds `maxChars`, persist the full text to disk and return
   * a summarized version that keeps:
   *   - The first 2000 characters
   *   - All lines matching security-relevant patterns
   *   - The last 500 characters
   *
   * Otherwise the original content is returned unchanged.
   */
  replaceIfLarge(content: string, maxChars: number, label: string): string {
    if (content.length <= maxChars) {
      return content;
    }

    // Persist full content to disk
    const id = this.generateId(content, label);
    const filePath = path.join(this.storageDir, `${id}.txt`);
    fs.writeFileSync(filePath, content, 'utf-8');

    // Build summary
    const size = content.length;
    const top = content.slice(0, 2000);
    const bottom = content.slice(-500);

    // Extract security-relevant lines from the middle portion that would
    // otherwise be truncated (skip the first 2000 and last 500 chars because
    // those are already included verbatim).
    const middleStart = 2000;
    const middleEnd = Math.max(middleStart, content.length - 500);
    const middle = content.slice(middleStart, middleEnd);
    const securityLines = this.extractSecurityLines(middle);

    let summary = top;

    if (securityLines.length > 0) {
      summary += '\n\n--- SECURITY-RELEVANT LINES (extracted from truncated middle) ---\n';
      // Cap security lines to avoid the summary itself becoming enormous
      const cappedLines = securityLines.slice(0, 200);
      summary += cappedLines.join('\n');
      if (securityLines.length > 200) {
        summary += `\n... (${securityLines.length - 200} additional security-relevant lines omitted)`;
      }
      summary += '\n--- END SECURITY-RELEVANT LINES ---\n';
    }

    summary += '\n\n... (middle content truncated) ...\n\n';
    summary += bottom;
    summary += `\n\n[Content saved to disk: ${label} (${size} chars). Key findings preserved above.]`;
    summary += `\n[Retrieve full content with id: ${id}]`;

    return summary;
  }

  /**
   * Retrieve previously saved content by its id.
   * Returns null if the content file does not exist.
   */
  retrieveContent(id: string): string | null {
    // Sanitize the id to prevent path traversal
    const safeId = path.basename(id).replace(/[^a-zA-Z0-9_-]/g, '');
    const filePath = path.join(this.storageDir, `${safeId}.txt`);
    try {
      return fs.readFileSync(filePath, 'utf-8');
    } catch {
      return null;
    }
  }

  /**
   * Remove cached content files older than `maxAgeMs` (default: 1 hour).
   */
  cleanup(maxAgeMs: number = 60 * 60 * 1000): void {
    try {
      const files = fs.readdirSync(this.storageDir);
      const now = Date.now();

      for (const file of files) {
        const filePath = path.join(this.storageDir, file);
        try {
          const stat = fs.statSync(filePath);
          if (now - stat.mtimeMs > maxAgeMs) {
            fs.unlinkSync(filePath);
          }
        } catch {
          // Ignore errors on individual files (may have been removed concurrently)
        }
      }
    } catch {
      // Storage directory may not exist yet; nothing to clean up
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Generate a deterministic but unique id from content hash + label.
   */
  private generateId(content: string, label: string): string {
    const hash = crypto.createHash('sha256').update(content).digest('hex').slice(0, 12);
    const safeLabel = label
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .slice(0, 40);
    return `${safeLabel}_${hash}`;
  }

  /**
   * Extract lines that match any of the security-relevant patterns.
   */
  private extractSecurityLines(text: string): string[] {
    const lines = text.split('\n');
    const matches: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;

      if (ContentReplacer.SECURITY_PATTERNS.test(trimmed)) {
        matches.push(trimmed);
      }
    }

    return matches;
  }
}
