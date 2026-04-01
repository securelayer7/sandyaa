import { REPLContext } from './rlm-types.js';
import { AgentTask } from '../agent-executor.js';

/**
 * Builds RLM-specific prompts that instruct Claude to use REPL environment
 * Based on arXiv paper's prompt engineering strategies
 */
export class RLMPromptBuilder {
  /**
   * Build REPL-aware prompt for given task type
   */
  buildREPLPrompt(task: AgentTask, replContext: REPLContext): string {
    const basePrompt = this.getBaseREPLInstructions(replContext);
    const taskSpecific = this.getTaskSpecificInstructions(task.type);

    return `${basePrompt}\n\n${taskSpecific}`;
  }

  /**
   * Base REPL instructions (common to all task types)
   */
  private getBaseREPLInstructions(context: REPLContext): string {
    return `# Recursive Language Model Analysis Task

You have access to a Python REPL environment with the target codebase loaded as structured data.

## Environment Variables

- \`context\`: CodeContext object with files, functions, data flows, trust boundaries
- \`metadata\`: Summary statistics
  - total_files: ${context.totalFiles}
  - languages: ${context.languages.join(', ')}
  - (Run \`print(metadata)\` to see full details)

## Available Tool Functions

**IMPORTANT:** Tool functions execute asynchronously. When you call a tool, I will execute it and show you the result in my next response. Check the execution results to see what each tool returned.

### 1. read_file_range(path, start_line, end_line)
Read specific lines from a file. Use this instead of loading entire files.

**Usage:**
\`\`\`python
# Call the tool (will execute on my side)
read_file_range("src/auth/login.ts", 100, 150)

# I will show you the result in the next turn
# You can then analyze the code shown
\`\`\`

### 2. search_pattern(regex_pattern, files=None)
Search codebase with regex. Returns list of matching files/locations.

**Usage:**
\`\`\`python
# Search for SQL operations
search_pattern(r'(SELECT|INSERT|UPDATE|query|execute)')

# I will show you: "search_pattern() found 23 matches (showing 23)"
# Then you can read specific files or analyze the results
\`\`\`

### 3. llm_query(context_chunk, question)
Recursive sub-LM call for semantic analysis of a code chunk.
Use this for deep analysis of filtered/chunked code.

**Usage:**
\`\`\`python
# Prepare chunk (keep <500K chars as per paper)
chunk_data = {
    "files": context['files'][:5],  # First 5 files
    "focus": "SQL operations"
}

# Call sub-LM for analysis
llm_query(json.dumps(chunk_data), "Find SQL injection vulnerabilities")

# I will show you the JSON result from the sub-analysis
# You can then aggregate multiple sub-analyses
\`\`\`

### 4. FINAL(answer)
Call this when analysis is complete to return your final answer.

**Usage:**
\`\`\`python
FINAL({
  "vulnerabilities": all_vulns,
  "totalFound": len(all_vulns)
})
# This signals completion and returns your answer
\`\`\`

## RLM Strategy (from arXiv paper)

1. **Examine metadata first** - Understand scope before diving in
2. **Filter with code** - Use regex/patterns to narrow to relevant files
3. **Chunk intelligently** - Keep chunks <500K chars (paper's finding)
4. **Deploy sub-LMs** - Use llm_query() for semantic analysis of chunks
5. **Aggregate programmatically** - Combine results in Python

## Critical Rules

- **Write Python code** - Don't just describe what you would do, write actual code
- **Show your work** - Print intermediate results so I can see your reasoning
- **Use tools liberally** - Don't try to hold everything in memory
- **Call FINAL() when done** - This signals completion

## Output Format

Wrap all Python code in \`\`\`python blocks. I will execute it and show you the results.`;
  }

  /**
   * Task-specific instructions based on analysis type
   */
  private getTaskSpecificInstructions(taskType: string): string {
    switch (taskType) {
      case 'context-building':
        return this.getContextBuildingInstructions();
      case 'vulnerability-detection':
        return this.getVulnerabilityDetectionInstructions();
      default:
        return this.getDefaultInstructions();
    }
  }

  /**
   * Context building specific instructions
   */
  private getContextBuildingInstructions(): string {
    return `## Task: Build Security Context

Your goal is to identify:
1. **Entry points** - Where user input enters (HTTP handlers, CLI args, IPC)
2. **Trust boundaries** - Where untrusted data crosses into trusted code
3. **Data flows** - Paths from inputs to dangerous sinks
4. **Sensitive operations** - SQL, exec, eval, file ops, memory ops

## Recommended Approach

\`\`\`python
# Step 1: Understand scope
print(f"Analyzing {metadata['total_files']} files in {', '.join(metadata['languages'])}")

# Step 2: Filter security-critical files
auth_files = search_pattern(r'(auth|login|session|token)')
io_files = search_pattern(r'(http|request|socket|ipc)')
dangerous = search_pattern(r'(sql|exec|eval|system)')

print(f"Found: {len(auth_files)} auth, {len(io_files)} I/O, {len(dangerous)} dangerous ops")

# Step 3: Chunk and analyze (example for auth files)
chunks = [auth_files[i:i+10] for i in range(0, len(auth_files), 10)]

entry_points = []
for i, chunk in enumerate(chunks):
    chunk_json = json.dumps(chunk)
    result = llm_query(
        chunk_json,
        "Identify entry points and trust boundaries in this code"
    )
    entry_points.extend(json.loads(result))

# Step 4: Return results
FINAL({
    "files": ...,
    "entryPoints": entry_points,
    "trustBoundaries": ...,
    "dataFlows": ...
})
\`\`\`

Begin your analysis.`;
  }

  /**
   * Vulnerability detection specific instructions
   */
  private getVulnerabilityDetectionInstructions(): string {
    return `## Task: Find Exploitable Vulnerabilities

**CRITICAL**: Report ONLY proven vulnerabilities with concrete evidence.
DO NOT report speculative or theoretical issues.

## Vulnerability Categories (not limited to these)

**Classic**: SQL injection, command injection, path traversal, XSS, SSRF, XXE, deserialization
**Auth/Logic**: Authentication bypass, privilege escalation, IDOR, business logic flaws
**Memory**: Buffer overflow, use-after-free, type confusion, integer overflow (C/C++)
**Concurrency**: Race conditions, TOCTOU, deadlocks, shared state without locks
**Crypto**: Weak random, timing attacks, padding oracle, key management
**Blindspot**: State machine confusion, multi-step attack chains, indirect user control, error path bypass

## Recommended Approach

\`\`\`python
# Step 1: Examine metadata and understand the codebase
print(f"Analyzing {metadata['total_files']} files")
print(f"Languages: {metadata['languages']}")
print(f"Entry points: {metadata['entry_points']}")

# Step 2: Search for high-risk patterns systematically
patterns = {
    "injection_sinks": r'(exec|eval|system|spawn|query|execute|\\$\\{)',
    "auth_logic": r'(auth|login|session|token|password|verify|permit)',
    "file_ops": r'(readFile|writeFile|unlink|path\\.join|path\\.resolve)',
    "user_input": r'(req\\.body|req\\.params|req\\.query|argv|stdin|getenv)',
    "crypto": r'(random|crypto|hash|encrypt|sign|verify|bcrypt)',
    "deserialization": r'(JSON\\.parse|deserializ|pickle|yaml\\.load|unserializ)',
}

for name, pattern in patterns.items():
    results = search_pattern(pattern)
    print(f"{name}: {len(results) if results else 0} matches")

# Step 3: For each high-risk area, read the actual code and analyze
# Use read_file_range() to get source code around matches
# Use llm_query() for deep semantic analysis of chunks

# Step 4: Trace data flows from user input to dangerous sinks
# Ask specific questions: "Can user input reach this exec() call?"
# Trace through every transformation step

# Step 5: Verify findings - check for defenses/sanitization
# Read surrounding code to see if there are validators

# Step 6: Return verified findings only
FINAL({
    "vulnerabilities": verified_vulns,
    "totalFound": len(verified_vulns)
})
\`\`\`

## Quality Requirements
- Every vulnerability MUST have: exact file:line, complete data flow, concrete attack steps
- If you can't prove it, don't report it
- 1 real bug > 10 theoretical ones

Begin your autonomous analysis.`;
  }

  /**
   * Default instructions for other task types
   */
  private getDefaultInstructions(): string {
    return `## Task: Code Analysis

Analyze the codebase using the RLM approach:

1. Examine \`metadata\` to understand scope
2. Use \`search_pattern()\` to filter relevant code
3. Chunk results into manageable pieces
4. Use \`llm_query()\` for semantic analysis
5. Aggregate results and call \`FINAL()\`

Begin your analysis.`;
  }
}
