# Sandyaa - Autonomous Security Bug Hunter

Sandyaa analyzes any codebase (Firefox, Chrome, web apps, embedded systems, etc.) to find exploitable security vulnerabilities with automated POC generation.

## Core Principles

1. **Evidence-Based**: Every finding backed by actual code paths with traceable evidence chains.
2. **High Exploitability Focus**: Prioritize bugs with real attack vectors and measurable impact.
3. **Universal Analysis**: Works on any codebase, any language.
4. **Validated POCs**: Generate and verify proof-of-concepts.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  1. Deep Context Building (Ultra-Granular Analysis)     │
│     - Entry points, data flows, trust boundaries        │
│     - Line-by-line semantic understanding               │
│     - Track assumptions vs facts                        │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  2. Vulnerability Detection                             │
│     - Memory safety (UAF, buffer overflow, etc.)        │
│     - Logic bugs (auth bypass, TOCTOU, etc.)            │
│     - Injection flaws (SQL, XSS, command injection)     │
│     - Crypto misuse, race conditions, integer overflow  │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  2.5. Recursive Analysis (Language Model Recursion)     │
│     - Recursively trace call chains across functions    │
│     - Recursively expand data flows end-to-end          │
│     - Model verifies its own findings (self-check)      │
│     - Find vulnerability chains (bugs that combine)     │
│     - Detect contradictions (anti-hallucination)        │
│     - Iteratively refine POCs                           │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  3. POC Generation + Validation                         │
│     - Working exploit code                              │
│     - Setup instructions                                │
│     - Impact demonstration                              │
│     - Validation that it actually works                 │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  4. Documentation + Reporting                           │
│     - Organized folders per bug                         │
│     - Analysis write-up with recursive findings         │
│     - Severity + exploitability rating                  │
│     - Call chains, vulnerability chains                 │
│     - Remediation guidance                              │
└─────────────────────────────────────────────────────────┘
```

## Vulnerability Classes

Sandyaa detects:

- **Memory Safety**: Use-after-free, buffer overflow, type confusion, double-free
- **Logic Bugs**: Authentication bypass, authorization flaws, TOCTOU, state confusion
- **Injection**: SQL injection, command injection, XSS, SSRF, path traversal
- **Crypto**: Weak algorithms, ECB mode, hardcoded keys, poor randomness
- **Race Conditions**: Thread safety issues, atomicity violations
- **Integer Issues**: Overflow, underflow, truncation, signedness bugs
- **API Misuse**: Unsafe deserialization, XXE, prototype pollution

## Output Structure

Each bug gets its own folder with complete documentation:

```
findings/
├── bug-001-sql-injection/
│   ├── analysis.md         # Full vulnerability analysis
│   ├── poc.py              # Working proof-of-concept exploit
│   ├── SETUP.md            # Setup instructions and expected impact
│   └── evidence.json       # Evidence chain (anti-hallucination proof)
├── bug-002-xss/
│   ├── analysis.md
│   ├── poc.js
│   ├── SETUP.md
│   └── evidence.json
└── SUMMARY.md              # Overall summary of all findings
```

## Configuration

`.sandyaa/config.yaml`:
```yaml
target:
  path: /path/to/codebase
  language: auto  # or specific: c, cpp, rust, go, javascript, etc.

analysis:
  depth: maximum  # granularity level
  focus_areas:    # optional: specific modules/files
    - src/parser
    - network/protocol

detection:
  min_severity: high  # only report high/critical
  exploitability_threshold: 0.7  # 0-1 scale

loop:
  stop_after_bugs: 10  # or "unlimited"
  max_iterations: 100
  timeout_per_phase: 3600  # seconds

output:
  findings_dir: ./findings
  generate_pocs: true
  validate_pocs: true
```

## Recursive Language Models

Sandyaa uses **recursive language model techniques** for deeper analysis:

- **Recursive Call Tracing**: Trace function calls across the entire codebase
- **Data Flow Expansion**: Recursively follow data transformations end-to-end
- **Self-Verification**: Model verifies its own findings recursively
- **Vulnerability Chaining**: Find bugs that combine into bigger exploits
- **POC Refinement**: Iteratively improve POCs through recursive refinement
- **Contradiction Detection**: Recursively check for logical errors

See [RECURSIVE.md](./RECURSIVE.md) for detailed documentation.

## Anti-Hallucination Safeguards

1. **Evidence Chain**: Every claim links to specific code locations
2. **Recursive Verification**: Model checks its own work at multiple depths
3. **Contradiction Detection**: Automatically filters findings with logical errors
4. **Assumption Tracking**: Explicit separation of facts vs inferences
5. **Cross-Validation**: POC must demonstrate the vulnerability
6. **False Positive Detection**: Filter out code patterns without exploit path

## Installation

```bash
# Clone and install dependencies
git clone <this-repo>
cd sandyaa
npm install
```

## Usage

Sandyaa works seamlessly with Claude Code - the API key is automatically provided.

```bash
# Analyze a local codebase
./sandyaa.sh hunt /path/to/target

# Analyze ANY GitHub repository (auto-clones)
./sandyaa.sh hunt https://github.com/user/repository

# Works with any git URL
./sandyaa.sh hunt git@github.com:user/repo.git

# Use custom config
./sandyaa.sh hunt --config custom-config.yaml /path/to/target
```

**Running with Claude Code**: When running inside Claude Code, the API key is automatically available - no configuration needed.

**Running standalone**: If running outside Claude Code, set the `ANTHROPIC_API_KEY` environment variable.

**Git auto-detection**: If git is not installed, Sandyaa will attempt to install it automatically (macOS/Linux).

## Architecture

- `orchestrator/` - Main loop and task coordination
- `analyzer/` - Deep context building and code understanding
- `detector/` - Vulnerability identification engine
- `poc-gen/` - POC generation and validation
- `reporter/` - Documentation and output formatting
- `utils/` - Shared utilities and helpers
