# Sandyaa

Autonomous source code audit. Point it at a local directory or a git URL and Sandyaa runs end-to-end until the audit is done — no pausing, no interactive prompts. It builds context, detects vulnerabilities, writes exploitable proof-of-concepts for each finding, and emits a folder of reports. Driven by Claude (and optionally Gemini).

> **Platforms:**
> - **macOS** — actively tested.
> - **Linux** — should work (no known blockers), but not yet actively tested. Please file an issue if you hit a platform-specific bug.
> - **Windows (native)** — not currently supported. Sandyaa shells out using Unix-only commands (`which claude`) and spawns the Claude CLI without a shell wrapper, so it will fail on native Windows. **WSL2** (running the Linux build of Claude Code) should work the same as Linux. Native Windows support is welcome as a PR.

> Status: alpha. Expect rough edges and false positives.

## What's different

Most LLM-based security scanners shove files at a model and hope. Sandyaa doesn't. Two things set it apart:

1. **No API key — it piggybacks on your Claude Code session.** You already pay for Claude Code, Sandyaa just reuses that CLI. Nothing to configure, no billing surprises.
2. **Recursive Language Models (RLM) for large codebases.** Instead of one giant context window, the model drives a Python REPL — it writes regex filters, chunks files, spawns sub-LLM queries, and aggregates results in code. Based on [arxiv.org/html/2512.24601v1](https://arxiv.org/html/2512.24601v1).

## Features

- Runs on your existing Claude Code login — no `ANTHROPIC_API_KEY`, no setup
- RLM pipeline with Python REPL, sub-LLM queries, and programmatic aggregation
- Eight recursive passes: call-chain tracing, data-flow expansion, self-verification, vulnerability chaining, POC refinement, contradiction detection, assumption validation, exploitability proof (`src/recursive/recursive-strategy.ts`)
- Attacker-control analysis to drop findings that aren't reachable from untrusted input (`src/detector/attacker-control-analyzer.ts`)
- Evidence chain (`evidence.json`) linking every claim to file + line
- Dynamic chunk sizing based on code density and token budget
- Automatic checkpointing — resume interrupted runs
- Optional Gemini routing via the `gemini` CLI (also no API key)
- Ink terminal dashboard for phase / progress / findings
- POC generation and optional execution to validate findings
- Autonomous end-to-end: start it, walk away, come back to a `findings/` folder

Sandyaa is not a standalone static analyzer — it orchestrates prompts, chunking, and parsing on top of the Claude CLI (and optionally Gemini).

## Install

Requirements:
- macOS (tested), Linux (untested but expected to work), or Windows via WSL2. Native Windows is not currently supported — see the platform note above.
- Node.js 18 or newer
- [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) installed and logged in
- `git` (used to clone remote targets; Sandyaa will try to install it automatically on macOS/Linux if missing)
- Optional: [`gemini`](https://github.com/google-gemini/gemini-cli) CLI, if you want Gemini-backed phases

```bash
git clone https://github.com/securelayer7/sandyaa.git
cd sandyaa
npm install
npm run build
npm link      # installs the `sandyaa` command globally
```

**No API key needed.** Sandyaa shells out to the Claude Code CLI, so as long as you are logged into Claude Code it uses your existing session — nothing to configure, no `ANTHROPIC_API_KEY` to set.

### Gemini (optional)

Some analysis phases can run on Gemini instead of Claude. This is opt-in and auto-detected:

- If the `gemini` CLI is on your `PATH` and authenticated, Sandyaa will use it — **no API key needed** (it reuses the CLI's own login).
- If you prefer the REST API, export `GEMINI_API_KEY` before running Sandyaa. This is only used to auto-resolve the latest Gemini model tiers at startup; without it, static defaults are used.

If neither is available, Sandyaa simply runs everything on Claude.

## Usage

```bash
# Local directory
sandyaa /path/to/project

# Remote git URL (cloned into a temp directory)
sandyaa https://github.com/user/repo

# Custom config
sandyaa -c ./my-config.yaml /path/to/project

# Ignore an existing checkpoint and start over
sandyaa --fresh /path/to/project
```

Findings are written under `findings/` in the target directory.

## Configuration

Sandyaa reads `.sandyaa/config.yaml` from the current working directory. A minimal example:

```yaml
target:
  path: /path/to/codebase
  language: auto

analysis:
  chunk_size: 15
  depth: maximum

detection:
  min_severity: high
  exploitability_threshold: 0.7

output:
  findings_dir: ./findings
  generate_pocs: true
  validate_pocs: true
```

## Output layout

```
findings/
├── bug-001-sql-injection/
│   ├── analysis.md
│   ├── poc.py
│   ├── SETUP.md
│   └── evidence.json
├── bug-002-xss/
│   └── ...
└── SUMMARY.md
```

`evidence.json` links each claim back to specific file paths and line numbers.

## What it looks for

- Memory safety: use-after-free, buffer overflow, type confusion, double-free
- Logic bugs: auth bypass, TOCTOU, state machine errors
- Injection: SQL, command, XSS, SSRF, path traversal
- Crypto misuse: weak algorithms, ECB, hardcoded keys, bad randomness
- Concurrency: races, atomicity violations
- Integer issues: overflow, underflow, truncation, signedness
- Unsafe APIs: deserialization, XXE, prototype pollution

Which of these run on a given chunk depends on the planner's view of the code.

## Share your CVEs

If Sandyaa helped you find a bug that was assigned a CVE, we'd like to know. Open a PR adding an entry to `CVES.md` (or a GitHub issue if you prefer) with:

- CVE ID
- Affected project and version
- One-line description
- Link to the public advisory or writeup
- Which Sandyaa phase surfaced it (context building, detection, recursive pass, etc.) — optional, but useful feedback for the tool

Only include CVEs that are already publicly disclosed. Do not submit embargoed findings.

## Contributing

Maintained by [SecureLayer7](https://securelayer7.net), who have used Sandyaa to surface a number of zero-days during their research. You don't have to wait for Mythos or the next Claude model — Sandyaa already finds real bugs on the current Claude Code. Run it against code you own or are authorized to test and see what it turns up.

Bug reports, patches, and PRs are welcome. If you find something real, add it under a `case-studies/` folder — include the target repo and commit hash, the `analysis.md`, and `evidence.json`. Redact anything sensitive before submitting.

## License

MIT. See [LICENSE](./LICENSE).
