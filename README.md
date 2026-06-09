# Dev-Guard Core: Static Secret Scanner

A high-performance, zero-allocation static code analysis tool built in Rust. Designed to enforce Shift-Left Security by preventing hardcoded secrets and high-entropy tokens from leaking into version control.

## Architecture Overview

`dev-guard-core` acts as an uncompromising pipeline breaker. It combines deterministic pattern matching with mathematical heuristics to evaluate code at rest, maintaining a sub-millisecond footprint through highly optimized synchronous buffered streaming and zero-cost abstractions.

* **Fast-Path Evaluation:** Highly optimized Regex compilation inside isolated signature structures for instant execution and detection of industry-standard credentials (AWS, OpenAI, etc).
* **Heuristic Fallback:** Implements Shannon Entropy mathematical models ($H = -\sum p_i \log_2 p_i$) to catch dynamic, zero-day API keys that bypass static patterns.
* **Memory Efficiency:** Built on a buffered stream reader (`BufReader`) with an $O(1)$ space complexity. It parses files line-by-line without ballooning RAM usage regardless of the codebase size.
* **Git Interoperability:** Relies on the `ignore` compilation engine for native `.gitignore` compliance and supports direct Git staging tree diffing (`--diff-filter=ACM`) for incremental scans.

## Installation & Usage

### 1. Build and install via Cargo:
```bash
cargo install --path .
```

### 2. Auto-Provision the Git Hook (Recommended):
Injects the scanner binary directly into your local repository's lifecycle.
```bash
dev-guard-core --install-hook
```

### 3. Run a Full Workspace Audit:
```bash
dev-guard-core
```

### 4. Run an Incremental Scan (Git Hook Optimized):
Scans strictly the files currently staged via `git add`.
```bash
dev-guard-core --diff
```

### 5. Export Audit Artifacts:
Generates a structured `dev-guard-report.json` via Serde architecture for SIEM or corporate CI/CD ingestion.
```bash
dev-guard-core --json
```

## Tech Stack & Core Decisions

* **Language:** Rust (Chosen for predictable latency, single-binary distribution, and memory-safe síncronous I/O operations).
* **Serialization:** Serde & Serde_JSON (The enterprise-grade industry standard for zero-overhead structural object compilation).
* **Error Handling:** thiserror (Strict adherence to fail-fast principles; safe enum mapping ensuring deterministic UNIX exit codes: `exit(1)` on compromise, `exit(0)` on clear audits).

**Trade-off Note:** Shannon Entropy calculations inherently utilize more CPU cycles than compiled Regex evaluation. This performance hit is aggressively mitigated by enforcing length constraints (>16 characters) and dynamic string pre-filtering prior to triggering the mathematical evaluation layer.

## License

Distributed under the MIT License.
