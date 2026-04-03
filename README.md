# Open Quantum Secure (OQS Scanner)

A post-quantum cryptography scanner that finds cryptographic algorithm usage in your codebase and tells you what needs to change before quantum computers break it.

It produces a Quantum Readiness Score (0-100), generates CycloneDX 1.7 CBOM output, and checks compliance against CNSA 2.0.

No backend required. Runs fully offline.

---

## Getting Started

### Step 1: Install the scanner

```bash
# Download pre-built binary (recommended)
curl -sSL https://raw.githubusercontent.com/jimbo111/open-quantum-secure/main/install.sh | sh

# Or install with Go
go install github.com/jimbo111/open-quantum-secure/cmd/oqs-scanner@latest

# Or build from source
git clone https://github.com/jimbo111/open-quantum-secure.git
cd open-quantum-secure
go build -o oqs-scanner ./cmd/oqs-scanner/
```

### Step 2: Check what's available

```bash
oqs-scanner engines doctor
```

Out of the box, you get **2 built-in engines** that are compiled into the binary:

| Engine | What it scans | Always available |
|--------|--------------|-----------------|
| **config-scanner** | YAML, JSON, .env, .properties, TOML, XML, INI, HCL config files | Yes (embedded) |
| **binary-scanner** | JAR/WAR, Go binaries, Python wheels, ELF/PE/Mach-O, .NET assemblies | Yes (embedded) |

These two engines can scan config files and binary artifacts without installing anything else.

### Step 3: Install additional engines (optional)

For source code scanning (JavaScript, Python, Go, Java, etc.), you need external engines. These are **separate open-source tools** that the scanner calls — they are not bundled due to licensing.

```bash
# Install ast-grep (Rust-based, pattern matching across 12 languages)
cargo install ast-grep
# or: npm install -g @ast-grep/cli

# Install semgrep (Python-based, taint/data flow analysis)
pip install semgrep

# Install syft (Go-based, container/binary SBOM generation)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Install cdxgen (Node.js-based, CycloneDX SBOM generation)
npm install -g @cyclonedx/cdxgen
```

Run `oqs-scanner engines doctor` again to verify. You don't need all of them — install what makes sense for your stack.

### Step 4: Scan

```bash
oqs-scanner scan --path .
```

Output:

```
Scanning /your/project with 4 engine(s)...
  • ast-grep (tier pattern)
  • semgrep (tier flow)
  • binary-scanner (tier binary)
  • config-scanner (tier pattern)
Scan completed in 1.2s — 37 findings

Total: 37 findings (28 algorithms, 8 dependencies)
Quantum: 6 vulnerable, 0 weakened, 10 safe/resistant, 0 deprecated
Quantum Readiness Score: 88/100 (Grade: A)
```

> **Note:** The number of findings depends on which engines are installed. With only the 2 built-in engines, you'll see findings from config files and binary artifacts. Adding ast-grep and semgrep enables source code scanning across all supported languages.

---

## How engines work

The scanner is an **orchestrator** — it coordinates external tools and merges their results through a 12-stage pipeline (normalization, deduplication, classification, impact analysis, scoring).

```
                    ┌──────────────────────────────────┐
                    │         oqs-scanner CLI          │
                    │  (orchestrator, Go, MIT license) │
                    └──────────┬───────────────────────┘
                               │ calls via subprocess
          ┌────────────────────┼────────────────────────┐
          │                    │                        │
   ┌──────┴──────┐    ┌────────┴──────┐    ┌────────────┴────────────┐
   │  Built-in   │    │   Optional    │    │      Optional           │
   │  (embedded) │    │   (install)   │    │      (install)          │
   ├─────────────┤    ├───────────────┤    ├─────────────────────────┤
   │config-scanner│   │ ast-grep      │    │ semgrep (taint/flow)    │
   │binary-scanner│   │ syft          │    │ cdxgen (SBOM)           │
   │             │    │ cryptodeps    │    │ cbomkit-theia(artifacts)│
   └─────────────┘    └───────────────┘    └─────────────────────────┘
```

Each engine is a separate project with its own license. The scanner never bundles or redistributes them — it discovers them from PATH or `~/.oqs/cache/engines/` at runtime.

---

## Output formats

```bash
oqs-scanner scan --path . --format table     # Human-readable table (default)
oqs-scanner scan --path . --format json      # Machine-readable JSON
oqs-scanner scan --path . --format sarif     # GitHub Code Scanning / IDE integration
oqs-scanner scan --path . --format cbom      # CycloneDX 1.7 CBOM
oqs-scanner scan --path . --format html      # Self-contained HTML report
```

## CNSA 2.0 compliance

Check your codebase against NSA's CNSA 2.0 requirements:

```bash
oqs-scanner scan --path . --compliance cnsa-2.0
```

This flags algorithms that don't meet CNSA 2.0:
- SLH-DSA (excluded despite being a NIST standard)
- ML-KEM below 1024, ML-DSA below 87
- SHA-256 (requires SHA-384 minimum)
- AES below 256, any non-AES cipher
- HQC (not yet CNSA 2.0 approved)

Generate a formal compliance report:

```bash
oqs-scanner compliance-report --path . --output report.md
```

## CI/CD

### GitHub Actions

```yaml
name: PQC Scan
on: [pull_request]
permissions:
  security-events: write
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jimbo111/open-quantum-secure@main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          path: '.'
          format: 'sarif'
          upload-sarif: 'true'
          pr-comment: 'true'
          compliance: 'cnsa-2.0'
          ci-mode: 'advisory'
```

> The Docker-based GitHub Action includes ast-grep and semgrep pre-installed, so CI scans use more engines than a local install.

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/jimbo111/open-quantum-secure/main/.gitlab-ci-template.yml'

oqs-scan:
  extends: .oqs-scanner
  variables:
    OQS_FORMAT: "sarif"
    OQS_COMPLIANCE: "cnsa-2.0"
```

### CI modes

- `blocking` — exit 1 on policy violations (default)
- `advisory` — print warnings but always exit 0 (for onboarding without breaking CI)
- `silent` — no policy output, always exit 0

## Dashboard

View scan history and trends locally:

```bash
oqs-scanner dashboard
# Open http://localhost:8899
```

Shows QRS trends over time, finding breakdown, HNDL urgency, compliance status, migration effort estimates, and per-finding drill-down with file paths and line numbers. All data stored locally in `~/.oqs/history/`.

## CBOM generation

Generate a signed CycloneDX 1.7 Cryptographic Bill of Materials:

```bash
oqs-scanner scan --path . --format cbom --output cbom.json

# With Ed25519 signing (for provenance/audit)
oqs-scanner scan --path . --format cbom --sign-cbom --output signed-cbom.json
```

## Key flags

| Flag | Description |
|------|-------------|
| `--compliance cnsa-2.0` | CNSA 2.0 compliance evaluation |
| `--ci-mode advisory` | Non-blocking CI mode |
| `--sign-cbom` | Ed25519 CBOM signing for provenance |
| `--data-lifetime-years 30` | Adjust HNDL urgency for long-lived data (healthcare=30, finance=7) |
| `--webhook-url https://...` | POST results to ITSM (Jira, ServiceNow) |
| `--fail-on critical` | Exit 1 if findings at or above severity |
| `--scan-type binary` | Scan binary artifacts only |
| `--incremental` | Skip unchanged files using local cache |
| `--exclude "vendor/**"` | Skip directories by glob pattern |

## Other commands

```bash
oqs-scanner diff --path . --base main            # Scan only changed files (PR mode)
oqs-scanner trends --project my-org/my-repo       # QRS trend analysis
oqs-scanner history --project my-org/my-repo      # Scan history
oqs-scanner compliance-report --path . -o report.md  # CNSA 2.0 report
oqs-scanner engines list                          # List all engines
oqs-scanner engines doctor                        # Check engine availability
oqs-scanner version                               # Version and engine status
```

## Standards supported

- NIST CNSA 2.0 (key exchange by 2030, signatures by 2035)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- HQC (NIST 5th PQC standard, March 2025)
- KCMVP (Korean: ARIA, SEED, LEA, KCDSA, HAS-160, LSH)
- K-PQC Round 4 (SMAUG-T, HAETAE, AIMer, NTRU+)
- CycloneDX 1.7 CBOM
- SARIF 2.1.0

## Contributing

Pull requests welcome. Run `go test -race ./...` before submitting. Requires Go 1.25+.

## License

MIT
