# Open Quantum Secure (OQS Scanner)

A post-quantum cryptography scanner that finds cryptographic algorithm usage in your codebase and tells you what needs to change before quantum computers break it.

It scans source code, config files, and binary artifacts across 14+ languages, produces a Quantum Readiness Score (0-100), and generates CycloneDX 1.7 CBOM output for compliance reporting.

No backend required. Runs fully offline.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/jimbo111/open-quantum-secure/main/install.sh | sh
```

Or with Go:

```bash
go install github.com/jimbo111/open-quantum-secure/cmd/oqs-scanner@latest
```

## Usage

Scan a project:

```bash
oqs-scanner scan --path .
```

Output:

```
Total: 37 findings (28 algorithms, 8 dependencies)
Quantum: 6 vulnerable, 0 weakened, 10 safe/resistant, 0 deprecated
Quantum Readiness Score: 88/100 (Grade: A)
```

## What it detects

The scanner orchestrates 10 detection engines across 4 tiers:

| Tier | Engines | What they find |
|------|---------|---------------|
| 1 - Pattern | cipherscope, cryptoscan, ast-grep, config-scanner | Algorithm names, API calls, config values |
| 2 - Flow | semgrep | Taint analysis, data flow from key generation to usage |
| 3 - SCA | cryptodeps, cdxgen, syft, cbomkit-theia | Crypto in dependencies, SBOMs, container images |
| 4 - Binary | binary-scanner | JAR/WAR, Go binaries, Python wheels, ELF/PE/Mach-O, .NET |

The config-scanner and binary-scanner are embedded (pure Go) and always available. Other engines are optional and detected from PATH.

## Output formats

```bash
oqs-scanner scan --path . --format json      # Machine-readable JSON
oqs-scanner scan --path . --format table     # Human-readable table (default)
oqs-scanner scan --path . --format sarif     # GitHub Code Scanning / IDE integration
oqs-scanner scan --path . --format cbom      # CycloneDX 1.7 CBOM
oqs-scanner scan --path . --format html      # Self-contained HTML report
```

## CNSA 2.0 compliance

Check your codebase against NSA's CNSA 2.0 requirements:

```bash
oqs-scanner scan --path . --compliance cnsa-2.0
```

This flags:
- SLH-DSA (excluded from CNSA 2.0 despite being a NIST standard)
- ML-KEM below 1024 and ML-DSA below 87
- SHA-256 (CNSA 2.0 requires SHA-384 minimum)
- AES below 256 bits
- Any non-AES symmetric cipher (ARIA, ChaCha20, etc.)

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
        with:
          path: '.'
          format: 'sarif'
          upload-sarif: 'true'
          pr-comment: 'true'
          compliance: 'cnsa-2.0'
          ci-mode: 'advisory'
```

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
- `advisory` — print warnings but exit 0 (for onboarding without breaking CI)
- `silent` — no policy output, exit 0

## Dashboard

View scan history and trends locally:

```bash
oqs-scanner dashboard
# Open http://localhost:8899
```

Shows QRS trends over time, finding breakdown by quantum risk, HNDL urgency panel, CNSA 2.0 compliance status, migration effort estimates, and per-finding drill-down with file paths and line numbers.

## CBOM generation

Generate a signed CycloneDX 1.7 Cryptographic Bill of Materials:

```bash
oqs-scanner scan --path . --format cbom --sign-cbom --output cbom.json
```

The CBOM includes per-component quantum risk, severity, migration effort, HNDL classification, data flow paths, and impact analysis. Components are deduped with merged occurrences.

## Other commands

```bash
oqs-scanner diff --path . --base main            # Scan only changed files (PR mode)
oqs-scanner trends --project my-org/my-repo       # QRS trend analysis
oqs-scanner history --project my-org/my-repo      # Scan history
oqs-scanner engines list                          # Available engines
oqs-scanner engines install --all                 # Download engine binaries
oqs-scanner version                               # Version and engine status
```

## Key flags

| Flag | Description |
|------|-------------|
| `--compliance cnsa-2.0` | CNSA 2.0 compliance evaluation |
| `--ci-mode advisory` | Non-blocking CI mode |
| `--sign-cbom` | Ed25519 CBOM signing for provenance |
| `--data-lifetime-years 30` | Adjust HNDL urgency for long-lived data |
| `--webhook-url https://...` | POST results to ITSM (Jira, ServiceNow) |
| `--fail-on critical` | Exit 1 if findings at or above severity |
| `--scan-type binary` | Scan binary artifacts only |
| `--incremental` | Skip unchanged files using local cache |
| `--remote-cache` | Share cache across CI runs |

## Standards supported

- NIST CNSA 2.0 (key exchange by 2030, signatures by 2035)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- HQC (NIST 5th PQC standard, selected March 2025)
- KCMVP (Korean: ARIA, SEED, LEA, KCDSA, HAS-160, LSH)
- K-PQC Round 4 (SMAUG-T, HAETAE, AIMer, NTRU+)
- CycloneDX 1.7 CBOM
- SARIF 2.1.0

## Building from source

```bash
git clone https://github.com/jimbo111/open-quantum-secure.git
cd open-quantum-secure
go build -o oqs-scanner ./cmd/oqs-scanner/
```

Requires Go 1.25+.

## How it works

The scanner runs a 12-stage pipeline:

1. Parallel engine execution (goroutine per engine)
2. Exclude pattern filtering
3. Changed-file filtering (diff mode)
4. Algorithm name normalization (CycloneDX registry)
5. Cross-engine deduplication with corroboration
6. Suppression (inline `// oqs:ignore` + `.oqs-ignore` files)
7. Constant enrichment (resolves key sizes from source constants)
8. Quantum risk classification (50+ algorithm families)
9. Impact analysis (forward propagation, protocol detection, blast radius)
10. Test/generated file marking
11. Priority calculation (P1-P4)
12. Deterministic sorting

Findings are classified into 6 quantum risk categories: vulnerable, weakened, safe, resistant, deprecated, and unknown. Each finding gets a migration effort estimate (simple/moderate/complex) and hybrid transition recommendation where applicable.

## Contributing

Pull requests welcome. Please run `go test -race ./...` before submitting.

## License

MIT
