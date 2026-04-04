# Open Quantum Secure (OQS Scanner)

Scans your codebase for cryptographic algorithms that quantum computers will break, and tells you exactly what to replace them with — down to copy-pasteable code snippets in your language.

Produces a Quantum Readiness Score (0-100), generates CycloneDX 1.7 CBOM, checks CNSA 2.0 compliance, and now suggests concrete PQC migration paths per finding.

No backend. Fully offline.

---

## Quick start

```bash
# Download pre-built binary
curl -sSL https://raw.githubusercontent.com/jimbo111/open-quantum-secure/main/install.sh | sh

# Or build from source
git clone https://github.com/jimbo111/open-quantum-secure.git
cd open-quantum-secure && go build -o oqs-scanner ./cmd/oqs-scanner/

# Run it
oqs-scanner scan --path .
```

You get 2 engines out of the box — **config-scanner** (YAML, JSON, .env, TOML, XML, INI, HCL) and **binary-scanner** (JAR, Go binaries, Python wheels, ELF/PE/Mach-O, .NET). These are compiled into the binary, no setup needed.

For source code scanning, install the engines that match your stack:

```bash
cargo install ast-grep        # AST pattern matching, 12 languages
pip install semgrep            # Data-flow / taint analysis
# Run `oqs-scanner engines doctor` to see what's available
```

You don't need all of them. Install what makes sense for your project.

---

## What the output looks like

```
Scanning /your/project with 4 engine(s)...
Scan completed in 1.2s — 37 findings

Total: 37 findings (28 algorithms, 8 dependencies)
Quantum: 6 vulnerable, 0 weakened, 10 safe/resistant, 0 deprecated
Quantum Readiness Score: 88/100 (Grade: A)
```

Each finding includes the file, line number, algorithm name, quantum risk level, and — when actionable — a target PQC replacement with a migration code snippet.

---

## PQC migration suggestions

This is the part that matters most. The scanner doesn't just flag problems — it shows you the fix.

Every vulnerable or deprecated finding gets mapped to a NIST-standardized PQC replacement:

| What you have | What to use instead | Standard |
|--------------|-------------------|----------|
| RSA-2048 (signing) | ML-DSA-44 | FIPS 204 |
| RSA-3072+ (signing) | ML-DSA-65 | FIPS 204 |
| ECDSA P-256 | ML-DSA-44 | FIPS 204 |
| ECDH / X25519 | ML-KEM-768 | FIPS 203 |
| DH / FFDH | ML-KEM-768 | FIPS 203 |
| MD5, SHA-1 | SHA-256 | — |
| DES, 3DES, RC4 | AES-256-GCM | — |
| AES-128 | AES-256 | — |

The mapping is key-size aware — RSA-4096 gets ML-DSA-87 (Level 5), not the same suggestion as RSA-2048.

### Code snippets by language

When the scanner finds a vulnerable algorithm in a source file, it generates a before/after snippet in that file's language. Currently supported: **Go, Python, Java, Rust, Swift, JavaScript, TypeScript, C, C++, C#**, and **config files** (nginx, Apache, HAProxy).

Example — a Go file using ECDH gets this in the JSON output:

```json
{
  "targetAlgorithm": "ML-KEM-768",
  "targetStandard": "FIPS 203",
  "migrationSnippet": {
    "language": "go",
    "before": "priv, _ := ecdh.P256().GenerateKey(rand.Reader)\nshared, _ := priv.ECDH(peerPub)",
    "after": "kem := oqs.KeyEncapsulation{}\n_ = kem.Init(\"ML-KEM-768\", nil)\npub, _ := kem.GenerateKeyPair()\nct, ss, _ := kem.EncapSecret(pub)",
    "explanation": "Replace ECDH key exchange with ML-KEM-768 (FIPS 203) via liboqs-go."
  }
}
```

Config files get server-specific suggestions — the scanner detects nginx vs Apache vs HAProxy from the filename and generates the right directives.

Snippets show up in JSON, SARIF (as properties), and the HTML report (collapsible before/after blocks). The dashboard also renders them in the findings drill-down.

### Runtime-aware recommendations

The scanner adjusts recommendations based on what you're actually running:

- **Go 1.24+**: `crypto/tls` already supports X25519MLKEM768 natively — the snippet tells you this instead of suggesting a library swap
- **OpenSSL 3.5+**: ML-KEM and ML-DSA are built in — no oqs-provider needed
- **Java**: Recommends Bouncy Castle (JCA provider, Maven Central) over liboqs-java (no Maven Central, no JCA)
- **Swift**: Notes that CryptoKit doesn't have PQC yet and suggests monitoring Apple's updates

---

## How engines work

The scanner is an orchestrator. It calls external tools, collects their output, normalizes it into a common format, deduplicates across engines, classifies each finding's quantum risk, and scores the result.

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
   │config-scanner│   │ cipherscope   │    │ semgrep (taint/flow)    │
   │binary-scanner│   │ cryptoscan    │    │ cdxgen (SBOM)           │
   │             │    │ ast-grep      │    │ cbomkit-theia(artifacts)│
   │             │    │ syft          │    │                         │
   │             │    │ cryptodeps    │    │                         │
   └─────────────┘    └───────────────┘    └─────────────────────────┘
```

Each engine is a separate project with its own license. The scanner never bundles them — it discovers them from PATH at runtime.

When multiple engines find the same algorithm at the same location, the finding gets corroborated — higher confidence, bigger penalty on the QRS.

---

## Quantum Readiness Score

| Score | Grade | What it means |
|-------|-------|--------------|
| 95-100 | A+ | Quantum-ready |
| 85-94 | A | Minimal risk |
| 70-84 | B | Some vulnerable algorithms, migration underway |
| 50-69 | C | Significant risk |
| 30-49 | D | High risk |
| 0-29 | F | Immediate action needed |

The score penalizes vulnerable and deprecated algorithms, rewards PQC-safe ones, and weights by severity and corroboration. The `--data-lifetime-years` flag amplifies urgency for long-lived data (healthcare, government, finance).

---

## Output formats

```bash
oqs-scanner scan --path . --format table     # Terminal table (default)
oqs-scanner scan --path . --format json      # Full JSON with migration snippets
oqs-scanner scan --path . --format sarif     # GitHub Code Scanning / IDE
oqs-scanner scan --path . --format cbom      # CycloneDX 1.7 CBOM
oqs-scanner scan --path . --format html      # Standalone HTML report
```

The HTML report and JSON output include migration snippets. SARIF carries them in the `properties` block. The table format shows the summary — use `--format html` when you want the full migration guidance.

---

## CNSA 2.0 compliance

```bash
oqs-scanner scan --path . --compliance cnsa-2.0
```

Flags algorithms that don't meet NSA's CNSA 2.0 requirements:
- SLH-DSA (excluded despite being a NIST standard)
- ML-KEM below 1024, ML-DSA below 87
- SHA-256 (requires SHA-384 minimum)
- AES below 256
- HQC (not yet approved)

Generate a formal report:

```bash
oqs-scanner compliance-report --path . --output report.md
```

---

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
      - uses: jimbo111/open-quantum-secure@v2.0.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          path: '.'
          format: 'sarif'
          upload-sarif: 'true'
          pr-comment: 'true'       # posts results as a PR comment
          compliance: 'cnsa-2.0'
          ci-mode: 'advisory'      # won't block merges — use 'blocking' when ready
```

The Docker-based action ships with ast-grep and semgrep pre-installed, so CI scans cover more languages than a bare local install.

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

Results feed into GitLab's Security Dashboard. Set `OQS_MR_NOTE: "true"` to post results as a merge request comment.

### CI modes

- **blocking** — exit 1 on policy violations (default, for enforcing standards)
- **advisory** — warnings only, always exit 0 (for onboarding without breaking builds)
- **silent** — no policy output, always exit 0

---

## Dashboard

```bash
oqs-scanner dashboard
# → http://localhost:8899
```

Shows QRS trends over time, finding breakdown by risk category, HNDL urgency classification, migration effort estimates, and a findings table with:
- **Target column** — the recommended PQC replacement for each finding
- **Expandable detail rows** — recommendation text plus side-by-side Before/After migration code snippets
- **Search/filter** — filter findings by algorithm, file, risk level, or target algorithm

All data stored locally in `~/.oqs/history/`. No cloud, no telemetry.

---

## CBOM generation

```bash
oqs-scanner scan --path . --format cbom --output cbom.json

# With Ed25519 signing for provenance
oqs-scanner scan --path . --format cbom --sign-cbom --output signed-cbom.json
```

---

## Key flags

| Flag | What it does |
|------|-------------|
| `--compliance cnsa-2.0` | CNSA 2.0 compliance check |
| `--ci-mode advisory` | Non-blocking CI |
| `--sign-cbom` | Ed25519 CBOM signing |
| `--data-lifetime-years 30` | Amplify HNDL urgency for long-lived data |
| `--webhook-url https://...` | POST results to Jira, ServiceNow, etc. |
| `--fail-on critical` | Exit 1 if findings at or above this severity |
| `--scan-type binary` | Scan binary artifacts only |
| `--incremental` | Skip unchanged files using local cache |
| `--exclude "vendor/**"` | Skip directories by glob |

## Other commands

```bash
oqs-scanner diff --path . --base main            # PR mode — scan only changed files
oqs-scanner trends --project my-org/my-repo       # QRS trend analysis
oqs-scanner history --project my-org/my-repo      # Scan history
oqs-scanner engines list                          # All engines and status
oqs-scanner engines doctor                        # Engine health check
oqs-scanner version                               # Version info
```

---

## Standards

- **NIST PQC**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- **CNSA 2.0**: Key exchange by 2030, signatures by 2035
- **HQC**: NIST 5th PQC standard (selected March 2025)
- **KCMVP**: Korean standards — ARIA, SEED, LEA, KCDSA, HAS-160, LSH
- **K-PQC Round 4**: SMAUG-T, HAETAE, AIMer, NTRU+
- **CycloneDX 1.7** CBOM
- **SARIF 2.1.0**

## Contributing

PRs welcome. Run `go test -race ./...` before submitting. Requires Go 1.25+.

## License

MIT
