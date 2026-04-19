# Open Quantum Secure (OQS Scanner)

Scans your codebase AND live TLS/SSH endpoints for cryptographic algorithms that quantum computers will break, and tells you exactly what to replace them with — down to copy-pasteable code snippets in your language.

Produces a Quantum Readiness Score (0-100), generates CycloneDX 1.7 CBOM, checks 7 compliance frameworks (CNSA 2.0, PCI DSS 4.0, NIST IR 8547, BSI, NCSC UK, ASD ISM, ANSSI), actively probes TLS endpoints for PQC support including hybrid KEM group + signature algorithm enumeration, ingests Zeek/Suricata network logs, and detects TLS 1.2 downgrade vulnerabilities.

No backend. Fully offline (except optional Certificate Transparency lookups).

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

You get 7 engines out of the box, all pure-Go and compiled in:

- **config-scanner** — YAML, JSON, .env, TOML, XML, INI, HCL
- **binary-scanner** — JAR, Go binaries, Python wheels, ELF/PE/Mach-O, .NET
- **tls-probe** — Live TLS endpoint scanning (CurveID + handshake volume + ECH detection + raw ClientHello deep-probe + group/sigalg enumeration + TLS 1.2 fallback detection)
- **ssh-probe** — OpenSSH KEXINIT inspection for mlkem768x25519-sha256, sntrup761x25519 + 7 PQ variants
- **ct-lookup** — Certificate Transparency log queries via crt.sh (auto-chains from ECH-enabled hosts)
- **zeek-log** — Ingests Zeek ssl.log + x509.log for passive network PQC inventory
- **suricata-log** — Ingests Suricata eve.json for passive TLS PQC inventory

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
   │tls-probe     │   │ ast-grep      │    │ cbomkit-theia(artifacts)│
   │ssh-probe     │   │ syft          │    │                         │
   │ct-lookup     │   │ cryptodeps    │    │                         │
   │zeek-log     │    │               │    │                         │
   │suricata-log │    │               │    │                         │
   └─────────────┘    └───────────────┘    └─────────────────────────┘
```

Each engine is a separate project with its own license. The scanner never bundles them — it discovers them from PATH at runtime.

When multiple engines find the same algorithm at the same location, the finding gets corroborated — higher confidence, bigger penalty on the QRS.

---

## TLS Probe (Dynamic Analysis)

Probe live TLS endpoints for quantum-vulnerable cipher suites and certificate algorithms:

```bash
oqs-scanner scan --path . --tls-targets api.example.com:443,db.internal:8443
```

The `tls-probe` engine connects to each target, inspects the TLS handshake, and reports vulnerable key exchange (ECDHE, RSA), signature algorithms (RSA, ECDSA), and weak symmetric ciphers (AES-128). Findings include the negotiated cipher suite and leaf certificate key type.

**PQC presence detection.** When the server negotiates a post-quantum group (ML-KEM or an IETF hybrid such as X25519MLKEM768), findings carry `negotiatedGroup` (uint16 IANA codepoint), `negotiatedGroupName`, `pqcPresent=true`, and `pqcMaturity` (`final` or `draft`). The table output shows a `[PQC]` or `[PQC:DRAFT]` badge.

**Size-based passive signals.** The probe also emits `handshakeVolumeClass` (`classical` / `hybrid-kem` / `full-pqc` / `unknown` based on handshake byte volume — thresholds per Mallick et al., arXiv:2503.17830) and `handshakeBytes` (total). These are deterministic signals that corroborate the codepoint classification and surface in JSON, SARIF (`result.properties`), and CBOM (`oqs:*` component properties).

**ECH-enabled hosts.** When the server advertises Encrypted Client Hello (ECH) via a DNS HTTPS RR, findings are annotated `partialInventory=true` with `partialInventoryReason="ECH_ENABLED"` — some handshake details are encrypted and the active probe's inventory is necessarily incomplete. A future Certificate Transparency lookup engine (Sprint 3) will recover the cert algorithm for these hosts.

**Security:** DNS pinning prevents rebinding attacks. RFC 1918/loopback IPs are blocked with `--tls-strict`. Under `--tls-strict`, the ECH DNS path also rejects a private/loopback system resolver in favour of public fallbacks (1.1.1.1, 8.8.8.8). TLS targets cannot be set via project config (`.oqs-scanner.yaml`) to prevent SSRF in CI.

| Flag | Default | Description |
|------|---------|-------------|
| `--tls-targets` | (none) | Comma-separated `host:port` endpoints |
| `--tls-insecure` | false | Skip certificate verification |
| `--tls-strict` | false (CLI) / true (Action) | Block private IP connections |

### Raw ClientHello deep-probe

TLS stdlib won't let you offer arbitrary PQC group codepoints. To probe support for groups the scanner's own Go runtime doesn't know about — or to enumerate everything a server will accept — use:

```bash
# Probe 6 PQC codepoints via hand-crafted ClientHellos
oqs-scanner scan --path . --tls-targets api.example.com:443 --deep-probe

# Full group + sig-alg enumeration + server preference detection
oqs-scanner scan --path . --tls-targets api.example.com:443 \
    --enumerate-groups \
    --enumerate-sigalgs \
    --detect-server-preference \
    --max-probes-per-target 50
```

- `--deep-probe` — 6-codepoint fast pass (X25519, X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, MLKEM1024, MLKEM512)
- `--enumerate-groups` — probes 13 codepoints (classical + hybrid + pure ML-KEM + deprecated Kyber)
- `--enumerate-sigalgs` — probes 17 signature schemes including ML-DSA (0x0904/05/06)
- `--detect-server-preference` — two-ordering probe reveals whether server has fixed preference or respects client order
- `--max-probes-per-target` — caps total TCP connections per target (default 30; enumeration can reach ~39 without cap)
- `--skip-tls12-fallback` — disable the TLS 1.2 downgrade detection (on by default for PQC-capable targets)

Findings report `supportedGroups`, `supportedSigAlgs`, `serverPreferredGroup`, `serverPreferenceMode`, and for downgrade-vulnerable targets a `#tls12-fallback` finding.

### X.509 certificate signature algorithm

The tls-probe engine inspects the leaf cert's signature algorithm OID and emits a `#cert-sig` finding separate from the cert-key finding. ML-DSA (`id-ml-dsa-44/65/87`) and SLH-DSA (all 12 variants) are recognised. A Cloudflare-signed ECDSA cert produces a `SHA256-RSA` or `ECDSA` cert-sig finding with `RiskVulnerable`; an ML-DSA-65 cert produces `RiskSafe`.

---

## SSH Probe

```bash
oqs-scanner scan --path . --ssh-targets github.com:22,bastion.internal:22
```

Reads the SSH banner and KEXINIT packet, reports advertised KEX algorithms. PQC-capable KEX detected: `mlkem768x25519-sha256` (OpenSSH 10.0+ final), `sntrup761x25519-sha512@openssh.com` (OpenSSH 8.5-9.9 draft), plus 7 vendor/draft variants. Heuristic substring match catches `mlkem`, `kyber`, `sntrup`, `frodo`, `ntruprime`, `bike`, `hqc`, `mceliece`.

RFC 4253 §4.2 preamble-compliant (handles Google Cloud IAP / Bastillion / fail2ban wrappers). SSH-1.x rejected; only SSH-2.0 / SSH-1.99 accepted. `--ssh-strict` blocks private/loopback IPs.

---

## Certificate Transparency lookup

```bash
# Explicit hostnames
oqs-scanner scan --path . --ct-lookup-targets api.example.com,admin.example.com

# Auto-chain from TLS-probe ECH findings
oqs-scanner scan --path . --tls-targets api.example.com:443 --ct-lookup-from-ech
```

Queries crt.sh for the hostname and extracts certificate signing algorithms from the returned CT log entries. When an active TLS probe can't see the real cert (ECH enabled), this engine fills in the gap. Hostnames extracted from ECH findings propagate automatically when `--ct-lookup-from-ech` is set. S2→S3 auto-chain survives combined ECH + enumeration truncation (PartialInventoryReason is composed, not overwritten).

---

## Passive network log ingestion

For networks where active probing is restricted, ingest pre-captured Zeek or Suricata logs:

```bash
# Zeek (TSV, JSON, or .gz)
oqs-scanner scan --path . \
    --zeek-ssl-log /var/log/zeek/ssl.log \
    --zeek-x509-log /var/log/zeek/x509.log

# Suricata (NDJSON eve.json, plain or .gz)
oqs-scanner scan --path . --suricata-eve /var/log/suricata/eve.json
```

Both engines:
- Parse streaming logs with 4 MB bufio buffer (handles long lines)
- Cap at 500k dedup entries per scan (truncation flagged as `DEDUP_CAP_REACHED` in PartialInventoryReason)
- Cap gzip at 100 MB decompressed (prevents gzip bombs)
- Sanitize all user-origin fields (strip control chars < 0x20 and DEL) to prevent ANSI/bidi injection into output

A companion Zeek script `contrib/zeek/oqs-pqc-key-share.zeek` logs the `key_share` extension group IDs (not in vanilla ssl.log). A companion Suricata config drop-in `contrib/suricata/oqs-tls.yaml` enables TLS metadata logging.

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
oqs-scanner scan --path . --format csv       # RFC 4180 CSV for Excel/BI pipelines
```

The HTML report and JSON output include migration snippets. SARIF carries them in the `properties` block. The table format shows the summary — use `--format html` when you want the full migration guidance. CSV output is RFC 4180 compliant with CRLF line endings and is hardened against Excel formula injection (values starting with `=`, `+`, `-`, `@`, tab, or CR are prefixed with `'`).

---

## Compliance frameworks

Seven frameworks supported, each with its own algorithm-approval rules and deadline calendar:

| ID | Authority | Jurisdiction | Notable policy |
|---|---|---|---|
| `cnsa-2.0` | NSA | US National Security Systems | SLH-DSA excluded; ML-KEM-1024 only; default-deny for unknown KEMs |
| `pci-dss-4.0` | PCI SSC | Global payment processors | Req 12.3.3 inventory evidence (mandatory since 2025-03) |
| `nist-ir-8547` | NIST | US federal civilian | All NIST PQC approved; RSA/ECDSA/DH deprecated 2030 |
| `bsi-tr-02102` | BSI | Germany / EU | Approves FrodoKEM, Classic McEliece, HQC; hybrid KEM warn |
| `ncsc-uk` | NCSC | United Kingdom | All 3 NIST standards approved; 2028/2031/2035 phased |
| `asd-ism` | ASD | Australia government | Strictest grade only: ML-KEM-1024 + ML-DSA-87; classical cease 2030 |
| `anssi-guide-pqc` | ANSSI | France | Hybrid PQC+classical warn; all NIST PQC approved |

Run a single framework:

```bash
oqs-scanner scan --path . --compliance cnsa-2.0
```

Run multiple at once, or all at once:

```bash
oqs-scanner scan --path . --compliance cnsa-2.0,bsi-tr-02102,ncsc-uk
oqs-scanner scan --path . --compliance all
```

**Cross-framework divergence is common by design.** A `SLH-DSA-128f` finding FAILS CNSA 2.0 (`cnsa2-slh-dsa-excluded`) but PASSES all six others. `X25519MLKEM768` PASSES ANSSI + BSI (it's the required hybrid) but FAILS CNSA 2.0 (`cnsa2-hybrid-sub-1024` — CNSA requires ML-KEM-**1024**) and ASD ISM (`asd-hybrid-sub-1024`). Running multiple frameworks reveals what's compliant *where*.

**Severity tiers.** Violations now carry `Severity: "error"` or `"warn"`. ANSSI and BSI's hybrid-KEM recommendation is a `warn` (per authoritative source language), not a blocker. `--ci-mode blocking` fails only on `error` severity.

Generate a formal report (one per framework, concatenated with `---` separators if multiple):

```bash
oqs-scanner compliance-report --path . --compliance pci-dss-4.0,ncsc-uk --output report.md
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
          tls-targets: 'api.staging.example.com:443'  # optional: probe TLS endpoints
          tls-strict: 'true'       # block private IP probing (CI default)
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
| `--compliance cnsa-2.0,bsi-tr-02102` | Multi-framework compliance check (`all` shortcut supported) |
| `--ci-mode advisory` | Non-blocking CI |
| `--sign-cbom` | Ed25519 CBOM signing |
| `--data-lifetime-years 30` | Amplify HNDL urgency for long-lived data |
| `--webhook-url https://...` | POST results to Jira, ServiceNow, etc. |
| `--fail-on critical` | Exit 1 if findings at or above this severity |
| `--scan-type binary` | Scan binary artifacts only |
| `--incremental` | Skip unchanged files using local cache |
| `--exclude "vendor/**"` | Skip directories by glob |
| `--tls-targets host:443` | Probe TLS endpoints for PQC support |
| `--deep-probe` | Raw ClientHello probe of PQC group codepoints |
| `--enumerate-groups` | Probe all 13 IANA TLS groups individually |
| `--enumerate-sigalgs` | Probe 17 TLS signature schemes (ML-DSA, RSA, ECDSA, EdDSA) |
| `--detect-server-preference` | Two-ordering probe for server preference mode |
| `--max-probes-per-target 30` | Cap TCP connections per target across all probe passes |
| `--skip-tls12-fallback` | Disable TLS 1.2 downgrade detection (enabled by default) |
| `--ssh-targets host:22` | Probe SSH endpoints for PQC KEX advertisement |
| `--ct-lookup-targets host` | Query Certificate Transparency logs |
| `--ct-lookup-from-ech` | Auto-query CT for ECH-enabled hosts found by tls-probe |
| `--zeek-ssl-log path` | Ingest Zeek ssl.log (TSV, JSON, or .gz) |
| `--zeek-x509-log path` | Ingest Zeek x509.log |
| `--suricata-eve path` | Ingest Suricata eve.json |
| `--verbose` | Enable detailed enum progress logging |

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
- **CNSA 2.0**: Key exchange by 2030, signatures by 2035 (NSS only)
- **NIST IR 8547**: US federal civilian transition (2030 deprecate, 2035 disallow)
- **PCI DSS 4.0** Req 12.3.3: cryptographic inventory mandatory since 2025-03
- **BSI TR-02102-1**: Germany; approves FrodoKEM, Classic McEliece, HQC
- **NCSC UK PQC Migration Timelines**: 2028/2031/2035 phased
- **ASD ISM**: Australia; classical asymmetric cease 2030
- **ANSSI Guide PQC**: France; hybrid PQC recommended
- **IETF drafts** used for codepoint tables: draft-ietf-tls-hybrid-design, draft-tls-mldsa
- **OpenSSH 10.0+** KEX: mlkem768x25519-sha256, sntrup761x25519-sha512@openssh.com
- **TLS 1.3** RFC 8446 (active probe + raw ClientHello builder + HRR + key_share parser)
- **HQC**: NIST 5th PQC standard (selected March 2025)
- **KCMVP**: Korean standards — ARIA, SEED, LEA, KCDSA, HAS-160, LSH
- **K-PQC Round 4**: SMAUG-T, HAETAE, AIMer, NTRU+
- **CycloneDX 1.7** CBOM
- **SARIF 2.1.0**
- **RFC 4180** CSV (strict CRLF, formula-injection hardened)

## Contributing

PRs welcome. Run `go test -race ./...` before submitting. Requires Go 1.25+.

## License

MIT
