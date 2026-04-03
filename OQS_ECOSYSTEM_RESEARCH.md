# Open Quantum Safe Ecosystem — Research Analysis

> Generated: 2026-04-03 | Purpose: Evaluate OQS repos for integration with open-quantum-secure scanner

## Executive Summary

The [open-quantum-safe](https://github.com/open-quantum-safe) organization maintains 21 repos. **7 are actively maintained and relevant** to this project. The ecosystem provides a complete PQC stack from C primitives through language bindings to application-level demos.

**Key finding:** liboqs-go is the most directly relevant repo for our Go-based scanner, but **should NOT be a runtime dependency** — the CGO requirement conflicts with our static binary distribution. Instead, use it as the reference for building an abstraction layer and generating migration code snippets.

---

## Repo-by-Repo Analysis

### 1. liboqs (C Library) — The Foundation

| Signal | Value |
|--------|-------|
| Stars | 2,848 |
| Language | C |
| Version | 0.15.0 (Nov 2025) |
| License | MIT |
| Status | Active (last push Apr 1, 2026) |

**Algorithms (250+ identifiers):**

| Category | NIST Standardized | Selected/Draft | Experimental |
|----------|-------------------|----------------|-------------|
| KEM | ML-KEM-512/768/1024 (FIPS 203) | HQC-128/192/256 | BIKE, FrodoKEM, Classic McEliece, NTRU |
| Signatures | ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205) | Falcon-512/1024 | MAYO, CROSS, SNOVA, UOV |

**Breaking changes:** Dilithium removed in 0.15.0 (renamed ML-DSA). SPHINCS+ being removed in 0.16.0 (renamed SLH-DSA).

**Production readiness:** Project explicitly warns: *"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT."* Suitable for prototyping and our scanner's suggestion engine — not as a drop-in production crypto backend.

**How it helps our scanner:**
- Source of truth for algorithm mapping tables (classical → PQC)
- `oqs.EnabledKEMs()` / `oqs.EnabledSigs()` provide runtime algorithm enumeration
- API shape informs code snippet generation

---

### 2. liboqs-go (Go Bindings) — Most Relevant

| Signal | Value |
|--------|-------|
| Stars | 117 |
| Version | 0.15.0 (Jan 2026) |
| Last commit | 2026-03-10 |
| Open issues | 0 |
| Bus factor | 1 (vsoftco: 273/296 commits) |

**API (single package `github.com/open-quantum-safe/liboqs-go/oqs`):**

```go
// KEM — replaces ECDH
kem := oqs.KeyEncapsulation{}
kem.Init("ML-KEM-768", nil)
pubKey, _ := kem.GenerateKeyPair()
ct, ss, _ := kem.EncapSecret(pubKey)
recovered, _ := kem.DecapSecret(ct)
kem.Clean()

// Signature — replaces RSA/ECDSA
sig := oqs.Signature{}
sig.Init("ML-DSA-65", nil)
pubKey, _ := sig.GenerateKeyPair()
signature, _ := sig.Sign(message)
valid, _ := sig.Verify(message, signature, pubKey)
sig.Clean()
```

**Critical limitation: CGO required.** No pure-Go fallback. Requires:
1. liboqs C library built and installed
2. `PKG_CONFIG_PATH` set
3. `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` at runtime

**How it helps our scanner:**
- Reference API for generating Go migration snippets
- Can wrap into `crypto.Signer` interface (~50 lines) for drop-in suggestions
- Discovery helpers: `EnabledKEMs()`, `EnabledSigs()`, `IsSigEnabled(name)`
- **Should NOT be a runtime dependency** — use for snippet templates only

**Gotchas:**
- Stateful lifecycle (Init/Clean) — easy to leak C memory
- No `crypto.Signer` compliance — raw `[]byte` keys
- Some algorithms can't run concurrently (stack size constraints)

---

### 3. oqs-provider (OpenSSL 3 Provider)

| Signal | Value |
|--------|-------|
| Stars | 461 |
| License | MIT |
| Status | Active |

**What it does:** Shared library plugin for OpenSSL 3 that adds PQC algorithms. No source patching needed — configure via `openssl.cnf`.

**Key insight for our scanner:** OpenSSL 3.5+ has **native ML-KEM and ML-DSA** — oqs-provider auto-disables its copies. Recommendations should branch on OpenSSL version.

**Scanner recommendation matrix:**

| Detected | OpenSSL Version | Recommendation |
|----------|----------------|----------------|
| RSA/ECDH in nginx/Apache | < 3.5 | Install oqs-provider, add `X25519MLKEM768` to curves |
| RSA/ECDH in nginx/Apache | >= 3.5 | Native ML-KEM available, add `X25519MLKEM768` to curves |
| Go service, Go < 1.23 | Any | Upgrade to Go 1.24+ (native `crypto/tls` ML-KEM support) |
| Go service, Go >= 1.24 | Any | Already PQC-ready for key exchange (X25519MLKEM768 default) |

**Go-specific:** Go does NOT use OpenSSL — `crypto/tls` is pure Go. oqs-provider is irrelevant for Go services. Go 1.24+ enables ML-KEM-768 hybrid key exchange by default.

---

### 4. oqs-demos (Integration Examples)

| Signal | Value |
|--------|-------|
| Stars | 177 |
| Maintained demos | 8 (nginx, curl, httpd, Node.js, Wireshark, Epiphany, Chromium, Locust) |
| Unmaintained | 6 (OpenSSH, HAproxy, OpenVPN, Mosquitto, ngtcp2, h2load) |

**All demos follow same pattern:** OpenSSL 3 + oqs-provider, Docker-based, zero application code changes.

**Easiest migration paths (ranked):**
1. **Node.js** — zero code changes, swap Docker base image
2. **curl** — runtime env var override
3. **nginx/Apache** — config-only (`ssl_ecdh_curve X25519MLKEM768`)
4. **Chromium** — requires source patching (hardest)

**Scanner remediation links:**

| Finding | Link to demo |
|---------|-------------|
| RSA/ECDH in nginx | `oqs-demos/tree/main/nginx` |
| Weak TLS in Node.js | `oqs-demos/tree/main/nodejs` |
| Classic ciphers in curl | `oqs-demos/tree/main/curl` |
| RSA in Apache | `oqs-demos/tree/main/httpd` |

**Warning:** Some demo READMEs still show pre-standard names (`kyber768`, `dilithium3`). Scanner should flag these as deprecated aliases.

---

### 5. liboqs-python (Python Bindings)

| Signal | Value |
|--------|-------|
| Stars | 226 |
| PyPI package | `liboqs-python` (import as `oqs`) |
| Version | 0.14.1 (Sep 2025) |

**Import patterns to detect:**
```python
import oqs
from oqs import KeyEncapsulation, Signature
oqs.KeyEncapsulation("ML-KEM-768")
oqs.Signature("ML-DSA-65")
```

**Scanner detection strategy:**
- Check `requirements.txt` / `pyproject.toml` for `liboqs-python`
- Detect `import oqs` in source (note: install name != import name)
- Flag `"BIKE-*"`, `"HQC-*"`, `"NTRU-*"` algorithm strings as experimental
- Flag co-existence of `from cryptography.hazmat.primitives.asymmetric import rsa` alongside `import oqs` as incomplete migration

---

### 6. liboqs-rust (Rust Bindings)

| Signal | Value |
|--------|-------|
| Stars | 176 |
| crates.io | `oqs` v0.11.0, 115K downloads |
| Competing crate | `pqcrypto` v0.18.1, 233K downloads |

**Cargo.toml patterns:**
```toml
oqs = "0.11"      # liboqs binding
oqs-sys = "0.11"   # low-level FFI
# OR competing:
pqcrypto = "0.18"
pqcrypto-kyber = "..."
```

**Rust import patterns:**
```rust
use oqs::kem::{Kem, Algorithm};
use oqs::sig::{Sig, Algorithm};
kem::Kem::new(kem::Algorithm::MlKem768)
sig::Sig::new(sig::Algorithm::MlDsa65)
```

**Scanner note:** Both `oqs` and `pqcrypto` crates wrap C — neither is pure Rust. Scanner should recognize both as PQC-positive signals.

---

### 7. liboqs-java (Java Bindings)

| Signal | Value |
|--------|-------|
| Stars | 68 |
| Version | 0.3.0 (Apr 2025) |
| Maven Central | **Not published** — build from source only |
| JCA Provider | **None** — raw classes only |

**Import patterns:**
```java
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Signature;
new KeyEncapsulation("ML-KEM-768");
new Signature("ML-DSA-65");
```

**vs. Bouncy Castle (recommended alternative for Java):**

| | liboqs-java | Bouncy Castle |
|---|---|---|
| Maven Central | No | Yes (`bcprov-jdk18on`) |
| JCA Provider | No | Yes (`BouncyCastlePQCProvider`) |
| Stars | 68 | 2,631 |
| Pure Java | No (JNI) | Yes |
| Production-ready | No | Yes |

**Scanner recommendation:** For Java projects, recommend **Bouncy Castle** over liboqs-java. Bouncy Castle provides JCA integration (`KeyPairGenerator.getInstance("ML-DSA", "BCPQC")`) and is production-grade.

**Bouncy Castle import patterns to detect:**
```java
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.crypto.mlkem.*;
KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
```

---

## Abstraction Layer Design (Proposed)

### Goal
Let users of our scanner easily switch from classical crypto to PQC with language-specific, actionable migration guidance.

### Architecture

```
┌─────────────────────────────────────────────┐
│            open-quantum-secure               │
│                (scanner)                     │
├─────────────────────────────────────────────┤
│         Migration Suggestion Engine          │
│  ┌─────────────────────────────────────────┐ │
│  │   Algorithm Mapping Table (hardcoded)   │ │
│  │   RSA-2048 → ML-DSA-44 (FIPS 204)      │ │
│  │   ECDSA P-256 → ML-DSA-44              │ │
│  │   ECDH P-256 → ML-KEM-768 (FIPS 203)   │ │
│  │   AES-128 → AES-256 (Grover)           │ │
│  │   Dilithium → ML-DSA (renamed)          │ │
│  └─────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────┐ │
│  │   Language-Specific Snippet Generator   │ │
│  │   Go:     liboqs-go API patterns        │ │
│  │   Python: liboqs-python API patterns    │ │
│  │   Rust:   oqs crate API patterns        │ │
│  │   Java:   Bouncy Castle JCA patterns    │ │
│  │   Infra:  oqs-provider/native OpenSSL   │ │
│  └─────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────┐ │
│  │   Runtime/Version-Aware Recommendations │ │
│  │   Go >= 1.24: native crypto/tls PQC     │ │
│  │   OpenSSL >= 3.5: native ML-KEM/DSA     │ │
│  │   OpenSSL < 3.5: oqs-provider           │ │
│  │   nginx/Apache: config-only change      │ │
│  │   Node.js: swap Docker base image       │ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Hardcode the mapping table** — do NOT depend on liboqs at runtime. The CGO requirement is too heavy for a static analysis tool.
2. **Version the mapping table** — algorithm names change between liboqs releases (Dilithium → ML-DSA, SPHINCS+ → SLH-DSA). Track upstream releases.
3. **Branch on language + runtime version** — the right PQC path differs dramatically by ecosystem.
4. **Recommend Bouncy Castle for Java** — liboqs-java lacks Maven Central and JCA support.
5. **Detect PQC-positive patterns** — recognize `import oqs`, `use oqs::*`, `org.openquantumsafe.*`, and Bouncy Castle PQC imports as "already migrating."

### Classical → PQC Mapping Table

| Classical Algorithm | PQC Replacement | NIST Standard | Security Level | Notes |
|--------------------|-----------------|---------------|----------------|-------|
| RSA-2048 | ML-DSA-44 | FIPS 204 | L2 | Signing |
| RSA-3072/4096 | ML-DSA-65 | FIPS 204 | L3 | Signing |
| ECDSA P-256 | ML-DSA-44 | FIPS 204 | L2 | Signing |
| ECDSA P-384 | ML-DSA-65 | FIPS 204 | L3 | Signing |
| ECDH P-256 / X25519 | ML-KEM-768 | FIPS 203 | L3 | Key exchange |
| ECDH P-384 | ML-KEM-1024 | FIPS 203 | L5 | Key exchange |
| DH-2048 | ML-KEM-768 | FIPS 203 | L3 | Key exchange |
| AES-128 | AES-256 | — | Grover-resistant | Symmetric (not PQC) |
| SHA-256 | SHA-384/512 | — | Grover-resistant | Hash (not PQC) |
| Dilithium-2/3/5 | ML-DSA-44/65/87 | FIPS 204 | Direct rename | Flag as pre-standard |
| Kyber-512/768/1024 | ML-KEM-512/768/1024 | FIPS 203 | Direct rename | Flag as pre-standard |
| SPHINCS+ | SLH-DSA | FIPS 205 | Direct rename | Flag as pre-standard |

---

## Deprecated / Skip Repos

| Repo | Status | Reason |
|------|--------|--------|
| openssl (OQS fork) | Deprecated | Replaced by oqs-provider for OpenSSL 3 |
| libssh | Deprecated | See notice in README |
| liboqs-dotnet | Deprecated | See notice in README |
| profiling | Deprecated | See notice in README |
| oqs-engine | Not supported | Superseded by oqs-provider |
| boringssl | Prototype | Low activity, niche use case |
| liboqs-cpp | Low priority | 53 stars, C++ projects can use liboqs directly |
| liboqs-js | Early stage | 4 stars, null description |

---

## Next Steps

1. **Implement algorithm mapping table** in scanner's suggestion engine
2. **Add language-specific snippet templates** referencing OQS APIs
3. **Detect PQC-positive imports** across Go, Python, Rust, Java
4. **Branch remediation on runtime version** (Go 1.24+, OpenSSL 3.5+)
5. **Link to oqs-demos** for infrastructure-level migration paths
6. **Track liboqs releases** for algorithm name changes
