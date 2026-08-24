package configscanner

// Server-config sprint tests: nginx.conf / sshd_config / krb5.conf /
// Terraform AWS KMS key specs. Covers the customer-reported gap where a scan
// of an nginx.conf with
//
//	ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA
//
// produced zero findings (.conf was not ingested at all, and even parsed
// values would have died on the plural key + first-match-wins-per-value).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// scanFixture writes content to dir/name and runs a full engine scan of dir.
func scanFixture(t *testing.T, name, content string) []findings.UnifiedFinding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir, Mode: engines.ModeFull})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fds {
		t.Logf("finding: algo=%+v line=%d raw=%q", f.Algorithm, f.Location.Line, f.RawIdentifier)
	}
	return fds
}

// hasFinding reports whether fds contains an algorithm finding with the given
// name/keySize on the given line (line 0 = any line).
func hasFinding(fds []findings.UnifiedFinding, name string, keySize, line int) bool {
	for _, f := range fds {
		if f.Algorithm == nil {
			continue
		}
		if f.Algorithm.Name == name && f.Algorithm.KeySize == keySize &&
			(line == 0 || f.Location.Line == line) {
			return true
		}
	}
	return false
}

func TestServerConfig_NginxCipherString(t *testing.T) {
	// The exact customer line. ssl_ciphers is on line 4.
	fds := scanFixture(t, "nginx.conf", `server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA;
    ssl_prefer_server_ciphers on;
}
`)

	want := []struct {
		name    string
		keySize int
	}{
		{"AES", 128},  // AES128-GCM
		{"ECDHE", 0},  // ECDHE key agreement
		{"RSA", 0},    // RSA auth/kex
		{"DHE", 0},    // DHE key agreement
		{"AES", 256},  // AES256
		{"SHA-1", 0},  // trailing -SHA = HMAC-SHA1 transcript MAC
	}
	for _, w := range want {
		if !hasFinding(fds, w.name, w.keySize, 4) {
			t.Errorf("missing %s/%d finding from ssl_ciphers on line 4", w.name, w.keySize)
		}
	}

	// ssl_protocols on line 3 must yield BOTH protocol versions (space-
	// separated multi-value, previously first-match-wins dropped the rest).
	if !hasFinding(fds, "TLSv1.2", 0, 3) {
		t.Error("missing TLSv1.2 finding from ssl_protocols on line 3")
	}
	if !hasFinding(fds, "TLSv1.3", 0, 3) {
		t.Error("missing TLSv1.3 finding from ssl_protocols on line 3")
	}

	// ssl_prefer_server_ciphers → info-level configuration note on line 5.
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "ssl_prefer_server_ciphers" {
			found = true
			if f.Severity != findings.SevInfo {
				t.Errorf("ssl_prefer_server_ciphers severity = %q, want %q", f.Severity, findings.SevInfo)
			}
			if f.Location.Line != 5 {
				t.Errorf("ssl_prefer_server_ciphers line = %d, want 5", f.Location.Line)
			}
		}
	}
	if !found {
		t.Error("missing info-level ssl_prefer_server_ciphers finding")
	}
}

func TestServerConfig_SshdKexAlgorithms(t *testing.T) {
	fds := scanFixture(t, "sshd_config", `Port 22
KexAlgorithms diffie-hellman-group14-sha1,curve25519-sha256,mlkem768x25519-sha256
Ciphers aes128-ctr,chacha20-poly1305@openssh.com
MACs hmac-sha2-256,hmac-sha1
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
`)

	// Classical kex atoms (line 2): DH group14 = 2048-bit, X25519, SHA-1.
	if !hasFinding(fds, "DH", 2048, 2) {
		t.Error("missing DH/2048 finding from diffie-hellman-group14-sha1")
	}
	if !hasFinding(fds, "X25519", 0, 2) {
		t.Error("missing X25519 finding from curve25519-sha256")
	}
	if !hasFinding(fds, "SHA-1", 0, 2) {
		t.Error("missing SHA-1 finding from diffie-hellman-group14-sha1")
	}
	// PQC hybrid kex: emitted under the canonical name that pkg/quantum's
	// pqcSafeFamilies recognizes.
	if !hasFinding(fds, "X25519MLKEM768", 0, 2) {
		t.Error("missing X25519MLKEM768 finding from mlkem768x25519-sha256")
	}

	// Classification cross-check: classical vulnerable, hybrid safe.
	for _, f := range fds {
		if f.Algorithm == nil || f.Location.Line != 2 {
			continue
		}
		c := quantum.ClassifyAlgorithm(f.Algorithm.Name, f.Algorithm.Primitive, f.Algorithm.KeySize)
		switch f.Algorithm.Name {
		case "X25519MLKEM768":
			if c.Risk != quantum.RiskSafe {
				t.Errorf("X25519MLKEM768 classified %q, want %q", c.Risk, quantum.RiskSafe)
			}
		case "DH", "X25519":
			if c.Risk != quantum.RiskVulnerable {
				t.Errorf("%s classified %q, want %q", f.Algorithm.Name, c.Risk, quantum.RiskVulnerable)
			}
		}
	}

	// Ciphers (line 3) and MACs (line 4) decompose too.
	if !hasFinding(fds, "AES", 128, 3) {
		t.Error("missing AES/128 finding from aes128-ctr")
	}
	if !hasFinding(fds, "ChaCha20-Poly1305", 0, 3) {
		t.Error("missing ChaCha20-Poly1305 finding from chacha20-poly1305@openssh.com")
	}
	if !hasFinding(fds, "HMAC-SHA256", 0, 4) {
		t.Error("missing HMAC-SHA256 finding from hmac-sha2-256")
	}
	if !hasFinding(fds, "HMAC-SHA1", 0, 4) {
		t.Error("missing HMAC-SHA1 finding from hmac-sha1")
	}

	// Host key algorithms (line 5).
	if !hasFinding(fds, "Ed25519", 0, 5) {
		t.Error("missing Ed25519 finding from ssh-ed25519")
	}
	if !hasFinding(fds, "RSA", 0, 5) {
		t.Error("missing RSA finding from rsa-sha2-512")
	}
}

func TestServerConfig_SshdPQCHybridNTRUPrime(t *testing.T) {
	// sntrup761x25519 has no pkg/quantum family yet; the literal hybrid name
	// is emitted (asserted on the name string per the classifier gap).
	fds := matchCryptoParams("sshd_config", []KeyValue{
		{Key: "KexAlgorithms", Value: "sntrup761x25519-sha512@openssh.com", Line: 1},
	})
	if !hasFinding(fds, "sntrup761x25519", 0, 1) {
		t.Fatal("missing sntrup761x25519 finding from sntrup761x25519-sha512@openssh.com")
	}
}

func TestServerConfig_Krb5Enctypes(t *testing.T) {
	fds := scanFixture(t, "krb5.conf", `[libdefaults]
    default_realm = EXAMPLE.COM
    permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
    default_tgs_enctypes = aes128-cts-hmac-sha256-128
`)

	if !hasFinding(fds, "AES", 256, 0) {
		t.Error("missing AES/256 finding from aes256-cts-hmac-sha1-96")
	}
	if !hasFinding(fds, "RC4", 0, 0) {
		t.Error("missing RC4 finding from rc4-hmac")
	}
	if !hasFinding(fds, "HMAC-SHA1", 0, 0) {
		t.Error("missing HMAC-SHA1 finding from aes256-cts-hmac-sha1-96")
	}
	if !hasFinding(fds, "AES", 128, 0) {
		t.Error("missing AES/128 finding from default_tgs_enctypes")
	}
}

func TestServerConfig_TerraformKMSKeySpec(t *testing.T) {
	fds := scanFixture(t, "main.tf", `resource "aws_kms_key" "signing" {
  description              = "signing key"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
`)

	if !hasFinding(fds, "RSA", 2048, 0) {
		t.Fatal("missing RSA/2048 finding from customer_master_key_spec = RSA_2048")
	}
}

func TestServerConfig_ApacheAndIPsecUnits(t *testing.T) {
	// Apache httpd directives (SSLCipherSuite / SSLProtocol / SSLOpenSSLConfCmd)
	// and ipsec.conf proposals, exercised at the matcher layer.
	fds := matchCryptoParams("httpd.conf", []KeyValue{
		{Key: "SSLProtocol", Value: "all -SSLv3 -TLSv1 -TLSv1.1", Line: 1},
		{Key: "SSLCipherSuite", Value: "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384", Line: 2},
		{Key: "SSLOpenSSLConfCmd", Value: "Curves X25519MLKEM768:prime256v1", Line: 3},
	})
	// Disabled ("-"-prefixed) protocols must NOT be reported as enabled.
	if hasFinding(fds, "SSLv3", 0, 1) {
		t.Error("disabled -SSLv3 must not produce an SSLv3 finding")
	}
	if !hasFinding(fds, "ECDHE", 0, 2) || !hasFinding(fds, "ECDSA", 0, 2) ||
		!hasFinding(fds, "ChaCha20-Poly1305", 0, 2) || !hasFinding(fds, "AES", 256, 2) {
		t.Error("missing decomposed atoms from SSLCipherSuite")
	}
	if !hasFinding(fds, "X25519MLKEM768", 0, 3) || !hasFinding(fds, "ECDH", 256, 3) {
		t.Error("missing decomposed atoms from SSLOpenSSLConfCmd Curves")
	}

	// ipsec.conf ike/esp proposals (parsed via parseINI in a real scan).
	fds = matchCryptoParams("ipsec.conf", []KeyValue{
		{Key: "ike", Value: "aes256-sha256-modp2048!", Line: 1},
		{Key: "esp", Value: "aes128gcm16-prfsha256-ecp256", Line: 2},
	})
	if !hasFinding(fds, "AES", 256, 1) || !hasFinding(fds, "SHA-256", 0, 1) || !hasFinding(fds, "DH", 2048, 1) {
		t.Error("missing decomposed atoms from ike proposal aes256-sha256-modp2048")
	}
	if !hasFinding(fds, "AES", 128, 2) || !hasFinding(fds, "ECDH", 256, 2) {
		t.Error("missing decomposed atoms from esp proposal aes128gcm16-prfsha256-ecp256")
	}
}

func TestServerConfig_MultiValueCommaFix(t *testing.T) {
	// Regression for the generic first-match-wins-per-value drop: a comma-
	// separated multi-algorithm value must yield one finding per algorithm.
	fds := matchCryptoParams("config.yml", []KeyValue{
		{Key: "tls.cipher", Value: "AES-256-GCM,ChaCha20-Poly1305", Line: 7},
	})
	if !hasFinding(fds, "AES", 256, 7) {
		t.Error("missing AES/256 finding from comma-separated cipher value")
	}
	if !hasFinding(fds, "ChaCha20-Poly1305", 0, 7) {
		t.Error("missing ChaCha20-Poly1305 finding from comma-separated cipher value (first-match-wins drop)")
	}
}

func TestServerConfig_NewValueHints(t *testing.T) {
	fds := matchCryptoParams("config.yml", []KeyValue{
		{Key: "signature.algorithm", Value: "Ed448", Line: 1},
		{Key: "kex.algorithm", Value: "X448", Line: 2},
		{Key: "signing_algorithm", Value: "RSASSA_PSS_SHA_256", Line: 3},
		{Key: "algorithm", Value: "ElGamal", Line: 4},
		{Key: "sign.algorithm", Value: "DSA", Line: 5},
	})
	for _, w := range []struct {
		name string
		line int
	}{
		{"Ed448", 1}, {"X448", 2}, {"RSA", 3}, {"ElGamal", 4}, {"DSA", 5},
	} {
		if !hasFinding(fds, w.name, 0, w.line) {
			t.Errorf("missing %s finding on line %d", w.name, w.line)
		}
	}
}

func TestServerConfig_ArbitraryConfNotIngested(t *testing.T) {
	// .conf is NOT a supported extension — only well-known basenames are.
	if isConfigFile("/etc/random-daemon.conf") {
		t.Error("arbitrary .conf must not be ingested")
	}
	for _, p := range []string{
		"/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf",
		"/etc/nginx/conf.d/ssl.conf", "/etc/tls.conf", "/etc/krb5.conf", "/etc/ipsec.conf",
		"/etc/ssh/sshd_config", "/Users/x/.ssh/ssh_config",
	} {
		if !isConfigFile(p) {
			t.Errorf("well-known server config %q must be ingested", p)
		}
	}
}
