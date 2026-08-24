package keyfile

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- fixture helpers ---------------------------------------------------------

// rsaTestKey is generated once — RSA keygen is the slow part of this suite.
var rsaTestKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func selfSignedCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaTestKey.PublicKey, rsaTestKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// sshString encodes one RFC 4251 string.
func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// sshMpint encodes a big.Int as an SSH mpint (leading zero when MSB set).
func sshMpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

func sshRSABlob(k *rsa.PublicKey) []byte {
	var blob []byte
	blob = append(blob, sshString([]byte("ssh-rsa"))...)
	blob = append(blob, sshMpint(big.NewInt(int64(k.E)))...)
	blob = append(blob, sshMpint(k.N)...)
	return blob
}

func sshEd25519Blob(pub ed25519.PublicKey) []byte {
	var blob []byte
	blob = append(blob, sshString([]byte("ssh-ed25519"))...)
	blob = append(blob, sshString(pub)...)
	return blob
}

func sshECDSABlob(curve string, point []byte) []byte {
	var blob []byte
	blob = append(blob, sshString([]byte("ecdsa-sha2-"+curve))...)
	blob = append(blob, sshString([]byte(curve))...)
	blob = append(blob, sshString(point)...)
	return blob
}

// opensshEnvelope builds an openssh-key-v1 blob containing one public key.
// The private section is irrelevant to the parser and left empty.
func opensshEnvelope(cipher string, pubBlob []byte) []byte {
	var out []byte
	out = append(out, []byte("openssh-key-v1\x00")...)
	out = append(out, sshString([]byte(cipher))...) // ciphername
	out = append(out, sshString([]byte("none"))...) // kdfname
	out = append(out, sshString(nil)...)            // kdfoptions
	var nkeys [4]byte
	binary.BigEndian.PutUint32(nkeys[:], 1)
	out = append(out, nkeys[:]...)
	out = append(out, sshString(pubBlob)...) // public key blob
	out = append(out, sshString(nil)...)     // encrypted private section
	return out
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func runScan(t *testing.T, dir string) []findings.UnifiedFinding {
	t.Helper()
	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return ff
}

// --- engine metadata ---------------------------------------------------------

func TestEngineMetadata(t *testing.T) {
	e := New()
	if e.Name() != "keyfile" {
		t.Errorf("Name = %q, want keyfile", e.Name())
	}
	if e.Tier() != engines.Tier1Pattern {
		t.Errorf("Tier = %v, want Tier1Pattern", e.Tier())
	}
	if !e.Available() {
		t.Error("Available = false, want true")
	}
	if e.Version() != "embedded" {
		t.Errorf("Version = %q, want embedded", e.Version())
	}
}

// --- table-driven parse cases ------------------------------------------------

func TestScan_KeyMaterial(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	tests := []struct {
		name      string
		file      string
		content   []byte
		wantAlg   string
		wantBits  int
		wantPrim  string
		wantLine  int
		wantCount int
	}{
		{
			name:      "rsa_2048_pem_certificate",
			file:      "server.crt",
			content:   pemEncode("CERTIFICATE", selfSignedCertDER(t, "example.com")),
			wantAlg:   "RSA",
			wantBits:  2048,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "rsa_der_certificate",
			file:      "server.der",
			content:   selfSignedCertDER(t, "der.example.com"),
			wantAlg:   "RSA",
			wantBits:  2048,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "ec_private_key_pem",
			file:      "ec.pem",
			content:   pemEncode("EC PRIVATE KEY", ecDER),
			wantAlg:   "ECDSA",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "ed25519_pkcs8_key",
			file:      "signing.key",
			content:   pemEncode("PRIVATE KEY", edDER),
			wantAlg:   "Ed25519",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "rsa_pkcs1_private_key",
			file:      "id_rsa_legacy.pem",
			content:   pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaTestKey)),
			wantAlg:   "RSA",
			wantBits:  2048,
			wantPrim:  "asymmetric",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name: "authorized_keys_rsa_line",
			file: "authorized_keys",
			content: []byte("ssh-rsa " +
				base64.StdEncoding.EncodeToString(sshRSABlob(&rsaTestKey.PublicKey)) +
				" user@host\n"),
			wantAlg:   "RSA",
			wantBits:  2048,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name: "known_hosts_ed25519_line",
			file: "known_hosts",
			content: []byte("example.com,10.0.0.1 ssh-ed25519 " +
				base64.StdEncoding.EncodeToString(sshEd25519Blob(edPub)) + "\n"),
			wantAlg:   "Ed25519",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name: "pub_file_ecdsa",
			file: "id_ecdsa.pub",
			content: []byte("ecdsa-sha2-nistp256 " +
				base64.StdEncoding.EncodeToString(sshECDSABlob("nistp256", []byte{4, 1, 2})) +
				" ci@runner\n"),
			wantAlg:   "ECDSA",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "openssh_private_key_ed25519",
			file:      "id_ed25519",
			content:   pemEncode("OPENSSH PRIVATE KEY", opensshEnvelope("none", sshEd25519Blob(edPub))),
			wantAlg:   "Ed25519",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
		{
			name:      "openssh_private_key_encrypted_still_reports_algo",
			file:      "id_ed25519_enc.key",
			content:   pemEncode("OPENSSH PRIVATE KEY", opensshEnvelope("aes256-ctr", sshEd25519Blob(edPub))),
			wantAlg:   "Ed25519",
			wantBits:  256,
			wantPrim:  "signature",
			wantLine:  1,
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file, tc.content)
			ff := runScan(t, dir)
			if len(ff) != tc.wantCount {
				t.Fatalf("got %d findings, want %d: %+v", len(ff), tc.wantCount, ff)
			}
			f := ff[0]
			if f.Algorithm == nil {
				t.Fatal("Algorithm is nil")
			}
			if f.Algorithm.Name != tc.wantAlg {
				t.Errorf("Algorithm.Name = %q, want %q", f.Algorithm.Name, tc.wantAlg)
			}
			if f.Algorithm.KeySize != tc.wantBits {
				t.Errorf("Algorithm.KeySize = %d, want %d", f.Algorithm.KeySize, tc.wantBits)
			}
			if f.Algorithm.Primitive != tc.wantPrim {
				t.Errorf("Algorithm.Primitive = %q, want %q", f.Algorithm.Primitive, tc.wantPrim)
			}
			if f.Location.Line != tc.wantLine {
				t.Errorf("Location.Line = %d, want %d", f.Location.Line, tc.wantLine)
			}
			if f.SourceEngine != "keyfile" {
				t.Errorf("SourceEngine = %q, want keyfile", f.SourceEngine)
			}
			if f.Confidence != findings.ConfidenceHigh {
				t.Errorf("Confidence = %q, want high", f.Confidence)
			}
		})
	}
}

func TestScan_CertificateContext(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "tls.pem", pemEncode("CERTIFICATE", selfSignedCertDER(t, "api.internal.example")))
	ff := runScan(t, dir)
	if len(ff) != 1 {
		t.Fatalf("got %d findings, want 1", len(ff))
	}
	raw := ff[0].RawIdentifier
	if want := `cn="api.internal.example"`; !contains(raw, want) {
		t.Errorf("RawIdentifier %q missing %q", raw, want)
	}
	if !contains(raw, "not-after=") {
		t.Errorf("RawIdentifier %q missing not-after", raw)
	}
}

func TestScan_AuthorizedKeysLineNumbers(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(
		"# managed by ansible\n" +
			"ssh-rsa " + base64.StdEncoding.EncodeToString(sshRSABlob(&rsaTestKey.PublicKey)) + " a@h\n" +
			"\n" +
			"no-pty,command=\"/bin/true\" ssh-ed25519 " + base64.StdEncoding.EncodeToString(sshEd25519Blob(edPub)) + " b@h\n")
	dir := t.TempDir()
	writeFile(t, dir, "authorized_keys", content)

	ff := runScan(t, dir)
	if len(ff) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(ff), ff)
	}
	if ff[0].Location.Line != 2 || ff[0].Algorithm.Name != "RSA" || ff[0].Algorithm.KeySize != 2048 {
		t.Errorf("first finding = line %d %s/%d, want line 2 RSA/2048",
			ff[0].Location.Line, ff[0].Algorithm.Name, ff[0].Algorithm.KeySize)
	}
	if ff[1].Location.Line != 4 || ff[1].Algorithm.Name != "Ed25519" {
		t.Errorf("second finding = line %d %s, want line 4 Ed25519",
			ff[1].Location.Line, ff[1].Algorithm.Name)
	}
}

func TestScan_MultiplePEMBlocksWithLineNumbers(t *testing.T) {
	certPEM := pemEncode("CERTIFICATE", selfSignedCertDER(t, "chain.example"))
	keyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaTestKey))
	combined := append(append([]byte{}, certPEM...), keyPEM...)

	dir := t.TempDir()
	writeFile(t, dir, "bundle.pem", combined)

	ff := runScan(t, dir)
	if len(ff) != 2 {
		t.Fatalf("got %d findings, want 2", len(ff))
	}
	if ff[0].Location.Line != 1 {
		t.Errorf("cert block line = %d, want 1", ff[0].Location.Line)
	}
	certLines := countLines(certPEM)
	if ff[1].Location.Line != certLines+1 {
		t.Errorf("key block line = %d, want %d", ff[1].Location.Line, certLines+1)
	}
	if ff[1].RawIdentifier != privateKeyRawID {
		t.Errorf("key RawIdentifier = %q, want %q", ff[1].RawIdentifier, privateKeyRawID)
	}
}

func TestScan_EncryptedKeys(t *testing.T) {
	t.Run("pkcs8_encrypted_envelope", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "enc.p8", pemEncode("ENCRYPTED PRIVATE KEY", []byte{0x30, 0x03, 0x02, 0x01, 0x00}))
		ff := runScan(t, dir)
		if len(ff) != 1 {
			t.Fatalf("got %d findings, want 1", len(ff))
		}
		if ff[0].Algorithm != nil {
			t.Errorf("Algorithm = %+v, want nil (opaque envelope)", ff[0].Algorithm)
		}
		if !contains(ff[0].RawIdentifier, "encrypted-private-key") {
			t.Errorf("RawIdentifier = %q, want encrypted-private-key marker", ff[0].RawIdentifier)
		}
	})

	t.Run("dek_info_rsa_key_reports_rsa", func(t *testing.T) {
		block := &pem.Block{
			Type: "RSA PRIVATE KEY",
			Headers: map[string]string{
				"Proc-Type": "4,ENCRYPTED",
				"DEK-Info":  "AES-128-CBC,0102030405060708090A0B0C0D0E0F10",
			},
			Bytes: []byte("not real ciphertext"),
		}
		dir := t.TempDir()
		writeFile(t, dir, "legacy.key", pem.EncodeToMemory(block))
		ff := runScan(t, dir)
		if len(ff) != 1 {
			t.Fatalf("got %d findings, want 1", len(ff))
		}
		if ff[0].Algorithm == nil || ff[0].Algorithm.Name != "RSA" {
			t.Fatalf("Algorithm = %+v, want RSA", ff[0].Algorithm)
		}
		if !contains(ff[0].RawIdentifier, "encrypted-private-key") {
			t.Errorf("RawIdentifier = %q, want encrypted-private-key marker", ff[0].RawIdentifier)
		}
	})
}

func TestScan_MalformedInputsNeverError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "garbage.pem", []byte("-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n"))
	writeFile(t, dir, "truncated.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"))
	writeFile(t, dir, "binary.der", []byte{0xde, 0xad, 0xbe, 0xef})
	writeFile(t, dir, "empty.key", nil)
	writeFile(t, dir, "authorized_keys", []byte("ssh-rsa notbase64!!! comment\nssh-rsa\n"))

	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan returned error on malformed input: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("got %d findings from malformed input, want 0: %+v", len(ff), ff)
	}
}

func TestScan_SkipsDotDirsVendorAndOversized(t *testing.T) {
	certPEM := pemEncode("CERTIFICATE", selfSignedCertDER(t, "skip.example"))
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".git", "cert.pem"), certPEM)
	writeFile(t, dir, filepath.Join(".ssh", "id_rsa.pub"), []byte("ssh-rsa AAAA x\n"))
	writeFile(t, dir, filepath.Join("vendor", "dep", "cert.pem"), certPEM)
	writeFile(t, dir, filepath.Join("node_modules", "m", "cert.pem"), certPEM)
	oversized := make([]byte, maxKeyFileSize+1)
	writeFile(t, dir, "huge.pem", oversized)
	writeFile(t, dir, "kept.pem", certPEM)

	ff := runScan(t, dir)
	if len(ff) != 1 {
		t.Fatalf("got %d findings, want only kept.pem: %+v", len(ff), ff)
	}
	if filepath.Base(ff[0].Location.File) != "kept.pem" {
		t.Errorf("finding file = %q, want kept.pem", ff[0].Location.File)
	}
}

func TestScan_IgnoresIrrelevantFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", []byte("ssh-rsa AAAA not scanned\n"))
	writeFile(t, dir, "main.go", []byte("package main\n"))
	ff := runScan(t, dir)
	if len(ff) != 0 {
		t.Errorf("got %d findings from irrelevant files, want 0", len(ff))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.pem", pemEncode("CERTIFICATE", selfSignedCertDER(t, "x")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Scan(ctx, engines.ScanOptions{TargetPath: dir})
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// --- small helpers -----------------------------------------------------------

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
