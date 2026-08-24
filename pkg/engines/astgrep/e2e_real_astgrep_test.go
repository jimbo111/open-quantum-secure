package astgrep

// End-to-end sanity test against a real ast-grep binary on PATH.
// Opt-in via OQS_ASTGREP_E2E=1 (skipped otherwise, so CI without ast-grep
// is unaffected). Pins the full pipeline: embedded rule flatten -> real CLI
// -> nested metaVariables JSON -> algorithm/keysize/mode extraction.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestE2E_RealAstGrep(t *testing.T) {
	if os.Getenv("OQS_ASTGREP_E2E") == "" {
		t.Skip("set OQS_ASTGREP_E2E=1 to run")
	}
	e := New()
	if !e.Available() {
		t.Fatal("ast-grep not on PATH")
	}
	dir := t.TempDir()
	files := map[string]string{
		"a.go": `package main
func main() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	h := md5.New()
	mac := hmac.New(sha256.New, key)
	kex, _ := ecdh.P256().GenerateKey(rand.Reader)
	_ = tls.Config{MinVersion: tls.VersionTLS12}
	_, _, _, _ = k, h, mac, kex
}`,
		"b.js": `const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki' } });
const h = crypto.createHash('md5');
const dh = crypto.createDiffieHellman(2048);
const ecdh = crypto.createECDH('secp256k1');
const tok = jwt.sign(payload, key, { algorithm: 'RS256', expiresIn: '1h' });
crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);`,
		"c.ts": `const kp = crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, cb);
const s = crypto.createSign('RSA-SHA256');`,
		"d.py": `import hashlib
h = hashlib.md5(data)
k = RSA.generate(2048)
c = AES.new(key, AES.MODE_CBC)`,
		"e.c": `void f() {
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
	SSL_CTX_new(TLSv1_2_client_method());
	RSA_generate_key_ex(rsa, 2048, e, NULL);
}`,
		"f.java": `class X { void m() throws Exception {
	Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
	Signature s = Signature.getInstance("SHA256withRSA");
	KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range res {
		alg := "<nil>"
		ks := 0
		mode, curve, prim := "", "", ""
		if f.Algorithm != nil {
			alg = f.Algorithm.Name
			ks = f.Algorithm.KeySize
			mode = f.Algorithm.Mode
			curve = f.Algorithm.Curve
			prim = f.Algorithm.Primitive
		}
		t.Logf("%-14s L%-3d %-42s alg=%-16s prim=%-10s ks=%-5d mode=%-4s curve=%s",
			filepath.Base(f.Location.File), f.Location.Line, f.RawIdentifier, alg, prim, ks, mode, curve)
	}
	// Spot-check the poisoning fixes end-to-end.
	want := map[string]string{
		"crypto-go-rsa-generate-key":                 "RSA",
		"crypto-go-md5-new":                          "MD5",
		"crypto-go-ecdh-generate-key":                "ECDH",
		"crypto-go-hmac-new":                         "HMAC-SHA256",
		"crypto-go-tls-config":                       "TLS",
		"crypto-node-generate-key-pair-sync":         "RSA",
		"crypto-node-create-hash":                    "MD5",
		"crypto-node-create-diffie-hellman":          "DH",
		"crypto-node-create-ecdh":                    "ECDH",
		"crypto-node-jwt-sign":                       "RSA",
		"crypto-node-generate-key-pair-ts":           "ECDSA",
		"crypto-python-hashlib-md5":                  "MD5",
		"crypto-python-pycryptodome-rsa-generate":    "RSA",
		"crypto-openssl-evp-encrypt-init":            "AES",
		"crypto-openssl-ssl-ctx-new":                 "TLSv1.2",
		"crypto-openssl-rsa-generate-key-ex":         "RSA",
		"crypto-java-cipher":                         "AES/CBC/PKCS5Padding",
		"crypto-java-signature":                      "RSA",
		"crypto-java-key-pair-generator":             "RSA",
	}
	got := map[string]string{}
	for _, f := range res {
		if f.Algorithm != nil {
			if _, seen := got[f.RawIdentifier]; !seen {
				got[f.RawIdentifier] = f.Algorithm.Name
			}
		}
	}
	for id, alg := range want {
		if got[id] != alg {
			t.Errorf("rule %s: alg=%q, want %q", id, got[id], alg)
		}
	}
}
