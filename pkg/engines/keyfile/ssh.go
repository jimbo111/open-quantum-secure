package keyfile

// Minimal SSH wire-format parsing (RFC 4251 §5 string encoding, RFC 4253
// public key blobs, and the OpenSSH openssh-key-v1 private key envelope).
//
// go.mod deliberately does not carry golang.org/x/crypto, so this file
// implements the small subset needed to inventory key TYPES and SIZES —
// no cryptographic operations are performed.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// sshBlobReader reads length-prefixed fields from an SSH wire-format blob.
type sshBlobReader struct{ b []byte }

// readString reads one RFC 4251 string (uint32 length + bytes).
func (r *sshBlobReader) readString() ([]byte, bool) {
	if len(r.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, false
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, true
}

// readUint32 reads one big-endian uint32.
func (r *sshBlobReader) readUint32() (uint32, bool) {
	if len(r.b) < 4 {
		return 0, false
	}
	n := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return n, true
}

// isSSHKeyType reports whether tok looks like an SSH public key algorithm
// name (the first field of a key entry after any options/host patterns).
func isSSHKeyType(tok string) bool {
	return strings.HasPrefix(tok, "ssh-") ||
		strings.HasPrefix(tok, "ecdsa-sha2-") ||
		strings.HasPrefix(tok, "sk-ssh-") ||
		strings.HasPrefix(tok, "sk-ecdsa-")
}

// nistCurveBits maps SSH nistp curve identifiers to bit sizes.
var nistCurveBits = map[string]int{
	"nistp256": 256,
	"nistp384": 384,
	"nistp521": 521,
}

// sshKeyTypeInfo resolves an SSH key type NAME to (algorithm, bits, curve)
// without decoding the blob. Used as a fallback when the base64 blob is
// truncated or malformed but the type token is recognizable.
func sshKeyTypeInfo(keyType string) (string, int, string) {
	t := strings.TrimSuffix(keyType, "-cert-v01@openssh.com")
	t = strings.TrimSuffix(t, "@openssh.com")
	t = strings.TrimPrefix(t, "sk-")
	switch {
	case t == "ssh-rsa":
		return "RSA", 0, ""
	case t == "ssh-dss":
		return "DSA", 0, ""
	case t == "ssh-ed25519":
		return "Ed25519", 256, ""
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		curve := strings.TrimPrefix(t, "ecdsa-sha2-")
		return "ECDSA", nistCurveBits[curve], curve
	}
	return "", 0, ""
}

// parseSSHPublicKeyBlob decodes an SSH wire-format public key blob into
// (algorithm, bits, curve). Certificate variants (*-cert-v01@openssh.com)
// are handled by skipping the leading nonce. Returns "" name on failure.
func parseSSHPublicKeyBlob(blob []byte) (string, int, string) {
	r := &sshBlobReader{blob}
	algoB, ok := r.readString()
	if !ok {
		return "", 0, ""
	}
	algo := string(algoB)
	if strings.HasSuffix(algo, "-cert-v01@openssh.com") {
		if _, ok := r.readString(); !ok { // nonce
			return sshKeyTypeInfo(algo)
		}
		algo = strings.TrimSuffix(algo, "-cert-v01@openssh.com")
	}

	switch {
	case algo == "ssh-rsa":
		if _, ok := r.readString(); !ok { // exponent e
			return sshKeyTypeInfo(algo)
		}
		n, ok := r.readString()
		if !ok {
			return sshKeyTypeInfo(algo)
		}
		return "RSA", new(big.Int).SetBytes(n).BitLen(), ""
	case algo == "ssh-dss":
		p, ok := r.readString()
		if !ok {
			return sshKeyTypeInfo(algo)
		}
		return "DSA", new(big.Int).SetBytes(p).BitLen(), ""
	case algo == "ssh-ed25519", algo == "sk-ssh-ed25519@openssh.com":
		return "Ed25519", 256, ""
	case strings.HasPrefix(algo, "ecdsa-sha2-"), strings.HasPrefix(algo, "sk-ecdsa-sha2-"):
		curveB, ok := r.readString()
		if !ok {
			return sshKeyTypeInfo(algo)
		}
		curve := string(curveB)
		return "ECDSA", nistCurveBits[curve], curve
	}
	return sshKeyTypeInfo(algo)
}

// scanSSHKeyLines scans authorized_keys / known_hosts / *.pub content.
// Both formats put "<keytype> <base64-blob>" somewhere on each line
// (known_hosts prefixes host patterns and optional @markers; authorized_keys
// may prefix options), so a single token scan covers all of them.
// Emits one finding per parseable key line with the correct line number.
func scanSSHKeyLines(path string, data []byte) []findings.UnifiedFinding {
	var out []findings.UnifiedFinding
	for i, ln := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(ln)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		fields := strings.Fields(string(trimmed))
		for j, tok := range fields {
			if !isSSHKeyType(tok) || j+1 >= len(fields) {
				continue
			}
			blob, err := base64.StdEncoding.DecodeString(fields[j+1])
			if err != nil {
				continue
			}
			name, size, curve := parseSSHPublicKeyBlob(blob)
			if name == "" {
				name, size, curve = sshKeyTypeInfo(tok)
			}
			if name == "" {
				continue
			}
			out = append(out, newFinding(path, i+1, &findings.Algorithm{
				Name:      name,
				Primitive: "signature",
				KeySize:   size,
				Curve:     curve,
			}, "ssh-public-key "+tok, findings.ConfidenceHigh))
			break // one key per line
		}
	}
	return out
}

// opensshMagic is the openssh-key-v1 envelope preamble.
var opensshMagic = []byte("openssh-key-v1\x00")

// opensshPrivateKeyFinding parses the openssh-key-v1 envelope. The embedded
// PUBLIC key blob is always plaintext — even when the private section is
// encrypted — so algorithm and size are recoverable either way.
func opensshPrivateKeyFinding(path string, line int, der []byte) *findings.UnifiedFinding {
	if !bytes.HasPrefix(der, opensshMagic) {
		return encryptedUnknownOpenSSH(path, line)
	}
	r := &sshBlobReader{der[len(opensshMagic):]}
	cipherName, ok := r.readString()
	if !ok {
		return encryptedUnknownOpenSSH(path, line)
	}
	if _, ok := r.readString(); !ok { // kdfname
		return encryptedUnknownOpenSSH(path, line)
	}
	if _, ok := r.readString(); !ok { // kdfoptions
		return encryptedUnknownOpenSSH(path, line)
	}
	if _, ok := r.readUint32(); !ok { // number of keys
		return encryptedUnknownOpenSSH(path, line)
	}
	pubBlob, ok := r.readString()
	if !ok {
		return encryptedUnknownOpenSSH(path, line)
	}

	name, size, curve := parseSSHPublicKeyBlob(pubBlob)
	encrypted := string(cipherName) != "none"

	rawID := privateKeyRawID + " (openssh)"
	if encrypted {
		rawID = "encrypted-private-key committed to repository (openssh)"
	}
	if name == "" {
		f := newFinding(path, line, nil, rawID, findings.ConfidenceMedium)
		return &f
	}
	f := newFinding(path, line, &findings.Algorithm{
		Name:      name,
		Primitive: "signature",
		KeySize:   size,
		Curve:     curve,
	}, rawID, findings.ConfidenceHigh)
	return &f
}

// encryptedUnknownOpenSSH is the tolerant fallback for a corrupt or
// unrecognized OPENSSH PRIVATE KEY body.
func encryptedUnknownOpenSSH(path string, line int) *findings.UnifiedFinding {
	f := newFinding(path, line, nil,
		"ssh-private-key (unparseable openssh-key-v1 envelope)",
		findings.ConfidenceMedium)
	return &f
}
