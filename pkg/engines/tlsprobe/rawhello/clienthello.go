package rawhello

import (
	"crypto/rand"
	"fmt"
)

// defaultCipherSuites are the TLS 1.3 cipher suites advertised in probes.
var defaultCipherSuites = []uint16{
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256
}

// DefaultCipherSuites returns a copy of the default TLS 1.3 cipher suite list.
// A copy is returned so callers cannot mutate the package-level slice.
func DefaultCipherSuites() []uint16 { return append([]uint16(nil), defaultCipherSuites...) }

// defaultSigAlgs is the default signature_algorithms list for probes.
var defaultSigAlgs = []uint16{
	0x0804, // rsa_pss_rsae_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	0x0807, // ed25519
	0x0401, // rsa_pkcs1_sha256
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
}

// defaultProbeGroups are the SupportedGroup codepoints tested by --deep-probe.
// Each group is probed individually to isolate server acceptance.
var defaultProbeGroups = []uint16{
	0x001d, // X25519 (classical baseline)
	0x11ec, // X25519MLKEM768 (hybrid, final)
	0x11eb, // SecP256r1MLKEM768 (hybrid, final)
	0x0201, // MLKEM768 (pure PQ, final)
	0x0202, // MLKEM1024 (pure PQ, final)
	0x0200, // MLKEM512 (pure PQ, final)
}

// DefaultProbeGroups returns a copy of the default group codepoint list probed
// by --deep-probe. A copy is returned so callers cannot mutate the package-level slice.
func DefaultProbeGroups() []uint16 { return append([]uint16(nil), defaultProbeGroups...) }

// KeyShareEntry is a single key_share advertised in the ClientHello key_share extension.
// PublicKey must contain the correct number of bytes for the group (see ProbeKeyShare).
// This is probe-only: the server responds HRR/SH based on the group codepoint,
// not on the actual key material, so random bytes of the right length suffice.
type KeyShareEntry struct {
	GroupID   uint16
	PublicKey []byte
}

// ClientHelloOpts configures the ClientHello message.
type ClientHelloOpts struct {
	SNI             string         // server_name extension value (empty = omit extension)
	SupportedGroups []uint16       // supported_groups extension (nil = omit)
	KeyShares       []KeyShareEntry // key_share extension entries (nil = omit)
	CipherSuites    []uint16       // nil = DefaultCipherSuites
	SigAlgs         []uint16       // nil = defaultSigAlgs
}

// BuildClientHello constructs a raw TLS record containing a TLS 1.3 ClientHello
// per RFC 8446 §4.1.2. Returns the full record bytes (record header included).
func BuildClientHello(opts ClientHelloOpts) ([]byte, error) {
	ciphers := opts.CipherSuites
	if len(ciphers) == 0 {
		ciphers = defaultCipherSuites
	}
	sigAlgs := opts.SigAlgs
	if len(sigAlgs) == 0 {
		sigAlgs = defaultSigAlgs
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("rawhello: BuildClientHello: crypto/rand: %w", err)
	}
	// legacy_session_id: 32 random bytes for middlebox compat (RFC 8446 appendix D.4).
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("rawhello: BuildClientHello: crypto/rand session_id: %w", err)
	}

	exts, err := buildExtensions(opts.SNI, opts.SupportedGroups, opts.KeyShares, sigAlgs)
	if err != nil {
		return nil, err
	}
	if len(exts) > 65535 {
		return nil, fmt.Errorf("rawhello: BuildClientHello: extensions total %d bytes exceeds uint16 max", len(exts))
	}

	cipherLen := len(ciphers) * 2
	if cipherLen > 65535 {
		return nil, fmt.Errorf("rawhello: BuildClientHello: cipher suite list too long")
	}

	// ClientHello body:
	//   legacy_version(2) + random(32) + session_id_len(1) + session_id(32) +
	//   cipher_suites_len(2) + cipher_suites(N*2) + compression(2) +
	//   extensions_len(2) + extensions(M)
	bodyLen := 2 + 32 + 1 + 32 + 2 + cipherLen + 2 + 2 + len(exts)
	if bodyLen > MaxHandshakeMsgLen {
		return nil, fmt.Errorf("rawhello: BuildClientHello: body %d bytes exceeds cap %d", bodyLen, MaxHandshakeMsgLen)
	}

	// Handshake message = type(1) + length(3) + body.
	msgLen := 4 + bodyLen
	if msgLen > MaxRecordLen {
		return nil, fmt.Errorf("rawhello: BuildClientHello: message %d bytes exceeds MaxRecordLen %d", msgLen, MaxRecordLen)
	}

	out := make([]byte, 0, 5+msgLen)

	// TLS record header (5 bytes).
	out = append(out, RecordTypeHandshake)
	out = appendU16(out, LegacyRecordVersion)
	out = appendU16(out, uint16(msgLen))

	// Handshake header: type=0x01 (client_hello) + uint24 body length.
	out = append(out, 0x01)
	out = appendU24(out, uint32(bodyLen))

	// legacy_version = 0x0303 (always, per RFC 8446 §4.1.2).
	out = append(out, 0x03, 0x03)
	out = append(out, random[:]...)
	// legacy_session_id: 1-byte length + 32 bytes.
	out = append(out, 32)
	out = append(out, sessionID[:]...)
	// cipher_suites: 2-byte length + ciphers.
	out = appendU16(out, uint16(cipherLen))
	for _, cs := range ciphers {
		out = appendU16(out, cs)
	}
	// legacy_compression_methods: length=1, only null(0x00).
	out = append(out, 0x01, 0x00)
	// extensions: 2-byte length + body.
	out = appendU16(out, uint16(len(exts)))
	out = append(out, exts...)

	return out, nil
}

// buildExtensions assembles the full extensions block in wire order.
func buildExtensions(sni string, groups []uint16, keyShares []KeyShareEntry, sigAlgs []uint16) ([]byte, error) {
	var b []byte

	if sni != "" {
		ext, err := extSNI(sni)
		if err != nil {
			return nil, err
		}
		b = append(b, ext...)
	}

	b = append(b, extSupportedVersions()...)

	if len(groups) > 0 {
		b = append(b, extSupportedGroups(groups)...)
	}

	if len(sigAlgs) > 0 {
		b = append(b, extSigAlgs(sigAlgs)...)
	}

	if len(keyShares) > 0 {
		ext, err := extKeyShare(keyShares)
		if err != nil {
			return nil, err
		}
		b = append(b, ext...)
	}

	return b, nil
}

// extSNI builds the server_name extension (RFC 6066 §3).
func extSNI(sni string) ([]byte, error) {
	if len(sni) > 255 {
		return nil, fmt.Errorf("rawhello: SNI too long (%d bytes)", len(sni))
	}
	sniB := []byte(sni)
	// HostName entry: type(1) + len(2) + name
	nameEntryLen := 1 + 2 + len(sniB)
	// ServerNameList: listLen(2) + entries
	var b []byte
	b = appendU16(b, 0x0000)                     // ExtensionType server_name
	b = appendU16(b, uint16(2+nameEntryLen))      // extension data length
	b = appendU16(b, uint16(nameEntryLen))        // ServerNameList length
	b = append(b, 0x00)                           // NameType host_name
	b = appendU16(b, uint16(len(sniB)))
	b = append(b, sniB...)
	return b, nil
}

// extSupportedVersions builds the supported_versions extension (RFC 8446 §4.2.1).
// Advertises only TLS 1.3 (0x0304).
func extSupportedVersions() []byte {
	var b []byte
	b = appendU16(b, 0x002b) // supported_versions
	b = appendU16(b, 3)      // extension data length: 1 + 2
	b = append(b, 0x02)      // VersionList length = 2 bytes
	b = append(b, 0x03, 0x04) // TLS 1.3
	return b
}

// extSupportedGroups builds the supported_groups extension (RFC 8446 §4.2.7).
func extSupportedGroups(groups []uint16) []byte {
	listLen := len(groups) * 2
	var b []byte
	b = appendU16(b, 0x000a)               // supported_groups
	b = appendU16(b, uint16(2+listLen))    // extension data length
	b = appendU16(b, uint16(listLen))      // NamedGroupList length
	for _, g := range groups {
		b = appendU16(b, g)
	}
	return b
}

// extSigAlgs builds the signature_algorithms extension (RFC 8446 §4.2.3).
func extSigAlgs(algs []uint16) []byte {
	listLen := len(algs) * 2
	var b []byte
	b = appendU16(b, 0x000d)               // signature_algorithms
	b = appendU16(b, uint16(2+listLen))    // extension data length
	b = appendU16(b, uint16(listLen))      // SignatureSchemeList length
	for _, a := range algs {
		b = appendU16(b, a)
	}
	return b
}

// extKeyShare builds the key_share extension for a ClientHello (RFC 8446 §4.2.8).
func extKeyShare(shares []KeyShareEntry) ([]byte, error) {
	var entries []byte
	for _, ks := range shares {
		if len(ks.PublicKey) > 65535 {
			return nil, fmt.Errorf("rawhello: key share group 0x%04x too long (%d bytes)", ks.GroupID, len(ks.PublicKey))
		}
		entries = appendU16(entries, ks.GroupID)
		entries = appendU16(entries, uint16(len(ks.PublicKey)))
		entries = append(entries, ks.PublicKey...)
	}
	if len(entries) > 65535 {
		return nil, fmt.Errorf("rawhello: key_share entries total %d bytes exceeds uint16 max", len(entries))
	}
	var b []byte
	b = appendU16(b, 0x0033)                    // key_share
	b = appendU16(b, uint16(2+len(entries)))    // extension data length
	b = appendU16(b, uint16(len(entries)))      // KeyShareClientHello list length
	b = append(b, entries...)
	return b, nil
}

// ProbeKeyShare generates a KeyShareEntry with cryptographically-random bytes
// of the correct length for the given group. This is probe-only — the server
// accepts or rejects based on the group codepoint, not the key material.
// Returns an error for unknown groups.
func ProbeKeyShare(groupID uint16) (KeyShareEntry, error) {
	size, ok := probeKeyShareClientSize(groupID)
	if !ok {
		return KeyShareEntry{}, fmt.Errorf("rawhello: unknown key share size for group 0x%04x", groupID)
	}
	pub := make([]byte, size)
	if _, err := rand.Read(pub); err != nil {
		return KeyShareEntry{}, fmt.Errorf("rawhello: ProbeKeyShare group 0x%04x: %w", groupID, err)
	}
	return KeyShareEntry{GroupID: groupID, PublicKey: pub}, nil
}

// probeKeyShareClientSize returns the client-side key_exchange byte length for a
// group per RFC 8446, FIPS 203, and draft-ietf-tls-hybrid-design-16.
// Hybrid KEM client sizes = classical_pubkey || mlkem_encapsulation_key.
func probeKeyShareClientSize(groupID uint16) (int, bool) {
	sizes := map[uint16]int{
		0x001d: 32,        // X25519
		0x0017: 65,        // secp256r1 uncompressed
		0x0018: 97,        // secp384r1
		0x0019: 133,       // secp521r1
		0x0200: 800,       // MLKEM512 encapsulation key (FIPS 203)
		0x0201: 1184,      // MLKEM768 encapsulation key
		0x0202: 1568,      // MLKEM1024 encapsulation key
		0x11eb: 65 + 1184, // SecP256r1MLKEM768
		0x11ec: 32 + 1184, // X25519MLKEM768
		0x11ed: 97 + 1568, // SecP384r1MLKEM1024
		0x11ee: 65 + 1184, // curveSM2MLKEM768
	}
	s, ok := sizes[groupID]
	return s, ok
}

// appendU16 appends a big-endian uint16 to b.
func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendU24 appends a 3-byte big-endian uint24 to b.
func appendU24(b []byte, v uint32) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}
