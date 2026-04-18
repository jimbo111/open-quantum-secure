package suricatalog

import (
	"context"
	"strings"
	"testing"
)

// TestJA3SMatrix_EmptyHash verifies that an empty hash is not found in the DB.
func TestJA3SMatrix_EmptyHash(t *testing.T) {
	_, ok := lookupJA3S("")
	if ok {
		t.Fatal("empty hash must not match any JA3S entry")
	}
}

// TestJA3SMatrix_AllZeroHash verifies that an all-zero hash is not found.
func TestJA3SMatrix_AllZeroHash(t *testing.T) {
	_, ok := lookupJA3S("00000000000000000000000000000000")
	if ok {
		t.Fatal("all-zero MD5 hash must not match any JA3S entry")
	}
}

// TestJA3SMatrix_ValidLookingUnknownHashes verifies well-formed MD5 hashes that
// are not in the DB return false.
func TestJA3SMatrix_ValidLookingUnknownHashes(t *testing.T) {
	unknowns := []string{
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"ffffffffffffffffffffffffffffffff",
		"0123456789abcdef0123456789abcdef",
		"1234567890abcdef1234567890abcdef",
	}
	for _, h := range unknowns {
		_, ok := lookupJA3S(h)
		if ok {
			t.Errorf("hash %q unexpectedly matched in JA3S DB (DB should be empty pending authoritative fingerprints)", h)
		}
	}
}

// TestJA3SMatrix_DBStructureInvariant ensures all current DB entries (if any)
// have non-empty keys and Labels. Enforces structural guarantees for future additions.
func TestJA3SMatrix_DBStructureInvariant(t *testing.T) {
	for hash, hint := range ja3sDB {
		if hash == "" {
			t.Error("ja3sDB has an entry with an empty string key — all keys must be non-empty")
		}
		if hint.Label == "" {
			t.Errorf("ja3sDB entry %q has empty Label — all entries must carry a human-readable label", hash)
		}
	}
}

// TestJA3SMatrix_HashVsStringDistinguishable verifies that the parser reads the JA3S
// "hash" field correctly and does NOT conflate it with the "string" field.
// The two fields must be independently parsed from the {"hash":..., "string":...} sub-object.
func TestJA3SMatrix_HashVsStringDistinguishable(t *testing.T) {
	// Use a valid 32-char lowercase hex hash (validateJA3Hash rejects non-conforming values).
	const wantHash = "aabbccddeeff00112233445566778899"
	const line = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","ja3s":{"hash":"aabbccddeeff00112233445566778899","string":"thetlsstring"}}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.JA3SHash != wantHash {
		t.Errorf("JA3SHash = %q, want %q (must come from 'hash' field, not 'string')", r.JA3SHash, wantHash)
	}
}

// TestJA3SMatrix_JA3AndJA3SIndependent verifies that JA3 (client) hash and JA3S
// (server) hash are independently parsed and stored.
func TestJA3SMatrix_JA3AndJA3SIndependent(t *testing.T) {
	// Use valid 32-char lowercase hex hashes (validateJA3Hash rejects non-conforming values).
	const wantClientHash = "11223344556677889900aabbccddeeff"
	const wantServerHash = "ffeeddccbbaa00998877665544332211"
	const line = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","ja3":{"hash":"11223344556677889900aabbccddeeff","string":"client-string"},"ja3s":{"hash":"ffeeddccbbaa00998877665544332211","string":"server-string"}}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.JA3Hash != wantClientHash {
		t.Errorf("JA3Hash = %q, want %q", r.JA3Hash, wantClientHash)
	}
	if r.JA3SHash != wantServerHash {
		t.Errorf("JA3SHash = %q, want %q", r.JA3SHash, wantServerHash)
	}
}

// TestJA3SMatrix_MissingJA3SSubObject verifies that a TLS event without a ja3s
// sub-object produces JA3SHash = "".
func TestJA3SMatrix_MissingJA3SSubObject(t *testing.T) {
	const line = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].JA3SHash != "" {
		t.Errorf("JA3SHash = %q, want empty string when ja3s object absent", recs[0].JA3SHash)
	}
}
