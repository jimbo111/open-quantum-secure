package suricatalog

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCorpus_Suricata6Classical exercises the curated Suricata 6.x corpus with
// classical TLS 1.2 and TLS 1.3 events.
//
// File: testdata/eve_suricata6_classical.json
//   - 3 TLS events (1x TLS1.2 ECDHE-RSA, 2x TLS1.3 AES-GCM), 1 alert, 1 http.
//   - Expected: 3 unique TLS records (non-TLS events discarded).
func TestCorpus_Suricata6Classical(t *testing.T) {
	recs, err := readEveJSON(context.Background(), "testdata/eve_suricata6_classical.json")
	if err != nil {
		t.Fatalf("readEveJSON: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("Suricata6 classical corpus: got %d records, want 3", len(recs))
	}

	// Verify TLS versions are represented.
	versions := make(map[string]bool)
	for _, r := range recs {
		versions[r.Version] = true
	}
	if !versions["TLSv1.2"] {
		t.Error("expected TLSv1.2 record in Suricata6 corpus")
	}
	if !versions["TLSv1.3"] {
		t.Error("expected TLSv1.3 record in Suricata6 corpus")
	}

	// At least one record should have a JA3S hash (from the first event in fixture).
	var hasJA3S bool
	for _, r := range recs {
		if r.JA3SHash != "" {
			hasJA3S = true
			break
		}
	}
	if !hasJA3S {
		t.Error("expected at least one JA3S hash in Suricata6 corpus")
	}
}

// TestCorpus_Suricata7SigAlgs exercises the curated Suricata 7.x corpus with
// custom sigalgs and groups fields (requires oqs-tls.yaml Suricata config).
//
// File: testdata/eve_suricata7_sigalgs.json
//   - 3 TLS events with sigalgs and groups, 1 dns event.
//   - Expected: 3 unique TLS records with SigAlgs and Groups populated.
func TestCorpus_Suricata7SigAlgs(t *testing.T) {
	recs, err := readEveJSON(context.Background(), "testdata/eve_suricata7_sigalgs.json")
	if err != nil {
		t.Fatalf("readEveJSON: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("Suricata7 sigalgs corpus: got %d records, want 3", len(recs))
	}

	// At least one record must have SigAlgs populated.
	var hasSigAlgs bool
	for _, r := range recs {
		if r.SigAlgs != "" {
			hasSigAlgs = true
			break
		}
	}
	if !hasSigAlgs {
		t.Error("expected at least one record with SigAlgs in Suricata7 corpus")
	}

	// At least one record must have Groups populated.
	var hasGroups bool
	for _, r := range recs {
		if r.Groups != "" {
			hasGroups = true
			break
		}
	}
	if !hasGroups {
		t.Error("expected at least one record with Groups in Suricata7 corpus")
	}

	// Verify that TLS findings are produced (sigalgs triggers per-algorithm findings).
	var allFindings int
	for _, r := range recs {
		allFindings += len(tlsRecordToFindings(r))
	}
	if allFindings == 0 {
		t.Error("no findings produced from Suricata7 sigalgs corpus")
	}
}

// TestCorpus_PQCChain exercises the corpus with a PQC-capable TLS event that
// includes a certificate chain array. The chain[] field is not parsed by the
// current implementation (the struct does not include it), so it is silently
// ignored — this test verifies graceful handling.
//
// File: testdata/eve_pqc_chain.json
//   - 2 TLS events (PQC groups: X25519MLKEM768), 1 flow event.
//   - Expected: 2 unique TLS records with Groups field populated.
func TestCorpus_PQCChain(t *testing.T) {
	recs, err := readEveJSON(context.Background(), "testdata/eve_pqc_chain.json")
	if err != nil {
		t.Fatalf("readEveJSON: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("PQC chain corpus: got %d records, want 2", len(recs))
	}

	// Verify Groups field includes PQC group names.
	var hasPQCGroup bool
	for _, r := range recs {
		if r.Groups != "" {
			hasPQCGroup = true
		}
	}
	if !hasPQCGroup {
		t.Error("expected at least one record with PQC Groups in pqc_chain corpus")
	}

	// Produce findings and verify at least one is produced.
	var count int
	for _, r := range recs {
		count += len(tlsRecordToFindings(r))
	}
	if count == 0 {
		t.Error("no findings produced from PQC chain corpus")
	}
}

// TestCorpus_Suricata6Gzip verifies that gzip-compressed eve.json produces the
// same records as the uncompressed version. The .gz file is created on-the-fly
// from the uncompressed golden fixture.
func TestCorpus_Suricata6Gzip(t *testing.T) {
	// Read the golden uncompressed fixture.
	src, err := os.ReadFile("testdata/eve_suricata6_classical.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}

	// Compress to a temp .gz file.
	tmp := filepath.Join(t.TempDir(), "eve_suricata6_classical.json.gz")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create gz: %v", err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(src); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	gz.Close()
	f.Close()

	// Parse both and compare record counts.
	plain, err := readEveJSON(context.Background(), "testdata/eve_suricata6_classical.json")
	if err != nil {
		t.Fatalf("read plain: %v", err)
	}
	compressed, err := readEveJSON(context.Background(), tmp)
	if err != nil {
		t.Fatalf("read gz: %v", err)
	}

	if len(plain) != len(compressed) {
		t.Errorf("record count mismatch: plain=%d gz=%d", len(plain), len(compressed))
	}

	// Verify dedup keys match.
	plainKeys := make(map[string]bool, len(plain))
	for _, r := range plain {
		plainKeys[r.dedupeKey()] = true
	}
	for _, r := range compressed {
		if !plainKeys[r.dedupeKey()] {
			t.Errorf("gz record with key %q missing from plain result", r.dedupeKey())
		}
	}
}
