package zeeklog

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestSSLTSV_RoundTrip verifies that parsing a TSV log and re-serializing the
// records back to TSV, then re-parsing, yields the same set of unique records.
// This exercises the dedup key and field extraction idempotency.
func TestSSLTSV_RoundTrip(t *testing.T) {
	recs, err := parseSSLLog(context.Background(), strings.NewReader(sslTSVGolden))
	if err != nil {
		t.Fatalf("initial parse: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no records parsed — round-trip vacuous")
	}

	// Re-serialize to TSV.
	var sb strings.Builder
	sb.WriteString("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n")
	sb.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n")
	sb.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n")
	for i, r := range recs {
		sb.WriteString(fmt.Sprintf("1704067200.%d\tCr%d\t10.0.0.%d\t9999\t%s\t%s\t%s\t%s\t%s\t%s\tT\n",
			i, i, i, r.RespHost, r.RespPort, r.Version, r.Cipher, r.Curve, r.ServerName))
	}

	recs2, err := parseSSLLog(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("re-parse after round-trip: %v", err)
	}

	if len(recs) != len(recs2) {
		t.Errorf("round-trip record count: initial=%d re-parsed=%d", len(recs), len(recs2))
	}

	// Dedup keys must match.
	keys1 := make(map[string]bool, len(recs))
	for _, r := range recs {
		keys1[r.dedupeKey()] = true
	}
	for _, r := range recs2 {
		if !keys1[r.dedupeKey()] {
			t.Errorf("round-trip introduced unexpected dedup key: %s", r.dedupeKey())
		}
	}
}

// TestSSLDedup_OrderIndependent verifies that the dedup result is the same
// regardless of the order rows appear in the log.
func TestSSLDedup_OrderIndependent(t *testing.T) {
	header := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n"

	type row struct{ cipher, curve, host, port string }
	rows := []row{
		{"TLS_AES_256_GCM_SHA384", "X25519MLKEM768", "1.2.3.4", "443"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "secp256r1", "5.6.7.8", "443"},
		{"TLS_AES_128_GCM_SHA256", "X25519", "9.10.11.12", "8443"},
		// Duplicate of row 0 — must be deduped.
		{"TLS_AES_256_GCM_SHA384", "X25519MLKEM768", "1.2.3.4", "443"},
	}

	buildTSV := func(order []int) string {
		var sb strings.Builder
		sb.WriteString(header)
		for i, idx := range order {
			r := rows[idx]
			sb.WriteString(fmt.Sprintf("1704067200.%d\tCx%d\t10.0.0.%d\t5000\t%s\t%s\tTLSv13\t%s\t%s\texample.com\tT\n",
				i, i, i, r.host, r.port, r.cipher, r.curve))
		}
		return sb.String()
	}

	// Parse in original order.
	orig := []int{0, 1, 2, 3}
	recsA, err := parseSSLLog(context.Background(), strings.NewReader(buildTSV(orig)))
	if err != nil {
		t.Fatalf("orig order: %v", err)
	}

	// Parse in shuffled order (deterministic shuffle).
	rng := rand.New(rand.NewSource(42))
	shuffled := []int{0, 1, 2, 3}
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	recsB, err := parseSSLLog(context.Background(), strings.NewReader(buildTSV(shuffled)))
	if err != nil {
		t.Fatalf("shuffled order: %v", err)
	}

	if len(recsA) != len(recsB) {
		t.Errorf("dedup count: order-A=%d order-B=%d — dedup is order-dependent", len(recsA), len(recsB))
	}

	// Unique dedup keys must be identical.
	keysA := make(map[string]bool, len(recsA))
	for _, r := range recsA {
		keysA[r.dedupeKey()] = true
	}
	keysB := make(map[string]bool, len(recsB))
	for _, r := range recsB {
		keysB[r.dedupeKey()] = true
	}
	for k := range keysA {
		if !keysB[k] {
			t.Errorf("key present in A but not B: %s", k)
		}
	}
	for k := range keysB {
		if !keysA[k] {
			t.Errorf("key present in B but not A: %s", k)
		}
	}
}

// TestSSLJSON_RoundTrip verifies JSON-parsed records are consistent.
func TestSSLJSON_RoundTrip(t *testing.T) {
	recs, err := parseSSLLog(context.Background(), strings.NewReader(sslJSONGolden))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no records — round-trip vacuous")
	}

	// All records must have non-empty dedup keys.
	for _, r := range recs {
		if r.dedupeKey() == "|||" {
			t.Errorf("record has empty dedup key: %+v", r)
		}
	}
}

// TestSSLDedupeKey_Uniqueness verifies that distinct (host,port,cipher,curve) combos
// each produce distinct dedup keys.
func TestSSLDedupeKey_Uniqueness(t *testing.T) {
	cases := []SSLRecord{
		{RespHost: "1.2.3.4", RespPort: "443", Cipher: "TLS_AES_256_GCM_SHA384", Curve: "X25519MLKEM768"},
		{RespHost: "1.2.3.4", RespPort: "443", Cipher: "TLS_AES_256_GCM_SHA384", Curve: "secp256r1"},
		{RespHost: "1.2.3.4", RespPort: "8443", Cipher: "TLS_AES_256_GCM_SHA384", Curve: "X25519MLKEM768"},
		{RespHost: "5.6.7.8", RespPort: "443", Cipher: "TLS_AES_256_GCM_SHA384", Curve: "X25519MLKEM768"},
		{RespHost: "1.2.3.4", RespPort: "443", Cipher: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Curve: "secp256r1"},
	}

	seen := make(map[string]int)
	for i, r := range cases {
		k := r.dedupeKey()
		if prev, ok := seen[k]; ok {
			t.Errorf("records[%d] and records[%d] have same dedup key %q — expected unique", prev, i, k)
		}
		seen[k] = i
	}
}
