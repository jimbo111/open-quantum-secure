package zeeklog

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestX509TSV_RoundTrip verifies that re-serializing parsed records and
// re-parsing yields the same count and dedup keys.
func TestX509TSV_RoundTrip(t *testing.T) {
	recs, err := parseX509Log(context.Background(), strings.NewReader(x509TSVGolden))
	if err != nil {
		t.Fatalf("initial parse: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no records — round-trip vacuous")
	}

	// Re-serialize to minimal TSV.
	var sb strings.Builder
	sb.WriteString("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tx509\n")
	sb.WriteString("#fields\tts\tid\tcertificate.key_alg\tcertificate.sig_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n")
	sb.WriteString("#types\ttime\tstring\tstring\tstring\tstring\tcount\tstring\tvector[string]\n")
	for i, r := range recs {
		curve := r.Curve
		if curve == "" {
			curve = "-"
		}
		san := r.SANDNS
		if san == "" {
			san = "-"
		}
		kl := fmt.Sprintf("%d", r.KeyLen)
		sb.WriteString(fmt.Sprintf("1704067200.%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i, r.ID, r.KeyAlg, r.SigAlg, r.KeyType, kl, curve, san))
	}

	recs2, err := parseX509Log(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(recs) != len(recs2) {
		t.Errorf("round-trip count: %d → %d", len(recs), len(recs2))
	}

	// Verify dedup key stability.
	keys1 := make(map[string]bool, len(recs))
	for _, r := range recs {
		keys1[r.dedupeKey()] = true
	}
	for _, r := range recs2 {
		if !keys1[r.dedupeKey()] {
			t.Errorf("unexpected dedup key after round-trip: %s", r.dedupeKey())
		}
	}
}

// TestX509Dedup_OrderIndependent verifies parsing in different row orders
// gives the same unique set.
func TestX509Dedup_OrderIndependent(t *testing.T) {
	header := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tx509\n" +
		"#fields\tts\tid\tcertificate.key_alg\tcertificate.sig_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n" +
		"#types\ttime\tstring\tstring\tstring\tstring\tcount\tstring\tvector[string]\n"

	type row struct{ keyAlg, sigAlg, keyType, keyLen, curve, sanDNS string }
	rows := []row{
		{"rsaEncryption", "sha256WithRSAEncryption", "rsa", "2048", "-", "rsa.example.com"},
		{"id-ecPublicKey", "ecdsa-with-SHA256", "ec", "256", "prime256v1", "ec.example.com"},
		{"id-ML-DSA-65", "ML-DSA-65", "unknown", "0", "-", "pqc.example.com"},
		// Duplicate of row 0.
		{"rsaEncryption", "sha256WithRSAEncryption", "rsa", "2048", "-", "rsa.example.com"},
	}

	buildTSV := func(order []int) string {
		var sb strings.Builder
		sb.WriteString(header)
		for i, idx := range order {
			r := rows[idx]
			sb.WriteString(fmt.Sprintf("1704067200.%d\tFuid%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
				i, i, r.keyAlg, r.sigAlg, r.keyType, r.keyLen, r.curve, r.sanDNS))
		}
		return sb.String()
	}

	recsA, err := parseX509Log(context.Background(), strings.NewReader(buildTSV([]int{0, 1, 2, 3})))
	if err != nil {
		t.Fatalf("orig order: %v", err)
	}

	rng := rand.New(rand.NewSource(99))
	shuffled := []int{0, 1, 2, 3}
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	recsB, err := parseX509Log(context.Background(), strings.NewReader(buildTSV(shuffled)))
	if err != nil {
		t.Fatalf("shuffled order: %v", err)
	}

	if len(recsA) != len(recsB) {
		t.Errorf("dedup count: A=%d B=%d — dedup is order-dependent", len(recsA), len(recsB))
	}

	keysA := make(map[string]bool, len(recsA))
	for _, r := range recsA {
		keysA[r.dedupeKey()] = true
	}
	for _, r := range recsB {
		if !keysA[r.dedupeKey()] {
			t.Errorf("key in B missing from A: %s", r.dedupeKey())
		}
	}
}

// TestX509DedupeKey_Uniqueness verifies that distinct certificate profiles produce distinct keys.
func TestX509DedupeKey_Uniqueness(t *testing.T) {
	cases := []X509Record{
		{SigAlg: "sha256WithRSAEncryption", KeyAlg: "rsaEncryption", KeyType: "rsa", KeyLen: 2048},
		{SigAlg: "sha256WithRSAEncryption", KeyAlg: "rsaEncryption", KeyType: "rsa", KeyLen: 4096},
		{SigAlg: "sha512WithRSAEncryption", KeyAlg: "rsaEncryption", KeyType: "rsa", KeyLen: 2048},
		{SigAlg: "ecdsa-with-SHA256", KeyAlg: "id-ecPublicKey", KeyType: "ec", KeyLen: 256, Curve: "prime256v1"},
		{SigAlg: "ML-DSA-65", KeyAlg: "id-ML-DSA-65", KeyType: "unknown", KeyLen: 0},
	}

	seen := make(map[string]int)
	for i, r := range cases {
		k := r.dedupeKey()
		if prev, ok := seen[k]; ok {
			t.Errorf("records[%d] and records[%d] share dedup key %q", prev, i, k)
		}
		seen[k] = i
	}
}
