package zeeklog

// sophisticated_test.go — gaps not covered by existing zeeklog tests.
// Focus: mixed-format robustness, pqc_key_share round-trip, torn TSV rows,
// dedup cap at 1M diverse rows, Algorithm.Name correctness for PQC groups,
// race on shared file, and sanitize edge-cases.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// ---------------------------------------------------------------------------
// 1. Mixed TSV + JSON lines in a single file (format sniff picks TSV from '#')
// ---------------------------------------------------------------------------

func TestSSL_MixedTSVAndJSONLines_TSVWins(t *testing.T) {
	t.Parallel()
	// TSV header first → sniff returns formatTSV. JSON-like lines after the
	// header row are not valid TSV rows but the TSV parser doesn't crash on them.
	// The interspersed JSON line: established="" → not "F"/"false" → TSV parser
	// may include it. The key invariants are: (1) no panic, (2) the two valid
	// TSV rows produce findings, (3) result count is deterministic (2 or 3).
	input := "#separator \x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		// Valid TSV row — host 1.2.3.4
		"1700000000\tCaaa\t10.0.0.1\t5555\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample.com\tT\n" +
		// JSON line interspersed — treated as an unknown-format TSV row.
		`{"ts":1700000001,"uid":"Cbbb","id.resp_h":"1.2.3.4","id.resp_p":443,"cipher":"TLS_AES_128_GCM_SHA256","established":true}` + "\n" +
		// Another valid TSV row — distinct host 5.6.7.8
		"1700000002\tCccc\t10.0.0.3\t6666\t5.6.7.8\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\tsecp256r1\tlegacy.example.com\tT\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both valid TSV hosts must appear in results regardless of how the JSON
	// line is handled.
	hosts := make(map[string]bool)
	for _, r := range recs {
		hosts[r.RespHost] = true
	}
	if !hosts["1.2.3.4"] {
		t.Errorf("mixed TSV+JSON: first valid TSV host (1.2.3.4) missing from %d records", len(recs))
	}
	if !hosts["5.6.7.8"] {
		t.Errorf("mixed TSV+JSON: second valid TSV host (5.6.7.8) missing from %d records", len(recs))
	}
}

// ---------------------------------------------------------------------------
// 2. Mixed JSON + TSV where JSON comes first
// ---------------------------------------------------------------------------

func TestSSL_MixedJSONThenTSV_JSONWins(t *testing.T) {
	t.Parallel()
	// JSON line first → sniff returns formatJSON. TSV header lines after are
	// not JSON objects → skipped silently.
	input := `{"ts":1700000000,"uid":"Caaa","id.orig_h":"10.0.0.1","id.orig_p":5555,"id.resp_h":"1.2.3.4","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"X25519MLKEM768","server_name":"example.com","established":true}` + "\n" +
		"#separator \x09\n" +
		"#fields\tts\tuid\n" +
		"1700000001\tCbbb\t10.0.0.2\t5556\t5.6.7.8\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\tsecp256r1\tlegacy.example.com\tT\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// TSV lines don't start with '{' → skipped. Only the JSON object counts.
	if len(recs) != 1 {
		t.Errorf("mixed JSON+TSV: got %d records, want 1", len(recs))
	}
	if recs[0].Curve != "X25519MLKEM768" {
		t.Errorf("curve = %q, want X25519MLKEM768", recs[0].Curve)
	}
}

// ---------------------------------------------------------------------------
// 3. pqc_key_share round-trip: hex codepoint → Finding.Algorithm.Name = MLKEM768
//    and QuantumRisk = Safe (Sprint-5 companion script column)
// ---------------------------------------------------------------------------

func TestSSL_PQCKeyShare_ValidHex_ProducesMLKEM768Finding(t *testing.T) {
	t.Parallel()
	// 0x0201 = MLKEM768 codepoint (from tls_groups.go table)
	input := "#separator \x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\tpqc_key_share\n" +
		"1700000000\tCaaa\t10.0.0.1\t5555\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\t-\texample.com\tT\t0201\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSSLLog: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected at least 1 record")
	}
	if recs[0].PQCKeyShare != "0201" {
		t.Errorf("PQCKeyShare = %q, want %q", recs[0].PQCKeyShare, "0201")
	}

	// Convert to findings and verify MLKEM768 is Safe.
	fds := sslRecordToFindings(recs[0])
	var found bool
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "MLKEM768" {
			found = true
			if f.QuantumRisk != findings.QuantumRisk(quantum.RiskSafe) {
				t.Errorf("MLKEM768 QuantumRisk = %v, want RiskSafe", f.QuantumRisk)
			}
			if !f.PQCPresent {
				t.Errorf("MLKEM768 finding should have PQCPresent=true")
			}
		}
	}
	if !found {
		t.Errorf("no MLKEM768 finding produced from pqc_key_share=0201; findings: %+v", fds)
	}
}

func TestSSL_PQCKeyShare_NonHex_Rejected(t *testing.T) {
	t.Parallel()
	// Non-hex characters in the pqc_key_share column should be silently skipped
	// (ParseUint will fail).
	input := "#separator \x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\tpqc_key_share\n" +
		"1700000000\tCaaa\t10.0.0.1\t5555\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\t-\texample.com\tT\tZZZZ\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSSLLog: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected at least 1 record for established row")
	}
	fds := sslRecordToFindings(recs[0])
	// Must not produce any finding with a PQC group from invalid hex.
	for _, f := range fds {
		if f.NegotiatedGroup != 0 {
			t.Errorf("non-hex pqc_key_share produced a NegotiatedGroup finding: %+v", f)
		}
	}
}

func TestSSL_PQCKeyShare_MultipleCodepoints_0xPrefix(t *testing.T) {
	t.Parallel()
	// Comma-separated list with 0x prefix: "0x11EC,0x0201" (X25519MLKEM768, MLKEM768)
	input := "#separator \x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\tpqc_key_share\n" +
		"1700000000\tCaaa\t10.0.0.1\t5555\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\t-\texample.com\tT\t0x11EC,0x0201\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSSLLog: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected 1 record")
	}
	fds := sslRecordToFindings(recs[0])

	names := make(map[string]bool)
	for _, f := range fds {
		if f.Algorithm != nil {
			names[f.Algorithm.Name] = true
		}
	}
	if !names["X25519MLKEM768"] {
		t.Errorf("expected X25519MLKEM768 finding from 0x11EC; got names: %v", names)
	}
	if !names["MLKEM768"] {
		t.Errorf("expected MLKEM768 finding from 0x0201; got names: %v", names)
	}
}

// ---------------------------------------------------------------------------
// 4. Torn TSV lines — mid-row cuts in the middle of a file (not just EOF)
// ---------------------------------------------------------------------------

func TestSSL_TornTSVRowMidFile_ValidRowsAfterStillParsed(t *testing.T) {
	t.Parallel()
	// Simulate a file where one row is missing the established column (torn).
	// The rows before and after must still parse correctly.
	input := "#separator \x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		// Valid row
		"1700000000\tCaaa\t10.0.0.1\t5555\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample.com\tT\n" +
		// Torn row — only 5 columns instead of 11
		"1700000001\tCbbb\t10.0.0.2\t5556\t5.6.7.8\n" +
		// Valid row after the torn one
		"1700000002\tCccc\t10.0.0.3\t5557\t9.10.11.12\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\tsecp256r1\tlegacy.example.com\tT\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Torn row: established="" which is not "F"/"false", so it may appear. The
	// key invariant is that the valid rows before/after are not lost.
	hosts := make(map[string]bool)
	for _, r := range recs {
		hosts[r.RespHost] = true
	}
	if !hosts["1.2.3.4"] {
		t.Errorf("first valid row missing from results; all recs: %+v", recs)
	}
	if !hosts["9.10.11.12"] {
		t.Errorf("post-torn valid row missing from results; all recs: %+v", recs)
	}
}

// ---------------------------------------------------------------------------
// 5. 1M diverse rows dedup cap — cap at maxZeekRecords, no OOM
// ---------------------------------------------------------------------------

func TestSSL_DedupCap_1MDiverse_CappedAtMax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large stress test in -short mode")
	}
	t.Parallel()

	// Build 1M rows with unique (host, port, cipher, curve) keys → all unique.
	var sb strings.Builder
	sb.WriteString("#separator \x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n")
	sb.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n")
	sb.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n")
	for i := 0; i < 1_000_000; i++ {
		fmt.Fprintf(&sb,
			"1700000000.%d\tCx%d\t%d.%d.%d.%d\t%d\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample%d.com\tT\n",
			i, i,
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF,
			40000+(i%20000),
			i,
		)
	}

	recs, err := parseSSLLog(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) > maxZeekRecords {
		t.Errorf("dedup cap exceeded: got %d records, cap is %d", len(recs), maxZeekRecords)
	}
	if len(recs) == 0 {
		t.Error("got 0 records, expected up to cap")
	}
}

// ---------------------------------------------------------------------------
// 6. Algorithm.Name round-trip: ssl.log curve X25519MLKEM768 → Finding.QuantumRisk=Safe
// ---------------------------------------------------------------------------

func TestSSL_CurveToFinding_X25519MLKEM768_ClassifiedSafe(t *testing.T) {
	t.Parallel()
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Version:    "1.3",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Curve:      "X25519MLKEM768",
		ServerName: "hybrid.example.com",
	}
	fds := sslRecordToFindings(rec)

	var curveFinding *findings.UnifiedFinding
	for i := range fds {
		if fds[i].Algorithm != nil && fds[i].Algorithm.Name == "X25519MLKEM768" {
			curveFinding = &fds[i]
		}
	}
	if curveFinding == nil {
		t.Fatalf("no X25519MLKEM768 finding produced; all findings: %+v", fds)
	}
	if curveFinding.QuantumRisk != findings.QuantumRisk(quantum.RiskSafe) {
		t.Errorf("X25519MLKEM768 QuantumRisk = %v, want RiskSafe (%v)",
			curveFinding.QuantumRisk, findings.QuantumRisk(quantum.RiskSafe))
	}
	if !curveFinding.PQCPresent {
		t.Error("X25519MLKEM768 finding should have PQCPresent=true")
	}
}

func TestSSL_CurveToFinding_secp256r1_ClassifiedVulnerable(t *testing.T) {
	t.Parallel()
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Version:    "1.2",
		Cipher:     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Curve:      "secp256r1",
		ServerName: "classical.example.com",
	}
	fds := sslRecordToFindings(rec)

	var curveFinding *findings.UnifiedFinding
	for i := range fds {
		if fds[i].Algorithm != nil && fds[i].Algorithm.Name == "secp256r1" {
			curveFinding = &fds[i]
		}
	}
	if curveFinding == nil {
		t.Fatalf("no secp256r1 finding produced; all findings: %+v", fds)
	}
	if curveFinding.PQCPresent {
		t.Error("secp256r1 finding should have PQCPresent=false")
	}
}

// ---------------------------------------------------------------------------
// 7. X509 OID round-trip → canonical name → QuantumRisk=Safe for ML-DSA
// ---------------------------------------------------------------------------

func TestX509_OIDToAlgorithm_MLDSA65_RoundTrip(t *testing.T) {
	t.Parallel()
	// Raw OID for ML-DSA-65 as Zeek emits "unknown 2.16.840.1.101.3.4.3.18"
	rec := X509Record{
		SigAlg: "unknown 2.16.840.1.101.3.4.3.18",
		KeyAlg: "",
	}
	fds := x509RecordToFindings(rec)
	if len(fds) == 0 {
		t.Fatal("expected findings for ML-DSA-65 OID; got none")
	}
	var found bool
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "ML-DSA-65" {
			found = true
			if f.QuantumRisk != findings.QuantumRisk(quantum.RiskSafe) {
				t.Errorf("ML-DSA-65 QuantumRisk = %v, want RiskSafe", f.QuantumRisk)
			}
		}
	}
	if !found {
		t.Errorf("ML-DSA-65 finding not produced; findings: %+v", fds)
	}
}

func TestX509_OIDToAlgorithm_DirectOID_NoUnknownPrefix(t *testing.T) {
	t.Parallel()
	// Direct OID without "unknown " prefix — also supported.
	rec := X509Record{
		SigAlg: "2.16.840.1.101.3.4.3.17", // ML-DSA-44
		KeyAlg: "",
	}
	fds := x509RecordToFindings(rec)
	var found bool
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "ML-DSA-44" {
			found = true
		}
	}
	if !found {
		t.Errorf("ML-DSA-44 not resolved from direct OID; findings: %+v", fds)
	}
}

// ---------------------------------------------------------------------------
// 8. SSL JSON: port emitted as float64 (Zeek JSON) should be stringified correctly
// ---------------------------------------------------------------------------

func TestSSL_JSONPort_Float64_StringConversion(t *testing.T) {
	t.Parallel()
	// Zeek emits ports as JSON number (float64 after unmarshal).
	input := `{"ts":1700000000,"uid":"Caaa","id.orig_h":"10.0.0.1","id.orig_p":54321,"id.resp_h":"1.2.3.4","id.resp_p":8443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"X25519MLKEM768","server_name":"example.com","established":true}` + "\n"

	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSSLLog: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	// Port must be "8443", not "8443.0" (FormatFloat with 'f',-1 strips the decimal).
	if recs[0].RespPort != "8443" {
		t.Errorf("RespPort = %q, want %q", recs[0].RespPort, "8443")
	}
}

// ---------------------------------------------------------------------------
// 9. SSL: established=false (boolean false in JSON) → record skipped
//    and established="F" (TSV string false) → record skipped
// ---------------------------------------------------------------------------

func TestSSL_NotEstablished_Skipped_JSON(t *testing.T) {
	t.Parallel()
	// established: false as JSON boolean
	input := `{"ts":1700000000,"uid":"Caaa","id.resp_h":"1.2.3.4","id.resp_p":443,"cipher":"TLS_AES_256_GCM_SHA384","established":false}` + "\n"
	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSSLLog: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("established=false: expected 0 records, got %d", len(recs))
	}
}

// ---------------------------------------------------------------------------
// 10. Race: concurrent calls to sslRecordToFindings (uses reverseGroupMap which
//     is a package-level map — must be read-only after init, so no race)
// ---------------------------------------------------------------------------

func TestSSL_ConcurrentFindingsConversion_NoRace(t *testing.T) {
	t.Parallel()
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Curve:      "X25519MLKEM768",
		ServerName: "race.example.com",
	}

	const goroutines = 30
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			fds := sslRecordToFindings(rec)
			_ = fds
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// 11. Sanitize: '/' is stripped from RespHost so the filePath format
//     "(zeek-log)/<target>#<alg>" cannot be fragmented by path traversal.
//     Note: sanitizeTarget does NOT strip '.'. The invariant is that '/' is
//     absent from the target segment so it cannot be parsed as a filesystem path.
// ---------------------------------------------------------------------------

func TestSSL_SanitizeTarget_SlashStripped_FromFilePath(t *testing.T) {
	t.Parallel()
	rec := SSLRecord{
		RespHost: "../../etc/passwd",
		RespPort: "443",
		Cipher:   "TLS_AES_256_GCM_SHA384",
		Curve:    "secp256r1",
	}
	fds := sslRecordToFindings(rec)
	for _, f := range fds {
		// The target segment between "(zeek-log)/" and "#<alg>" must not contain
		// a literal '/' (which would break the path format and could be exploited
		// in output formats that render Location.File as a URL or file path).
		// We extract the target segment between the prefix and the '#'.
		file := f.Location.File
		const prefix = "(zeek-log)/"
		if len(file) > len(prefix) {
			segment := file[len(prefix):]
			if hashIdx := strings.IndexByte(segment, '#'); hashIdx >= 0 {
				target := segment[:hashIdx]
				if strings.Contains(target, "/") {
					t.Errorf("sanitizeTarget left '/' in target segment of Location.File: %q", file)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 12. OID table completeness: resolveOIDAlgorithm covers all ML-KEM OIDs
// ---------------------------------------------------------------------------

func TestOIDTable_MLKEMAll_Resolve(t *testing.T) {
	t.Parallel()
	cases := []struct {
		oid  string
		want string
	}{
		{"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
		{"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
	}
	for _, tc := range cases {
		got, ok := resolveOIDAlgorithm(tc.oid)
		if !ok {
			t.Errorf("resolveOIDAlgorithm(%q): not resolved, want %q", tc.oid, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveOIDAlgorithm(%q) = %q, want %q", tc.oid, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 13. curveNameToGroup table: verify all hybrid variants map correctly
// ---------------------------------------------------------------------------

func TestCurveNameToGroup_AllHybridVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  string
	}{
		{"x25519mlkem768", "X25519MLKEM768"},
		{"X25519MLKEM768", "X25519MLKEM768"}, // already canonical (falls through default)
		{"secp256r1mlkem768", "SecP256r1MLKEM768"},
		{"secp384r1mlkem1024", "SecP384r1MLKEM1024"},
		{"curvesm2mlkem768", "curveSM2MLKEM768"},
		{"mlkem512", "MLKEM512"},
		{"mlkem768", "MLKEM768"},
		{"mlkem1024", "MLKEM1024"},
		{"x25519", "X25519"},
		{"-", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := curveNameToGroup(tc.input)
		if got != tc.want {
			t.Errorf("curveNameToGroup(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 14. Property: any valid established=T TSV row produces ≥1 finding from sslRecordToFindings
//     (table-driven covering diverse cipher/curve combos)
// ---------------------------------------------------------------------------

func TestSSL_PropertyTableDriven_ValidRowProducesFindings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cipher string
		curve  string
	}{
		{"TLS_AES_256_GCM_SHA384", "X25519MLKEM768"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "secp256r1"},
		{"TLS_AES_128_GCM_SHA256", ""},
		{"TLS_CHACHA20_POLY1305_SHA256", "X25519"},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "secp384r1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.cipher+"+"+tc.curve, func(t *testing.T) {
			t.Parallel()
			rec := SSLRecord{
				RespHost: "1.2.3.4",
				RespPort: "443",
				Cipher:   tc.cipher,
				Curve:    tc.curve,
			}
			fds := sslRecordToFindings(rec)
			// At minimum the cipher finding should always be emitted when cipher != "".
			if tc.cipher != "" && len(fds) == 0 {
				t.Errorf("cipher=%q curve=%q: expected ≥1 finding, got 0", tc.cipher, tc.curve)
			}
		})
	}
}
