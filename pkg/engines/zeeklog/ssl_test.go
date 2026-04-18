package zeeklog

import (
	"context"
	"strings"
	"testing"
)

var sslTSVGolden = `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	2024-01-01-00:00:00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fuids	client_cert_chain_fuids	subject	issuer	validation_status
#types	time	string	addr	port	addr	port	string	string	string	string	bool	count	string	bool	string	vector[string]	vector[string]	string	string	string
1704067200.000000	CaBC12	10.0.0.1	54321	1.2.3.4	443	TLSv13	TLS_AES_256_GCM_SHA384	X25519MLKEM768	example.com	F	-	h2	T	-	-	-	-	-	ok
1704067201.000000	CbCD34	10.0.0.2	54322	1.2.3.4	443	TLSv13	TLS_AES_256_GCM_SHA384	X25519MLKEM768	example.com	F	-	h2	T	-	-	-	-	-	ok
1704067202.000000	CcDE56	10.0.0.3	54323	5.6.7.8	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	secp256r1	legacy.example.com	F	-	-	T	-	-	-	-	-	ok
1704067203.000000	CdEF78	10.0.0.4	54324	9.10.11.12	443	TLSv13	TLS_AES_128_GCM_SHA256	secp256r1	classical.example.com	F	-	-	F	-	-	-	-	-	ok
`

func TestParseSSLTSV(t *testing.T) {
	recs, err := parseSSLLog(context.Background(), strings.NewReader(sslTSVGolden))
	if err != nil {
		t.Fatalf("parseSSLLog TSV: %v", err)
	}
	// Row 4 has established=F — should be skipped.
	// Rows 1+2 have same (host,port,cipher,curve) → deduplicated to 1.
	// Row 3 is unique.
	// Expected: 2 unique records.
	if len(recs) != 2 {
		t.Errorf("TSV: got %d records, want 2", len(recs))
		for i, r := range recs {
			t.Logf("  [%d] host=%s cipher=%s curve=%s", i, r.RespHost, r.Cipher, r.Curve)
		}
	}
}

var sslJSONGolden = `{"ts":1704067200.0,"uid":"CaBC12","id.orig_h":"10.0.0.1","id.orig_p":54321,"id.resp_h":"1.2.3.4","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"X25519MLKEM768","server_name":"example.com","resumed":false,"established":true,"next_protocol":"h2"}
{"ts":1704067202.0,"uid":"CcDE56","id.orig_h":"10.0.0.2","id.orig_p":54323,"id.resp_h":"5.6.7.8","id.resp_p":443,"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","curve":"secp256r1","server_name":"legacy.example.com","resumed":false,"established":true}
{"ts":1704067203.0,"uid":"CdEF78","id.orig_h":"10.0.0.3","id.orig_p":54324,"id.resp_h":"9.10.11.12","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"secp256r1","server_name":"classical.example.com","resumed":false,"established":false}
`

func TestParseSSLJSON(t *testing.T) {
	recs, err := parseSSLLog(context.Background(), strings.NewReader(sslJSONGolden))
	if err != nil {
		t.Fatalf("parseSSLLog JSON: %v", err)
	}
	// Row 3 established=false → skipped. Rows 1+2 are unique.
	if len(recs) != 2 {
		t.Errorf("JSON: got %d records, want 2", len(recs))
	}
}

func TestSSLCurveMapping(t *testing.T) {
	input := `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	established
#types	time	string	addr	port	addr	port	string	string	string	string	bool
1704067200.0	C1	1.1.1.1	1000	2.2.2.2	443	TLSv13	TLS_AES_256_GCM_SHA384	x25519mlkem768	hybrid.example.com	T
`
	recs, err := parseSSLLog(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Curve != "X25519MLKEM768" {
		t.Errorf("curve = %q, want X25519MLKEM768", recs[0].Curve)
	}
}

func TestSSLDedup(t *testing.T) {
	// Same host+port+cipher+curve repeated 100 times → 1 unique record.
	var sb strings.Builder
	sb.WriteString("#separator \x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n")
	sb.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n")
	sb.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n")
	for i := 0; i < 100; i++ {
		sb.WriteString("1704067200.0\tCx\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample.com\tT\n")
	}
	recs, err := parseSSLLog(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(recs) != 1 {
		t.Errorf("dedup: got %d records, want 1", len(recs))
	}
}
