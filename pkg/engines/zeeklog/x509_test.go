package zeeklog

import (
	"strings"
	"testing"
)

var x509TSVGolden = `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	x509
#fields	ts	id	certificate.version	certificate.serial	certificate.subject	certificate.issuer	certificate.not_valid_before	certificate.not_valid_after	certificate.key_alg	certificate.sig_alg	certificate.key_type	certificate.key_length	certificate.exponent	certificate.curve	san.dns	san.uri	san.email	san.ip	basic_constraints.ca
#types	time	string	count	string	string	string	time	time	string	string	string	count	count	string	vector[string]	vector[string]	vector[string]	vector[string]	bool
1704067200.000000	Fuid01	3	01	CN=example.com	CN=TrustCA	1700000000.0	1800000000.0	rsaEncryption	sha256WithRSAEncryption	rsa	2048	65537	-	example.com	-	-	-	F
1704067201.000000	Fuid02	3	02	CN=pqc.example.com	CN=PQC-CA	1700000000.0	1800000000.0	id-ML-DSA-65	ML-DSA-65	unknown	0	-	-	pqc.example.com	-	-	-	F
1704067202.000000	Fuid03	3	03	CN=oid.example.com	CN=OID-CA	1700000000.0	1800000000.0	id-ML-DSA-65	unknown 2.16.840.1.101.3.4.3.18	unknown	0	-	-	oid.example.com	-	-	-	F
`

func TestParseX509TSV(t *testing.T) {
	recs, err := parseX509Log(strings.NewReader(x509TSVGolden))
	if err != nil {
		t.Fatalf("parseX509Log TSV: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("TSV: got %d records, want 3", len(recs))
	}

	// Record 0: RSA classical cert
	if recs[0].KeyType != "rsa" {
		t.Errorf("[0] KeyType = %q, want rsa", recs[0].KeyType)
	}
	if recs[0].KeyLen != 2048 {
		t.Errorf("[0] KeyLen = %d, want 2048", recs[0].KeyLen)
	}
	if recs[0].SigAlg != "sha256WithRSAEncryption" {
		t.Errorf("[0] SigAlg = %q, want sha256WithRSAEncryption", recs[0].SigAlg)
	}

	// Record 1: ML-DSA-65 PQC cert
	if recs[1].SigAlg != "ML-DSA-65" {
		t.Errorf("[1] SigAlg = %q, want ML-DSA-65", recs[1].SigAlg)
	}
	if recs[1].SANDNS != "pqc.example.com" {
		t.Errorf("[1] SANDNS = %q, want pqc.example.com", recs[1].SANDNS)
	}

	// Record 2: raw OID — should parse without error; OID resolution happens in classify.go
	if recs[2].SigAlg != "unknown 2.16.840.1.101.3.4.3.18" {
		t.Errorf("[2] SigAlg = %q, want raw OID string", recs[2].SigAlg)
	}
}

var x509JSONGolden = `{"ts":1704067200.0,"id":"Fuid01","certificate":{"version":3,"serial":"01","subject":"CN=example.com","issuer":"CN=TrustCA","key_alg":"rsaEncryption","sig_alg":"sha256WithRSAEncryption","key_type":"rsa","key_length":2048,"curve":""},"san":{"dns":"example.com"}}
{"ts":1704067201.0,"id":"Fuid02","certificate":{"version":3,"serial":"02","subject":"CN=pqc.example.com","issuer":"CN=PQC-CA","key_alg":"id-ML-DSA-65","sig_alg":"ML-DSA-65","key_type":"unknown","key_length":0,"curve":""},"san":{"dns":"pqc.example.com"}}
{"ts":1704067202.0,"id":"Fuid03","certificate":{"version":3,"serial":"03","subject":"CN=oid.example.com","issuer":"CN=OID-CA","key_alg":"id-ML-DSA-65","sig_alg":"unknown 2.16.840.1.101.3.4.3.18","key_type":"unknown","key_length":0,"curve":""},"san":{"dns":"oid.example.com"}}
`

func TestParseX509JSON(t *testing.T) {
	recs, err := parseX509Log(strings.NewReader(x509JSONGolden))
	if err != nil {
		t.Fatalf("parseX509Log JSON: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("JSON: got %d records, want 3", len(recs))
	}
	if recs[1].SigAlg != "ML-DSA-65" {
		t.Errorf("[1] SigAlg = %q, want ML-DSA-65", recs[1].SigAlg)
	}
}

func TestX509OIDResolutionInFindings(t *testing.T) {
	// Verify that x509RecordToFindings resolves raw OIDs to canonical names.
	rec := X509Record{
		ID:     "Fuid03",
		SigAlg: "unknown 2.16.840.1.101.3.4.3.18",
		SANDNS: "oid.example.com",
	}
	fs := x509RecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("x509RecordToFindings: got 0 findings, want >= 1")
	}
	var found bool
	for _, f := range fs {
		if f.Algorithm != nil && f.Algorithm.Name == "ML-DSA-65" {
			found = true
		}
	}
	if !found {
		t.Errorf("OID 2.16.840.1.101.3.4.3.18 was not resolved to ML-DSA-65 in findings")
	}
}
