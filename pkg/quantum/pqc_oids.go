package quantum

// pqcSigAlgOIDs maps IANA/NIST OID strings (dotted notation) to the canonical
// human-readable PQC signature algorithm name used for finding classification.
// Source: draft-ietf-lamps-dilithium-certificates + FIPS 204/205 registrations.
var pqcSigAlgOIDs = map[string]string{
	// ML-DSA (FIPS 204) – id-ml-dsa-44/65/87
	"2.16.840.1.101.3.4.3.17": "mldsa44",
	"2.16.840.1.101.3.4.3.18": "mldsa65",
	"2.16.840.1.101.3.4.3.19": "mldsa87",
	// SLH-DSA SHA-2 (FIPS 205) – id-slh-dsa-sha2-*
	"2.16.840.1.101.3.4.3.20": "slhdsa-sha2-128s",
	"2.16.840.1.101.3.4.3.21": "slhdsa-sha2-128f",
	"2.16.840.1.101.3.4.3.22": "slhdsa-sha2-192s",
	"2.16.840.1.101.3.4.3.23": "slhdsa-sha2-192f",
	"2.16.840.1.101.3.4.3.24": "slhdsa-sha2-256s",
	"2.16.840.1.101.3.4.3.25": "slhdsa-sha2-256f",
	// SLH-DSA SHAKE (FIPS 205) – id-slh-dsa-shake-*
	"2.16.840.1.101.3.4.3.26": "slhdsa-shake-128s",
	"2.16.840.1.101.3.4.3.27": "slhdsa-shake-128f",
	"2.16.840.1.101.3.4.3.28": "slhdsa-shake-192s",
	"2.16.840.1.101.3.4.3.29": "slhdsa-shake-192f",
	"2.16.840.1.101.3.4.3.30": "slhdsa-shake-256s",
	"2.16.840.1.101.3.4.3.31": "slhdsa-shake-256f",
}

// LookupPQCSigAlgName returns the human-readable PQC signature algorithm name
// for a given OID string, or "" when the OID is unknown.
func LookupPQCSigAlgName(oid string) string {
	return pqcSigAlgOIDs[oid]
}
