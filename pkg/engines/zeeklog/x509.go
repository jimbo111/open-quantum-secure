package zeeklog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// X509Record holds fields extracted from a single x509.log row relevant to PQC.
type X509Record struct {
	ID      string // certificate fingerprint / fuid
	SigAlg  string // certificate.sig_alg (may be raw OID string from Zeek)
	KeyAlg  string // certificate.key_alg
	KeyType string // certificate.key_type (e.g. "rsa", "ec", "unknown")
	KeyLen  int    // certificate.key_length in bits (0 = unknown)
	Curve   string // certificate.curve for EC keys
	SANDNS  string // san.dns (comma-separated; first entry used as target)
}

func (r X509Record) dedupeKey() string {
	return r.SigAlg + "|" + r.KeyAlg + "|" + r.KeyType + "|" + strconv.Itoa(r.KeyLen) + "|" + r.Curve
}

// parseX509Log reads x509.log records. Handles TSV and JSON. Returns unique
// records deduplicated by (sig_alg, key_alg, key_type, key_length, curve).
func parseX509Log(r io.Reader) ([]X509Record, error) {
	peeked, fmt_, err := sniffFormat(r)
	if err != nil {
		return nil, fmt.Errorf("zeek-log x509.log: sniff format: %w", err)
	}
	full := multiReader(peeked, r)
	switch fmt_ {
	case formatTSV:
		return parseX509TSV(full)
	case formatJSON, formatUnknown:
		recs, err := parseX509JSON(full)
		if err != nil && fmt_ == formatUnknown {
			return parseX509TSV(multiReader(peeked, r))
		}
		return recs, err
	}
	return nil, fmt.Errorf("zeek-log x509.log: unrecognized format")
}

func parseX509TSV(r io.Reader) ([]X509Record, error) {
	scanner := bufio.NewScanner(r)
	var colIdx map[string]int
	seen := map[string]bool{}
	var recs []X509Record

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#separator") || strings.HasPrefix(line, "#set_separator") ||
			strings.HasPrefix(line, "#empty_field") || strings.HasPrefix(line, "#unset_field") ||
			strings.HasPrefix(line, "#open") || strings.HasPrefix(line, "#close") ||
			strings.HasPrefix(line, "#path") || strings.HasPrefix(line, "#types") {
			continue
		}
		if strings.HasPrefix(line, "#fields") {
			rawFields := strings.SplitN(line, "\t", 2)
			if len(rawFields) == 2 {
				cols := strings.Split(rawFields[1], "\t")
				colIdx = make(map[string]int, len(cols))
				for i, c := range cols {
					colIdx[c] = i
				}
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if colIdx == nil {
			continue
		}
		rec, ok := extractX509TSVRow(line, colIdx)
		if !ok {
			continue
		}
		dk := rec.dedupeKey()
		if seen[dk] {
			continue
		}
		seen[dk] = true
		recs = append(recs, rec)
	}
	return recs, scanner.Err()
}

func extractX509TSVRow(line string, colIdx map[string]int) (X509Record, bool) {
	cols := strings.Split(line, "\t")
	get := func(name string) string {
		i, ok := colIdx[name]
		if !ok || i >= len(cols) {
			return ""
		}
		v := cols[i]
		if v == "-" || v == "(empty)" {
			return ""
		}
		return v
	}
	kl := 0
	if s := get("certificate.key_length"); s != "" {
		kl, _ = strconv.Atoi(s)
	}
	rec := X509Record{
		ID:      get("id"),
		SigAlg:  get("certificate.sig_alg"),
		KeyAlg:  get("certificate.key_alg"),
		KeyType: get("certificate.key_type"),
		KeyLen:  kl,
		Curve:   get("certificate.curve"),
		SANDNS:  get("san.dns"),
	}
	if rec.SigAlg == "" && rec.KeyAlg == "" {
		return X509Record{}, false
	}
	return rec, true
}

// jsonX509Row is the JSON deserialization target for x509.log NDJSON lines.
type jsonX509Row struct {
	ID          string `json:"id"`
	Certificate struct {
		SigAlg    string `json:"sig_alg"`
		KeyAlg    string `json:"key_alg"`
		KeyType   string `json:"key_type"`
		KeyLength any    `json:"key_length"` // may be int or string
		Curve     string `json:"curve"`
	} `json:"certificate"`
	SAN struct {
		DNS string `json:"dns"`
	} `json:"san"`
}

func parseX509JSON(r io.Reader) ([]X509Record, error) {
	scanner := bufio.NewScanner(r)
	seen := map[string]bool{}
	var recs []X509Record

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row jsonX509Row
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		kl := 0
		switch v := row.Certificate.KeyLength.(type) {
		case float64:
			kl = int(v)
		case string:
			kl, _ = strconv.Atoi(v)
		}
		rec := X509Record{
			ID:      row.ID,
			SigAlg:  row.Certificate.SigAlg,
			KeyAlg:  row.Certificate.KeyAlg,
			KeyType: row.Certificate.KeyType,
			KeyLen:  kl,
			Curve:   row.Certificate.Curve,
			SANDNS:  row.SAN.DNS,
		}
		if rec.SigAlg == "" && rec.KeyAlg == "" {
			continue
		}
		dk := rec.dedupeKey()
		if seen[dk] {
			continue
		}
		seen[dk] = true
		recs = append(recs, rec)
	}
	return recs, scanner.Err()
}
