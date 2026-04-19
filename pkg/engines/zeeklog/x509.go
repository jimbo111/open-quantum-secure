package zeeklog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
func parseX509Log(ctx context.Context, r io.Reader) ([]X509Record, error) {
	peeked, fmt_, err := sniffFormat(r)
	if err != nil {
		return nil, fmt.Errorf("zeek-log x509.log: sniff format: %w", err)
	}

	switch fmt_ {
	case formatTSV:
		return parseX509TSV(ctx, io.MultiReader(bytes.NewReader(peeked), r))
	case formatJSON:
		return parseX509JSON(ctx, io.MultiReader(bytes.NewReader(peeked), r))
	case formatUnknown:
		all, readErr := io.ReadAll(io.MultiReader(bytes.NewReader(peeked), r))
		if readErr != nil {
			return nil, readErr
		}
		recs, _ := parseX509JSON(ctx, bytes.NewReader(all))
		if len(recs) > 0 {
			return recs, nil
		}
		return parseX509TSV(ctx, bytes.NewReader(all))
	}
	return nil, fmt.Errorf("zeek-log x509.log: unrecognized format")
}

func parseX509TSV(ctx context.Context, r io.Reader) ([]X509Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	hdr := defaultTSVHeader()
	var colIdx map[string]int
	seen := map[string]bool{}
	var recs []X509Record

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#separator") {
			// Column separator (almost always tab). #set_separator is within-set
			// separator and does NOT share this prefix — safe to parse independently.
			parts := strings.Fields(line)
			if len(parts) == 2 {
				sep := parts[1]
				if sep == `\x09` || sep == `\t` {
					hdr.separator = "\t"
				} else if len(sep) == 1 {
					hdr.separator = sep
				}
			}
			continue
		}
		if strings.HasPrefix(line, "#set_separator") {
			// Within-set separator — does not affect column splitting; skip.
			continue
		}
		if strings.HasPrefix(line, "#unset_field") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				hdr.unsetField = parts[1]
			}
			continue
		}
		if strings.HasPrefix(line, "#empty_field") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				hdr.emptyField = parts[1]
			}
			continue
		}
		if strings.HasPrefix(line, "#open") || strings.HasPrefix(line, "#close") ||
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
		rec, ok := extractX509TSVRow(line, colIdx, hdr)
		if !ok {
			continue
		}
		dk := rec.dedupeKey()
		if seen[dk] {
			continue
		}
		seen[dk] = true
		recs = append(recs, rec)

		if len(recs) >= maxZeekRecords {
			fmt.Fprintf(os.Stderr, "zeeklog: record cap %d reached\n", maxZeekRecords)
			break
		}
		if len(recs)%500 == 0 {
			if ctx.Err() != nil {
				return recs, ctx.Err()
			}
		}
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return recs, nil
		}
		return recs, err
	}
	return recs, nil
}

func extractX509TSVRow(line string, colIdx map[string]int, hdr zeekTSVHeader) (X509Record, bool) {
	cols := strings.Split(line, hdr.separator)
	get := func(name string) string {
		i, ok := colIdx[name]
		if !ok || i >= len(cols) {
			return ""
		}
		v := cols[i]
		if v == hdr.unsetField || v == hdr.emptyField {
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
// Zeek's JSON output is flat with dotted keys ("certificate.sig_alg", "san.dns"),
// NOT nested structs. Using dotted json tags correctly maps these fields (B1 fix).
type jsonX509Row struct {
	ID        string `json:"id"`
	SigAlg    string `json:"certificate.sig_alg"`
	KeyAlg    string `json:"certificate.key_alg"`
	KeyType   string `json:"certificate.key_type"`
	KeyLength any    `json:"certificate.key_length"` // number or string
	Curve     string `json:"certificate.curve"`
	SANDNS    any    `json:"san.dns"` // string or []interface{} in Zeek JSON
}

func parseX509JSON(ctx context.Context, r io.Reader) ([]X509Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

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
		switch v := row.KeyLength.(type) {
		case float64:
			kl = int(v)
		case string:
			kl, _ = strconv.Atoi(v)
		}
		curve := row.Curve
		if curve == "-" {
			curve = ""
		}
		rec := X509Record{
			ID:      row.ID,
			SigAlg:  row.SigAlg,
			KeyAlg:  row.KeyAlg,
			KeyType: row.KeyType,
			KeyLen:  kl,
			Curve:   curve,
			SANDNS:  x509SANString(row.SANDNS),
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

		if len(recs) >= maxZeekRecords {
			fmt.Fprintf(os.Stderr, "zeeklog: record cap %d reached\n", maxZeekRecords)
			break
		}
		if len(recs)%500 == 0 {
			if ctx.Err() != nil {
				return recs, ctx.Err()
			}
		}
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return recs, nil
		}
		return recs, err
	}
	return recs, nil
}

// x509SANString extracts the first DNS SAN from the san.dns field.
// Zeek JSON emits san.dns as either a string or a JSON array.
func x509SANString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []any:
		if len(s) > 0 {
			if first, ok := s[0].(string); ok {
				return first
			}
		}
	}
	return ""
}
