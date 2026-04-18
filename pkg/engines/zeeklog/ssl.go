package zeeklog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SSLRecord holds the fields extracted from a single ssl.log row that are
// relevant to PQC inventory.
type SSLRecord struct {
	UID        string
	RespHost   string
	RespPort   string
	Version    string
	Cipher     string
	Curve      string // from vanilla ssl.log or companion script pqc_key_share
	ServerName string
	// PQCKeyShare is the comma-separated hex codepoints from the companion
	// script. Empty when the companion script is not loaded.
	PQCKeyShare string
}

// dedupeKey returns a string used to suppress repeated findings for the same
// (server, cipher, curve) triple. A busy network trace may contain thousands
// of handshakes to the same server — we emit one finding per unique algorithm.
func (r SSLRecord) dedupeKey() string {
	return r.RespHost + ":" + r.RespPort + "|" + r.Cipher + "|" + r.Curve + "|" + r.PQCKeyShare
}

// parseSSLLog reads ssl.log records from r (already gzip-decoded if needed).
// Handles both TSV and JSON formats. Returns unique records deduplicated by
// (host, port, cipher, curve).
func parseSSLLog(r io.Reader) ([]SSLRecord, error) {
	peeked, fmt_, err := sniffFormat(r)
	if err != nil {
		return nil, fmt.Errorf("zeek-log ssl.log: sniff format: %w", err)
	}
	full := multiReader(peeked, r)

	switch fmt_ {
	case formatTSV:
		return parseSSLTSV(full)
	case formatJSON, formatUnknown:
		recs, err := parseSSLJSON(full)
		if err != nil && fmt_ == formatUnknown {
			// Last resort: try TSV
			return parseSSLTSV(multiReader(peeked, r))
		}
		return recs, err
	}
	return nil, fmt.Errorf("zeek-log ssl.log: unrecognized format")
}

// parseSSLTSV parses the Zeek native TSV format.
func parseSSLTSV(r io.Reader) ([]SSLRecord, error) {
	scanner := bufio.NewScanner(r)
	var colIdx map[string]int
	seen := map[string]bool{}
	var recs []SSLRecord

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
			fields := strings.Split(line, "\t")
			colIdx = make(map[string]int, len(fields))
			for i, f := range fields {
				colIdx[strings.TrimPrefix(f, "#fields\t")] = i
				colIdx[f] = i
			}
			// Re-parse without the #fields prefix
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
			continue // no header yet
		}

		rec, ok := extractSSLTSVRow(line, colIdx)
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

func extractSSLTSVRow(line string, colIdx map[string]int) (SSLRecord, bool) {
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
	// Skip non-established connections — they have no completed handshake.
	if est := get("established"); est == "F" || est == "false" {
		return SSLRecord{}, false
	}
	return SSLRecord{
		UID:         get("uid"),
		RespHost:    get("id.resp_h"),
		RespPort:    get("id.resp_p"),
		Version:     normalizeTLSVersion(get("version")),
		Cipher:      get("cipher"),
		Curve:       curveNameToGroup(get("curve")),
		ServerName:  get("server_name"),
		PQCKeyShare: get("pqc_key_share"),
	}, true
}

// jsonSSLRow is the deserialization target for NDJSON ssl.log lines.
type jsonSSLRow struct {
	UID        string `json:"uid"`
	IDRespH    string `json:"id.resp_h"`
	IDRespP    any    `json:"id.resp_p"` // Zeek JSON emits as number
	Version    string `json:"version"`
	Cipher     string `json:"cipher"`
	Curve      string `json:"curve"`
	ServerName string `json:"server_name"`
	Established any    `json:"established"` // bool or string
	PQCKeyShare string `json:"pqc_key_share"`
}

// parseSSLJSON parses NDJSON ssl.log (one JSON object per line).
func parseSSLJSON(r io.Reader) ([]SSLRecord, error) {
	scanner := bufio.NewScanner(r)
	seen := map[string]bool{}
	var recs []SSLRecord

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row jsonSSLRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue // skip malformed lines
		}
		// Skip non-established
		switch v := row.Established.(type) {
		case bool:
			if !v {
				continue
			}
		case string:
			if v == "F" || v == "false" {
				continue
			}
		}
		portStr := fmt.Sprintf("%v", row.IDRespP)
		rec := SSLRecord{
			UID:         row.UID,
			RespHost:    row.IDRespH,
			RespPort:    portStr,
			Version:     normalizeTLSVersion(row.Version),
			Cipher:      row.Cipher,
			Curve:       curveNameToGroup(row.Curve),
			ServerName:  row.ServerName,
			PQCKeyShare: row.PQCKeyShare,
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
