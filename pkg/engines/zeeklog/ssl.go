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
func parseSSLLog(ctx context.Context, r io.Reader) ([]SSLRecord, error) {
	peeked, fmt_, err := sniffFormat(r)
	if err != nil {
		return nil, fmt.Errorf("zeek-log ssl.log: sniff format: %w", err)
	}

	switch fmt_ {
	case formatTSV:
		return parseSSLTSV(ctx, io.MultiReader(bytes.NewReader(peeked), r))
	case formatJSON:
		return parseSSLJSON(ctx, io.MultiReader(bytes.NewReader(peeked), r))
	case formatUnknown:
		// Buffer all content so both parsers can attempt from the beginning.
		all, readErr := io.ReadAll(io.MultiReader(bytes.NewReader(peeked), r))
		if readErr != nil {
			return nil, readErr
		}
		recs, _ := parseSSLJSON(ctx, bytes.NewReader(all))
		if len(recs) > 0 {
			return recs, nil
		}
		return parseSSLTSV(ctx, bytes.NewReader(all))
	}
	return nil, fmt.Errorf("zeek-log ssl.log: unrecognized format")
}

// zeekTSVHeader holds parsed Zeek TSV directive values.
type zeekTSVHeader struct {
	separator  string
	unsetField string
	emptyField string
}

func defaultTSVHeader() zeekTSVHeader {
	return zeekTSVHeader{separator: "\t", unsetField: "-", emptyField: "(empty)"}
}

// parseSSLTSV parses the Zeek native TSV format.
func parseSSLTSV(ctx context.Context, r io.Reader) ([]SSLRecord, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	hdr := defaultTSVHeader()
	var colIdx map[string]int
	seen := map[string]bool{}
	var recs []SSLRecord

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#separator") {
			// #separator \x09 — column separator (almost always tab).
			// #set_separator is within-set separator (e.g. ",") — NOT the column sep.
			// HasPrefix("#separator") does NOT match "#set_separator" (different prefix).
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
			continue // no header yet
		}

		rec, ok := extractSSLTSVRow(line, colIdx, hdr)
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

func extractSSLTSVRow(line string, colIdx map[string]int, hdr zeekTSVHeader) (SSLRecord, bool) {
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
	Established any   `json:"established"` // bool or string
	PQCKeyShare string `json:"pqc_key_share"`
}

// parseSSLJSON parses NDJSON ssl.log (one JSON object per line).
func parseSSLJSON(ctx context.Context, r io.Reader) ([]SSLRecord, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

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
		portStr := sslPortString(row.IDRespP)
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

// sslPortString converts the IDRespP any-typed field to a port string (B4).
// Zeek JSON emits ports as numbers; "<nil>" from fmt.Sprintf("%v", nil) is avoided.
func sslPortString(v any) string {
	switch p := v.(type) {
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(p, 'f', -1, 64)
	case int:
		return strconv.Itoa(p)
	case int64:
		return strconv.FormatInt(p, 10)
	case string:
		return p
	default:
		return ""
	}
}
