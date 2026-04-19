package suricatalog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// maxSuricataRecords caps the dedup map to prevent unbounded memory on
// adversarially large or pathological log files.
const maxSuricataRecords = 500_000

// eveEvent is the top-level eve.json record shape.
type eveEvent struct {
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	TLS       *eveTLS   `json:"tls,omitempty"`
}

// eveTLS holds the tls sub-object from a Suricata TLS event.
type eveTLS struct {
	Version      string   `json:"version"`
	CipherSuite  string   `json:"cipher_suite"`
	CipherSecurity string `json:"cipher_security"`
	SNI          string   `json:"sni"`
	Subject      string   `json:"subject"`
	Issuerdn     string   `json:"issuerdn"`
	Serial       string   `json:"serial"`
	Fingerprint  string   `json:"fingerprint"`
	Notbefore    string   `json:"notbefore"`
	Notafter     string   `json:"notafter"`
	JA3          *eveJA3  `json:"ja3,omitempty"`
	JA3S         *eveJA3  `json:"ja3s,omitempty"`
	// Custom Suricata config fields (requires oqs-tls.yaml + Suricata build support):
	SigAlgs string `json:"sigalgs,omitempty"` // comma-separated signature algorithms
	Groups  string `json:"groups,omitempty"`  // comma-separated supported groups
}

// eveJA3 is the shared structure for JA3 and JA3S sub-objects.
type eveJA3 struct {
	Hash   string `json:"hash"`
	String string `json:"string"`
}

// TLSRecord is the normalized, deduplicated representation of a Suricata TLS event.
type TLSRecord struct {
	DestIP      string
	DestPort    string
	CipherSuite string
	Version     string
	SNI         string
	// Subject and Issuerdn removed — Sprint 6 audit M2: fields were captured but
	// never emitted into UnifiedFinding. Use Zeek x509.log for cert chain inventory.
	JA3Hash  string
	JA3SHash string
	SigAlgs  string
	Groups   string
}

// dedupeKey returns a string used to suppress repeated findings for the same
// (server, cipher, version, sni) tuple. A busy capture may contain thousands
// of handshakes to the same server — emit one finding per unique combination.
func (r TLSRecord) dedupeKey() string {
	return r.DestIP + ":" + r.DestPort + "|" + r.CipherSuite + "|" + r.Version + "|" + r.SNI
}

// parseEveJSON reads Suricata eve.json NDJSON from r, dispatches on
// event_type="tls", and returns unique TLS records deduplicated by
// (dest_ip, dest_port, cipher_suite, version, sni).
// The optional pathHint is used only in operator-facing stderr warnings.
func parseEveJSON(ctx context.Context, r io.Reader, pathHint ...string) ([]TLSRecord, error) {
	logPath := "(stream)"
	if len(pathHint) > 0 && pathHint[0] != "" {
		logPath = pathHint[0]
	}

	scanner := bufio.NewScanner(r)
	// 4 MB per-line buffer — same cap as zeeklog to handle verbose eve.json lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	seen := make(map[string]bool)
	var recs []TLSRecord
	lineNum := 0
	warnedCap := false

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return recs, ctx.Err()
		default:
		}

		line := scanner.Bytes()
		lineNum++
		if len(line) == 0 {
			continue
		}

		var ev eveEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Skip malformed lines without aborting — live rotation can
			// produce incomplete trailing lines.
			continue
		}

		if ev.EventType != "tls" || ev.TLS == nil {
			continue
		}

		destPort := fmt.Sprintf("%d", ev.DestPort)
		rec := TLSRecord{
			DestIP:      ev.DestIP,
			DestPort:    destPort,
			CipherSuite: ev.TLS.CipherSuite,
			Version:     ev.TLS.Version,
			SNI:         ev.TLS.SNI,
			SigAlgs:     ev.TLS.SigAlgs,
			Groups:      ev.TLS.Groups,
		}
		if ev.TLS.JA3 != nil {
			rec.JA3Hash = validateJA3Hash(ev.TLS.JA3.Hash)
		}
		if ev.TLS.JA3S != nil {
			rec.JA3SHash = validateJA3Hash(ev.TLS.JA3S.Hash)
		}

		k := rec.dedupeKey()
		if seen[k] {
			continue
		}
		if len(seen) >= maxSuricataRecords {
			if !warnedCap {
				fmt.Fprintf(os.Stderr, "suricata-log: dedup cap %d reached for %s; inventory may be incomplete\n", maxSuricataRecords, logPath)
				warnedCap = true
			}
			break
		}
		seen[k] = true
		recs = append(recs, rec)
	}

	if err := scanner.Err(); err != nil {
		return recs, fmt.Errorf("suricata-log: scanner error: %w", err)
	}
	return recs, nil
}
