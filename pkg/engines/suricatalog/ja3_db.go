package suricatalog

import "sync"

// ja3sHint carries a PQC detection note derived from a JA3S fingerprint.
type ja3sHint struct {
	// PQCPresent indicates the server is known to negotiate PQC key exchange.
	PQCPresent bool
	// Label is a human-readable description of the server stack, used as the
	// Algorithm.Name in findings (e.g. "MLKEM768"). Must be a valid ClassifyAlgorithm key.
	Label string
}

// ja3sDB and ja3sDBOnce guard the immutable fingerprint table.
// DO NOT MUTATE ja3sDB directly — see Sprint 6 M-S1.
// Add entries via initJA3SDB only, with a cited public source per entry.
var (
	ja3sDBOnce sync.Once
	ja3sDB     map[string]ja3sHint
)

func initJA3SDB() {
	ja3sDB = map[string]ja3sHint{
		// Table intentionally empty — awaiting authoritative fingerprints.
		// TODO(S7): populate from https://blog.cloudflare.com/pq-2024
		// When entries are added, each must cite a public source in a comment.
	}
}

// lookupJA3S returns the hint for hash h and whether it was found.
func lookupJA3S(hash string) (ja3sHint, bool) {
	ja3sDBOnce.Do(initJA3SDB)
	h, ok := ja3sDB[hash]
	return h, ok
}
