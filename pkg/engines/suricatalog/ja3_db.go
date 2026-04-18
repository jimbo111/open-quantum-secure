package suricatalog

// ja3sHint carries a PQC detection note derived from a JA3S fingerprint.
type ja3sHint struct {
	// PQCPresent indicates the server is known to negotiate PQC key exchange.
	PQCPresent bool
	// Label is a human-readable description of the server stack.
	Label string
}

// ja3sDB maps JA3S hash → PQC hint. The table is intentionally sparse.
// JA3S-based PQC detection is speculative: the same hash may appear on
// non-PQC servers if they share cipher/extension sets. Use as a
// corroborating signal only — never as sole PQC evidence.
//
// TODO(S7): populate with authoritative Cloudflare PQ Experiment hashes
// once published. See: https://blog.cloudflare.com/pq-2024
// Cloudflare Research has published JA3S fingerprints for their
// 2023–2024 PQC-enabled edge nodes; add them here when confirmed.
var ja3sDB = map[string]ja3sHint{
	// Table intentionally empty — awaiting authoritative fingerprints.
	// When entries are added, each must cite a public source in a comment.
}

// lookupJA3S returns the hint for hash h and whether it was found.
func lookupJA3S(hash string) (ja3sHint, bool) {
	h, ok := ja3sDB[hash]
	return h, ok
}
