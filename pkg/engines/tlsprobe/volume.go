package tlsprobe

// HandshakeVolumeClass is a three-tier classifier for the total byte volume of
// a TLS handshake. It is a corroborating signal used when the CurveID-based
// classification is unavailable (e.g., TLS 1.2 with no named group, or an
// unknown codepoint). When CurveID is known and classifies successfully, volume
// is reported as metadata only — it does NOT override the deterministic signal.
//
// Thresholds are derived from:
//   - Sikeridis et al., NDSS 2020
//   - Westerbaan et al., PQCrypto 2025
//   - Kwiatkowski/Valenta, Cloudflare PQ Experiment (practical measurements)
type HandshakeVolumeClass int

const (
	// VolumeClassical covers handshakes < 7 KB. All classical TLS 1.3
	// handshakes (X25519, secp256r1, etc.) fall well within this range.
	VolumeClassical HandshakeVolumeClass = iota

	// VolumeHybridKEM covers handshakes in [7 KB, 12 KB]. The additional ~1.2 KB
	// from ML-KEM-768's key material pushes X25519MLKEM768 handshakes into this
	// band compared to a classical baseline.
	VolumeHybridKEM

	// VolumeUnknown is the transitional gap [12 KB, 20 KB] that does not map
	// cleanly to either hybrid or full-PQC. Do not misclassify — report as unknown.
	VolumeUnknown

	// VolumeFullPQC covers handshakes > 20 KB. Pure ML-KEM with ML-DSA
	// certificates pushes handshakes into this range.
	VolumeFullPQC
)

// thresholdHybridMin is the lower bound (inclusive) of the hybrid-KEM band.
const thresholdHybridMin int64 = 7_000

// thresholdHybridMax is the upper bound (exclusive) of the hybrid-KEM band.
const thresholdHybridMax int64 = 12_000

// thresholdFullPQC is the lower bound (exclusive) for full-PQC classification.
const thresholdFullPQC int64 = 20_000

// ClassifyHandshakeVolume maps the total bytes transferred during a TLS
// handshake (BytesIn + BytesOut from countingConn) to a HandshakeVolumeClass.
// The thresholds represent conservative estimates; the CurveID signal always
// takes precedence when available.
func ClassifyHandshakeVolume(totalBytes int64) HandshakeVolumeClass {
	switch {
	case totalBytes < thresholdHybridMin:
		return VolumeClassical
	case totalBytes < thresholdHybridMax:
		return VolumeHybridKEM
	case totalBytes > thresholdFullPQC:
		return VolumeFullPQC
	default:
		// 12 000 ≤ totalBytes ≤ 20 000: transitional gap.
		return VolumeUnknown
	}
}

// String returns the canonical string representation used in ProbeResult and
// output formats.
func (c HandshakeVolumeClass) String() string {
	switch c {
	case VolumeClassical:
		return "classical"
	case VolumeHybridKEM:
		return "hybrid-kem"
	case VolumeFullPQC:
		return "full-pqc"
	default:
		return "unknown"
	}
}
