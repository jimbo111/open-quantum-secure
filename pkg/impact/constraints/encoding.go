package constraints

// CalculateEncodedSize returns the byte length of rawBytes after applying the
// named encoding. Supported encodings:
//
//   - "base64" — standard base64: ceil(n/3)*4 bytes
//   - "hex"    — lowercase hex:    n*2 bytes
//   - "pem"    — base64 with 64-char line breaks plus BEGIN/END headers (52 bytes)
//   - "der"    — DER envelope:     n+8 bytes
//   - "raw" or "" — identity:      n bytes
//
// Unknown encodings are treated as "raw".
func CalculateEncodedSize(rawBytes int, encoding string) int {
	switch encoding {
	case "base64":
		return base64Size(rawBytes)
	case "hex":
		return rawBytes * 2
	case "pem":
		b64 := base64Size(rawBytes)
		// Line wrapping: ceil(b64/64) newline characters
		lines := (b64 + 63) / 64
		// PEM headers: "-----BEGIN <TYPE>-----\n" + "-----END <TYPE>-----\n" = 52 bytes total
		return b64 + lines + 52
	case "der":
		return rawBytes + 8
	default:
		// "raw", "", or any unknown encoding — no overhead
		return rawBytes
	}
}

// base64Size returns the base64-encoded length for n raw bytes (no line breaks).
func base64Size(n int) int {
	return ((n + 2) / 3) * 4
}
