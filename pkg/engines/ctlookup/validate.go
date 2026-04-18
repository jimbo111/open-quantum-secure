package ctlookup

import (
	"errors"
	"net"
	"strings"
	"unicode"
)

// validateHostname is the package-internal alias for ValidateHostname.
func validateHostname(h string) error { return ValidateHostname(h) }

// ValidateHostname returns an error when h is not a valid DNS hostname suitable
// for a crt.sh query. Accepts bare hostnames and hostnames with an optional
// :port suffix (port is stripped before validation — only the hostname goes to
// crt.sh). Rules applied:
//
//   - Must not be empty
//   - Must not contain a URI scheme (e.g. "https://")
//   - Must not be an IP literal (IPv4 or IPv6)
//   - Must not contain CRLF, whitespace, or NUL bytes
//   - Total hostname length ≤ 253 bytes
//   - Each label 1–63 bytes, [a-zA-Z0-9-], no leading or trailing hyphen
func ValidateHostname(h string) error {
	if h == "" {
		return errors.New("empty hostname")
	}
	// Reject any URI scheme (e.g. "https://", "file://").
	if idx := strings.Index(h, "://"); idx >= 0 {
		return errors.New("hostname must not contain a URI scheme")
	}
	// Reject CRLF, whitespace, and NUL — common injection vectors.
	for _, r := range h {
		if r == '\r' || r == '\n' || r == 0 || unicode.IsSpace(r) {
			return errors.New("hostname contains invalid whitespace or control characters")
		}
	}
	// Strip optional :port suffix before further validation.
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		// No port or malformed — treat the whole string as the hostname.
		host = h
	}
	// Reject IP literals (both IPv4 and IPv6).
	if net.ParseIP(host) != nil {
		return errors.New("hostname must not be an IP literal; use a DNS name")
	}
	// Strip trailing dot (root label).
	host = strings.TrimRight(host, ".")
	if len(host) == 0 {
		return errors.New("empty hostname after normalization")
	}
	if len(host) > 253 {
		return errors.New("hostname exceeds 253-byte limit")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// validateLabel enforces RFC 1123 DNS label rules.
func validateLabel(label string) error {
	if len(label) == 0 {
		return errors.New("empty DNS label")
	}
	if len(label) > 63 {
		return errors.New("DNS label exceeds 63-byte limit")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return errors.New("DNS label must not start or end with a hyphen")
	}
	for _, c := range label {
		if !isLDHChar(c) {
			return errors.New("DNS label contains invalid character")
		}
	}
	return nil
}

// isLDHChar reports whether c is a letter, digit, or hyphen (LDH set).
func isLDHChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-'
}
