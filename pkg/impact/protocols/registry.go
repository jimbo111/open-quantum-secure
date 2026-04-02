package protocols

import "strings"

// ProtocolConstraint describes the maximum allowable crypto artifact size for a protocol.
type ProtocolConstraint struct {
	Name        string
	MaxBytes    int
	HardLimit   bool
	Description string
}

// registry holds the 8 supported protocol constraints in definition order.
var registry = []ProtocolConstraint{
	{
		Name:        "JWT",
		MaxBytes:    4096,
		HardLimit:   true,
		Description: "JSON Web Token header limit",
	},
	{
		Name:        "TLS",
		MaxBytes:    16384,
		HardLimit:   true,
		Description: "TLS record max payload",
	},
	{
		Name:        "gRPC",
		MaxBytes:    8192,
		HardLimit:   false,
		Description: "gRPC metadata soft limit",
	},
	{
		Name:        "X.509",
		MaxBytes:    16384,
		HardLimit:   false,
		Description: "X.509 certificate practical limit",
	},
	{
		Name:        "DTLS",
		MaxBytes:    1500,
		HardLimit:   true,
		Description: "DTLS MTU constraint",
	},
	{
		Name:        "SSH",
		MaxBytes:    35000,
		HardLimit:   true,
		Description: "SSH max packet payload",
	},
	{
		Name:        "OCSP",
		MaxBytes:    2048,
		HardLimit:   false,
		Description: "OCSP response practical limit",
	},
	{
		Name:        "S/MIME",
		MaxBytes:    51200,
		HardLimit:   false,
		Description: "S/MIME attachment practical limit",
	},
}

// All returns a copy of all protocol constraints.
func All() []ProtocolConstraint {
	out := make([]ProtocolConstraint, len(registry))
	copy(out, registry)
	return out
}

// Lookup returns the ProtocolConstraint for the given protocol name.
// Matching is case-insensitive. Returns false when not found.
func Lookup(protocol string) (ProtocolConstraint, bool) {
	upper := strings.ToUpper(protocol)
	for _, p := range registry {
		if strings.ToUpper(p.Name) == upper {
			return p, true
		}
	}
	return ProtocolConstraint{}, false
}
