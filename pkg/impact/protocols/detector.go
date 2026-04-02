package protocols

import (
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// protocolPatterns maps protocol names to the API call substrings that indicate
// a crossing of that protocol boundary.
var protocolPatterns = map[string][]string{
	"JWT": {
		"jwt.Sign",
		"jwt.Encode",
		"Set-Cookie",
		"JWSHeader",
	},
	"TLS": {
		"tls.Config",
		"tls.Listen",
		"tls.Dial",
		"TLSClientConfig",
	},
	"gRPC": {
		"metadata.Pairs",
		"grpc.SetHeader",
		"metadata.New",
	},
	"X.509": {
		"x509.CreateCertificate",
		"ParseCertificate",
		"CertPool",
	},
	"DTLS": {
		"dtls.Config",
		"dtls.Listen",
		"dtls.Dial",
	},
	"SSH": {
		"ssh.PublicKey",
		"ssh.NewSignerFromKey",
		"authorized_keys",
	},
	"OCSP": {
		"ocsp.CreateRequest",
		"ocsp.CreateResponse",
	},
	"S/MIME": {
		"smime.Encrypt",
		"smime.Sign",
		"pkcs7.Sign",
	},
}

// sortedProtocols holds the keys of protocolPatterns in sorted order, ensuring
// DetectFromPath iterates protocols deterministically regardless of map ordering.
var sortedProtocols []string

func init() {
	sortedProtocols = make([]string, 0, len(protocolPatterns))
	for k := range protocolPatterns {
		sortedProtocols = append(sortedProtocols, k)
	}
	sort.Strings(sortedProtocols)
}

// DetectFromPath inspects each FlowStep message for protocol API call patterns
// and returns a BoundaryHit for every match found.
func DetectFromPath(path []findings.FlowStep) []impact.BoundaryHit {
	var hits []impact.BoundaryHit

	for _, step := range path {
		for _, protocol := range sortedProtocols {
			subs := protocolPatterns[protocol]
			for _, sub := range subs {
				if strings.Contains(step.Message, sub) {
					hits = append(hits, impact.BoundaryHit{
						Protocol: protocol,
						File:     step.File,
						Line:     step.Line,
					})
					// One match per protocol per step is sufficient; avoid duplicate hits
					// for the same protocol from multiple pattern tokens in a single message.
					break
				}
			}
		}
	}

	return hits
}
