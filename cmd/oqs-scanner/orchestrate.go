// orchestrate.go wires up the scanner orchestrator and its engine set.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/astgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cbomkit"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cdxgen"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cipherscope"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/configscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptodeps"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptoscan"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/ctlookup"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/semgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/sshprobe"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/suricatalog"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/syft"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/zeeklog"
	"github.com/jimbo111/open-quantum-secure/pkg/orchestrator"
)

func engineDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "engines")
}

func buildOrchestrator() *orchestrator.Orchestrator {
	dirs := enginesSearchDirs()

	// Tier 1: Pattern/AST engines
	cs := cipherscope.New(dirs...)
	cscan := cryptoscan.New(dirs...)
	ag := astgrep.New(dirs...)

	// Tier 2: Taint/flow engines
	sg := semgrep.New(dirs...)

	// Tier 3: SCA / supply-chain engines
	cdeps := cryptodeps.New(dirs...)
	cdx := cdxgen.New(dirs...)
	sy := syft.New(dirs...)
	cbk := cbomkit.New(dirs...)

	// Tier 4: Binary scanning engine (pure Go, always available)
	bs := binaryscanner.New()

	// Tier 1: Config file scanner (pure Go, always available)
	cfgs := configscanner.New()

	// Tier 5: TLS probe engine (pure Go, always available)
	tlsp := tlsprobe.New()

	// Tier 5: CT log lookup engine (pure Go, always available)
	// Registered after tls-probe so the orchestrator's two-pass network loop
	// runs tls-probe first and can enrich ct-lookup with ECH hostnames.
	ct := ctlookup.New()

	// Tier 5: SSH probe engine (pure Go, always available; Sprint 4).
	sshp := sshprobe.New()

	// Tier 5: Zeek log ingestion engine (pure Go, always available; Sprint 5).
	// Reads ssl.log + x509.log produced by Zeek network monitoring.
	zeek := zeeklog.New()

	// Tier 5: Suricata eve.json log ingestion engine (pure Go, always available; Sprint 6).
	suri := suricatalog.New()

	return orchestrator.New(cs, cscan, ag, sg, cdeps, cdx, sy, cbk, bs, cfgs, tlsp, ct, sshp, zeek, suri)
}

// engineVersionsHash computes a stable SHA-256 hex digest over the
// name→version map of the provided engines. The sort order is deterministic
// (sorted by name) so the same set of engine versions always produces the
// same hash, regardless of map iteration order.
func engineVersionsHash(engs []engines.Engine) string {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(engs))
	for _, e := range engs {
		pairs = append(pairs, kv{e.Name(), e.Version()})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.k)
		sb.WriteByte('=')
		sb.WriteString(p.v)
		sb.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}
