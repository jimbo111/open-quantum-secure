package constraints

import (
	"regexp"
	"strconv"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// constraintPattern pairs a regex with the constraint type it represents.
type constraintPattern struct {
	typ string
	re  *regexp.Regexp
}

// patterns is the compiled set of constraint-detection regexes.
// Each regex must capture the numeric limit in group 1 (and optionally group 2
// for the CONSTANT=N form).
var patterns = []constraintPattern{
	{
		typ: "buffer-alloc",
		re:  regexp.MustCompile(`make\(\[\]byte,\s*(\d+)\)`),
	},
	{
		typ: "buffer-alloc",
		re:  regexp.MustCompile(`new\s+byte\[(\d+)\]`),
	},
	{
		typ: "db-column",
		re:  regexp.MustCompile(`VARCHAR\((\d+)\)`),
	},
	{
		typ: "config",
		re:  regexp.MustCompile(`max_len\s*=\s*(\d+)`),
	},
	{
		typ: "constant",
		re:  regexp.MustCompile(`(\w+_MAX_\w+)\s*=\s*(\d+)`),
	},
}

// DetectFromPath scans FlowStep messages for size-constraint patterns and
// returns a ConstraintHit for every match found. EffectiveMax is set equal to
// MaxBytes (encoding adjustment is deferred to the solver layer).
func DetectFromPath(path []findings.FlowStep) []impact.ConstraintHit {
	var hits []impact.ConstraintHit

	for _, step := range path {
		for _, p := range patterns {
			matches := p.re.FindAllStringSubmatch(step.Message, -1)
			for _, m := range matches {
				rawN := m[1]
				// constant pattern: group 1 = constant name, group 2 = value
				if p.typ == "constant" && len(m) >= 3 {
					rawN = m[2]
				}
				n, err := strconv.Atoi(rawN)
				if err != nil || n <= 0 {
					continue
				}
				hits = append(hits, impact.ConstraintHit{
					Type:         p.typ,
					File:         step.File,
					Line:         step.Line,
					MaxBytes:     n,
					EffectiveMax: n,
				})
			}
		}
	}

	return hits
}
