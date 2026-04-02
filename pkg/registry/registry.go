package registry

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

//go:embed cryptography-defs.json
var registryJSON []byte

// Registry holds the parsed CycloneDX cryptography definitions and derived lookup indices.
type Registry struct {
	LastUpdated string            `json:"lastUpdated"`
	Algorithms  []AlgorithmFamily `json:"algorithms"`
	Curves      []CurveFamily     `json:"curves"`

	// Derived indices — built once at Load() time.
	familyIndex    map[string]*AlgorithmFamily
	familyPrefixes []string // sorted by length descending for longest-prefix matching
	patternIndex   []compiledPattern
	curveNameIndex  map[string]*Curve
	curveAliasIndex map[string]string // alias (lower) → canonical ("family/Name")
	curveOIDIndex   map[string]string // OID → canonical
}

// AlgorithmFamily groups variants of a single cryptographic algorithm family.
type AlgorithmFamily struct {
	Family   string     `json:"family"`
	Standard []Standard `json:"standard"`
	Variant  []Variant  `json:"variant"`
}

// Standard references a normative specification for an algorithm.
type Standard struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Variant describes a specific parameterisation of an algorithm family.
type Variant struct {
	Pattern   string `json:"pattern"`
	Primitive string `json:"primitive"`
}

// CurveFamily groups elliptic curves from the same authority or standard.
type CurveFamily struct {
	Name   string  `json:"name"`
	Curves []Curve `json:"curves"`
}

// Curve represents a single named elliptic curve with optional OID and aliases.
type Curve struct {
	Name    string       `json:"name"`
	OID     string       `json:"oid,omitempty"`
	Form    string       `json:"form,omitempty"`
	Aliases []CurveAlias `json:"aliases,omitempty"`
}

// CurveAlias is an alternative name for a curve in a given category.
type CurveAlias struct {
	Category string `json:"category"`
	Name     string `json:"name"`
}

var (
	globalRegistry *Registry
	loadOnce       sync.Once
)

// Load returns the singleton Registry, parsing and indexing the embedded JSON on the first call.
// Subsequent calls return the same instance without re-parsing.
// Panics if the embedded JSON is malformed (programming error, not a runtime condition).
func Load() *Registry {
	loadOnce.Do(func() {
		r := &Registry{}
		if err := json.Unmarshal(registryJSON, r); err != nil {
			panic("cyclonedx registry: " + err.Error())
		}
		r.buildIndices()
		globalRegistry = r // assign only after full init succeeds
	})
	return globalRegistry
}

// buildIndices constructs all O(1) lookup maps from the parsed data.
func (r *Registry) buildIndices() {
	// Family index: UPPER(family) → *AlgorithmFamily
	r.familyIndex = make(map[string]*AlgorithmFamily, len(r.Algorithms))
	for i := range r.Algorithms {
		fam := &r.Algorithms[i]
		r.familyIndex[strings.ToUpper(fam.Family)] = fam
	}

	// Sorted family prefixes for deterministic longest-prefix matching.
	r.familyPrefixes = make([]string, 0, len(r.familyIndex))
	for k := range r.familyIndex {
		r.familyPrefixes = append(r.familyPrefixes, k)
	}
	sort.Slice(r.familyPrefixes, func(i, j int) bool {
		return len(r.familyPrefixes[i]) > len(r.familyPrefixes[j])
	})

	// Pattern index: compile each variant pattern to a regex once.
	r.patternIndex = nil
	for i := range r.Algorithms {
		fam := &r.Algorithms[i]
		for _, v := range fam.Variant {
			cp, err := compilePattern(v.Pattern, fam.Family)
			if err == nil {
				cp.primitive = v.Primitive
				r.patternIndex = append(r.patternIndex, cp)
			}
		}
	}

	// Curve indices.
	r.curveNameIndex = make(map[string]*Curve)
	r.curveAliasIndex = make(map[string]string)
	r.curveOIDIndex = make(map[string]string)

	for i := range r.Curves {
		cf := &r.Curves[i]
		for j := range cf.Curves {
			c := &cf.Curves[j]
			canonical := cf.Name + "/" + c.Name

			// Both the short name and the "family/Name" canonical form resolve to the same Curve.
			r.curveNameIndex[canonical] = c
			r.curveNameIndex[c.Name] = c

			if c.OID != "" {
				r.curveOIDIndex[c.OID] = canonical
			}
			for _, alias := range c.Aliases {
				r.curveAliasIndex[strings.ToLower(alias.Name)] = canonical
			}
		}
	}
}

// FamilyCount returns the number of algorithm families in the registry.
func (r *Registry) FamilyCount() int { return len(r.Algorithms) }

// CurveCount returns the total number of curves across all curve families.
func (r *Registry) CurveCount() int {
	count := 0
	for _, cf := range r.Curves {
		count += len(cf.Curves)
	}
	return count
}

// PatternCount returns the number of compiled variant patterns.
func (r *Registry) PatternCount() int { return len(r.patternIndex) }

// LookupFamily retrieves an AlgorithmFamily by name (case-insensitive).
func (r *Registry) LookupFamily(name string) (*AlgorithmFamily, bool) {
	fam, ok := r.familyIndex[strings.ToUpper(name)]
	return fam, ok
}
