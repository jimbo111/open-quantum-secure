package cdxgen

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// This file builds the explicit -t/--type allow-list cdxgen is invoked with.
//
// cdxgen's own project-type auto-detection — what happens whenever no -t is
// passed — walks the invoking user's REAL browser profile directories
// (~/Library/Application Support/{Chrome,Edge,...} via os.homedir()) to probe
// for the "chrome-extension" project type. That single ecosystem probe is a
// ~39s / ~3GB fixed cost on every scan, entirely unrelated to the target
// repo (audit/review-2026-07-05/perf-empirical.md), and a privacy problem for
// a security-scanning tool. cdxgen's --exclude-type is NOT a safe mitigation:
// traced into the installed @cyclonedx/cdxgen's
// lib/helpers/utils.js:hasAnyProjectType, the "exclude-only" branch (no -t
// given, only --exclude-type) only special-cases oci/oci-dir/os/docker — for
// any other type, including chrome-extension, --exclude-type is silently a
// no-op. The only mechanism that suppresses auto-detection entirely is
// passing a non-empty -t allow-list, so every arg list this package builds
// must contain at least one -t.

// langToCdxgenType maps this engine's SupportedLanguages() entries to
// cdxgen's canonical -t/--type project-type strings. Verified against the
// installed @cyclonedx/cdxgen's lib/helpers/utils.js:PROJECT_TYPE_ALIASES
// (canonical keys) and the dispatch checks in lib/cli/index.js (e.g.
// hasAnyProjectType(["oci", "csharp"], options)) — js/java/py/go/rust/php/
// ruby/csharp/swift/c are the canonical type strings cdxgen's own dispatch
// code checks directly. dotnet/typescript/kotlin/scala are cdxgen aliases
// that resolve to these canonical types internally, but we pass the
// canonical form directly rather than depend on that alias-resolution path.
var langToCdxgenType = map[string]string{
	"javascript": "js",
	"typescript": "js",
	"java":       "java",
	"kotlin":     "java",
	"scala":      "java",
	"python":     "py",
	"go":         "go",
	"ruby":       "ruby",
	"rust":       "rust",
	"dotnet":     "csharp",
	"php":        "php",
	"swift":      "swift",
	"cpp":        "c",
	"c":          "c",
}

// extensionToCdxgenType maps file extensions to cdxgen -t types, derived from
// the shared pkg/engines.LanguageExtensions table (the "cheap source" already
// available for every engine) rather than a hand-rolled duplicate. Some
// extensions are shared across languages with different cdxgen types (e.g.
// ".xml" appears under "java" for pom.xml-style manifests); over-inclusion
// only costs one extra bounded ecosystem probe (~0.3-3.5s per the audit's
// bisection table), never the chrome-extension-class host walk.
var extensionToCdxgenType = buildExtensionToCdxgenType()

func buildExtensionToCdxgenType() map[string]string {
	out := make(map[string]string, 64)
	for lang, cdxType := range langToCdxgenType {
		for _, ext := range engines.LanguageExtensions[lang] {
			if ext == "" {
				continue
			}
			out[ext] = cdxType
		}
	}
	return out
}

// defaultCdxgenTypes is the conservative -t allow-list used when a target
// walk finds no recognizable files (empty repo, unreadable path, or nothing
// matched within the walk cap) — the union of cdxgen types covering every
// language this engine advertises. Never empty, never includes
// chrome-extension-class probes.
var defaultCdxgenTypes = sortedUniqueValues(langToCdxgenType)

func sortedUniqueValues(m map[string]string) []string {
	set := make(map[string]bool, len(m))
	for _, v := range m {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// cdxgenWalkEntryCap bounds detectCdxgenTypes's directory walk so that
// deriving a -t allow-list never itself becomes a perf problem on huge
// monorepos.
const cdxgenWalkEntryCap = 5000

// cdxgenSkipDirs are directory names never worth descending into when
// looking for language signal: .git (VCS internals), vendor and
// node_modules (vendored third-party code that would just echo back
// whatever ecosystems are already vendored, not what the repo itself uses).
var cdxgenSkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
}

// detectCdxgenTypes derives a -t allow-list from targetPath's contents.
func detectCdxgenTypes(targetPath string) []string {
	return detectCdxgenTypesLimit(targetPath, cdxgenWalkEntryCap)
}

// detectCdxgenTypesLimit is detectCdxgenTypes with an explicit entry cap,
// split out for deterministic testing of the cap behavior.
func detectCdxgenTypesLimit(targetPath string, limit int) []string {
	found := make(map[string]bool)
	visited := 0
	capped := false

	_ = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry (permissions, race with deletion, or the root
			// itself missing) — skip it and keep walking; never abort the
			// whole detection because of one bad entry.
			return nil
		}
		if visited >= limit {
			capped = true
			return filepath.SkipAll
		}
		visited++

		if d.IsDir() {
			if path != targetPath && cdxgenSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == "" {
			return nil
		}
		if t, ok := extensionToCdxgenType[ext]; ok {
			found[t] = true
		}
		return nil
	})

	if len(found) == 0 {
		return defaultCdxgenTypes
	}
	// Cap exhausted with partial signal: the walk may have stopped before
	// reaching a later-sorted ecosystem (a 5000-entry JS frontend hides a
	// services/ Go tree). Union the partial result with the full default
	// allow-list — over-inclusion costs seconds per extra type, silent
	// omission drops entire ecosystems from the SBOM (wave-2 review V7/V8).
	if capped {
		for _, t := range defaultCdxgenTypes {
			found[t] = true
		}
	}
	types := make([]string, 0, len(found))
	for t := range found {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// buildCdxgenArgs assembles cdxgen's CLI args around an explicit -t
// allow-list. types must never be empty when passed to the cdxgen binary —
// see the package-level comment for why (chrome-extension host-probe +
// --exclude-type being a no-op upstream). If a caller somehow provides an
// empty slice, fall back to defaultCdxgenTypes as a defense-in-depth guard
// rather than silently building an auto-detect-everything invocation.
func buildCdxgenArgs(tmpPath string, types []string, targetPath string) []string {
	if len(types) == 0 {
		types = defaultCdxgenTypes
	}
	args := make([]string, 0, 2+2*len(types)+3)
	args = append(args, "-o", tmpPath)
	for _, t := range types {
		args = append(args, "-t", t)
	}
	return append(args, "--spec-version", "1.5", targetPath)
}
