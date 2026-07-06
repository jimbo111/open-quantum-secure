package cdxgen

// Tests for the cdxgen -t/--type allow-list construction (E1 fix).
//
// cdxgen's own project-type auto-detection — triggered whenever no -t is
// passed — walks the invoking user's real browser profile directories to
// probe for the "chrome-extension" project type: a ~39s / ~3GB fixed cost on
// every scan, unrelated to the target repo (see
// audit/review-2026-07-05/perf-empirical.md). These tests pin down that the
// engine (a) derives a -t allow-list from the target repo's contents when
// possible, (b) falls back to a conservative non-empty allow-list otherwise,
// and (c) never constructs an arg list that omits -t entirely.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestLangToCdxgenType_CoversAllSupportedLanguages(t *testing.T) {
	e := &Engine{}
	for _, lang := range e.SupportedLanguages() {
		if _, ok := langToCdxgenType[lang]; !ok {
			t.Errorf("langToCdxgenType missing entry for SupportedLanguages() member %q", lang)
		}
	}
}

func TestDefaultCdxgenTypes_NonEmptyAndSorted(t *testing.T) {
	if len(defaultCdxgenTypes) == 0 {
		t.Fatal("defaultCdxgenTypes must never be empty — an empty -t list means cdxgen auto-detects everything")
	}
	if !sort.StringsAreSorted(defaultCdxgenTypes) {
		t.Errorf("defaultCdxgenTypes not sorted: %v", defaultCdxgenTypes)
	}
	// Must never contain chrome-extension-class probes.
	for _, banned := range []string{"chrome-extension", "vscode-extension", "oci", "os", "android"} {
		for _, got := range defaultCdxgenTypes {
			if got == banned {
				t.Errorf("defaultCdxgenTypes contains banned auto-probe type %q", banned)
			}
		}
	}
}

func TestDetectCdxgenTypesLimit_MatchesExtensions(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "main.go"), "package main")
	mustWrite(t, filepath.Join(dir, "script.py"), "print('hi')")

	got := detectCdxgenTypesLimit(dir, cdxgenWalkEntryCap)
	want := []string{"go", "py"}
	assertStringSlicesEqual(t, got, want)
}

func TestDetectCdxgenTypesLimit_SkipsGitVendorNodeModules(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "main.go"), "package main")
	mustWrite(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main")
	mustWrite(t, filepath.Join(dir, "vendor", "lib.rb"), "# ruby")
	mustWrite(t, filepath.Join(dir, "node_modules", "pkg", "index.js"), "module.exports = {}")

	got := detectCdxgenTypesLimit(dir, cdxgenWalkEntryCap)
	want := []string{"go"}
	assertStringSlicesEqual(t, got, want)
}

func TestDetectCdxgenTypesLimit_EmptyDirFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	got := detectCdxgenTypesLimit(dir, cdxgenWalkEntryCap)
	assertStringSlicesEqual(t, got, defaultCdxgenTypes)
}

func TestDetectCdxgenTypesLimit_NonexistentPathFallsBackToDefault(t *testing.T) {
	got := detectCdxgenTypesLimit(filepath.Join(t.TempDir(), "does-not-exist"), cdxgenWalkEntryCap)
	assertStringSlicesEqual(t, got, defaultCdxgenTypes)
}

// TestDetectCdxgenTypesLimit_CapsWalkEntries proves the walk actually stops
// once it hits the entry cap, instead of always finishing a full recursive
// walk of TargetPath (which is the whole point of capping it — an
// uncapped walk on a huge monorepo would itself become a perf problem).
// Wave-2 review V7/V8 changed the cap-hit RESULT: a truncated walk can no
// longer silently narrow the allow-list, so a cap-hit result is the union
// of what was found with the full default list (the .py file below is
// never visited, yet "py" is present via the union). The walk still stops
// — proven by the cap flag path, and by the uncapped variant staying
// narrow.
func TestDetectCdxgenTypesLimit_CapsWalkEntries(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a_first.go"), "package main")
	mustWrite(t, filepath.Join(dir, "z_second.py"), "print('hi')")

	got := detectCdxgenTypesLimit(dir, 2) // root dir entry + first file only
	assertStringSlicesEqual(t, got, defaultCdxgenTypes)

	// No cap pressure → detection stays narrow, no union.
	narrow := detectCdxgenTypesLimit(dir, cdxgenWalkEntryCap)
	assertStringSlicesEqual(t, narrow, []string{"go", "py"})
}

func TestBuildCdxgenArgs_AlwaysContainsTypeFlag(t *testing.T) {
	args := buildCdxgenArgs("/tmp/out.json", []string{"go", "py"}, "/repo")
	if !containsArg(args, "-t") {
		t.Fatalf("args missing -t flag entirely: %v", args)
	}
}

func TestBuildCdxgenArgs_RepeatedFlagsInOrder(t *testing.T) {
	args := buildCdxgenArgs("/tmp/out.json", []string{"go", "py"}, "/repo")
	want := []string{"-o", "/tmp/out.json", "-t", "go", "-t", "py", "--spec-version", "1.5", "/repo"}
	assertStringSlicesEqual(t, args, want)
}

// TestBuildCdxgenArgs_EmptyTypesNeverAutoDetects is the defense-in-depth
// guard: even if a caller somehow passes an empty types slice, buildCdxgenArgs
// must never hand cdxgen a bare arg list (which means "auto-detect
// everything", including chrome-extension).
func TestBuildCdxgenArgs_EmptyTypesNeverAutoDetects(t *testing.T) {
	args := buildCdxgenArgs("/tmp/out.json", nil, "/repo")
	if !containsArg(args, "-t") {
		t.Fatalf("empty types must fall back to a non-empty -t allow-list, got: %v", args)
	}
}

// TestScan_InvokesBinaryWithExplicitTypeFlag is the end-to-end guard: it
// drives the real Scan() path against a fake cdxgen binary that records its
// full argv, and asserts the recorded invocation always contains -t — i.e.
// Scan() never shells out to cdxgen in bare auto-detect mode.
func TestScan_InvokesBinaryWithExplicitTypeFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	recorder := filepath.Join(t.TempDir(), "argv.txt")
	body := `
for a in "$@"; do echo "$a"; done > ` + recorder + `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"components":[]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "main.go"), "package main")

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: target})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	raw, err := os.ReadFile(recorder)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	if !containsArg(argv, "-t") {
		t.Fatalf("cdxgen invoked without -t flag — auto-detect mode. argv: %v", argv)
	}
	if !containsArg(argv, "go") {
		t.Errorf("expected detected type %q in argv (target has main.go), got: %v", "go", argv)
	}
}

// --- test helpers ---

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertStringSlicesEqual(t *testing.T, got, want []string) {
	t.Helper()
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func containsArg(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}

