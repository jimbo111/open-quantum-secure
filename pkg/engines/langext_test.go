package engines

import (
	"context"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- helpers / mock engines ------------------------------------------------

// mockEngine implements Engine for testing.
type mockEngine struct {
	name  string
	tier  Tier
	langs []string
}

func (m *mockEngine) Name() string                  { return m.name }
func (m *mockEngine) Tier() Tier                    { return m.tier }
func (m *mockEngine) SupportedLanguages() []string  { return m.langs }
func (m *mockEngine) Available() bool               { return true }
func (m *mockEngine) Version() string               { return "test" }
func (m *mockEngine) Scan(_ context.Context, _ ScanOptions) ([]findings.UnifiedFinding, error) {
	return nil, nil
}

// --- TestLanguageExtensions_AllEngineLanguagesCovered ----------------------

// allEngineLanguages enumerates every language string returned by every real
// engine so we can assert they all have an entry in LanguageExtensions.
//
// This list must be kept in sync with SupportedLanguages() across all engines.
// It is intentionally duplicated here (not imported from engine packages) to
// keep the test free from circular-import concerns and to make the coverage
// explicit.
var allEngineLanguages = []string{
	// cipherscope
	"c", "cpp", "java", "python", "go", "swift", "php", "objc", "rust", "javascript", "typescript",
	// cryptoscan (adds ruby, csharp, kotlin, scala)
	"ruby", "csharp", "kotlin", "scala",
	// astgrep — subset of already-listed languages; no new ones
	// semgrep — subset of already-listed languages; no new ones
	// cdxgen (adds dotnet)
	"dotnet",
	// syft — subset of already-listed languages; no new ones
	// cryptodeps — subset of already-listed languages; no new ones
	// cbomkit-theia
	"(artifacts)",
	// binaryscanner — subset of already-listed languages; no new ones
	// configscanner
	"yaml", "json", "properties", "env", "toml", "xml", "ini", "hcl",
}

func TestLanguageExtensions_AllEngineLanguagesCovered(t *testing.T) {
	for _, lang := range allEngineLanguages {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			if _, ok := LanguageExtensions[lang]; !ok {
				t.Errorf("LanguageExtensions missing entry for language %q", lang)
			}
		})
	}
}

func TestLanguageExtensions_ExtensionsHaveDotPrefix(t *testing.T) {
	for lang, exts := range LanguageExtensions {
		for _, ext := range exts {
			if ext == "" {
				t.Errorf("LanguageExtensions[%q] contains empty extension string", lang)
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				t.Errorf("LanguageExtensions[%q] extension %q missing dot prefix", lang, ext)
			}
		}
	}
}

// --- TestExtensionsForEngine -----------------------------------------------

func TestExtensionsForEngine(t *testing.T) {
	t.Run("go_engine_includes_go_mod_sum", func(t *testing.T) {
		e := &mockEngine{name: "test-go", langs: []string{"go"}}
		exts := ExtensionsForEngine(e)
		if exts == nil {
			t.Fatal("expected non-nil extension set for go engine")
		}
		for _, want := range []string{".go", ".mod", ".sum"} {
			if !exts[want] {
				t.Errorf("expected extension %q in go engine set, got %v", want, exts)
			}
		}
	})

	t.Run("java_engine_includes_gradle_xml", func(t *testing.T) {
		e := &mockEngine{name: "test-java", langs: []string{"java"}}
		exts := ExtensionsForEngine(e)
		if exts == nil {
			t.Fatal("expected non-nil extension set for java engine")
		}
		for _, want := range []string{".java", ".gradle", ".xml"} {
			if !exts[want] {
				t.Errorf("expected extension %q in java engine set, got %v", want, exts)
			}
		}
	})

	t.Run("artifacts_engine_returns_nil", func(t *testing.T) {
		e := &mockEngine{name: "test-artifacts", langs: []string{"(artifacts)"}}
		if got := ExtensionsForEngine(e); got != nil {
			t.Errorf("expected nil for (artifacts) engine, got %v", got)
		}
	})

	t.Run("multi_lang_engine_union", func(t *testing.T) {
		e := &mockEngine{name: "test-multi", langs: []string{"go", "python"}}
		exts := ExtensionsForEngine(e)
		if exts == nil {
			t.Fatal("expected non-nil extension set")
		}
		for _, want := range []string{".go", ".mod", ".sum", ".py", ".pyi"} {
			if !exts[want] {
				t.Errorf("expected %q in multi-lang set, got %v", want, exts)
			}
		}
	})

	t.Run("unknown_language_only_returns_nil", func(t *testing.T) {
		e := &mockEngine{name: "test-unknown", langs: []string{"nonexistent-lang"}}
		if got := ExtensionsForEngine(e); got != nil {
			t.Errorf("expected nil for all-unknown languages, got %v", got)
		}
	})

	t.Run("empty_languages_returns_nil", func(t *testing.T) {
		e := &mockEngine{name: "test-empty", langs: []string{}}
		if got := ExtensionsForEngine(e); got != nil {
			t.Errorf("expected nil for empty languages, got %v", got)
		}
	})

	t.Run("env_lang_only_does_not_return_nil_unless_only_env", func(t *testing.T) {
		// "env" alone has an empty extension slice, so the result set is empty
		// and ExtensionsForEngine returns nil — callers must use IsRelevantFile
		// which has special basename logic for .env files.
		e := &mockEngine{name: "test-env", langs: []string{"env"}}
		// env alone → empty set → nil
		got := ExtensionsForEngine(e)
		if got != nil {
			t.Errorf("expected nil for env-only engine (basename matched by IsRelevantFile), got %v", got)
		}
	})

	t.Run("env_combined_with_yaml_is_non_nil", func(t *testing.T) {
		e := &mockEngine{name: "test-cfg", langs: []string{"yaml", "json", "properties", "env", "toml", "xml"}}
		exts := ExtensionsForEngine(e)
		if exts == nil {
			t.Fatal("expected non-nil for configscanner-like languages")
		}
		for _, want := range []string{".yaml", ".yml", ".json", ".properties", ".toml", ".xml", ".config"} {
			if !exts[want] {
				t.Errorf("expected %q in config-scanner set, got %v", want, exts)
			}
		}
	})
}

// --- TestExtensionsForEngines ----------------------------------------------

func TestExtensionsForEngines(t *testing.T) {
	t.Run("union_of_two_engines", func(t *testing.T) {
		engs := []Engine{
			&mockEngine{name: "a", langs: []string{"go"}},
			&mockEngine{name: "b", langs: []string{"python"}},
		}
		exts := ExtensionsForEngines(engs)
		if exts == nil {
			t.Fatal("expected non-nil union")
		}
		for _, want := range []string{".go", ".py"} {
			if !exts[want] {
				t.Errorf("expected %q in union, got %v", want, exts)
			}
		}
	})

	t.Run("nil_when_any_engine_has_no_filter", func(t *testing.T) {
		engs := []Engine{
			&mockEngine{name: "a", langs: []string{"go"}},
			&mockEngine{name: "b", langs: []string{"(artifacts)"}},
		}
		if got := ExtensionsForEngines(engs); got != nil {
			t.Errorf("expected nil when one engine is (artifacts), got %v", got)
		}
	})

	t.Run("empty_slice_returns_nil", func(t *testing.T) {
		if got := ExtensionsForEngines(nil); got != nil {
			t.Errorf("expected nil for nil engine slice, got %v", got)
		}
		if got := ExtensionsForEngines([]Engine{}); got != nil {
			t.Errorf("expected nil for empty engine slice, got %v", got)
		}
	})

	t.Run("three_engines_proper_union", func(t *testing.T) {
		engs := []Engine{
			&mockEngine{name: "a", langs: []string{"go"}},
			&mockEngine{name: "b", langs: []string{"java"}},
			&mockEngine{name: "c", langs: []string{"rust"}},
		}
		exts := ExtensionsForEngines(engs)
		if exts == nil {
			t.Fatal("expected non-nil union")
		}
		for _, want := range []string{".go", ".java", ".rs", ".toml", ".gradle"} {
			if !exts[want] {
				t.Errorf("expected %q in three-engine union, got %v", want, exts)
			}
		}
		// Python extensions should NOT be present.
		if exts[".py"] {
			t.Error("did not expect .py in three-engine union")
		}
	})
}

// --- TestIsRelevantFile ----------------------------------------------------

func TestIsRelevantFile(t *testing.T) {
	goExts := map[string]bool{".go": true, ".mod": true, ".sum": true}
	javaExts := map[string]bool{".java": true, ".gradle": true, ".xml": true}

	tests := []struct {
		name string
		path string
		exts map[string]bool
		want bool
	}{
		// Go extensions
		{"go file match", "/src/main.go", goExts, true},
		{"go.mod match", "/project/go.mod", goExts, true},
		{"go.sum match", "/project/go.sum", goExts, true},
		{"python file no match", "/src/main.py", goExts, false},

		// Java extensions
		{"java file match", "/src/Main.java", javaExts, true},
		{"gradle file match", "/build.gradle", javaExts, true},
		{"xml file match", "/config/beans.xml", javaExts, true},
		{"go file no match against java", "/main.go", javaExts, false},

		// Mixed set
		{"typescript match", "/app/index.ts",
			map[string]bool{".ts": true, ".js": true}, true},
		{"tsx match", "/app/App.tsx",
			map[string]bool{".tsx": true}, true},
		{"jsx no match when not in set", "/app/App.jsx",
			map[string]bool{".ts": true}, false},

		// Extensionless file
		{"no extension no match", "/usr/bin/elf-binary", goExts, false},

		// Case insensitivity on path extension
		{"upper case ext", "/src/Main.GO", goExts, true},
		{"mixed case .Java", "/src/Foo.Java", javaExts, true},

		// Deep path
		{"deep path go", "/a/b/c/d/e/f.go", goExts, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := IsRelevantFile(tc.path, tc.exts)
			if got != tc.want {
				t.Errorf("IsRelevantFile(%q, exts) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// --- TestIsRelevantFile_DotEnv ---------------------------------------------

func TestIsRelevantFile_DotEnv(t *testing.T) {
	// .env files must match regardless of what extension set is provided,
	// as long as exts is non-nil (some filter is active).
	someExts := map[string]bool{".go": true}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"bare .env", "/project/.env", true},
		{"env.local", "/project/.env.local", true},
		{"env.production", "/project/.env.production", true},
		{"env.development", "/project/.env.development", true},
		{"env.staging", "/project/.env.staging", true},
		{"env.test", "/project/.env.test", true},
		{"env deep path", "/a/b/c/.env", true},
		{"env deep path with suffix", "/a/b/c/.env.ci", true},
		// Should NOT match a file merely named "env" (no dot)
		{"plain env no dot", "/project/env", false},
		// Should NOT match ".envrc" — that's direnv, not an env file
		{"envrc", "/project/.envrc", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := IsRelevantFile(tc.path, someExts)
			if got != tc.want {
				t.Errorf("IsRelevantFile(%q, someExts) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// --- TestIsRelevantFile_NilExts --------------------------------------------

func TestIsRelevantFile_NilExts(t *testing.T) {
	paths := []string{
		"/any/file.go",
		"/any/file.java",
		"/etc/passwd",
		"/usr/bin/some-binary",
		"/project/.env",
		"/project/.env.local",
	}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			if !IsRelevantFile(path, nil) {
				t.Errorf("IsRelevantFile(%q, nil) = false, want true (nil means match-all)", path)
			}
		})
	}
}

// --- TestLanguageExtensions_NoDuplicatesWithinLang -------------------------

func TestLanguageExtensions_NoDuplicatesWithinLang(t *testing.T) {
	for lang, exts := range LanguageExtensions {
		seen := make(map[string]bool, len(exts))
		for _, ext := range exts {
			if seen[ext] {
				t.Errorf("LanguageExtensions[%q] contains duplicate extension %q", lang, ext)
			}
			seen[ext] = true
		}
	}
}

// --- TestExtensionsForEngine_Idempotent ------------------------------------

func TestExtensionsForEngine_Idempotent(t *testing.T) {
	e := &mockEngine{name: "idem", langs: []string{"go", "java", "python"}}
	first := ExtensionsForEngine(e)
	second := ExtensionsForEngine(e)

	if len(first) != len(second) {
		t.Fatalf("ExtensionsForEngine not idempotent: first=%v second=%v", first, second)
	}
	for k := range first {
		if !second[k] {
			t.Errorf("key %q present in first call but not second", k)
		}
	}
}
