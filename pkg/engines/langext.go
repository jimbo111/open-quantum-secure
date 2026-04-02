package engines

import (
	"path/filepath"
	"strings"
)

// LanguageExtensions maps language names (as returned by Engine.SupportedLanguages)
// to the file extensions (with dot prefix) that belong to that language.
//
// SCA manifest filenames are included as extensions so that SCA engines which
// declare a language (e.g. "java") automatically filter in the manifest files
// for that ecosystem (e.g. pom.xml, build.gradle).
//
// "(artifacts)" has an empty slice — it signals "scan everything" and is
// handled specially by ExtensionsForEngine/ExtensionsForEngines.
var LanguageExtensions = map[string][]string{
	// Source languages — compiled / interpreted
	"c":          {".c", ".h"},
	"cpp":        {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".inl"},
	"go":         {".go", ".mod", ".sum"},
	"java":       {".java", ".kt", ".kts", ".gradle", ".gradle.kts", ".xml"},
	"kotlin":     {".kt", ".kts"},
	"scala":      {".scala", ".sbt"},
	"python":     {".py", ".pyi", ".pyw"},
	"ruby":       {".rb", ".rake", ".gemspec"},
	"rust":       {".rs", ".toml"},
	"javascript": {".js", ".mjs", ".cjs"},
	"typescript": {".ts", ".tsx", ".mts", ".cts"},
	"swift":      {".swift"},
	"objc":       {".m", ".mm"},
	"php":        {".php", ".php3", ".php4", ".php5", ".phtml"},
	"csharp":     {".cs", ".csx", ".csproj", ".fsproj", ".vbproj", ".sln"},
	"dotnet":     {".cs", ".csx", ".vb", ".fs", ".csproj", ".fsproj", ".vbproj", ".sln"},

	// Config file formats used by configscanner
	"yaml":       {".yaml", ".yml"},
	"json":       {".json"},
	"properties": {".properties"},
	"env":        {}, // matched by basename prefix (.env, .env.local, etc.)
	"toml":       {".toml"},
	"xml":        {".xml", ".config"},
	"ini":        {".ini", ".cfg", ".cnf"},
	"hcl":        {".tf", ".hcl", ".tfvars"},

	// Artifact scanner — matches any file type
	"(artifacts)": {},
}

// ExtensionsForEngine returns the deduplicated set of file extensions relevant
// to an engine, derived from its SupportedLanguages() return values and the
// LanguageExtensions table.
//
// Returns nil when the engine should match all files — i.e., when:
//   - The engine advertises "(artifacts)" in SupportedLanguages, or
//   - The engine supports "env" (matched by basename, not extension), or
//   - The resulting extension set is empty after consulting the table.
//
// Callers must treat a nil return as "no filter — include all files".
func ExtensionsForEngine(e Engine) map[string]bool {
	langs := e.SupportedLanguages()

	// "(artifacts)" signals scan-all; return nil immediately.
	for _, l := range langs {
		if l == "(artifacts)" {
			return nil
		}
	}

	out := make(map[string]bool)
	for _, l := range langs {
		exts, ok := LanguageExtensions[l]
		if !ok {
			continue
		}
		// "env" has no extension — matched by basename prefix. Including it would
		// require returning nil (match-all), which is too broad. IsRelevantFile
		// handles .env files separately; the extension set just excludes them.
		for _, ext := range exts {
			out[ext] = true
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// ExtensionsForEngines returns the union of extension sets across all provided
// engines. Returns nil if any engine has no extension filter (meaning at least
// one engine must scan all files, so no filtering is possible).
func ExtensionsForEngines(engs []Engine) map[string]bool {
	union := make(map[string]bool)
	for _, e := range engs {
		exts := ExtensionsForEngine(e)
		if exts == nil {
			// At least one engine needs all files — no filtering possible.
			return nil
		}
		for ext := range exts {
			union[ext] = true
		}
	}
	if len(union) == 0 {
		return nil
	}
	return union
}

// IsRelevantFile reports whether path is relevant given the extension filter
// set exts.
//
// Special cases handled:
//   - nil exts means "match all" — always returns true.
//   - Files whose basename starts with ".env" are matched regardless of extension.
//   - The comparison uses filepath.Ext, which returns the last dot-prefixed suffix.
func IsRelevantFile(path string, exts map[string]bool) bool {
	if exts == nil {
		return true
	}

	base := strings.ToLower(filepath.Base(path))

	// .env and .env.* files are config-scanner targets — they have no extension
	// (the whole basename is ".env") or a non-standard suffix (.env.local).
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}

	return exts[ext]
}
