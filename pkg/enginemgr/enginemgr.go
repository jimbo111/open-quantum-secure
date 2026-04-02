package enginemgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
)

// EngineInfo describes a known engine and how to install it.
type EngineInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tier        int      `json:"tier"` // 1, 2, or 3
	Languages   []string `json:"languages"`
	BinaryName  string   `json:"binaryName"`
	BuildTool   string   `json:"buildTool"`
	InstallHint string   `json:"installHint"`
}

// Status represents the health of an installed engine.
type Status struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

// registry is the canonical list of all known engines.
var registry = []EngineInfo{
	{
		Name:        "cipherscope",
		Description: "Rust-based AST scanner for cryptographic usage",
		Tier:        1,
		Languages:   []string{"c", "cpp", "java", "python", "go", "swift", "php", "objc", "rust", "javascript", "typescript"},
		BinaryName:  "cipherscope",
		BuildTool:   "cargo",
		InstallHint: "cargo build --release in OQS/cipherscope-main",
	},
	{
		Name:        "cryptoscan",
		Description: "Go-based static analysis scanner",
		Tier:        1,
		Languages:   []string{"c", "cpp", "java", "python", "go", "swift", "php", "rust", "javascript", "typescript", "ruby", "csharp", "kotlin", "scala"},
		BinaryName:  "cryptoscan",
		BuildTool:   "go",
		InstallHint: "go build ./cmd/cryptoscan in OQS/cryptoscan-main",
	},
	{
		Name:        "astgrep",
		Description: "Structural search for cryptographic patterns",
		Tier:        1,
		Languages:   []string{"c", "cpp", "java", "python", "go", "javascript", "typescript", "rust", "ruby", "csharp", "kotlin", "php"},
		BinaryName:  "ast-grep",
		BuildTool:   "cargo",
		InstallHint: "cargo install ast-grep\n  # or: npm install -g @ast-grep/cli",
	},
	{
		Name:        "semgrep",
		Description: "Semgrep-based taint analysis for cryptographic data flow",
		Tier:        2,
		Languages:   []string{"java", "python", "go", "javascript", "typescript", "c", "cpp", "ruby", "rust", "php"},
		BinaryName:  "semgrep",
		BuildTool:   "pip",
		InstallHint: "pip install semgrep\n  # or: pipx install semgrep",
	},
	{
		Name:        "cryptodeps",
		Description: "Dependency-level cryptographic library detection",
		Tier:        3,
		Languages:   []string{"go", "java", "python", "javascript", "rust", "ruby", "dotnet", "php"},
		BinaryName:  "cryptodeps",
		BuildTool:   "go",
		InstallHint: "go build ./cmd/cryptodeps in OQS/cryptodeps-main",
	},
	{
		Name:        "cdxgen",
		Description: "CycloneDX SBOM generator",
		Tier:        3,
		Languages:   []string{"javascript", "typescript", "java", "python", "go", "ruby", "rust", "dotnet", "php", "swift", "kotlin", "scala", "cpp", "c"},
		BinaryName:  "cdxgen",
		BuildTool:   "npm",
		InstallHint: "npm install -g @cyclonedx/cdxgen",
	},
	{
		Name:        "syft",
		Description: "Anchore SBOM scanner",
		Tier:        3,
		Languages:   []string{"go", "java", "python", "javascript", "ruby", "rust", "dotnet", "php", "cpp", "c"},
		BinaryName:  "syft",
		BuildTool:   "go",
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh",
	},
	{
		Name:        "cbomkit-theia",
		Description: "IBM CBOM generation toolkit",
		Tier:        3,
		Languages:   []string{"(artifacts)"},
		BinaryName:  "cbomkit-theia",
		BuildTool:   "go",
		InstallHint: "go build -o cbomkit-theia . in OQS/cbomkit-theia-main",
	},
	{
		Name:        "binary-scanner",
		Description: "Binary artifact scanning (JAR, Go binaries, native ELF/PE/Mach-O, Python wheels)",
		Tier:        4,
		Languages:   []string{"java", "go", "c", "cpp", "python"},
		BinaryName:  "", // embedded — no external binary needed
		BuildTool:   "embedded",
		InstallHint: "Built-in (no installation required)",
	},
	{
		Name:        "config-scanner",
		Description: "Config file scanning for cryptographic parameters (YAML, JSON, .properties, .env, TOML, XML, INI, HCL)",
		Tier:        1,
		Languages:   []string{"yaml", "json", "properties", "env", "toml", "xml", "ini", "hcl"},
		BinaryName:  "", // embedded — no external binary needed
		BuildTool:   "embedded",
		InstallHint: "Built-in (no installation required)",
	},
}

// Registry returns the list of all known engines.
func Registry() []EngineInfo {
	result := make([]EngineInfo, len(registry))
	copy(result, registry)
	return result
}

// InstallDir returns the default engine install directory.
// Delegates to config.EngineCacheDir() for platform-aware path resolution
// (Windows uses %APPDATA%\oqs, Unix uses ~/.oqs).
// Returns an error if the resolved path is not absolute (e.g. $HOME unset).
func InstallDir() (string, error) {
	dir := config.EngineCacheDir()
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("engine install dir %q is not an absolute path (is $HOME set?)", dir)
	}
	return dir, nil
}

// CheckEngine checks if a single engine is available and healthy.
// It searches searchDirs first, then falls back to exec.LookPath.
// For astgrep, it also checks for "sg" as an alternative binary name.
func CheckEngine(info EngineInfo, searchDirs []string) Status {
	return checkEngineCtx(context.Background(), info, searchDirs)
}

// checkEngineCtx is the context-aware implementation of CheckEngine.
// The context is passed through to probeVersionCtx so that a parent deadline
// or cancellation is respected during version probing.
func checkEngineCtx(ctx context.Context, info EngineInfo, searchDirs []string) Status {
	status := Status{Name: info.Name}

	// Embedded engines (BinaryName == "") are always available.
	if info.BinaryName == "" {
		status.Available = true
		status.Version = "embedded"
		return status
	}

	binaryPath := findBinary(info.BinaryName, searchDirs)

	// For astgrep, also try the "sg" alias.
	if binaryPath == "" && info.BinaryName == "ast-grep" {
		binaryPath = findBinary("sg", searchDirs)
	}

	if binaryPath == "" {
		status.Available = false
		status.Error = "not found"
		return status
	}

	status.Available = true
	status.Path = binaryPath
	status.Version = probeVersionCtx(ctx, binaryPath)
	return status
}

// CheckAll checks all registered engines in parallel and returns one Status per
// engine in registry order. The parent context is propagated to each engine
// health check so that a caller-provided deadline is respected.
func CheckAll(searchDirs []string) []Status {
	return checkAllCtx(context.Background(), searchDirs)
}

// checkAllCtx is the context-aware implementation of CheckAll.
// It fans out to goroutines (one per engine) and collects results into an
// indexed slice so that the output order matches the registry order.
func checkAllCtx(ctx context.Context, searchDirs []string) []Status {
	reg := Registry()
	statuses := make([]Status, len(reg))

	type result struct {
		idx    int
		status Status
	}
	ch := make(chan result, len(reg))

	for i, info := range reg {
		i, info := i, info // capture loop variables
		go func() {
			defer func() {
				if r := recover(); r != nil {
					ch <- result{idx: i, status: Status{
						Name:  info.Name,
						Error: fmt.Sprintf("panic: %v", r),
					}}
				}
			}()
			ch <- result{idx: i, status: checkEngineCtx(ctx, info, searchDirs)}
		}()
	}

	for range reg {
		r := <-ch
		statuses[r.idx] = r.status
	}
	return statuses
}

// findBinary searches the given directories for the binary, then falls back to PATH.
// On Windows, it also checks for the name with a .exe suffix.
func findBinary(name string, searchDirs []string) string {
	for _, dir := range searchDirs {
		candidate := filepath.Join(dir, name)
		if isExecutable(candidate) {
			return candidate
		}
		// On Windows, try with .exe suffix since downloadOne appends it.
		if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".exe") {
			candidate = filepath.Join(dir, name+".exe")
			if isExecutable(candidate) {
				return candidate
			}
		}
	}
	p, err := exec.LookPath(name)
	if err == nil {
		return p
	}
	return ""
}

// isExecutable returns true if the path exists and is a regular file that can be executed.
// On Unix, checks for execute permission bits. On Windows, checks for .exe/.cmd/.bat extension
// since permission bits are not meaningful.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		ext := strings.ToLower(filepath.Ext(path))
		return ext == ".exe" || ext == ".cmd" || ext == ".bat"
	}
	return info.Mode()&0o111 != 0
}

// probeVersion runs `<binary> --version` with a 5-second timeout derived from
// context.Background() and returns the trimmed first line of output.
// Returns "unknown" on any failure.
func probeVersion(binaryPath string) string {
	return probeVersionCtx(context.Background(), binaryPath)
}

// probeVersionCtx runs `<binary> --version` with a 5-second timeout derived
// from the parent context. If the parent context has a shorter deadline, that
// shorter deadline is used instead. Returns "unknown" on any failure.
func probeVersionCtx(parent context.Context, binaryPath string) string {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, binaryPath, "--version").CombinedOutput()
	if err != nil {
		return "unknown"
	}

	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	line = strings.TrimSpace(line)
	if line == "" {
		return "unknown"
	}
	return line
}
