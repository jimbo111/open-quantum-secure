package engines

import (
	"os"
	"os/exec"
	"path/filepath"
)

// FindBinary locates an executable by searching extraDirs first (in order),
// then falling back to PATH via exec.LookPath. Each name in names is tried
// against each extraDir before moving to the next dir; this preserves the
// "first dir wins" precedence relied on by callers that point at vendored
// engines/ directories before system PATH.
//
// Variadic names support tools that ship under multiple binary names
// (e.g. ast-grep ships as both "ast-grep" and "sg"). When names is empty
// FindBinary returns "".
//
// Returns "" if no candidate is found in extraDirs or on PATH.
func FindBinary(extraDirs []string, names ...string) string {
	for _, dir := range extraDirs {
		for _, name := range names {
			p := filepath.Join(dir, name)
			if IsExecutable(p) {
				return p
			}
		}
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// IsExecutable reports whether path refers to a regular file with at least
// one executable bit set. Directories return false even when their mode bits
// would otherwise pass — directory exec bits mean "traversable", not
// "runnable".
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}
