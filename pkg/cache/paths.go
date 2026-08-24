package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
)

// legacyCacheFileName is the pre-hardening repo-local cache file name. Caches
// at this location inside the scanned tree are NO LONGER loaded by default:
// a hostile repository could ship a crafted cache with correct content hashes
// and matching versions, suppressing or fabricating findings without any
// engine ever running (cache poisoning). See LegacyRepoLocalPath.
const legacyCacheFileName = ".oqs-scanner-cache.json"

// slugUnsafeRe matches characters that are stripped from the project basename
// when building the cache slug (keep it filesystem- and shell-safe).
var slugUnsafeRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// DefaultPath returns the default incremental-cache file location for a scan
// target. The cache lives OUTSIDE the scanned tree, under the user's OQS
// config directory (~/.oqs/cache/scans/<slug>.json), so that a malicious
// repository cannot pre-seed a poisoned cache that the scanner would trust.
//
// The slug is derived from the ABSOLUTE scan path: a sanitized basename for
// human readability plus a 12-hex-char SHA-256 prefix of the absolute path
// for uniqueness across projects with the same directory name.
func DefaultPath(scanPath string) string {
	abs, err := filepath.Abs(scanPath)
	if err != nil {
		abs = scanPath
	}
	return filepath.Join(config.ConfigDir(), "cache", "scans", projectSlug(abs)+".json")
}

// LegacyRepoLocalPath returns the old (untrusted) repo-local cache location
// for a scan target. Callers use this only to detect and warn about stale
// legacy caches — never to load them.
func LegacyRepoLocalPath(scanPath string) string {
	return filepath.Join(scanPath, legacyCacheFileName)
}

// projectSlug builds "<sanitized-base>-<sha256(absPath)[:12]>".
func projectSlug(absPath string) string {
	base := filepath.Base(absPath)
	base = slugUnsafeRe.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-.")
	if base == "" {
		base = "project"
	}
	if len(base) > 64 {
		base = base[:64]
	}
	sum := sha256.Sum256([]byte(absPath))
	return base + "-" + hex.EncodeToString(sum[:])[:12]
}
