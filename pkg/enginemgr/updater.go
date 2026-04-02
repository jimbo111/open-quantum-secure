package enginemgr

import (
	"context"
	"regexp"
	"strings"
)

// UpdateCheck describes whether an engine has an available update.
type UpdateCheck struct {
	Name             string `json:"name"`
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	ManifestVersion  string `json:"manifestVersion,omitempty"`
	UpdateAvailable  bool   `json:"updateAvailable"`
	// Reason is a human-readable description of the check result.
	Reason string `json:"reason"`
}

// CheckForUpdates compares installed engine versions against manifest versions.
// It returns one UpdateCheck per target engine. Embedded and non-downloadable
// engines are reported as not needing updates.
func CheckForUpdates(ctx context.Context, targets []EngineInfo, manifest *Manifest, searchDirs []string) []UpdateCheck {
	results := make([]UpdateCheck, len(targets))

	// Nil manifest guard (consistent with DownloadEngines).
	if manifest == nil {
		for i, info := range targets {
			results[i] = UpdateCheck{Name: info.Name, Reason: "no manifest available"}
		}
		return results
	}

	for i, info := range targets {
		if ctx.Err() != nil {
			results[i] = UpdateCheck{Name: info.Name, Reason: "cancelled"}
			continue
		}

		uc := UpdateCheck{Name: info.Name}

		// Embedded engines don't need updates through this mechanism.
		if info.BinaryName == "" {
			uc.Reason = "built-in engine (no update needed)"
			results[i] = uc
			continue
		}

		// Check manifest entry.
		entry, ok := manifest.Engines[info.Name]
		if !ok {
			uc.Reason = "not in manifest"
			results[i] = uc
			continue
		}
		if !entry.DownloadSupported {
			uc.ManifestVersion = entry.Version
			uc.Reason = "not available for download"
			results[i] = uc
			continue
		}

		uc.ManifestVersion = entry.Version

		// Check if engine is installed.
		status := checkEngineCtx(ctx, info, searchDirs)
		if !status.Available {
			uc.Reason = "not installed"
			results[i] = uc
			continue
		}

		uc.Installed = true
		uc.InstalledVersion = status.Version

		// Compare versions. The probed version may contain extra text
		// (e.g., "cipherscope 0.5.0"), so we check if the manifest version
		// appears anywhere in the probed output.
		if versionMatches(status.Version, entry.Version) {
			uc.Reason = "up to date"
		} else {
			uc.UpdateAvailable = true
			uc.Reason = "update available"
		}

		results[i] = uc
	}

	return results
}

// semverRe extracts version-like substrings, optionally preceded by "v".
// Uses submatch to capture the numeric part without the "v" prefix.
// Matches at word boundary OR after "v" (e.g., "v1.21.0" → "1.21.0").
var semverRe = regexp.MustCompile(`(?:^|[^\d.])v?(\d+\.\d+(?:\.\d+)?)(?:$|[^\d.])`)

// extractVersions returns all semver-like substrings from s.
func extractVersions(s string) []string {
	matches := semverRe.FindAllStringSubmatch(s, -1)
	var out []string
	for _, m := range matches {
		out = append(out, m[1]) // capture group 1 = version without "v"
	}
	return out
}

// versionMatches returns true if the manifest version matches the installed
// version. Uses semver extraction for robust matching:
//   - "0.5.0" matches "cipherscope 0.5.0"
//   - "0.38.0" matches "ast-grep 0.38.0"
//   - "v0.5.0" matches "0.5.0" (v-prefix handled)
//   - "1.21.0" matches "syft v1.21.0" (v-prefix in installed)
//   - "1.2" does NOT match "1.21.0" (word-boundary prevents false positives)
//
// Falls back to normalized equality when semver extraction fails.
// Returns false for "unknown" or empty installed versions.
func versionMatches(installed, manifestVersion string) bool {
	if installed == "" || installed == "unknown" || manifestVersion == "" {
		return false
	}

	// 1. Try semver extraction: extract all version-like substrings from both
	// and check if any match. This handles "cipherscope 0.5.0" vs "0.5.0"
	// and "syft v1.21.0" vs "1.21.0".
	manifestVersions := extractVersions(manifestVersion)
	installedVersions := extractVersions(installed)

	if len(manifestVersions) > 0 && len(installedVersions) > 0 {
		for _, mv := range manifestVersions {
			for _, iv := range installedVersions {
				if mv == iv {
					return true
				}
			}
		}
		return false
	}

	// 2. Fallback: normalized equality after stripping "v" prefix.
	normManifest := strings.TrimPrefix(manifestVersion, "v")
	normInstalled := strings.TrimPrefix(installed, "v")
	return normManifest == normInstalled
}
