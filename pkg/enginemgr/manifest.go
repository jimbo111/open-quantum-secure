package enginemgr

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"time"
)

//go:embed manifest.json
var embeddedManifest []byte

// Manifest is the top-level structure for the engine download manifest.
type Manifest struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Engines       map[string]ManifestEngine `json:"engines"`
}

// ManifestEngine describes a downloadable engine entry.
type ManifestEngine struct {
	Version             string                      `json:"version"`
	DownloadSupported   bool                        `json:"downloadSupported"`
	BinaryOverride      string                      `json:"binaryOverride,omitempty"`
	InstallHintOverride string                      `json:"installHintOverride,omitempty"`
	Platforms           map[string]ManifestPlatform `json:"platforms,omitempty"`
}

// ManifestPlatform describes a platform-specific binary download.
type ManifestPlatform struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// PlatformKey returns the manifest key for the current OS/arch (e.g. "darwin/arm64").
func PlatformKey() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// parseManifest decodes JSON bytes into a Manifest.
func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.SchemaVersion < 1 {
		return nil, fmt.Errorf("unsupported manifest schemaVersion: %d", m.SchemaVersion)
	}
	return &m, nil
}

// LoadEmbeddedManifest returns the manifest embedded at build time.
func LoadEmbeddedManifest() (*Manifest, error) {
	return parseManifest(embeddedManifest)
}

// LoadManifest fetches a remote manifest from url. If the fetch fails or url is
// empty, it falls back to the embedded manifest. The remoteErr return value
// contains the remote fetch error (if any) for diagnostic logging by callers.
func LoadManifest(ctx context.Context, url string, client *http.Client) (manifest *Manifest, fallback bool, remoteErr error, err error) {
	if url != "" && client != nil {
		m, fetchErr := fetchRemoteManifest(ctx, url, client)
		if fetchErr == nil {
			return m, false, nil, nil // remote success
		}
		remoteErr = fetchErr
		// Fall back to embedded on any remote failure.
	}
	m, err := LoadEmbeddedManifest()
	if err != nil {
		return nil, false, remoteErr, err
	}
	return m, true, remoteErr, nil // fallback
}

// fetchRemoteManifest downloads and parses a manifest from the given URL.
// The URL must use HTTPS to prevent manifest tampering over plaintext.
func fetchRemoteManifest(ctx context.Context, rawURL string, client *http.Client) (*Manifest, error) {
	// Enforce HTTPS on manifest URL (same policy as binary downloads).
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("manifest URL must use HTTPS: %s", rawURL)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch: HTTP %d", resp.StatusCode)
	}

	// Read up to 1MB+1 to detect oversized manifests.
	const maxManifestSize = 1 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestSize {
		return nil, fmt.Errorf("manifest exceeds %d byte size limit", maxManifestSize)
	}
	return parseManifest(data)
}
