// Command manifest-hash downloads engine binaries from the manifest URLs,
// computes their SHA-256 hashes, and writes an updated manifest.json.
//
// This tool is run during the release process after engine binaries have been
// uploaded to releases.oqs.dev. It replaces "placeholder" SHA-256 values with
// real hashes computed from the actual downloaded bytes.
//
// Usage:
//
//	go run ./cmd/manifest-hash -input pkg/enginemgr/manifest.json -output pkg/enginemgr/manifest.json
//	go run ./cmd/manifest-hash -input pkg/enginemgr/manifest.json -dry-run   # print hashes without writing
//	go run ./cmd/manifest-hash -input pkg/enginemgr/manifest.json -validate  # exit 1 if any placeholders remain
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// manifestFile mirrors the embedded manifest schema. We intentionally use
// json.RawMessage-free types so we can round-trip the JSON cleanly.
type manifestFile struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Engines       map[string]manifestEngine `json:"engines"`
}

type manifestEngine struct {
	Version             string                      `json:"version"`
	DownloadSupported   bool                        `json:"downloadSupported"`
	BinaryOverride      string                      `json:"binaryOverride,omitempty"`
	InstallHintOverride string                      `json:"installHintOverride,omitempty"`
	Platforms           map[string]manifestPlatform  `json:"platforms,omitempty"`
}

type manifestPlatform struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

func main() {
	inputPath := flag.String("input", "pkg/enginemgr/manifest.json", "path to manifest.json")
	outputPath := flag.String("output", "", "output path (default: same as input)")
	dryRun := flag.Bool("dry-run", false, "print hashes without writing")
	validate := flag.Bool("validate", false, "exit 1 if any placeholder hashes remain")
	timeout := flag.Duration("timeout", 5*time.Minute, "per-download timeout")
	flag.Parse()

	if *outputPath == "" {
		*outputPath = *inputPath
	}

	data, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read manifest: %v\n", err)
		os.Exit(1)
	}

	var mf manifestFile
	if err := json.Unmarshal(data, &mf); err != nil {
		fmt.Fprintf(os.Stderr, "error: parse manifest: %v\n", err)
		os.Exit(1)
	}

	// Validate mode: check for placeholder hashes.
	if *validate {
		placeholders := findPlaceholders(mf)
		if len(placeholders) > 0 {
			fmt.Fprintf(os.Stderr, "FAIL: %d placeholder SHA-256 values found:\n", len(placeholders))
			for _, p := range placeholders {
				fmt.Fprintf(os.Stderr, "  %s/%s: %q\n", p.engine, p.platform, p.sha256)
			}
			os.Exit(1)
		}
		fmt.Println("OK: no placeholder SHA-256 values found")
		os.Exit(0)
	}

	// Download mode: fetch each URL and compute hash.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	updated := 0
	failed := 0

	// Sort engine names for deterministic output.
	engineNames := make([]string, 0, len(mf.Engines))
	for name := range mf.Engines {
		engineNames = append(engineNames, name)
	}
	sort.Strings(engineNames)

	for _, name := range engineNames {
		engine := mf.Engines[name]
		if !engine.DownloadSupported || engine.Platforms == nil {
			continue
		}

		// Sort platform keys for deterministic output.
		platKeys := make([]string, 0, len(engine.Platforms))
		for pk := range engine.Platforms {
			platKeys = append(platKeys, pk)
		}
		sort.Strings(platKeys)

		for _, pk := range platKeys {
			plat := engine.Platforms[pk]
			if plat.SHA256 != "" && plat.SHA256 != "placeholder" {
				fmt.Printf("  %s/%s: already has hash %s\n", name, pk, plat.SHA256[:16]+"...")
				continue
			}

			if err := validateURL(plat.URL); err != nil {
				fmt.Fprintf(os.Stderr, "  %s/%s: ERROR: %v\n", name, pk, err)
				failed++
				continue
			}

			fmt.Printf("  %s/%s: downloading %s ...\n", name, pk, plat.URL)
			hash, size, err := downloadAndHash(ctx, client, plat.URL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s/%s: ERROR: %v\n", name, pk, err)
				failed++
				continue
			}

			fmt.Printf("  %s/%s: sha256=%s (%d bytes)\n", name, pk, hash, size)
			plat.SHA256 = hash
			engine.Platforms[pk] = plat
			updated++
		}
		mf.Engines[name] = engine
	}

	fmt.Printf("\nUpdated: %d, Failed: %d\n", updated, failed)

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d downloads failed — manifest has incomplete hashes\n", failed)
	}

	if *dryRun {
		fmt.Println("Dry run: not writing manifest")
		if failed > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Skip writing manifest when downloads failed to avoid partial hashes on disk.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "error: refusing to write manifest with %d failed downloads\n", failed)
		os.Exit(1)
	}

	// Write updated manifest using atomic temp-rename pattern.
	out, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal manifest: %v\n", err)
		os.Exit(1)
	}
	out = append(out, '\n')

	if err := atomicWriteFile(*outputPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write manifest: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Manifest written to %s\n", *outputPath)
}

// downloadAndHash fetches a URL and returns its SHA-256 hex digest and size.
func downloadAndHash(ctx context.Context, client *http.Client, url string) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read body: %w", err)
	}
	if n == 0 {
		return "", 0, fmt.Errorf("empty response (0 bytes)")
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type placeholderEntry struct {
	engine   string
	platform string
	sha256   string
}

// validateURL checks that the URL is well-formed and uses HTTPS.
func validateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("empty download URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS URL: %s", rawURL)
	}
	if u.Host == "" {
		return fmt.Errorf("URL has no host: %s", rawURL)
	}
	return nil
}

// atomicWriteFile writes data to path using the temp-rename pattern.
// On failure, the original file is not modified.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".manifest-hash-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up on any error path.
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	success = true
	return nil
}

func findPlaceholders(mf manifestFile) []placeholderEntry {
	var entries []placeholderEntry
	for name, engine := range mf.Engines {
		if !engine.DownloadSupported || engine.Platforms == nil {
			continue
		}
		for pk, plat := range engine.Platforms {
			if plat.SHA256 == "" || plat.SHA256 == "placeholder" {
				entries = append(entries, placeholderEntry{
					engine:   name,
					platform: pk,
					sha256:   plat.SHA256,
				})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].engine != entries[j].engine {
			return entries[i].engine < entries[j].engine
		}
		return entries[i].platform < entries[j].platform
	})
	return entries
}
