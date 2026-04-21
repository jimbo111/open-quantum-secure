package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for oqs-scanner loaded from .oqs-scanner.yaml.
type Config struct {
	Scan     ScanConfig   `yaml:"scan"`
	Output   OutputConfig `yaml:"output"`
	Policy   PolicyConfig `yaml:"policy"`
	Upload   UploadConfig `yaml:"upload"`
	Cache    CacheConfig  `yaml:"cache"`
	Endpoint string       `yaml:"endpoint"`
	CACert   string       `yaml:"caCert"`
	TLS      TLSConfig    `yaml:"tls,omitempty"`
}

// TLSConfig controls TLS probe engine behavior. For security, TLS targets are
// blocked from project config (.oqs-scanner.yaml) and only loaded from global
// config (~/.oqs/config.yaml) or CLI flags.
type TLSConfig struct {
	Targets  []string `yaml:"targets,omitempty"`
	Insecure bool     `yaml:"insecure,omitempty"`
	Strict   bool     `yaml:"strict,omitempty"`
	Timeout  int      `yaml:"timeout,omitempty"`
	CACert   string   `yaml:"caCert,omitempty"`
}

// CacheConfig controls remote scan cache behaviour.
type CacheConfig struct {
	// Remote enables remote cache upload/download when set to true.
	Remote bool `yaml:"remote"`
	// RemoteBranch overrides the branch name used as the remote cache key.
	// When empty, the branch is auto-detected from git.
	RemoteBranch string `yaml:"remoteBranch,omitempty"`
}

// UploadConfig controls CBOM upload behavior.
type UploadConfig struct {
	AutoUpload bool   `yaml:"autoUpload"`
	Project    string `yaml:"project"`
}

// ScanConfig controls scan behavior.
type ScanConfig struct {
	Timeout         int      `yaml:"timeout"`
	MaxFileMB       int      `yaml:"maxFileMB"`
	Engines         []string `yaml:"engines"`
	Exclude         []string `yaml:"exclude"`
	ScanType        string   `yaml:"scanType"`        // "source" (default), "binary", or "all"
	MaxArchiveDepth int      `yaml:"maxArchiveDepth"` // max nested archive recursion depth (default 3)
	MaxBinarySize   int      `yaml:"maxBinarySize"`   // max binary file size in MB (default 500)
}

// OutputConfig controls output format.
type OutputConfig struct {
	Format string `yaml:"format"`
}

// PolicyConfig controls policy enforcement.
// All fields are optional. FailOn is preserved for backward compatibility with
// the --fail-on CLI flag. The remaining fields map directly to policy.Policy.
type PolicyConfig struct {
	FailOn               string   `yaml:"failOn"`
	AllowedAlgorithms    []string `yaml:"allowedAlgorithms"`
	BlockedAlgorithms    []string `yaml:"blockedAlgorithms"`
	RequirePQC           bool     `yaml:"requirePQC"`
	MaxQuantumVulnerable *int     `yaml:"maxQuantumVulnerable"`
	MinQRS               int      `yaml:"minQRS"`
}

// candidatePaths returns ordered list of project-level paths to search for a
// config file. Global config (~/.oqs/config.yaml) is handled separately by
// LoadGlobal. First found wins.
func candidatePaths(targetPath string) []string {
	paths := []string{
		".oqs-scanner.yaml",
	}

	if targetPath != "" {
		paths = append(paths, filepath.Join(targetPath, ".oqs-scanner.yaml"))
	}

	return paths
}

// loadProjectConfig searches candidatePaths for the first readable project
// config file and parses it. Returns zero Config (no error) when none is found.
func loadProjectConfig(targetPath string) (Config, error) {
	for _, p := range candidatePaths(targetPath) {
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Config{}, err
		}

		var cfg Config
		if err := unmarshalStrict(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", p, err)
		}
		return cfg, nil
	}

	return Config{}, nil
}

// unmarshalStrict decodes YAML into out and rejects unknown keys. Typos like
// `fail_on` (vs canonical `failOn`) surface as an immediate error instead of
// being silently dropped, which would leave a fail-on rule disabled without
// the user noticing.
func unmarshalStrict(data []byte, out interface{}) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if err == io.EOF {
			return nil // empty document is valid
		}
		return err
	}
	return nil
}

// Load searches for a project config file, loads the global config, and merges
// them (project values override global). If no config files are found,
// a zero-value Config is returned without error.
func Load(targetPath string) (Config, error) {
	global, err := LoadGlobal()
	if err != nil {
		return Config{}, err
	}

	project, err := loadProjectConfig(targetPath)
	if err != nil {
		return Config{}, err
	}

	// TLS config from project config is blocked for security (prevents SSRF
	// via malicious .oqs-scanner.yaml in PRs). Only global config and CLI flags
	// can set TLS targets.
	projectHadTLS := len(project.TLS.Targets) > 0 || project.TLS.Insecure || project.TLS.Strict || project.TLS.Timeout != 0 || project.TLS.CACert != ""
	if projectHadTLS {
		project.TLS = TLSConfig{} // zero out before merge
	}

	merged := MergeConfigs(global, project)

	if projectHadTLS {
		fmt.Fprintf(os.Stderr, "WARNING: tls config in .oqs-scanner.yaml ignored for security. Use ~/.oqs/config.yaml or CLI flags.\n")
		merged.TLS = global.TLS // restore global TLS only
	}

	return merged, nil
}
