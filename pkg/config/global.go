package config

import (
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// ConfigDir returns the path to the OQS configuration directory.
// On Linux/macOS: ~/.oqs
// On Windows: %APPDATA%\oqs
func ConfigDir() string {
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "oqs")
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".oqs")
	}
	return ".oqs"
}

// EnsureConfigDir creates the config directory with mode 0700 if it does not
// already exist. It is safe to call on an existing directory.
func EnsureConfigDir() error {
	return os.MkdirAll(ConfigDir(), 0700)
}

// GlobalConfigPath returns the path to the global config file.
func GlobalConfigPath() string {
	return filepath.Join(ConfigDir(), "config.yaml")
}

// CredentialsPath returns the path to the credentials file.
func CredentialsPath() string {
	return filepath.Join(ConfigDir(), "credentials.json")
}

// EngineCacheDir returns the path to the engine binary cache directory.
func EngineCacheDir() string {
	return filepath.Join(ConfigDir(), "cache", "engines")
}

// HistoryDir returns the path to the local scan history directory.
func HistoryDir() string {
	return filepath.Join(ConfigDir(), "history")
}

// UploadsDir returns the path to the local CBOM uploads directory.
func UploadsDir() string {
	return filepath.Join(ConfigDir(), "uploads")
}

// LoadGlobal reads the global config file. If the file does not exist, a
// zero-value Config is returned without error.
func LoadGlobal() (Config, error) {
	data, err := os.ReadFile(GlobalConfigPath())
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// MergeConfigs merges a global and project Config, returning the combined
// result. Project values override global for every field:
//   - strings: project wins if non-empty
//   - ints: project wins if non-zero
//   - bools: project wins if true (a false project value cannot unset a global true)
//   - slices: project wins if non-nil (no appending — project slice replaces global)
func MergeConfigs(global, project Config) Config {
	merged := global

	// Scan
	if project.Scan.Timeout != 0 {
		merged.Scan.Timeout = project.Scan.Timeout
	}
	if project.Scan.MaxFileMB != 0 {
		merged.Scan.MaxFileMB = project.Scan.MaxFileMB
	}
	if project.Scan.Engines != nil {
		merged.Scan.Engines = project.Scan.Engines
	}
	if project.Scan.Exclude != nil {
		merged.Scan.Exclude = project.Scan.Exclude
	}
	if project.Scan.ScanType != "" {
		merged.Scan.ScanType = project.Scan.ScanType
	}
	if project.Scan.MaxArchiveDepth != 0 {
		merged.Scan.MaxArchiveDepth = project.Scan.MaxArchiveDepth
	}
	if project.Scan.MaxBinarySize != 0 {
		merged.Scan.MaxBinarySize = project.Scan.MaxBinarySize
	}

	// Output
	if project.Output.Format != "" {
		merged.Output.Format = project.Output.Format
	}

	// Policy
	if project.Policy.FailOn != "" {
		merged.Policy.FailOn = project.Policy.FailOn
	}
	if project.Policy.AllowedAlgorithms != nil {
		merged.Policy.AllowedAlgorithms = project.Policy.AllowedAlgorithms
	}
	if project.Policy.BlockedAlgorithms != nil {
		merged.Policy.BlockedAlgorithms = project.Policy.BlockedAlgorithms
	}
	if project.Policy.RequirePQC {
		merged.Policy.RequirePQC = true
	}
	if project.Policy.MaxQuantumVulnerable != nil {
		merged.Policy.MaxQuantumVulnerable = project.Policy.MaxQuantumVulnerable
	}
	if project.Policy.MinQRS != 0 {
		merged.Policy.MinQRS = project.Policy.MinQRS
	}

	// Upload
	if project.Upload.AutoUpload {
		merged.Upload.AutoUpload = true
	}
	if project.Upload.Project != "" {
		merged.Upload.Project = project.Upload.Project
	}

	// Cache
	if project.Cache.Remote {
		merged.Cache.Remote = true
	}
	if project.Cache.RemoteBranch != "" {
		merged.Cache.RemoteBranch = project.Cache.RemoteBranch
	}

	// Top-level
	if project.Endpoint != "" {
		merged.Endpoint = project.Endpoint
	}
	if project.CACert != "" {
		merged.CACert = project.CACert
	}

	return merged
}
