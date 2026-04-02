package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ErrNoCredentials is returned by Load when no credentials file exists.
var ErrNoCredentials = errors.New("auth: no credentials found")

// Credential holds the stored authentication data for the OQS platform.
type Credential struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserEmail    string    `json:"user_email"`
	OrgName      string    `json:"org_name"`
	Plan         string    `json:"plan"`
	Endpoint     string    `json:"endpoint"`
}

// Store manages credential persistence on disk. It is thread-safe.
type Store struct {
	mu sync.Mutex
}

// configDir returns the OQS config directory:
//   - ~/.oqs on Linux/macOS
//   - %APPDATA%\oqs on Windows
func configDir() (string, error) {
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", errors.New("auth: APPDATA environment variable not set")
		}
		return filepath.Join(appdata, "oqs"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".oqs"), nil
}

// credentialsPath returns the path to the credentials JSON file.
func credentialsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

// EnsureConfigDir creates the config directory with 0700 permissions if it does
// not already exist. It is a no-op if the directory already exists.
func (s *Store) EnsureConfigDir() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(dir, 0700)
}

// Save marshals cred to JSON and writes it to the credentials file with 0600
// permissions. It creates the config directory if necessary.
func (s *Store) Save(cred Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureConfigDirLocked(); err != nil {
		return err
	}

	path, err := credentialsPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Symlink guard: reject if target is a symlink to prevent symlink-following attacks.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("auth: refusing to write credentials to symlink target")
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	tmpPath = "" // prevent defer cleanup
	return nil
}

// Load reads and unmarshals the credentials file. It returns ErrNoCredentials
// (wrapped) if the file does not exist.
func (s *Store) Load() (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := credentialsPath()
	if err != nil {
		return Credential{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credential{}, ErrNoCredentials
		}
		return Credential{}, err
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return Credential{}, err
	}
	if cred.AccessToken == "" {
		return Credential{}, ErrNoCredentials
	}
	return cred, nil
}

// Delete removes the credentials file. It is a no-op if the file does not exist.
func (s *Store) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := credentialsPath()
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// IsExpired reports whether the credential's access token has expired.
func (s *Store) IsExpired(cred Credential) bool {
	if cred.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(cred.ExpiresAt)
}

// ensureConfigDirLocked creates the config directory; must be called with mu held.
func (s *Store) ensureConfigDirLocked() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(dir, 0700)
}
