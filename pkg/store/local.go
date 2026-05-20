package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxSlugLen caps the project slug length to stay within filesystem limits.
const maxSlugLen = 200

// LocalStore persists scan records as JSON arrays under {baseDir}/history/.
// Each project maps to a single file named {project-slug}.json.
// LocalStore is safe for concurrent use within a single process AND across
// multiple processes: the in-process sync.Mutex serialises goroutine access
// and an advisory flock(2) on a per-project .lock sibling serialises access
// across separate oqs-scanner invocations writing to the same baseDir
// (POSIX only; see flock_windows.go for the Windows caveat).
type LocalStore struct {
	baseDir string
	mu      sync.Mutex
}

// NewLocalStore returns a LocalStore rooted at baseDir.
// The directory is created lazily on the first SaveScan call.
func NewLocalStore(baseDir string) *LocalStore {
	return &LocalStore{baseDir: baseDir}
}

// SaveScan appends record to the project's history file using an atomic
// temp-rename write. If the file does not exist it is created.
//
// The destination must not be a symlink; if it is, SaveScan returns an error
// without modifying any file.
func (s *LocalStore) SaveScan(_ context.Context, project string, record ScanRecord) error {
	if project == "" {
		return errors.New("store: project name must not be empty")
	}

	slug := ProjectSlug(project)
	if slug == "" {
		return errors.New("store: project name resolves to empty slug")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	historyDir := filepath.Join(s.baseDir, "history")
	if err := os.MkdirAll(historyDir, 0700); err != nil {
		return fmt.Errorf("store: create history dir: %w", err)
	}

	destPath := filepath.Join(historyDir, slug+".json")

	// Cross-process advisory lock — blocks any other oqs-scanner invocation
	// trying to SaveScan the same project until this function returns.
	// Without it, two concurrent CI workers' read-append-rename cycles race
	// and the second worker's record silently overwrites the first.
	//
	// Lock files live under <baseDir>/.locks/ (sibling of history/) so the
	// user-visible history directory stays clean of implementation artefacts.
	lockDir := filepath.Join(s.baseDir, ".locks")
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return fmt.Errorf("store: create lock dir: %w", err)
	}
	lockPath := filepath.Join(lockDir, slug+".lock")
	release, err := acquireFileLock(lockPath)
	if err != nil {
		return fmt.Errorf("store: acquire file lock: %w", err)
	}
	defer func() {
		if relErr := release(); relErr != nil {
			// Lock release failure is non-fatal — the kernel releases on
			// process exit. Surface it for diagnosability.
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", relErr)
		}
	}()

	// Load existing records (treat missing file as empty list).
	records, err := readRecords(destPath)
	if err != nil {
		return fmt.Errorf("store: read existing records: %w", err)
	}
	records = append(records, record)

	// Encode to JSON with indentation.
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal records: %w", err)
	}
	// json.MarshalIndent does not append a trailing newline.
	data = append(data, '\n')

	// Atomic write: create temp → chmod → write → sync → close → rename.
	tmp, err := os.CreateTemp(historyDir, "*.tmp")
	if err != nil {
		return fmt.Errorf("store: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Clean up the temp file on any failure path.
	cleanup := func() { os.Remove(tmpPath) }

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("store: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("store: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("store: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("store: close temp file: %w", err)
	}

	// Symlink guard: refuse to overwrite a symlink target.
	if info, err := os.Lstat(destPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		cleanup()
		return fmt.Errorf("store: refusing to write to symlink at %s", destPath)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		cleanup()
		return fmt.Errorf("store: rename temp file: %w", err)
	}
	return nil
}

// ListScans returns stored scan records for project. Records are ordered
// oldest-first (most recent at the end of the slice). If opts.Limit > 0, only
// the last N records are returned. Returns an empty non-nil slice when no
// records exist for the project — never returns an error for a missing file.
func (s *LocalStore) ListScans(_ context.Context, project string, opts ListOptions) ([]ScanRecord, error) {
	if project == "" {
		return []ScanRecord{}, nil
	}

	slug := ProjectSlug(project)
	if slug == "" {
		return []ScanRecord{}, nil
	}
	destPath := filepath.Join(s.baseDir, "history", slug+".json")
	records, err := readRecords(destPath)
	if err != nil {
		return nil, fmt.Errorf("store: read records: %w", err)
	}

	if opts.Limit > 0 && len(records) > opts.Limit {
		records = records[len(records)-opts.Limit:]
	}
	return records, nil
}

// projectSlug converts a project name to a safe filename component.
// Slashes are replaced with "--" and leading/trailing dashes are stripped.
//
// Examples:
//
//	"github.com/org/repo" → "github.com--org--repo"
//	"/org/repo/"          → "org--repo"
// ProjectSlug converts a project name to a safe filename component.
// Exported so that callers (e.g., saveLocalCBOM) can reuse the same slug logic.
func ProjectSlug(project string) string {
	// Replace both forward and back slashes to prevent path traversal on Windows
	// (filepath.Join treats backslashes as separators on Windows).
	slug := strings.ReplaceAll(project, "/", "--")
	slug = strings.ReplaceAll(slug, "\\", "--")
	slug = strings.Trim(slug, "-")
	if len(slug) > maxSlugLen {
		slug = slug[:maxSlugLen]
	}
	return slug
}

// readRecords reads and unmarshals the JSON array at path. Returns an empty
// non-nil slice when the file does not exist.
func readRecords(path string) ([]ScanRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []ScanRecord{}, nil
		}
		return nil, err
	}

	var records []ScanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("corrupt history file %s: %w", path, err)
	}
	if records == nil {
		records = []ScanRecord{}
	}
	return records, nil
}
