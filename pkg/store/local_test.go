package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// makeRecord returns a ScanRecord with the given scanID for use in tests.
func makeRecord(scanID string) ScanRecord {
	return ScanRecord{
		ScanID:                scanID,
		Timestamp:             "2026-04-02T12:00:00Z",
		Branch:                "main",
		CommitSHA:             "abc123",
		ScanMode:              "full",
		QuantumReadinessScore: 72,
		QuantumReadinessGrade: "B",
		FindingSummary: FindingSummary{
			Total:    5,
			Critical: 1,
			High:     2,
			Medium:   1,
			Low:      1,
			Info:     0,
		},
		Duration: "1.2s",
	}
}

func TestSaveScan_AppendsRecords(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStore(t.TempDir())

	r1 := makeRecord("scan-001")
	r2 := makeRecord("scan-002")

	if err := s.SaveScan(ctx, "myproject", r1); err != nil {
		t.Fatalf("SaveScan first: %v", err)
	}
	if err := s.SaveScan(ctx, "myproject", r2); err != nil {
		t.Fatalf("SaveScan second: %v", err)
	}

	records, err := s.ListScans(ctx, "myproject", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].ScanID != "scan-001" {
		t.Errorf("records[0].ScanID = %q, want %q", records[0].ScanID, "scan-001")
	}
	if records[1].ScanID != "scan-002" {
		t.Errorf("records[1].ScanID = %q, want %q", records[1].ScanID, "scan-002")
	}
}

func TestListScans_MostRecentLast(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStore(t.TempDir())

	ids := []string{"scan-a", "scan-b", "scan-c"}
	for _, id := range ids {
		if err := s.SaveScan(ctx, "proj", makeRecord(id)); err != nil {
			t.Fatalf("SaveScan %s: %v", id, err)
		}
	}

	records, err := s.ListScans(ctx, "proj", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	// Appended in order: oldest first, most recent last.
	for i, want := range ids {
		if records[i].ScanID != want {
			t.Errorf("records[%d].ScanID = %q, want %q", i, records[i].ScanID, want)
		}
	}
}

func TestListScans_Limit(t *testing.T) {
	tests := []struct {
		name        string
		totalScans  int
		limit       int
		wantLen     int
		wantLastID  string
	}{
		{
			name:       "limit smaller than total",
			totalScans: 5,
			limit:      3,
			wantLen:    3,
			wantLastID: "scan-004",
		},
		{
			name:       "limit equal to total",
			totalScans: 3,
			limit:      3,
			wantLen:    3,
			wantLastID: "scan-002",
		},
		{
			name:       "limit larger than total",
			totalScans: 2,
			limit:      10,
			wantLen:    2,
			wantLastID: "scan-001",
		},
		{
			name:       "zero limit means no limit",
			totalScans: 4,
			limit:      0,
			wantLen:    4,
			wantLastID: "scan-003",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewLocalStore(t.TempDir())
			for i := 0; i < tc.totalScans; i++ {
				id := "scan-" + zeroPad(i, 3)
				if err := s.SaveScan(ctx, "proj", makeRecord(id)); err != nil {
					t.Fatalf("SaveScan: %v", err)
				}
			}

			records, err := s.ListScans(ctx, "proj", ListOptions{Limit: tc.limit})
			if err != nil {
				t.Fatalf("ListScans: %v", err)
			}
			if len(records) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(records), tc.wantLen)
			}
			if records[len(records)-1].ScanID != tc.wantLastID {
				t.Errorf("last ScanID = %q, want %q", records[len(records)-1].ScanID, tc.wantLastID)
			}
		})
	}
}

// zeroPad returns n zero-padded to width digits (e.g. zeroPad(3, 3) = "003").
func zeroPad(n, width int) string {
	s := ""
	for n > 0 || width > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
		width--
	}
	// Handle n == 0 with remaining width.
	for len(s) < width {
		s = "0" + s
	}
	return s
}

func TestListScans_NonexistentProject_ReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStore(t.TempDir())

	records, err := s.ListScans(ctx, "no-such-project", ListOptions{})
	if err != nil {
		t.Fatalf("expected no error for missing project, got: %v", err)
	}
	if records == nil {
		t.Fatal("expected non-nil slice, got nil")
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice, got %d records", len(records))
	}
}

func TestMultipleProjects_SeparateFiles(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	if err := s.SaveScan(ctx, "project-alpha", makeRecord("alpha-1")); err != nil {
		t.Fatalf("SaveScan alpha: %v", err)
	}
	if err := s.SaveScan(ctx, "project-beta", makeRecord("beta-1")); err != nil {
		t.Fatalf("SaveScan beta: %v", err)
	}
	if err := s.SaveScan(ctx, "project-beta", makeRecord("beta-2")); err != nil {
		t.Fatalf("SaveScan beta second: %v", err)
	}

	alpha, err := s.ListScans(ctx, "project-alpha", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans alpha: %v", err)
	}
	if len(alpha) != 1 || alpha[0].ScanID != "alpha-1" {
		t.Errorf("alpha: got %+v", alpha)
	}

	beta, err := s.ListScans(ctx, "project-beta", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans beta: %v", err)
	}
	if len(beta) != 2 {
		t.Fatalf("beta: expected 2 records, got %d", len(beta))
	}

	// Verify separate files exist on disk.
	histDir := filepath.Join(baseDir, "history")
	entries, err := os.ReadDir(histDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 files in history dir, got %d", len(entries))
	}
}

func TestProjectSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"github.com/org/repo", "github.com--org--repo"},
		{"/org/repo/", "org--repo"},
		{"simple", "simple"},
		{"org/repo", "org--repo"},
		{"github.com/jimbo111/open-quantum-secure", "github.com--jimbo111--open-quantum-secure"},
		{"a/b/c/d", "a--b--c--d"},
		{"//double//slash//", "double----slash"},
		{"with spaces/repo", "with spaces--repo"},
		{"dots.and-dashes/repo", "dots.and-dashes--repo"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ProjectSlug(tc.input)
			if got != tc.want {
				t.Errorf("ProjectSlug(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSymlinkGuard(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	// Create the history directory so we can place a symlink in it.
	histDir := filepath.Join(baseDir, "history")
	if err := os.MkdirAll(histDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create the destination path as a symlink pointing at a harmless target.
	target := filepath.Join(baseDir, "harmless.json")
	if err := os.WriteFile(target, []byte("[]"), 0600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	slug := ProjectSlug("symlink-project")
	destPath := filepath.Join(histDir, slug+".json")
	if err := os.Symlink(target, destPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := s.SaveScan(ctx, "symlink-project", makeRecord("scan-x"))
	if err == nil {
		t.Fatal("expected error when destination is a symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not mention symlink", err.Error())
	}

	// The symlink target must be unmodified.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile target after guard: %v", readErr)
	}
	if string(data) != "[]" {
		t.Errorf("symlink target was modified: %q", string(data))
	}
}

func TestEmptyProjectName(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStore(t.TempDir())

	// SaveScan with empty project must return an error.
	err := s.SaveScan(ctx, "", makeRecord("scan-1"))
	if err == nil {
		t.Fatal("expected error for empty project name in SaveScan, got nil")
	}

	// ListScans with empty project must return empty slice, not error.
	records, err := s.ListScans(ctx, "", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans with empty project: unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected empty slice, got %d records", len(records))
	}
}

func TestSaveScan_FileIsValidJSON(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	records := []ScanRecord{makeRecord("r1"), makeRecord("r2"), makeRecord("r3")}
	for _, r := range records {
		if err := s.SaveScan(ctx, "json-check", r); err != nil {
			t.Fatalf("SaveScan: %v", err)
		}
	}

	histFile := filepath.Join(baseDir, "history", "json-check.json")
	data, err := os.ReadFile(histFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var parsed []ScanRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v — raw content:\n%s", err, data)
	}
	if len(parsed) != 3 {
		t.Errorf("expected 3 records in file, got %d", len(parsed))
	}
}

func TestCorruptFile_ListScansReturnsError(t *testing.T) {
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	// Write corrupt data to the history file.
	histDir := filepath.Join(baseDir, "history")
	if err := os.MkdirAll(histDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	corruptPath := filepath.Join(histDir, "corrupt-project.json")
	if err := os.WriteFile(corruptPath, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := s.ListScans(context.Background(), "corrupt-project", ListOptions{})
	if err == nil {
		t.Fatal("expected error for corrupt history file, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error %q does not mention 'corrupt'", err.Error())
	}
	if !strings.Contains(err.Error(), corruptPath) {
		t.Errorf("error %q does not include filepath", err.Error())
	}
}

func TestCorruptFile_SaveScanReturnsError(t *testing.T) {
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	histDir := filepath.Join(baseDir, "history")
	if err := os.MkdirAll(histDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(histDir, "bad-proj.json"), []byte("garbage"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := s.SaveScan(context.Background(), "bad-proj", makeRecord("scan-1"))
	if err == nil {
		t.Fatal("expected error for corrupt file in SaveScan, got nil")
	}
}

func TestConcurrentSaveScan(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = s.SaveScan(ctx, "concurrent-project", makeRecord(fmt.Sprintf("scan-%d", idx)))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: SaveScan error: %v", i, err)
		}
	}

	records, err := s.ListScans(ctx, "concurrent-project", ListOptions{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != goroutines {
		t.Errorf("expected %d records, got %d (lost records under concurrency)", goroutines, len(records))
	}
}

func TestSlashOnlyProject_ReturnsError(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStore(t.TempDir())

	err := s.SaveScan(ctx, "/", makeRecord("scan-1"))
	if err == nil {
		t.Fatal("expected error for slash-only project, got nil")
	}
	if !strings.Contains(err.Error(), "empty slug") {
		t.Errorf("error %q does not mention 'empty slug'", err.Error())
	}
}

func TestLongProjectName_Truncated(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	s := NewLocalStore(baseDir)

	longName := strings.Repeat("a", 300)
	if err := s.SaveScan(ctx, longName, makeRecord("scan-1")); err != nil {
		t.Fatalf("SaveScan with long name: %v", err)
	}

	slug := ProjectSlug(longName)
	if len(slug) > maxSlugLen {
		t.Errorf("slug length %d exceeds maxSlugLen %d", len(slug), maxSlugLen)
	}

	records, err := s.ListScans(ctx, longName, ListOptions{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
}
