package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/store"
)

func TestHasPlatformEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{"empty", "", false},
		{"configured", "https://api.oqs.dev", true},
		{"custom", "https://my-platform.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{Endpoint: tt.endpoint}
			if got := hasPlatformEndpoint(cfg); got != tt.want {
				t.Errorf("hasPlatformEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildScanRecord(t *testing.T) {
	sr := output.BuildResult("1.0.0", "/tmp/test", []string{"cipherscope"}, []findings.UnifiedFinding{
		{Severity: findings.SevCritical},
		{Severity: findings.SevHigh},
		{Severity: findings.SevHigh},
		{Severity: findings.SevMedium},
		{Severity: findings.SevLow},
		{Severity: findings.SevInfo},
	})

	record := buildScanRecordFromInfo(sr, nil, 5*time.Second, 0)

	if record.ScanID == "" {
		t.Error("ScanID should not be empty")
	}
	if record.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if record.ScanMode != "full" {
		t.Errorf("ScanMode = %q, want %q", record.ScanMode, "full")
	}
	if record.Duration != "5s" {
		t.Errorf("Duration = %q, want %q", record.Duration, "5s")
	}

	fs := record.FindingSummary
	if fs.Total != 6 {
		t.Errorf("Total = %d, want 6", fs.Total)
	}
	if fs.Critical != 1 {
		t.Errorf("Critical = %d, want 1", fs.Critical)
	}
	if fs.High != 2 {
		t.Errorf("High = %d, want 2", fs.High)
	}
	if fs.Medium != 1 {
		t.Errorf("Medium = %d, want 1", fs.Medium)
	}
	if fs.Low != 1 {
		t.Errorf("Low = %d, want 1", fs.Low)
	}
	if fs.Info != 1 {
		t.Errorf("Info = %d, want 1", fs.Info)
	}
}

func TestSaveLocalCBOM(t *testing.T) {
	// Override UploadsDir via HOME.
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	sr := output.BuildResult("1.0.0", "/tmp/test", []string{"cipherscope"}, []findings.UnifiedFinding{})

	if err := saveLocalCBOMFromResult(sr, "org/repo"); err != nil {
		t.Fatalf("saveLocalCBOM() error: %v", err)
	}

	// Verify file was created.
	slug := "org--repo"
	dir := filepath.Join(tmpDir, ".oqs", "uploads", slug)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	if filepath.Ext(entries[0].Name()) != ".json" {
		t.Errorf("file extension = %q, want .json", filepath.Ext(entries[0].Name()))
	}

	// Verify file content is valid JSON.
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(data) == 0 {
		t.Error("CBOM file is empty")
	}
}

func TestNewScanStore_LocalWhenNoPlatform(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg := config.Config{} // no endpoint
	s := newScanStore(cfg, "")

	// Should be a LocalStore, not RemoteStore. Verify by using it.
	records, err := s.ListScans(nil, "nonexistent", store.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListScans error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestValidateCIMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"blocking accepted", "blocking", false},
		{"advisory accepted", "advisory", false},
		{"silent accepted", "silent", false},
		{"empty rejected", "", true},
		{"unknown value rejected", "foo", true},
		{"uppercase rejected", "Blocking", true},
		{"mixed case rejected", "Advisory", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIMode(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCIMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
		})
	}
}
