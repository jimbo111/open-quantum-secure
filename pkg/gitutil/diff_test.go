package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseFileList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single file", "src/main.go\n", 1},
		{"multiple files", "a.go\nb.go\nc.go\n", 3},
		{"with blank lines", "a.go\n\nb.go\n\n", 2},
		{"with spaces", "  a.go  \n  b.go  \n", 2},
		{"no trailing newline", "a.go", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFileList(tt.input)
			if len(got) != tt.want {
				t.Errorf("parseFileList(%q) returned %d files, want %d", tt.input, len(got), tt.want)
			}
		})
	}
}

func TestAbsChangedFiles(t *testing.T) {
	abs := AbsChangedFiles("/repo", []string{"src/main.go", "pkg/util.go"})
	if len(abs) != 2 {
		t.Fatalf("expected 2 files, got %d", len(abs))
	}
	if abs[0] != filepath.Join("/repo", "src/main.go") {
		t.Errorf("abs[0] = %q, want %q", abs[0], filepath.Join("/repo", "src/main.go"))
	}
}

func TestIsGitRepo(t *testing.T) {
	ctx := context.Background()

	// A temp dir that is NOT a git repo
	tmpDir := t.TempDir()
	if IsGitRepo(ctx, tmpDir) {
		t.Error("expected non-git dir to return false")
	}
}

func TestChangedFiles_Integration(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()

	// Create a temporary git repo with two commits
	tmpDir := t.TempDir()

	// Init repo and create initial commit
	runGit(t, tmpDir, "init")
	runGit(t, tmpDir, "config", "user.email", "test@test.com")
	runGit(t, tmpDir, "config", "user.name", "Test")

	// Create initial file and commit
	os.WriteFile(filepath.Join(tmpDir, "base.go"), []byte("package main"), 0644)
	runGit(t, tmpDir, "add", ".")
	runGit(t, tmpDir, "commit", "-m", "initial")

	// Create a branch for the base
	runGit(t, tmpDir, "branch", "base-branch")

	// Add new files on HEAD
	os.WriteFile(filepath.Join(tmpDir, "new.go"), []byte("package new"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "changed.go"), []byte("package changed"), 0644)
	runGit(t, tmpDir, "add", ".")
	runGit(t, tmpDir, "commit", "-m", "add new files")

	// Get changed files
	files, err := ChangedFiles(ctx, tmpDir, "base-branch")
	if err != nil {
		t.Fatalf("ChangedFiles() error: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 changed files, got %d: %v", len(files), files)
	}

	// Verify the files are the ones we added
	fileSet := make(map[string]bool)
	for _, f := range files {
		fileSet[f] = true
	}
	if !fileSet["new.go"] {
		t.Error("expected new.go in changed files")
	}
	if !fileSet["changed.go"] {
		t.Error("expected changed.go in changed files")
	}
}

func TestChangedFiles_DeletedExcluded(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	runGit(t, tmpDir, "init")
	runGit(t, tmpDir, "config", "user.email", "test@test.com")
	runGit(t, tmpDir, "config", "user.name", "Test")

	// Create files and commit
	os.WriteFile(filepath.Join(tmpDir, "keep.go"), []byte("package keep"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "delete-me.go"), []byte("package gone"), 0644)
	runGit(t, tmpDir, "add", ".")
	runGit(t, tmpDir, "commit", "-m", "initial")

	runGit(t, tmpDir, "branch", "base")

	// Delete a file, modify another
	os.Remove(filepath.Join(tmpDir, "delete-me.go"))
	os.WriteFile(filepath.Join(tmpDir, "keep.go"), []byte("package keep // modified"), 0644)
	runGit(t, tmpDir, "add", ".")
	runGit(t, tmpDir, "commit", "-m", "delete and modify")

	files, err := ChangedFiles(ctx, tmpDir, "base")
	if err != nil {
		t.Fatalf("ChangedFiles() error: %v", err)
	}

	// Only keep.go should be in the list (modified), not delete-me.go
	if len(files) != 1 {
		t.Errorf("expected 1 changed file (deleted excluded), got %d: %v", len(files), files)
	}
	if len(files) == 1 && files[0] != "keep.go" {
		t.Errorf("expected keep.go, got %q", files[0])
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00+00:00",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00+00:00",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\noutput: %s", args, err, out)
	}
}
