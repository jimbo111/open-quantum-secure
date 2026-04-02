package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "https with .git",
			input: "https://github.com/org/repo.git",
			want:  "org/repo",
		},
		{
			name:  "https without .git",
			input: "https://github.com/org/repo",
			want:  "org/repo",
		},
		{
			name:  "ssh scp-style with .git",
			input: "git@github.com:org/repo.git",
			want:  "org/repo",
		},
		{
			name:  "ssh scp-style without .git",
			input: "git@github.com:org/repo",
			want:  "org/repo",
		},
		{
			name:  "gitlab subgroup with .git",
			input: "https://gitlab.com/group/subgroup/repo.git",
			want:  "group/subgroup/repo",
		},
		{
			name:  "ssh url scheme bitbucket",
			input: "ssh://git@bitbucket.org/team/repo.git",
			want:  "team/repo",
		},
		{
			name:  "https trailing slash",
			input: "https://github.com/org/repo/",
			want:  "org/repo",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "not a url",
			input:   "not-a-url",
			wantErr: true,
		},
		{
			name:    "ssh without path",
			input:   "git@github.com:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRemoteURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRemoteURL(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parseRemoteURL(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parseRemoteURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestInferProject_Integration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	dir := t.TempDir()

	// Init repo
	runGitProj(t, dir, "init")
	runGitProj(t, dir, "config", "user.email", "test@test.com")
	runGitProj(t, dir, "config", "user.name", "Test")

	// Add remote
	runGitProj(t, dir, "remote", "add", "origin", "https://github.com/testorg/testrepo.git")

	// Create initial commit (needed for HEAD/branch)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	runGitProj(t, dir, "add", ".")
	runGitProj(t, dir, "commit", "-m", "init")

	info, err := InferProject(ctx, dir)
	if err != nil {
		t.Fatalf("InferProject: %v", err)
	}

	if info.Project != "testorg/testrepo" {
		t.Errorf("Project = %q, want testorg/testrepo", info.Project)
	}
	if info.Branch == "" {
		t.Error("Branch should not be empty")
	}
	if len(info.CommitSHA) != 40 {
		t.Errorf("CommitSHA = %q, want 40-char SHA", info.CommitSHA)
	}
}

func TestInferProject_DetachedHEAD(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	dir := t.TempDir()

	runGitProj(t, dir, "init")
	runGitProj(t, dir, "config", "user.email", "test@test.com")
	runGitProj(t, dir, "config", "user.name", "Test")
	runGitProj(t, dir, "remote", "add", "origin", "https://github.com/testorg/testrepo.git")

	// Create two commits
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0644); err != nil {
		t.Fatal(err)
	}
	runGitProj(t, dir, "add", ".")
	runGitProj(t, dir, "commit", "-m", "first")

	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b"), 0644); err != nil {
		t.Fatal(err)
	}
	runGitProj(t, dir, "add", ".")
	runGitProj(t, dir, "commit", "-m", "second")

	// Detach HEAD by checking out the first commit
	firstSHA := gitOutputProj(t, dir, "rev-parse", "HEAD~1")
	runGitProj(t, dir, "checkout", firstSHA)

	info, err := InferProject(ctx, dir)
	if err != nil {
		t.Fatalf("InferProject with detached HEAD: %v", err)
	}

	if len(info.CommitSHA) != 40 {
		t.Errorf("CommitSHA = %q, want 40-char SHA", info.CommitSHA)
	}
	// Branch should equal the commit SHA (not literally "HEAD")
	if info.Branch == "HEAD" {
		t.Error("Branch should be replaced with CommitSHA when detached, not 'HEAD'")
	}
	if info.Branch != info.CommitSHA {
		t.Errorf("detached HEAD: Branch = %q, want CommitSHA = %q", info.Branch, info.CommitSHA)
	}
}

func TestInferProject_NonGitDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	dir := t.TempDir()

	_, err := InferProject(ctx, dir)
	if err == nil {
		t.Error("InferProject on non-git directory should return error")
	}
}

func TestInferProject_NoOriginRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	dir := t.TempDir()

	runGitProj(t, dir, "init")
	runGitProj(t, dir, "config", "user.email", "test@test.com")
	runGitProj(t, dir, "config", "user.name", "Test")
	// No remote added

	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0644); err != nil {
		t.Fatal(err)
	}
	runGitProj(t, dir, "add", ".")
	runGitProj(t, dir, "commit", "-m", "init")

	_, err := InferProject(ctx, dir)
	if err == nil {
		t.Error("InferProject without origin remote should return error")
	}
}

// runGitProj is a helper that runs a git command in dir and fatals on error.
func runGitProj(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00+00:00",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00+00:00",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// gitOutputProj runs a git command and returns trimmed stdout.
func gitOutputProj(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}
