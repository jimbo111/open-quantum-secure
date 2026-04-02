package gitutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedFiles returns the list of files changed between diffBase and HEAD
// within the given repository path. Only files that still exist (added or
// modified) are included — deleted files are excluded.
//
// diffBase can be a branch name ("main"), a commit SHA, or any valid git ref.
// The returned paths are relative to repoDir.
func ChangedFiles(ctx context.Context, repoDir, diffBase string) ([]string, error) {
	// Validate that we're in a git repo
	if err := validateGitRepo(ctx, repoDir); err != nil {
		return nil, err
	}

	// Validate git ref to prevent argument injection
	if err := validateRef(diffBase); err != nil {
		return nil, err
	}

	// Get files that were added, modified, or renamed (exclude deleted)
	// --diff-filter=ACMR: Added, Copied, Modified, Renamed
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=ACMR", diffBase+"...HEAD")
	cmd.Dir = repoDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Try without three-dot notation (for cases where merge-base can't be found)
		cmd2 := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=ACMR", diffBase, "HEAD")
		cmd2.Dir = repoDir
		stdout.Reset()
		stderr.Reset()
		cmd2.Stdout = &stdout
		cmd2.Stderr = &stderr

		if err2 := cmd2.Run(); err2 != nil {
			return nil, fmt.Errorf("git diff failed: %s (stderr: %s)", err2, strings.TrimSpace(stderr.String()))
		}
	}

	return parseFileList(stdout.String()), nil
}

// ChangedFilesFromManifest reads a newline-delimited file list from a manifest
// file (as used by CI systems that pass --changed-files manifest.json).
func ChangedFilesFromManifest(manifestPath string) ([]string, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}
	return parseFileList(string(data)), nil
}

// IsGitRepo checks whether the given directory is inside a git repository.
func IsGitRepo(ctx context.Context, dir string) bool {
	return validateGitRepo(ctx, dir) == nil
}

// MergeBase returns the best common ancestor between two refs.
func MergeBase(ctx context.Context, repoDir, ref1, ref2 string) (string, error) {
	if err := validateRef(ref1); err != nil {
		return "", err
	}
	if err := validateRef(ref2); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "git", "merge-base", ref1, ref2)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git merge-base %s %s: %w", ref1, ref2, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// AbsChangedFiles returns absolute paths for changed files.
func AbsChangedFiles(repoDir string, relFiles []string) []string {
	abs := make([]string, len(relFiles))
	for i, f := range relFiles {
		abs[i] = filepath.Join(repoDir, f)
	}
	return abs
}

func validateGitRepo(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--git-dir")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s is not a git repository", dir)
	}
	return nil
}

// validateRef rejects git refs that start with "-" to prevent argument injection.
func validateRef(ref string) error {
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("invalid git ref: %q (must not start with -)", ref)
	}
	return nil
}

func parseFileList(output string) []string {
	var files []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			files = append(files, line)
		}
	}
	return files
}
