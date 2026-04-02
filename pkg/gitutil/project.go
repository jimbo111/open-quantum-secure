package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

// ProjectInfo holds inferred git project metadata.
type ProjectInfo struct {
	Project   string // "org/repo" extracted from remote URL
	Branch    string // current branch name (or commit SHA when detached)
	CommitSHA string // full 40-character commit SHA
}

// InferProject infers git project metadata from the repository at dir.
//
// It runs:
//  1. git -C {dir} remote get-url origin  → parses org/repo from the URL
//  2. git -C {dir} rev-parse --abbrev-ref HEAD → branch name
//  3. git -C {dir} rev-parse HEAD → full commit SHA
//
// Returns an error if dir is not a git repository or has no origin remote.
func InferProject(ctx context.Context, dir string) (*ProjectInfo, error) {
	rawURL, err := gitOutput(ctx, dir, "remote", "get-url", "origin")
	if err != nil {
		return nil, fmt.Errorf("git remote get-url origin: %w", err)
	}

	project, err := parseRemoteURL(rawURL)
	if err != nil {
		// Redact userinfo (e.g., https://user:token@...) to avoid leaking credentials.
		redacted := rawURL
		if u, parseErr := url.Parse(rawURL); parseErr == nil && u.User != nil {
			u.User = url.User("REDACTED")
			redacted = u.String()
		}
		return nil, fmt.Errorf("parse remote URL %q: %w", redacted, err)
	}

	branch, err := gitOutput(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("git rev-parse --abbrev-ref HEAD: %w", err)
	}

	sha, err := gitOutput(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("git rev-parse HEAD: %w", err)
	}

	// When HEAD is detached, git prints "HEAD" for --abbrev-ref. Replace it
	// with the commit SHA so callers always have a meaningful identifier.
	if branch == "HEAD" {
		branch = sha
	}

	return &ProjectInfo{
		Project:   project,
		Branch:    branch,
		CommitSHA: sha,
	}, nil
}

// parseRemoteURL extracts "org/repo" from a git remote URL.
//
// Supported formats:
//   - https://github.com/org/repo.git
//   - https://github.com/org/repo
//   - git@github.com:org/repo.git
//   - git@github.com:org/repo
//   - ssh://git@github.com/org/repo.git
//   - GitLab subgroups: https://gitlab.com/group/subgroup/repo.git → group/subgroup/repo
func parseRemoteURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("empty remote URL")
	}

	var path string

	switch {
	case strings.HasPrefix(rawURL, "git@"):
		// SCP-style SSH: git@github.com:org/repo.git
		colonIdx := strings.IndexByte(rawURL, ':')
		if colonIdx < 0 {
			return "", fmt.Errorf("invalid SCP SSH URL: %q", rawURL)
		}
		path = rawURL[colonIdx+1:]

	default:
		// Standard URL (https://, ssh://, git://, etc.)
		u, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
		}
		path = u.Path
	}

	// Normalise: strip leading slash, trailing slash, trailing .git
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")

	// Require at least "org/repo" (two segments)
	if !strings.Contains(path, "/") || path == "" {
		return "", fmt.Errorf("cannot infer org/repo from URL %q", rawURL)
	}

	return path, nil
}

// gitOutput runs a git subcommand with -C {dir}, returns trimmed stdout, or
// wraps stderr into the error.
func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	fullArgs := append([]string{"-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}
