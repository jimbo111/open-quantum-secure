// gitresolve.go resolves git-derived scan metadata (branch, project, cache path).

package main

import (
	"context"
	"path/filepath"

	"github.com/jimbo111/open-quantum-secure/pkg/gitutil"
)

// resolveRemoteBranch returns the branch to use for remote cache scoping.
// Priority: explicit flag > config > git auto-detect > "main".
func resolveRemoteBranch(ctx context.Context, flagBranch, cfgBranch, scanPath string) string {
	if flagBranch != "" {
		return flagBranch
	}
	if cfgBranch != "" {
		return cfgBranch
	}
	if projInfo, err := gitutil.InferProject(ctx, scanPath); err == nil {
		return projInfo.Branch
	}
	return "main"
}

// resolveRemoteBranchFromInfo is like resolveRemoteBranch but uses a pre-fetched ProjectInfo
// to avoid redundant git subprocess calls.
func resolveRemoteBranchFromInfo(flagBranch, cfgBranch string, projInfo *gitutil.ProjectInfo) string {
	if flagBranch != "" {
		return flagBranch
	}
	if cfgBranch != "" {
		return cfgBranch
	}
	if projInfo != nil {
		return projInfo.Branch
	}
	return "main"
}

// resolveProject returns the project name for remote cache scoping.
// Priority: config > git auto-detect > base directory name.
func resolveProject(ctx context.Context, cfgProject, scanPath string) string {
	if cfgProject != "" {
		return cfgProject
	}
	if projInfo, err := gitutil.InferProject(ctx, scanPath); err == nil {
		return projInfo.Project
	}
	return filepath.Base(scanPath)
}

// resolveProjectFromInfo is like resolveProject but uses a pre-fetched ProjectInfo
// to avoid redundant git subprocess calls.
func resolveProjectFromInfo(cfgProject string, projInfo *gitutil.ProjectInfo, scanPath string) string {
	if cfgProject != "" {
		return cfgProject
	}
	if projInfo != nil {
		return projInfo.Project
	}
	return filepath.Base(scanPath)
}

// resolveCachePath returns the effective local cache file path.
func resolveCachePath(override, scanPath string) string {
	if override != "" {
		return override
	}
	return filepath.Join(scanPath, ".oqs-scanner-cache.json")
}
