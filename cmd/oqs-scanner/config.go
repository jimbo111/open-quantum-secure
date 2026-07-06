// config.go implements the `config` subcommand family and shared config fallbacks.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
)

// applyCommonConfigFallbacks applies config-file defaults for flags shared between
// scanCmd and diffCmd. It only applies a default if the flag was not explicitly set.
func applyCommonConfigFallbacks(cmd *cobra.Command, cfg config.Config,
	format *string, timeout *int, maxFileMB *int, engineNames *[]string,
	excludePatterns *[]string, failOn *string,
) {
	if !cmd.Flags().Changed("format") && cfg.Output.Format != "" {
		*format = cfg.Output.Format
	}
	if !cmd.Flags().Changed("timeout") && cfg.Scan.Timeout != 0 {
		*timeout = cfg.Scan.Timeout
	}
	if !cmd.Flags().Changed("max-file-mb") && cfg.Scan.MaxFileMB != 0 {
		*maxFileMB = cfg.Scan.MaxFileMB
	}
	if !cmd.Flags().Changed("engine") && len(cfg.Scan.Engines) > 0 {
		*engineNames = cfg.Scan.Engines
	}
	if !cmd.Flags().Changed("exclude") && len(cfg.Scan.Exclude) > 0 {
		*excludePatterns = cfg.Scan.Exclude
	}
	if !cmd.Flags().Changed("fail-on") && cfg.Policy.FailOn != "" {
		*failOn = cfg.Policy.FailOn
	}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage scanner configuration",
	}
	cmd.AddCommand(configShowCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configInitCmd())
	return cmd
}

func configShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the resolved configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	}
}

func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a global configuration value in ~/.oqs/config.yaml",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			if err := config.EnsureConfigDir(); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}

			// Load existing global config.
			cfg, err := config.LoadGlobal()
			if err != nil {
				return fmt.Errorf("load global config: %w", err)
			}

			// Set the value based on key.
			switch key {
			case "endpoint":
				cfg.Endpoint = value
			case "caCert", "ca-cert":
				cfg.CACert = value
			case "format":
				cfg.Output.Format = value
			default:
				return fmt.Errorf("unknown config key: %q (supported: endpoint, ca-cert, format)", key)
			}

			// Write back as YAML.
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}

			path := config.GlobalConfigPath()
			dir := filepath.Dir(path)
			tmp, err := os.CreateTemp(dir, ".config-*.tmp")
			if err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			tmpPath := tmp.Name()
			defer func() {
				if tmpPath != "" {
					os.Remove(tmpPath)
				}
			}()
			if err := tmp.Chmod(0600); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if _, err := tmp.Write(data); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if err := tmp.Sync(); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if err := tmp.Close(); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			// Symlink guard: reject symlinks at destination to prevent symlink-following.
			if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("config path is a symlink (possible attack): %s", path)
			}
			if err := os.Rename(tmpPath, path); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			tmpPath = "" // prevent defer cleanup

			fmt.Fprintf(os.Stderr, "Set %s = %s in %s\n", key, value, path)
			return nil
		},
	}
}

func configInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a .oqs-scanner.yaml config file in the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ".oqs-scanner.yaml"
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists", path)
			}

			defaultConfig := `# OQS Scanner configuration
# See: https://github.com/jimbo111/open-quantum-secure

scan:
  timeout: 300          # seconds
  # engines: []         # empty = all available
  # exclude:
  #   - "vendor/**"
  #   - "node_modules/**"

output:
  format: table         # json, table, sarif, cbom, html

policy:
  # failOn: critical    # critical, high, medium, low
  # blockedAlgorithms:
  #   - "MD5"
  #   - "SHA-1"
  # requirePQC: false
  # minQRS: 0

upload:
  # autoUpload: false   # auto-upload CBOM after scan
  # project: ""         # project name (default: inferred from git remote)
`

			if err := os.WriteFile(path, []byte(defaultConfig), 0644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Created %s with defaults.\n", path)
			return nil
		},
	}
}
