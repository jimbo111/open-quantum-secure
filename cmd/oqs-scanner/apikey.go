// apikey.go implements the `apikey` subcommand family (create/list/revoke).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
)

// apikeyCmd returns the parent "apikey" command with create/list/revoke subcommands.
func apikeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apikey",
		Short: "Manage API keys for CI/CD authentication",
		Long: `Create, list, and revoke API keys for programmatic access to the OQS platform.

API keys are suited for CI/CD pipelines where interactive browser login is not
possible. They carry the prefix "oqs_k_" and do not expire via OAuth refresh.

The raw key is shown exactly once at creation time — save it immediately.

Examples:
  oqs-scanner apikey create --name "github-actions-prod"
  oqs-scanner apikey list
  oqs-scanner apikey revoke oqs_k_Ab`,
	}
	cmd.AddCommand(apikeyCreateCmd())
	cmd.AddCommand(apikeyListCmd())
	cmd.AddCommand(apikeyRevokeCmd())
	return cmd
}

func apikeyCreateCmd() *cobra.Command {
	var (
		name       string
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client, err := newAPIClient(cfg, apiKeyFlag)
			if err != nil {
				return fmt.Errorf("api client: %w", err)
			}

			result, err := client.CreateAPIKey(ctx, name)
			if err != nil {
				return fmt.Errorf("create API key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "API key created successfully.\n")
			fmt.Printf("Key:    %s\n", result.RawKey)
			fmt.Printf("Prefix: %s\n", result.KeyPrefix)
			fmt.Printf("Name:   %s\n", result.Name)
			fmt.Fprintf(os.Stderr, "\nSave this key — it will not be shown again.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Human-readable label for the API key (required)")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}

func apikeyListCmd() *cobra.Command {
	var (
		asJSON     bool
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all API keys (masked)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client, err := newAPIClient(cfg, apiKeyFlag)
			if err != nil {
				return fmt.Errorf("api client: %w", err)
			}

			result, err := client.ListAPIKeys(ctx)
			if err != nil {
				return fmt.Errorf("list API keys: %w", err)
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if len(result.Keys) == 0 {
				fmt.Fprintln(os.Stderr, "No API keys found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PREFIX\tNAME\tLAST USED\tCREATED\tSTATUS")
			for _, k := range result.Keys {
				lastUsed := k.LastUsed
				if lastUsed == "" {
					lastUsed = "never"
				} else if len(lastUsed) > 16 {
					lastUsed = lastUsed[:16]
				}
				created := k.CreatedAt
				if len(created) > 16 {
					created = created[:16]
				}
				status := "active"
				if k.Revoked {
					status = "revoked"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					k.KeyPrefix, k.Name, lastUsed, created, status)
			}
			return w.Flush()
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}

func apikeyRevokeCmd() *cobra.Command {
	var apiKeyFlag string

	cmd := &cobra.Command{
		Use:   "revoke <key-prefix>",
		Short: "Revoke an API key by its prefix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPrefix := args[0]

			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client, err := newAPIClient(cfg, apiKeyFlag)
			if err != nil {
				return fmt.Errorf("api client: %w", err)
			}

			if err := client.RevokeAPIKey(ctx, keyPrefix); err != nil {
				return fmt.Errorf("revoke API key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "API key %q revoked.\n", keyPrefix)
			return nil
		},
	}

	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}
