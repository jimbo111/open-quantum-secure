// auth.go implements OAuth/device-code login, logout, whoami, and the shared auth resolver.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
	"github.com/jimbo111/open-quantum-secure/pkg/auth"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
)

// newResolver builds an auth.Resolver with the full RefreshFn wiring.
// Used by both isAuthenticated and newAPIClient to avoid divergence.
func newResolver(cfg config.Config, apiKeyFlag string) *auth.Resolver {
	s := &auth.Store{}
	endpoint := resolveEndpoint(cfg)
	return &auth.Resolver{
		APIKeyFlag: apiKeyFlag,
		Store:      s,
		RefreshFn: func(ctx context.Context, ep, refreshToken string) (*auth.Credential, error) {
			if ep == "" {
				ep = endpoint
			}
			da := &auth.DeviceAuth{Endpoint: ep}
			tok, err := da.RefreshToken(ctx, refreshToken)
			if err != nil {
				return nil, err
			}
			return &auth.Credential{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
				Endpoint:     ep,
			}, nil
		},
	}
}

// isAuthenticated checks whether the current session has a non-empty token.
// It is a lightweight best-effort check — authentication failures during the
// actual API call are handled by the remote cache helpers.
func isAuthenticated(ctx context.Context, cfg config.Config, apiKeyFlag string) bool {
	resolver := newResolver(cfg, apiKeyFlag)
	token, _, err := resolver.Resolve(ctx)
	return err == nil && token != ""
}

func loginCmd() *cobra.Command {
	var (
		endpoint  string
		noBrowser bool
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the OQS platform",
		Long: `Authenticate with the OQS platform using browser-based login.
In headless environments (SSH, CI), use --no-browser for device code flow.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no explicit --endpoint and no configured endpoint, show guidance.
			// Only read global config (~/.oqs/config.yaml) — never project-level
			// .oqs-scanner.yaml, which could redirect OAuth to an attacker's server.
			if !cmd.Flags().Changed("endpoint") {
				globalCfg, _ := config.LoadGlobal()
				if !hasPlatformEndpoint(globalCfg) {
					fmt.Fprintln(os.Stderr, noPlatformMessage)
					return nil
				}
				// Use globally configured endpoint instead of default.
				endpoint = globalCfg.Endpoint
			}

			ctx := context.Background()

			da := &auth.DeviceAuth{Endpoint: endpoint}

			dcResp, err := da.RequestDeviceCode(ctx)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			// Try to open browser unless --no-browser was set.
			if !noBrowser {
				verifyURL := dcResp.VerificationURI
				if dcResp.UserCode != "" {
					verifyURL += "?code=" + url.QueryEscape(dcResp.UserCode)
				}
				if browserErr := auth.OpenBrowser(verifyURL); browserErr != nil {
					noBrowser = true // Fall through to device code display.
				} else {
					fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
				}
			}

			if noBrowser {
				fmt.Fprintf(os.Stderr, "No browser detected. Use device code flow:\n")
				fmt.Fprintf(os.Stderr, "  1. Visit: %s\n", dcResp.VerificationURI)
				fmt.Fprintf(os.Stderr, "  2. Enter code: %s\n", dcResp.UserCode)
			}

			fmt.Fprintf(os.Stderr, "Waiting for authentication...")

			// Set a timeout for the device code poll.
			expiry := dcResp.ExpiresIn
			if expiry <= 0 {
				expiry = 900 // default 15 minutes
			}
			pollCtx, cancel := context.WithTimeout(ctx, time.Duration(expiry)*time.Second)
			defer cancel()

			tokResp, err := da.PollForToken(pollCtx, dcResp.DeviceCode, dcResp.Interval)
			if err != nil {
				fmt.Fprintln(os.Stderr, " failed")
				return fmt.Errorf("login failed: %w", err)
			}

			fmt.Fprintln(os.Stderr, " done")

			// Save credentials.
			store := &auth.Store{}
			cred := auth.Credential{
				AccessToken:  tokResp.AccessToken,
				RefreshToken: tokResp.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second),
				Endpoint:     endpoint,
			}

			// Fetch identity to populate user fields.
			client, clientErr := api.NewClient(endpoint, version, func(_ context.Context) (string, error) {
				return tokResp.AccessToken, nil
			})
			if clientErr != nil {
				return fmt.Errorf("api client: %w", clientErr)
			}
			identity, identErr := client.GetIdentity(ctx)
			if identErr == nil {
				cred.UserEmail = identity.Email
				cred.OrgName = identity.Org
				cred.Plan = identity.Plan
			}

			if err := store.Save(cred); err != nil {
				return fmt.Errorf("save credentials: %w", err)
			}

			if cred.UserEmail != "" {
				fmt.Fprintf(os.Stderr, "Authenticated as: %s\n", cred.UserEmail)
			} else {
				fmt.Fprintf(os.Stderr, "Authenticated successfully.\n")
			}
			if cred.OrgName != "" {
				fmt.Fprintf(os.Stderr, "Organization: %s\n", cred.OrgName)
			}
			if cred.Plan != "" {
				fmt.Fprintf(os.Stderr, "Plan: %s\n", cred.Plan)
			}
			fmt.Fprintf(os.Stderr, "Credentials saved to %s\n", config.CredentialsPath())
			return nil
		},
	}

	cmd.Flags().StringVar(&endpoint, "endpoint", defaultEndpoint, "API endpoint URL")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Force device code flow (skip browser)")

	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear stored credentials and revoke tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			store := &auth.Store{}

			// Try to revoke on server (best effort).
			cred, loadErr := store.Load()
			if loadErr == nil && cred.Endpoint != "" {
				da := &auth.DeviceAuth{Endpoint: cred.Endpoint}
				_ = da.RevokeToken(ctx, cred.AccessToken, cred.RefreshToken)
			}

			if err := store.Delete(); err != nil {
				return fmt.Errorf("delete credentials: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Logged out successfully.")
			return nil
		},
	}
}

func whoamiCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show current identity, organization, and plan",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			store := &auth.Store{}

			cred, err := store.Load()
			if err != nil {
				cfg, _ := config.Load(".")
				if !hasPlatformEndpoint(cfg) {
					fmt.Fprintln(os.Stderr, "Not connected to any OQS platform.")
					fmt.Fprintln(os.Stderr, "The scanner works fully offline — no login required for local scanning.")
					return nil
				}
				return fmt.Errorf("not authenticated. Run 'oqs-scanner login' first.")
			}

			endpoint := cred.Endpoint
			if endpoint == "" {
				endpoint = defaultEndpoint
			}

			// Fetch fresh identity from server using fully-wired resolver
			// (including RefreshFn so expired-but-refreshable tokens auto-refresh).
			cfg, _ := config.Load(".")
			client, err := newAPIClient(cfg, "")
			if err != nil {
				return fmt.Errorf("api client: %w", err)
			}

			identity, err := client.GetIdentity(ctx)
			if err != nil {
				// Fall back to cached credential data.
				identity = &api.Identity{
					Email: cred.UserEmail,
					Org:   cred.OrgName,
					Plan:  cred.Plan,
				}
			}
			identity.Endpoint = endpoint

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(identity)
			}

			fmt.Printf("Email:        %s\n", identity.Email)
			fmt.Printf("Organization: %s\n", identity.Org)
			fmt.Printf("Plan:         %s\n", identity.Plan)
			fmt.Printf("API Endpoint: %s\n", identity.Endpoint)
			if !cred.ExpiresAt.IsZero() {
				remaining := time.Until(cred.ExpiresAt).Round(time.Minute)
				if remaining > 0 {
					fmt.Printf("Token Expires: %s (in %s)\n", cred.ExpiresAt.Format(time.RFC3339), remaining)
				} else {
					fmt.Printf("Token Expires: %s (expired)\n", cred.ExpiresAt.Format(time.RFC3339))
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}
