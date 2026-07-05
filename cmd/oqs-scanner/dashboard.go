// dashboard.go implements the `dashboard` subcommand.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/dashboard"
)

// dashboardCmd returns the "dashboard" command which starts a local web server
// that visualises scan history stored in ~/.oqs/history/.
func dashboardCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start a local web dashboard to visualise scan history",
		Long: `Start a local web dashboard to visualise scan history.

Opens a lightweight HTTP server at the given address serving an interactive
dashboard with QRS trend charts, finding breakdowns, and recent scan tables.
History is read directly from local files — no backend server required.

Press Ctrl+C to stop the dashboard.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			histDir := config.HistoryDir()
			return dashboard.ServeWithReady(addr, histDir, func(boundAddr string) {
				// Print only after the listener is bound — a port-in-use
				// failure now surfaces as a normal error instead of an
				// out-of-order "Dashboard running … Error: bind: address
				// already in use" sequence.
				fmt.Fprintf(os.Stderr, "Dashboard running at http://%s\n", boundAddr)
				fmt.Fprintf(os.Stderr, "History directory: %s\n", histDir)
				fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n")
			})
		},
	}
	// Default binds to LOOPBACK ONLY. Previously the default `:8899` bound
	// `0.0.0.0:8899` so scan history was reachable from any host on the same
	// LAN / public WiFi — a privacy/data-exposure surface for a tool that is
	// inherently a single-user local dev utility. Users who want LAN/remote
	// reachability can opt in explicitly via `--addr 0.0.0.0:8899` (and
	// should pair that with a reverse proxy + auth).
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8899", "Address to listen on. Default is loopback-only (127.0.0.1:8899); use 0.0.0.0:8899 to expose on all interfaces (NOT recommended without a reverse proxy + auth).")
	return cmd
}
