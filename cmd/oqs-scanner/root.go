// root.go builds the top-level Cobra command tree.

package main

import "github.com/spf13/cobra"

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "oqs-scanner",
		Short:         "Post-Quantum Cryptography scanner — detect crypto usage across codebases",
		SilenceErrors: true, // we handle errors in main()
		SilenceUsage:  true, // don't print usage on RunE errors
	}

	root.AddCommand(scanCmd())
	root.AddCommand(diffCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(enginesCmd())
	root.AddCommand(loginCmd())
	root.AddCommand(logoutCmd())
	root.AddCommand(whoamiCmd())
	root.AddCommand(uploadCmd())
	root.AddCommand(historyCmd())
	root.AddCommand(trendsCmd())
	root.AddCommand(apikeyCmd())
	root.AddCommand(configCmd())
	root.AddCommand(complianceReportCmd())
	root.AddCommand(dashboardCmd())

	return root
}
