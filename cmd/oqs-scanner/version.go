// version.go implements the `version` subcommand.

package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and detected engines",
		Run: func(cmd *cobra.Command, args []string) {
			v := strings.TrimPrefix(version, "v")
			fmt.Printf("oqs-scanner v%s\n\n", v)

			orch := buildOrchestrator()
			fmt.Println("Engines:")
			for _, e := range orch.Engines() {
				status := "unavailable"
				if e.Available() {
					status = "available"
				}
				fmt.Printf("  %-15s tier=%s  status=%s  languages=%s\n",
					e.Name(),
					e.Tier(),
					status,
					strings.Join(e.SupportedLanguages(), ","),
				)
			}
		},
	}
}
