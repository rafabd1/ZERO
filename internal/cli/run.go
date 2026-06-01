package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the main Zero pipeline.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "once",
		Short: "Run sync, scan, validation, and reporting once.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipeline(cmd)
		},
	})
	return cmd
}

func runPipeline(parent *cobra.Command) error {
	steps := [][]string{
		{"sync", "h1"},
		{"enum", "subfinder"},
		{"probe", "httpx"},
		{"analyze", "cves"},
		{"analyze", "nuclei"},
		{"report", "generate"},
		{"notify", "discord"},
	}
	for _, step := range steps {
		fmt.Fprintf(parent.OutOrStdout(), "zero pipeline step: %v\n", step)
		if err := runChildE(parent, step...); err != nil {
			return err
		}
	}
	return nil
}
