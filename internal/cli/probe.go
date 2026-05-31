package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/probe"
	"github.com/spf13/cobra"
)

func newProbeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Run live host probing and fingerprinting tasks.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "httpx",
		Short: "Probe enumerated subdomains with httpx JSON tech detection.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			runner := probe.NewHTTPXRunner(repo, cfg.Tools.HTTPXBin)
			result, err := runner.Run(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "probed %d hosts and upserted %d HTTP services\n", result.Hosts, result.Services)
			return nil
		},
	})
	return cmd
}
