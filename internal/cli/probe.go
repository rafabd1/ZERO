package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/probe"
	"github.com/spf13/cobra"
)

func newProbeCommand() *cobra.Command {
	var httpxLimit int
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

			scanID, err := startScanRun(ctx, repo, "probe")
			if err != nil {
				return err
			}
			runner := probe.NewHTTPXRunner(repo, cfg.Tools.HTTPXBin).WithLimit(httpxLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Hosts, result.Services, map[string]any{
				"hosts":    result.Hosts,
				"services": result.Services,
				"tool":     "httpx",
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "probed %d hosts and upserted %d HTTP services\n", result.Hosts, result.Services)
			return nil
		},
	})
	cmd.Commands()[0].Flags().IntVar(&httpxLimit, "limit", 0, "limit number of hosts to probe")
	return cmd
}
