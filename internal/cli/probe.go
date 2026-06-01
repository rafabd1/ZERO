package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/probe"
	"github.com/spf13/cobra"
)

func newProbeCommand() *cobra.Command {
	var httpxLimit int
	var dnsxLimit int
	var dnsxProgramID string
	var programID string
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Run live host probing and fingerprinting tasks.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "dnsx",
		Short: "Resolve discovered subdomains before HTTP probing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "probe", dnsxProgramID)
			if err != nil {
				return err
			}
			runner := probe.NewDNSXRunner(repo, cfg.Tools.DNSXBin).
				WithScanRunID(scanID).
				WithProgramID(dnsxProgramID).
				WithResolvers(cfg.Tools.DNSXResolvers).
				WithRate(cfg.Tools.DNSXRate).
				WithLimit(dnsxLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Hosts, result.Updated, map[string]any{
				"hosts":      result.Hosts,
				"resolved":   result.Resolved,
				"updated":    result.Updated,
				"tool":       "dnsx",
				"program_id": dnsxProgramID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "resolved %d of %d hosts and updated %d DNS states\n", result.Resolved, result.Hosts, result.Updated)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "httpx",
		Short: "Probe enumerated subdomains with httpx JSON tech detection.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "probe", programID)
			if err != nil {
				return err
			}
			runner := probe.NewHTTPXRunner(repo, cfg.Tools.HTTPXBin).WithScanRunID(scanID).WithProgramID(programID).WithLimit(httpxLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Hosts, result.Services, map[string]any{
				"hosts":      result.Hosts,
				"services":   result.Services,
				"tool":       "httpx",
				"program_id": programID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "probed %d hosts and upserted %d HTTP services\n", result.Hosts, result.Services)
			return nil
		},
	})
	cmd.Commands()[0].Flags().IntVar(&dnsxLimit, "limit", 0, "limit number of hosts to resolve")
	cmd.Commands()[0].Flags().StringVar(&dnsxProgramID, "program-id", "", "limit DNS validation to one program id")
	cmd.Commands()[1].Flags().IntVar(&httpxLimit, "limit", 0, "limit number of hosts to probe")
	cmd.Commands()[1].Flags().StringVar(&programID, "program-id", "", "limit probing to one program id")
	return cmd
}
