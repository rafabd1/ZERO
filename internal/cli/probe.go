package cli

import (
	"fmt"
	"time"

	"github.com/rafabd1/ZERO/internal/probe"
	"github.com/spf13/cobra"
)

func newProbeCommand() *cobra.Command {
	var httpxLimit int
	var httpxTimeout int
	var httpxThreads int
	var httpxBatchSize int
	var httpxBatchTimeout time.Duration
	var httpxPatternMinGroup int
	var httpxPatternCap int
	var httpxPatternFamilyCap int
	var httpxTLSProbe bool
	var dnsxLimit int
	var dnsxBatchSize int
	var dnsxBatchTimeout time.Duration
	var dnsxProgramID string
	var programID string
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Run live host probing and fingerprinting tasks.",
	}
	dnsx := &cobra.Command{
		Use:   "dnsx",
		Short: "Resolve discovered subdomains before HTTP probing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			scanID, err := startScanRun(ctx, cmd, repo, "probe", dnsxProgramID)
			if err != nil {
				return err
			}
			runner := probe.NewDNSXRunner(repo, cfg.Tools.DNSXBin).
				WithScanRunID(scanID).
				WithProgramID(dnsxProgramID).
				WithResolvers(cfg.Tools.DNSXResolvers).
				WithRate(cfg.Tools.DNSXRate).
				WithLimit(dnsxLimit).
				WithBatchSize(firstPositive(dnsxBatchSize, cfg.Tools.DNSXBatchSize)).
				WithBatchTimeout(firstDuration(dnsxBatchTimeout, cfg.Tools.DNSXBatchTimeout))
			result, err := runner.Run(ctx)
			stats := map[string]any{
				"hosts":         result.Hosts,
				"resolved":      result.Resolved,
				"updated":       result.Updated,
				"tool":          "dnsx",
				"program_id":    dnsxProgramID,
				"batch_size":    firstPositive(dnsxBatchSize, cfg.Tools.DNSXBatchSize),
				"batch_timeout": firstDuration(dnsxBatchTimeout, cfg.Tools.DNSXBatchTimeout).String(),
			}
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, result.Hosts, result.Updated, stats)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Hosts, result.Updated, stats); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "resolved %d of %d hosts and updated %d DNS states\n", result.Resolved, result.Hosts, result.Updated)
			return nil
		},
	}
	httpx := &cobra.Command{
		Use:   "httpx",
		Short: "Probe enumerated subdomains with httpx JSON tech detection.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			scanID, err := startScanRun(ctx, cmd, repo, "probe", programID)
			if err != nil {
				return err
			}
			runner := probe.NewHTTPXRunner(repo, cfg.Tools.HTTPXBin).
				WithScanRunID(scanID).
				WithProgramID(programID).
				WithLimit(httpxLimit).
				WithRequestPolicy(firstPositive(httpxTimeout, cfg.Tools.HTTPXTimeout), firstPositive(httpxThreads, cfg.Tools.HTTPXThreads)).
				WithBatchSize(firstPositive(httpxBatchSize, cfg.Tools.HTTPXBatchSize)).
				WithBatchTimeout(firstDuration(httpxBatchTimeout, cfg.Tools.HTTPXBatchTimeout)).
				WithPatternBudget(firstPositive(httpxPatternMinGroup, cfg.Tools.HTTPXPatternMinGroup), firstPositive(httpxPatternCap, cfg.Tools.HTTPXPatternCap), firstPositive(httpxPatternFamilyCap, cfg.Tools.HTTPXPatternFamilyCap)).
				WithTLSProbe(httpxTLSProbe || cfg.Tools.HTTPXTLSProbe)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, result.Hosts, result.Services, map[string]any{
					"hosts":              result.Hosts,
					"services":           result.Services,
					"deactivated":        result.Deactivated,
					"tool":               "httpx",
					"timeout":            firstPositive(httpxTimeout, cfg.Tools.HTTPXTimeout),
					"threads":            firstPositive(httpxThreads, cfg.Tools.HTTPXThreads),
					"batch_size":         firstPositive(httpxBatchSize, cfg.Tools.HTTPXBatchSize),
					"batch_timeout":      firstDuration(httpxBatchTimeout, cfg.Tools.HTTPXBatchTimeout).String(),
					"pattern_min_group":  firstPositive(httpxPatternMinGroup, cfg.Tools.HTTPXPatternMinGroup),
					"pattern_cap":        firstPositive(httpxPatternCap, cfg.Tools.HTTPXPatternCap),
					"pattern_family_cap": firstPositive(httpxPatternFamilyCap, cfg.Tools.HTTPXPatternFamilyCap),
					"skipped_by_pattern": result.SkippedByPattern,
					"priority_kept":      result.PriorityKept,
					"budgeted_roots":     result.BudgetedRoots,
					"budgeted_families":  result.BudgetedFamilies,
					"tls_probe":          httpxTLSProbe || cfg.Tools.HTTPXTLSProbe,
					"program_id":         programID,
				})
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Hosts, result.Services, map[string]any{
				"hosts":              result.Hosts,
				"services":           result.Services,
				"deactivated":        result.Deactivated,
				"tool":               "httpx",
				"timeout":            firstPositive(httpxTimeout, cfg.Tools.HTTPXTimeout),
				"threads":            firstPositive(httpxThreads, cfg.Tools.HTTPXThreads),
				"batch_size":         firstPositive(httpxBatchSize, cfg.Tools.HTTPXBatchSize),
				"batch_timeout":      firstDuration(httpxBatchTimeout, cfg.Tools.HTTPXBatchTimeout).String(),
				"pattern_min_group":  firstPositive(httpxPatternMinGroup, cfg.Tools.HTTPXPatternMinGroup),
				"pattern_cap":        firstPositive(httpxPatternCap, cfg.Tools.HTTPXPatternCap),
				"pattern_family_cap": firstPositive(httpxPatternFamilyCap, cfg.Tools.HTTPXPatternFamilyCap),
				"skipped_by_pattern": result.SkippedByPattern,
				"priority_kept":      result.PriorityKept,
				"budgeted_roots":     result.BudgetedRoots,
				"budgeted_families":  result.BudgetedFamilies,
				"tls_probe":          httpxTLSProbe || cfg.Tools.HTTPXTLSProbe,
				"program_id":         programID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "probed %d hosts, upserted %d HTTP services, and deactivated %d stale service(s) (%d hosts skipped by pattern budget)\n", result.Hosts, result.Services, result.Deactivated, result.SkippedByPattern)
			return nil
		},
	}
	dnsx.Flags().IntVar(&dnsxLimit, "limit", 0, "limit number of hosts to resolve")
	dnsx.Flags().IntVar(&dnsxBatchSize, "batch-size", 0, "override number of hosts per dnsx process")
	dnsx.Flags().DurationVar(&dnsxBatchTimeout, "batch-timeout", 0, "override max wall-clock time per dnsx batch, for example 10m")
	dnsx.Flags().StringVar(&dnsxProgramID, "program-id", "", "limit DNS validation to one program id")
	httpx.Flags().IntVar(&httpxLimit, "limit", 0, "limit number of hosts to probe")
	httpx.Flags().IntVar(&httpxTimeout, "timeout", 0, "override httpx per-request timeout seconds")
	httpx.Flags().IntVar(&httpxThreads, "threads", 0, "override httpx worker threads")
	httpx.Flags().IntVar(&httpxBatchSize, "batch-size", 0, "override number of hosts per httpx process")
	httpx.Flags().DurationVar(&httpxBatchTimeout, "batch-timeout", 0, "override max wall-clock time per httpx batch, for example 5m")
	httpx.Flags().IntVar(&httpxPatternMinGroup, "pattern-min-group", 0, "override minimum root group size before host pattern budgeting")
	httpx.Flags().IntVar(&httpxPatternCap, "pattern-cap", 0, "override tenant-like hosts kept per budgeted root; 0 disables when config is also 0")
	httpx.Flags().IntVar(&httpxPatternFamilyCap, "pattern-family-cap", 0, "override similar host-family representatives kept before httpx; 0 disables when config is also 0")
	httpx.Flags().BoolVar(&httpxTLSProbe, "tls-probe", false, "enable httpx TLS probe for this run")
	httpx.Flags().StringVar(&programID, "program-id", "", "limit probing to one program id")
	cmd.AddCommand(dnsx, httpx)
	return cmd
}
