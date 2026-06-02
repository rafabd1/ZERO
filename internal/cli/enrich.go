package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/enrich"
	"github.com/spf13/cobra"
)

func newEnrichCommand() *cobra.Command {
	var limit int
	var programID string
	var apps string
	var workers int
	var crawl int
	var batchSize int

	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Run target intelligence enrichment tasks.",
	}
	webanalyze := &cobra.Command{
		Use:   "webanalyze",
		Short: "Fingerprint alive HTTP services with Webanalyze/Wappalyzer definitions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "intel", programID)
			if err != nil {
				return err
			}
			appsPath := apps
			if appsPath == "" {
				appsPath = cfg.Tools.WebanalyzeApps
			}
			workerCount := workers
			if workerCount <= 0 {
				workerCount = cfg.Tools.WebanalyzeWorkers
			}
			crawlDepth := crawl
			if crawlDepth < 0 {
				crawlDepth = cfg.Tools.WebanalyzeCrawl
			}
			result, err := enrich.NewWebanalyzeRunner(repo, cfg.Tools.WebanalyzeBin).
				WithScanRunID(scanID).
				WithProgramID(programID).
				WithApps(appsPath).
				WithWorkers(workerCount).
				WithCrawl(crawlDepth).
				WithLimit(limit).
				WithBatchSize(firstPositive(batchSize, cfg.Tools.WebanalyzeBatchSize)).
				WithTimeout(cfg.Tools.ToolTimeout).
				Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, result.Targets, result.Inserted, map[string]any{
					"targets":        result.Targets,
					"matches":        result.Matches,
					"inserted":       result.Inserted,
					"versioned":      result.Versioned,
					"skipped_output": result.SkippedOutput,
					"program_id":     programID,
					"tool":           "webanalyze",
					"apps":           appsPath,
					"workers":        workerCount,
					"crawl":          crawlDepth,
					"batch_size":     firstPositive(batchSize, cfg.Tools.WebanalyzeBatchSize),
				})
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Targets, result.Inserted, map[string]any{
				"targets":        result.Targets,
				"matches":        result.Matches,
				"inserted":       result.Inserted,
				"versioned":      result.Versioned,
				"skipped_output": result.SkippedOutput,
				"program_id":     programID,
				"tool":           "webanalyze",
				"apps":           appsPath,
				"workers":        workerCount,
				"crawl":          crawlDepth,
				"batch_size":     firstPositive(batchSize, cfg.Tools.WebanalyzeBatchSize),
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "webanalyze processed %d services, observed %d tech matches, inserted %d new observations and %d versioned matches\n", result.Targets, result.Matches, result.Inserted, result.Versioned)
			return nil
		},
	}
	webanalyze.Flags().IntVar(&limit, "limit", 0, "limit number of alive services to fingerprint")
	webanalyze.Flags().StringVar(&programID, "program-id", "", "limit enrichment to one program id")
	webanalyze.Flags().StringVar(&apps, "apps", "", "custom Webanalyze/Wappalyzer technologies file for this run only")
	webanalyze.Flags().IntVar(&workers, "workers", 0, "Webanalyze workers for this run only")
	webanalyze.Flags().IntVar(&crawl, "crawl", -1, "Webanalyze crawl depth for this run only")
	webanalyze.Flags().IntVar(&batchSize, "batch-size", 0, "override number of services per Webanalyze process")
	cmd.AddCommand(webanalyze)
	return cmd
}
