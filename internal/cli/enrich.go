package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/enrich"
	"github.com/spf13/cobra"
)

func newEnrichCommand() *cobra.Command {
	var limit int
	var programID string
	var apps []string
	var probePaths []string
	var workers int
	var crawl int
	var batchSize int
	var batchTimeout time.Duration
	var scanRequestID string

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
			appPaths := apps
			authoritative := len(appPaths) == 0 && len(probePaths) == 0
			if len(appPaths) == 0 && strings.TrimSpace(cfg.Tools.WebanalyzeApps) != "" {
				appPaths = []string{cfg.Tools.WebanalyzeApps}
			}
			workerCount := workers
			if workerCount <= 0 {
				workerCount = cfg.Tools.WebanalyzeWorkers
			}
			crawlDepth := crawl
			if crawlDepth < 0 {
				crawlDepth = cfg.Tools.WebanalyzeCrawl
			}
			effectiveBatchSize := webanalyzeEffectiveBatchSize(batchSize, cfg.Tools.WebanalyzeBatchSize)
			effectiveBatchTimeout := webanalyzeEffectiveBatchTimeout(batchTimeout, cfg.Tools.WebanalyzeBatchTimeout)
			runner := enrich.NewWebanalyzeRunner(repo, cfg.Tools.WebanalyzeBin).
				WithScanRunID(scanID).
				WithProgramID(programID).
				WithApps(appPaths).
				WithProbePaths(probePaths).
				WithAuthoritative(authoritative).
				WithWorkers(workerCount).
				WithCrawl(crawlDepth).
				WithLimit(limit).
				WithBatchSize(effectiveBatchSize).
				WithTimeout(effectiveBatchTimeout)
			if strings.TrimSpace(scanRequestID) != "" {
				runner = runner.WithBatchProgress(func(batch, totalBatches, processed, totalTargets, size int) {
					if err := repo.UpdateScanRequestProgress(ctx, scanRequestID, db.ScanRequestProgress{
						Stage:   "enrich webanalyze",
						Current: processed,
						Total:   totalTargets,
						Message: fmt.Sprintf("webanalyze batch %d/%d", batch, totalBatches),
						Meta: map[string]any{
							"program_id":     programID,
							"batch":          batch,
							"total_batches":  totalBatches,
							"batch_size":     effectiveBatchSize,
							"batch_urls":     size,
							"batch_timeout":  effectiveBatchTimeout.String(),
							"workers":        workerCount,
							"probe_paths":    probePaths,
							"custom_apps":    appPaths,
							"expanded_urls":  totalTargets,
							"processed_urls": processed,
						},
					}); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "webanalyze progress update failed request=%s: %v\n", scanRequestID, err)
					}
					if shouldLogWebanalyzeBatch(batch, totalBatches) {
						fmt.Fprintf(cmd.OutOrStdout(), "webanalyze batch progress program=%s request=%s batch=%d/%d processed=%d/%d size=%d batch_timeout=%s\n", programID, scanRequestID, batch, totalBatches, processed, totalTargets, size, effectiveBatchTimeout)
					}
				})
			}
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, result.Targets, result.Inserted, map[string]any{
					"targets":        result.Targets,
					"matches":        result.Matches,
					"inserted":       result.Inserted,
					"versioned":      result.Versioned,
					"deactivated":    result.Deactivated,
					"skipped_output": result.SkippedOutput,
					"program_id":     programID,
					"tool":           "webanalyze",
					"apps":           appPaths,
					"probe_paths":    probePaths,
					"authoritative":  authoritative,
					"workers":        workerCount,
					"crawl":          crawlDepth,
					"batch_size":     effectiveBatchSize,
					"batch_timeout":  effectiveBatchTimeout.String(),
				})
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Targets, result.Inserted, map[string]any{
				"targets":        result.Targets,
				"matches":        result.Matches,
				"inserted":       result.Inserted,
				"versioned":      result.Versioned,
				"deactivated":    result.Deactivated,
				"skipped_output": result.SkippedOutput,
				"program_id":     programID,
				"tool":           "webanalyze",
				"apps":           appPaths,
				"probe_paths":    probePaths,
				"authoritative":  authoritative,
				"workers":        workerCount,
				"crawl":          crawlDepth,
				"batch_size":     effectiveBatchSize,
				"batch_timeout":  effectiveBatchTimeout.String(),
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "webanalyze processed %d services, observed %d tech matches, inserted %d new observations, %d versioned matches and deactivated %d stale observations\n", result.Targets, result.Matches, result.Inserted, result.Versioned, result.Deactivated)
			return nil
		},
	}
	webanalyze.Flags().IntVar(&limit, "limit", 0, "limit number of alive services to fingerprint")
	webanalyze.Flags().StringVar(&programID, "program-id", "", "limit enrichment to one program id")
	webanalyze.Flags().StringArrayVar(&apps, "apps", nil, "custom Webanalyze/Wappalyzer technologies file for this run only; repeatable")
	webanalyze.Flags().StringArrayVar(&probePaths, "probe-path", nil, "additional relative path to fingerprint on every service, for example /admin/; repeatable")
	webanalyze.Flags().IntVar(&workers, "workers", 0, "Webanalyze workers for this run only")
	webanalyze.Flags().IntVar(&crawl, "crawl", -1, "Webanalyze crawl depth for this run only")
	webanalyze.Flags().IntVar(&batchSize, "batch-size", 0, "override number of expanded URLs per Webanalyze process")
	webanalyze.Flags().DurationVar(&batchTimeout, "batch-timeout", 0, "override max wall-clock time per Webanalyze batch, for example 10m")
	webanalyze.Flags().StringVar(&scanRequestID, "scan-request-id", "", "internal scan request id for persisted progress")
	cmd.AddCommand(webanalyze)
	return cmd
}

func shouldLogWebanalyzeBatch(batch, total int) bool {
	return batch == 1 || batch == total || batch%10 == 0
}

func webanalyzeEffectiveBatchSize(requested, configured int) int {
	if requested > 0 {
		return requested
	}
	return firstPositive(configured, 50)
}

func webanalyzeEffectiveBatchTimeout(requested, configured time.Duration) time.Duration {
	if requested > 0 {
		return requested
	}
	if configured > 0 {
		return configured
	}
	return 10 * time.Minute
}
