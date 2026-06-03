package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/intel"
	"github.com/rafabd1/ZERO/internal/validate"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
	var nucleiLimit int
	var nucleiTemplateID string
	var nucleiTemplatePaths []string
	var nucleiTechFilter string
	var nucleiTechMaxAge time.Duration
	var nucleiTargetSource string
	var nucleiProtocol string
	var nucleiTags string
	var nucleiSeverities string
	var nucleiHeaders []string
	var nucleiProxy string
	var nucleiScanStrategy string
	var nucleiMaxHostError int
	var nucleiRate int
	var nucleiConcurrency int
	var nucleiBulkSize int
	var nucleiRetries int
	var nucleiTimeout int
	var nucleiFromCVEs bool
	var nucleiAllCVETemplates bool
	var nucleiForce bool
	var nucleiCVELimit int
	var cvesProgramID string
	var cvesLimit int
	var nucleiProgramID string
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run vulnerability intelligence matching tasks.",
	}
	cves := &cobra.Command{
		Use:   "cves",
		Short: "Record passive intel policy for CVE matching.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "intel", cvesProgramID)
			if err != nil {
				return err
			}
			aliases, err := intel.LoadTechnologyAliases(cfg.Intel.TechAliasesFile)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			result, err := intel.NewNVDRunner(repo, cfg.Intel.NVDAPIKey).
				WithAliases(aliases).
				WithProgramID(cvesProgramID).
				WithScanRunID(scanID).
				WithLimit(cvesLimit).
				WithMinYear(cfg.Intel.CVEMinYear).
				WithRetry(cfg.Intel.NVDRetries, cfg.Intel.NVDRetryWait).
				Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Technologies, result.Inserted, map[string]any{
				"passive_cve_matching": "potential-reporting",
				"technologies":         result.Technologies,
				"cves":                 result.CVEs,
				"inserted":             result.Inserted,
				"matches":              result.Matches,
				"inserted_matches":     result.InsertedMatches,
				"template_eligible":    result.TemplateEligible,
				"program_id":           cvesProgramID,
				"source":               "nvd",
				"validator":            "nuclei",
				"cve_min_year":         cfg.Intel.CVEMinYear,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "queried %d versioned technologies against NVD, observed %d CVE records, inserted %d records, linked %d tech/CVE matches and marked %d as Nuclei-template eligible; report generation can include unconfirmed passive CVEs when Nuclei has no confirming result\n", result.Technologies, result.CVEs, result.Inserted, result.Matches, result.TemplateEligible)
			return nil
		},
	}
	nuclei := &cobra.Command{
		Use:   "nuclei",
		Short: "Run optimized Nuclei validation against configurable target sources.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			templateIDs := cfg.Tools.NucleiTemplateIDs
			if nucleiTemplateID != "" {
				templateIDs = nucleiTemplateID
			}
			tags := firstNonEmpty(nucleiTags, cfg.Tools.NucleiTags)
			severities := firstNonEmpty(nucleiSeverities, cfg.Tools.NucleiSeverities)
			targetSource := firstNonEmpty(nucleiTargetSource, cfg.Tools.NucleiTargetSource)
			protocol := firstNonEmpty(nucleiProtocol, cfg.Tools.NucleiProtocol)
			rate := firstPositive(nucleiRate, cfg.Tools.NucleiRate)
			concurrency := firstPositive(nucleiConcurrency, cfg.Tools.NucleiC)
			bulkSize := firstPositive(nucleiBulkSize, cfg.Tools.NucleiBulkSize)
			headers := validate.SplitHeaderConfig(cfg.Tools.NucleiHeaders)
			if len(nucleiHeaders) > 0 {
				headers = nucleiHeaders
			}
			proxy := firstNonEmpty(nucleiProxy, cfg.Tools.NucleiProxy)
			scanStrategy := firstNonEmpty(nucleiScanStrategy, cfg.Tools.NucleiScanStrategy)
			maxHostError := firstPositive(nucleiMaxHostError, cfg.Tools.NucleiMaxHostError)
			retries := nucleiRetries
			if retries < 0 {
				retries = 1
			}
			timeout := firstPositive(nucleiTimeout, 8)
			scanID, err := startScanRun(ctx, repo, "nuclei", nucleiProgramID)
			if err != nil {
				return err
			}
			fromCVEs := (cfg.Tools.NucleiFromCVEs || nucleiFromCVEs) && !nucleiAllCVETemplates && !nucleiForce && templateIDs == "" && len(nucleiTemplatePaths) == 0
			if fromCVEs {
				cveLimit := nucleiCVELimit
				if cveLimit <= 0 {
					cveLimit = cfg.Tools.NucleiCVELimit
				}
				ids, err := repo.ListCVETemplateIDsFromMatches(ctx, nucleiProgramID, severities, cveLimit, cfg.Intel.CVEMinYear)
				if err != nil {
					return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
				}
				if len(ids) == 0 {
					if err := finishScanRun(ctx, repo, scanID, nil, 0, 0, map[string]any{
						"program_id":   nucleiProgramID,
						"tool":         "nuclei",
						"from_cves":    true,
						"cve_min_year": cfg.Intel.CVEMinYear,
						"skipped":      "no passive CVE/template candidates",
					}); err != nil {
						return err
					}
					fmt.Fprintln(cmd.OutOrStdout(), "nuclei skipped: no medium/high/critical passive CVE template candidates for this scope")
					return nil
				}
				templateIDs = strings.Join(ids, ",")
			}
			runner := validate.NewNucleiRunner(repo, cfg.Tools.NucleiBin).
				WithTargeting(targetSource, protocol).
				WithPolicy(tags, severities, templateIDs, rate, concurrency, bulkSize).
				WithRequestProfile(headers, proxy, scanStrategy, maxHostError).
				WithTechFilter(nucleiTechFilter, nucleiTechMaxAge).
				WithTemplates(nucleiTemplatePaths).
				WithTemplateDir(cfg.Tools.NucleiTemplateDir).
				WithRuntime(retries, timeout).
				WithScanRunID(scanID).
				WithProgramID(nucleiProgramID).
				WithLimit(nucleiLimit).
				WithWAFDetection(cfg.Tools.NucleiWAFDetect, cfg.Tools.NucleiWAFSampleSize, cfg.Tools.NucleiWAFProbeTimeout).
				WithToolTimeout(cfg.Tools.ToolTimeout)
			result, err := runner.Run(ctx)
			stats := map[string]any{
				"targets":           result.Targets,
				"results":           result.Results,
				"inserted_results":  result.Inserted,
				"inserted_findings": result.FindingsInserted,
				"program_id":        nucleiProgramID,
				"tool":              "nuclei",
				"from_cves":         fromCVEs,
				"template_ids":      templateIDs,
				"template_paths":    nucleiTemplatePaths,
				"tech_filter":       nucleiTechFilter,
				"tech_max_age":      nucleiTechMaxAge.String(),
				"target_source":     targetSource,
				"protocol":          protocol,
				"cve_min_year":      cfg.Intel.CVEMinYear,
				"tags":              tags,
				"severities":        severities,
				"headers":           headers,
				"proxy_configured":  proxy != "",
				"scan_strategy":     scanStrategy,
				"max_host_error":    maxHostError,
				"rate":              rate,
				"concurrency":       concurrency,
				"bulk_size":         bulkSize,
				"retries":           retries,
				"timeout":           timeout,
				"skipped":           result.Skipped,
			}
			if result.WAF.Enabled {
				stats["waf_diagnostic"] = result.WAF
			}
			if err != nil {
				alertOnWAF(ctx, cmd, cfg, nucleiProgramID, "", []string{"analyze", "nuclei"}, result.WAF)
				return finishScanRun(ctx, repo, scanID, err, result.Targets, result.FindingsInserted, stats)
			}
			alertOnWAF(ctx, cmd, cfg, nucleiProgramID, "", []string{"analyze", "nuclei"}, result.WAF)
			if err := finishScanRun(ctx, repo, scanID, nil, result.Targets, result.FindingsInserted, stats); err != nil {
				return err
			}
			if result.Skipped != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "nuclei skipped: %s\n", result.Skipped)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei scanned %d URLs, observed %d results, inserted %d new results and %d new findings\n", result.Targets, result.Results, result.Inserted, result.FindingsInserted)
			return nil
		},
	}
	cves.Flags().StringVar(&cvesProgramID, "program-id", "", "query passive CVE intel for one program id")
	cves.Flags().IntVar(&cvesLimit, "limit", 25, "maximum versioned technologies to query")
	nuclei.Flags().IntVar(&nucleiLimit, "limit", 0, "limit number of URLs to validate")
	nuclei.Flags().StringVar(&nucleiTemplateID, "template-id", "", "run only matching Nuclei template id(s)")
	nuclei.Flags().StringArrayVar(&nucleiTemplatePaths, "template-path", nil, "run Nuclei template file/directory path; repeatable")
	nuclei.Flags().StringVar(&nucleiTechFilter, "tech-filter", "", "limit Nuclei targets to services with matching fingerprint technology/title/server text")
	nuclei.Flags().DurationVar(&nucleiTechMaxAge, "tech-max-age", 0, "with --tech-filter, only accept fingerprints reobserved within this duration, for example 2h")
	nuclei.Flags().StringVar(&nucleiTargetSource, "target-source", "", "Nuclei target source: http-services or subdomains")
	nuclei.Flags().StringVar(&nucleiProtocol, "protocol", "", "Nuclei protocol type, for example http, dns, ssl, tcp, or auto")
	nuclei.Flags().StringVar(&nucleiTags, "tags", "", "override Nuclei tags for this run")
	nuclei.Flags().StringVar(&nucleiSeverities, "severity", "", "override Nuclei severities for this run")
	nuclei.Flags().StringArrayVar(&nucleiHeaders, "header", nil, "override Nuclei request header for this run, header:value; repeatable")
	nuclei.Flags().StringVar(&nucleiProxy, "proxy", "", "override Nuclei proxy for this run")
	nuclei.Flags().StringVar(&nucleiScanStrategy, "scan-strategy", "", "override Nuclei scan strategy for this run")
	nuclei.Flags().IntVar(&nucleiMaxHostError, "max-host-error", 0, "override Nuclei max errors per host for this run")
	nuclei.Flags().IntVar(&nucleiRate, "rate-limit", 0, "override Nuclei rate limit for this run")
	nuclei.Flags().IntVar(&nucleiConcurrency, "concurrency", 0, "override Nuclei concurrency for this run")
	nuclei.Flags().IntVar(&nucleiBulkSize, "bulk-size", 0, "override Nuclei bulk size for this run")
	nuclei.Flags().IntVar(&nucleiRetries, "retries", -1, "override Nuclei retries for this run")
	nuclei.Flags().IntVar(&nucleiTimeout, "timeout", 0, "override Nuclei timeout seconds for this run")
	nuclei.Flags().BoolVar(&nucleiFromCVEs, "from-cves", false, "run only Nuclei template ids linked from passive CVE matching")
	nuclei.Flags().BoolVar(&nucleiAllCVETemplates, "all-cve-templates", false, "ignore passive CVE matches and run configured tag/template policy")
	nuclei.Flags().BoolVar(&nucleiForce, "force", false, "force Nuclei to run the configured template/tag policy instead of deriving templates from passive CVEs")
	nuclei.Flags().IntVar(&nucleiCVELimit, "cve-limit", 0, "maximum passive CVE template ids to pass to Nuclei")
	nuclei.Flags().StringVar(&nucleiProgramID, "program-id", "", "limit Nuclei validation to one program id")
	cmd.AddCommand(cves, nuclei)
	return cmd
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
