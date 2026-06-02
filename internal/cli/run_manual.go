package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type manualRunOptions struct {
	ProgramID            string
	SkipSync             bool
	SkipEnum             bool
	SkipDNS              bool
	SkipProbe            bool
	ReuseActiveServices  bool
	SkipEnrich           bool
	SkipCVEs             bool
	SkipNuclei           bool
	SkipReport           bool
	SkipNotify           bool
	SubfinderLimit       int
	DNSXLimit            int
	HTTPXLimit           int
	HTTPXTimeout         int
	HTTPXThreads         int
	HTTPXBatchSize       int
	HTTPXBatchTimeout    string
	HTTPXPatternMin      int
	HTTPXPatternCap      int
	HTTPXTLSProbe        bool
	WebanalyzeLimit      int
	CVELimit             int
	WebanalyzeApps       string
	WebanalyzeProbePaths []string
	WebanalyzeWorkers    int
	WebanalyzeCrawl      int
	WebanalyzeBatch      int
	NucleiLimit          int
	NucleiTemplateID     string
	NucleiTemplate       string
	NucleiTechFilter     string
	NucleiTechMaxAge     string
	NucleiTags           string
	NucleiSeverity       string
	NucleiHeaders        []string
	NucleiProxy          string
	NucleiStrategy       string
	NucleiMaxHostErr     int
	NucleiRateLimit      int
	NucleiConcurrency    int
	NucleiBulkSize       int
	NucleiRetries        int
	NucleiTimeout        int
	NucleiFromCVEs       bool
	NucleiAllCVEs        bool
	NucleiForce          bool
	NucleiCVELimit       int
}

func addManualRunCommand(parent *cobra.Command) {
	var opts manualRunOptions
	cmd := &cobra.Command{
		Use:   "manual",
		Short: "Run a one-off custom scan without changing global configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runManualPipeline(cmd, opts)
		},
	}
	bindManualRunFlags(cmd, &opts)
	parent.AddCommand(cmd)
}

func addScheduledRunCommand(parent *cobra.Command) {
	var opts manualRunOptions
	var name string
	var runAfter string
	var allPrograms bool
	var dueOnly bool
	var campaignLimit int
	var campaignParallelism int
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Queue a one-off custom scan request for the worker.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			when, err := parseRunAfter(runAfter)
			if err != nil {
				return err
			}
			if allPrograms {
				result, err := repo.CreateScanCampaign(ctx, name, "cli", when, opts, dueOnly, campaignLimit, campaignParallelism)
				if err != nil {
					return err
				}
				fmt.Fprintf(
					cmd.OutOrStdout(),
					"queued scan campaign %s for %s: %d program(s), parallelism=%d, due_only=%t\n",
					result.ID,
					when.UTC().Format(time.RFC3339),
					result.Total,
					result.Parallel,
					result.DueOnly,
				)
				return nil
			}
			id, err := repo.CreateScanRequest(ctx, opts.ProgramID, name, "cli", when, opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "queued scan request %s for %s\n", id, when.UTC().Format(time.RFC3339))
			return nil
		},
	}
	bindManualRunFlags(cmd, &opts)
	cmd.Flags().StringVar(&name, "name", "", "optional scan request name")
	cmd.Flags().StringVar(&runAfter, "run-after", "", "when to run: empty/now, duration like 30m, or RFC3339 timestamp")
	cmd.Flags().BoolVar(&allPrograms, "all-programs", false, "queue this custom scan for every active program")
	cmd.Flags().BoolVar(&dueOnly, "due-only", false, "with --all-programs, include only programs due for their configured interval")
	cmd.Flags().IntVar(&campaignLimit, "campaign-limit", 0, "with --all-programs, cap the number of programs queued")
	cmd.Flags().IntVar(&campaignParallelism, "campaign-parallelism", 1, "with --all-programs, maximum program scans from this campaign running at once")
	parent.AddCommand(cmd)
}

func bindManualRunFlags(cmd *cobra.Command, opts *manualRunOptions) {
	cmd.Flags().StringVar(&opts.ProgramID, "program-id", "", "limit manual scan to one program id")
	cmd.Flags().BoolVar(&opts.SkipSync, "skip-sync", false, "skip the daily scope-sync guard")
	cmd.Flags().BoolVar(&opts.SkipEnum, "skip-enum", false, "skip subfinder")
	cmd.Flags().BoolVar(&opts.SkipDNS, "skip-dns", false, "skip dnsx resolution")
	cmd.Flags().BoolVar(&opts.SkipProbe, "skip-probe", false, "skip dnsx/httpx active probing")
	cmd.Flags().BoolVar(&opts.ReuseActiveServices, "reuse-active-services", false, "skip dnsx/httpx and load active HTTP services already stored in the database")
	cmd.Flags().BoolVar(&opts.SkipEnrich, "skip-enrich", false, "skip Webanalyze enrichment")
	cmd.Flags().BoolVar(&opts.SkipCVEs, "skip-cves", false, "skip passive CVE matching")
	cmd.Flags().BoolVar(&opts.SkipNuclei, "skip-nuclei", false, "skip Nuclei validation")
	cmd.Flags().BoolVar(&opts.SkipReport, "skip-report", false, "skip report generation")
	cmd.Flags().BoolVar(&opts.SkipNotify, "skip-notify", false, "skip Discord notification")
	cmd.Flags().IntVar(&opts.SubfinderLimit, "subfinder-limit", 0, "manual subfinder root limit")
	cmd.Flags().IntVar(&opts.DNSXLimit, "dnsx-limit", 0, "manual dnsx host limit")
	cmd.Flags().IntVar(&opts.HTTPXLimit, "httpx-limit", 0, "manual httpx target limit")
	cmd.Flags().IntVar(&opts.HTTPXTimeout, "httpx-timeout", 0, "manual httpx per-request timeout seconds")
	cmd.Flags().IntVar(&opts.HTTPXThreads, "httpx-threads", 0, "manual httpx worker threads")
	cmd.Flags().IntVar(&opts.HTTPXBatchSize, "httpx-batch-size", 0, "manual httpx hosts per process")
	cmd.Flags().StringVar(&opts.HTTPXBatchTimeout, "httpx-batch-timeout", "", "manual max wall-clock time per httpx batch, for example 5m")
	cmd.Flags().IntVar(&opts.HTTPXPatternMin, "httpx-pattern-min-group", 0, "manual minimum root group size before httpx host pattern budgeting")
	cmd.Flags().IntVar(&opts.HTTPXPatternCap, "httpx-pattern-cap", 0, "manual tenant-like hosts kept per budgeted root")
	cmd.Flags().BoolVar(&opts.HTTPXTLSProbe, "httpx-tls-probe", false, "enable httpx TLS probe for this run only")
	cmd.Flags().IntVar(&opts.WebanalyzeLimit, "webanalyze-limit", 0, "manual Webanalyze service limit")
	cmd.Flags().IntVar(&opts.CVELimit, "cve-limit", 0, "manual passive CVE technology limit")
	cmd.Flags().StringVar(&opts.WebanalyzeApps, "webanalyze-apps", "", "custom Webanalyze apps file for this run only")
	cmd.Flags().StringArrayVar(&opts.WebanalyzeProbePaths, "webanalyze-probe-path", nil, "additional relative path to fingerprint on every service, for example /admin/; repeatable")
	cmd.Flags().IntVar(&opts.WebanalyzeWorkers, "webanalyze-workers", 0, "custom Webanalyze workers for this run only")
	cmd.Flags().IntVar(&opts.WebanalyzeCrawl, "webanalyze-crawl", -1, "custom Webanalyze crawl depth for this run only")
	cmd.Flags().IntVar(&opts.WebanalyzeBatch, "webanalyze-batch-size", 0, "custom Webanalyze services per process")
	cmd.Flags().IntVar(&opts.NucleiLimit, "nuclei-limit", 0, "manual Nuclei URL limit")
	cmd.Flags().StringVar(&opts.NucleiTemplateID, "nuclei-template-id", "", "custom Nuclei template id(s) for this run only")
	cmd.Flags().StringVar(&opts.NucleiTemplate, "nuclei-template", "", "custom Nuclei template file/directory path(s) for this run only")
	cmd.Flags().StringVar(&opts.NucleiTechFilter, "nuclei-tech-filter", "", "limit Nuclei targets to services with matching fingerprint technology/title/server text")
	cmd.Flags().StringVar(&opts.NucleiTechMaxAge, "nuclei-tech-max-age", "", "with --nuclei-tech-filter, only accept fingerprints reobserved within this duration, for example 2h")
	cmd.Flags().StringVar(&opts.NucleiTags, "nuclei-tags", "", "custom Nuclei tags for this run only")
	cmd.Flags().StringVar(&opts.NucleiSeverity, "nuclei-severity", "", "custom Nuclei severities for this run only")
	cmd.Flags().StringArrayVar(&opts.NucleiHeaders, "nuclei-header", nil, "custom Nuclei request header for this run only, header:value; repeatable")
	cmd.Flags().StringVar(&opts.NucleiProxy, "nuclei-proxy", "", "custom Nuclei proxy for this run only")
	cmd.Flags().StringVar(&opts.NucleiStrategy, "nuclei-scan-strategy", "", "custom Nuclei scan strategy for this run only")
	cmd.Flags().IntVar(&opts.NucleiMaxHostErr, "nuclei-max-host-error", 0, "custom Nuclei max errors per host for this run only")
	cmd.Flags().IntVar(&opts.NucleiRateLimit, "nuclei-rate-limit", 0, "custom Nuclei rate limit for this run only")
	cmd.Flags().IntVar(&opts.NucleiConcurrency, "nuclei-concurrency", 0, "custom Nuclei concurrency for this run only")
	cmd.Flags().IntVar(&opts.NucleiBulkSize, "nuclei-bulk-size", 0, "custom Nuclei bulk size for this run only")
	cmd.Flags().IntVar(&opts.NucleiRetries, "nuclei-retries", -1, "custom Nuclei retries for this run only")
	cmd.Flags().IntVar(&opts.NucleiTimeout, "nuclei-timeout", 0, "custom Nuclei timeout seconds for this run only")
	cmd.Flags().BoolVar(&opts.NucleiFromCVEs, "nuclei-from-cves", false, "derive Nuclei template ids from passive CVE matches for this run only")
	cmd.Flags().BoolVar(&opts.NucleiAllCVEs, "nuclei-all-cve-templates", false, "run configured Nuclei tag/template policy instead of passive CVE matches")
	cmd.Flags().BoolVar(&opts.NucleiForce, "nuclei-force", false, "force Nuclei to run the configured template/tag policy instead of deriving templates from passive CVEs")
	cmd.Flags().IntVar(&opts.NucleiCVELimit, "nuclei-cve-limit", 0, "maximum passive CVE template ids for this run only")
}

func runManualPipeline(parent *cobra.Command, opts manualRunOptions) error {
	ctx := commandContext()
	cfg := loadConfig()
	opts = normalizeManualRunOptions(opts)

	if !opts.SkipSync {
		fmt.Fprintln(parent.OutOrStdout(), "zero manual step: [scope sync if due]")
		if err := runScopeSyncIfDue(parent, cfg); err != nil {
			alertOnTimeout(ctx, parent, cfg, opts.ProgramID, "", []string{"sync", "all"}, err)
			return err
		}
	}

	steps := [][]string{}
	if !opts.SkipEnum {
		step := []string{"enum", "subfinder"}
		step = appendProgramFlag(step, opts.ProgramID)
		step = appendIntFlag(step, "--limit", opts.SubfinderLimit)
		steps = append(steps, step)
	}
	if !opts.SkipProbe {
		if !opts.SkipDNS {
			step := []string{"probe", "dnsx"}
			step = appendProgramFlag(step, opts.ProgramID)
			step = appendIntFlag(step, "--limit", opts.DNSXLimit)
			steps = append(steps, step)
		}
		step := []string{"probe", "httpx"}
		step = appendProgramFlag(step, opts.ProgramID)
		step = appendIntFlag(step, "--limit", opts.HTTPXLimit)
		step = appendIntFlag(step, "--timeout", opts.HTTPXTimeout)
		step = appendIntFlag(step, "--threads", opts.HTTPXThreads)
		step = appendIntFlag(step, "--batch-size", opts.HTTPXBatchSize)
		step = appendStringFlag(step, "--batch-timeout", opts.HTTPXBatchTimeout)
		step = appendIntFlag(step, "--pattern-min-group", opts.HTTPXPatternMin)
		step = appendIntFlag(step, "--pattern-cap", opts.HTTPXPatternCap)
		if opts.HTTPXTLSProbe {
			step = append(step, "--tls-probe")
		}
		steps = append(steps, step)
	}
	if !opts.SkipEnrich {
		step := []string{"enrich", "webanalyze"}
		step = appendProgramFlag(step, opts.ProgramID)
		step = appendIntFlag(step, "--limit", opts.WebanalyzeLimit)
		if opts.WebanalyzeApps != "" {
			step = append(step, "--apps", opts.WebanalyzeApps)
		}
		for _, path := range opts.WebanalyzeProbePaths {
			step = append(step, "--probe-path", path)
		}
		step = appendIntFlag(step, "--workers", opts.WebanalyzeWorkers)
		if opts.WebanalyzeCrawl >= 0 {
			step = append(step, "--crawl", fmt.Sprint(opts.WebanalyzeCrawl))
		}
		step = appendIntFlag(step, "--batch-size", opts.WebanalyzeBatch)
		steps = append(steps, step)
	}
	if !opts.SkipCVEs {
		step := []string{"analyze", "cves"}
		step = appendProgramFlag(step, opts.ProgramID)
		step = appendIntFlag(step, "--limit", opts.CVELimit)
		steps = append(steps, step)
	}
	if !opts.SkipNuclei {
		step := []string{"analyze", "nuclei"}
		step = appendProgramFlag(step, opts.ProgramID)
		step = appendIntFlag(step, "--limit", opts.NucleiLimit)
		if opts.NucleiTemplateID != "" {
			step = append(step, "--template-id", opts.NucleiTemplateID)
		}
		if opts.NucleiTemplate != "" {
			step = append(step, "--template-path", opts.NucleiTemplate)
		}
		if opts.NucleiTechFilter != "" {
			step = append(step, "--tech-filter", opts.NucleiTechFilter)
		}
		techMaxAge := strings.TrimSpace(opts.NucleiTechMaxAge)
		if techMaxAge == "" && opts.NucleiTechFilter != "" && runRefreshesFingerprint(opts) {
			techMaxAge = automaticTechMaxAge(cfg.Tools.ToolTimeout)
		}
		if techMaxAge != "" {
			step = append(step, "--tech-max-age", techMaxAge)
		}
		if opts.NucleiTags != "" {
			step = append(step, "--tags", opts.NucleiTags)
		}
		if opts.NucleiSeverity != "" {
			step = append(step, "--severity", opts.NucleiSeverity)
		}
		for _, header := range opts.NucleiHeaders {
			step = append(step, "--header", header)
		}
		if opts.NucleiProxy != "" {
			step = append(step, "--proxy", opts.NucleiProxy)
		}
		if opts.NucleiStrategy != "" {
			step = append(step, "--scan-strategy", opts.NucleiStrategy)
		}
		step = appendIntFlag(step, "--max-host-error", opts.NucleiMaxHostErr)
		step = appendIntFlag(step, "--rate-limit", opts.NucleiRateLimit)
		step = appendIntFlag(step, "--concurrency", opts.NucleiConcurrency)
		step = appendIntFlag(step, "--bulk-size", opts.NucleiBulkSize)
		if opts.NucleiRetries >= 0 {
			step = append(step, "--retries", fmt.Sprint(opts.NucleiRetries))
		}
		step = appendIntFlag(step, "--timeout", opts.NucleiTimeout)
		if opts.NucleiFromCVEs {
			step = append(step, "--from-cves")
		}
		if opts.NucleiAllCVEs {
			step = append(step, "--all-cve-templates")
		}
		if opts.NucleiForce {
			step = append(step, "--force")
		}
		step = appendIntFlag(step, "--cve-limit", opts.NucleiCVELimit)
		steps = append(steps, step)
	}
	if !opts.SkipReport {
		step := []string{"report", "generate"}
		step = appendProgramFlag(step, opts.ProgramID)
		steps = append(steps, step)
	}
	if !opts.SkipNotify {
		step := []string{"notify", "discord"}
		step = appendProgramFlag(step, opts.ProgramID)
		steps = append(steps, step)
	}

	for _, step := range steps {
		fmt.Fprintf(parent.OutOrStdout(), "zero manual step: %v\n", step)
		if err := runChildE(parent, step...); err != nil {
			alertOnTimeout(ctx, parent, cfg, opts.ProgramID, "", step, err)
			return err
		}
	}
	return nil
}

func appendProgramFlag(step []string, programID string) []string {
	if programID != "" {
		step = append(step, "--program-id", programID)
	}
	return step
}

func appendIntFlag(step []string, name string, value int) []string {
	if value > 0 {
		step = append(step, name, fmt.Sprint(value))
	}
	return step
}

func appendStringFlag(step []string, name string, value string) []string {
	value = strings.TrimSpace(value)
	if value != "" {
		step = append(step, name, value)
	}
	return step
}

func normalizeManualRunOptions(opts manualRunOptions) manualRunOptions {
	if opts.ReuseActiveServices {
		opts.SkipDNS = true
		opts.SkipProbe = true
	}
	return opts
}

func runRefreshesFingerprint(opts manualRunOptions) bool {
	return !opts.SkipProbe || !opts.SkipEnrich
}

func automaticTechMaxAge(toolTimeout time.Duration) string {
	window := 30 * time.Minute
	if toolTimeout > 0 && toolTimeout+10*time.Minute > window {
		window = toolTimeout + 10*time.Minute
	}
	return window.String()
}

func parseRunAfter(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "now") {
		return time.Now().UTC(), nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return time.Now().UTC().Add(d), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --run-after %q: use a duration like 30m or an RFC3339 timestamp", value)
	}
	return t, nil
}

func manualRunOptionsFromJSON(raw json.RawMessage) (manualRunOptions, error) {
	var opts manualRunOptions
	if len(raw) == 0 {
		return opts, nil
	}
	if err := json.Unmarshal(raw, &opts); err != nil {
		return opts, fmt.Errorf("decode scan request params: %w", err)
	}
	return normalizeManualRunOptions(opts), nil
}
