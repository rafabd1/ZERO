package config

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	DatabaseURL       string
	DatabaseMaxConns  int
	DatabaseRetries   int
	DatabaseRetryWait time.Duration
	AutoMigrate       bool
	Supabase          SupabaseConfig
	TargetParallelism int

	HackerOne HackerOneConfig
	Scope     ScopeConfig
	Tools     ToolConfig
	Schedule  ScheduleConfig
	API       APIConfig
	Notify    NotifyConfig
	Worker    WorkerConfig
	Intel     IntelConfig
	Data      DataConfig
}

type SupabaseConfig struct {
	URL            string
	AnonKey        string
	ServiceRoleKey string
}

type HackerOneConfig struct {
	Username string
	Token    string
}

type ScopeConfig struct {
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
}

type ToolConfig struct {
	SubfinderBin            string
	SubfinderProviderConfig string
	SubfinderSources        string
	SubfinderRateLimits     string
	DNSXBin                 string
	DNSXResolvers           string
	DNSXRate                int
	HTTPXBin                string
	HTTPXTimeout            int
	HTTPXThreads            int
	HTTPXBatchSize          int
	HTTPXBatchTimeout       time.Duration
	HTTPXPatternMinGroup    int
	HTTPXPatternCap         int
	HTTPXTLSProbe           bool
	WebanalyzeBin           string
	WebanalyzeApps          string
	WebanalyzeWorkers       int
	WebanalyzeCrawl         int
	WebanalyzeBatchSize     int
	NucleiBin               string
	NucleiTemplateDir       string
	NucleiUpdateTemplates   bool
	NucleiFromCVEs          bool
	NucleiTags              string
	NucleiSeverities        string
	NucleiTemplateIDs       string
	NucleiCVELimit          int
	NucleiRate              int
	NucleiC                 int
	NucleiBulkSize          int
	ToolTimeout             time.Duration
}

type APIConfig struct {
	Addr  string
	Token string
}

type NotifyConfig struct {
	DiscordWebhookURL          string
	DiscordPassiveWebhookURL   string
	DiscordValidatedWebhookURL string
	DiscordAlertWebhookURL     string
}

type WorkerConfig struct {
	RunOnStartup        bool
	RecoverRunningScans bool
}

type IntelConfig struct {
	NVDAPIKey       string
	TechAliasesFile string
	CVEMinYear      int
	NVDRetries      int
	NVDRetryWait    time.Duration
}

type DataConfig struct {
	StaleAfterHours int
}

type ScheduleConfig struct {
	Full            string
	ScopeSync       string
	Enum            string
	Probe           string
	CVE             string
	Nuclei          string
	NucleiTemplates string
}

func Load() (Config, error) {
	loadDotEnv()

	v := viper.New()
	v.SetEnvPrefix("ZERO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	v.SetDefault("scope.bounty_only", true)
	v.SetDefault("scope.private_only", false)
	v.SetDefault("scope.categories", "url,wildcard")
	v.SetDefault("tools.subfinder_bin", "subfinder")
	v.SetDefault("tools.subfinder_provider_config", "")
	v.SetDefault("tools.subfinder_sources", "shodan,bevigil,virustotal,securitytrails")
	v.SetDefault("tools.subfinder_rate_limits", "shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s")
	v.SetDefault("tools.dnsx_bin", "dnsx")
	v.SetDefault("tools.dnsx_resolvers", "")
	v.SetDefault("tools.dnsx_rate", 200)
	v.SetDefault("tools.httpx_bin", "httpx")
	v.SetDefault("tools.httpx_timeout", 4)
	v.SetDefault("tools.httpx_threads", 20)
	v.SetDefault("tools.httpx_batch_size", 50)
	v.SetDefault("tools.httpx_batch_timeout", "5m")
	v.SetDefault("tools.httpx_pattern_min_group", 200)
	v.SetDefault("tools.httpx_pattern_cap", 120)
	v.SetDefault("tools.httpx_tls_probe", false)
	v.SetDefault("tools.webanalyze_bin", "webanalyze")
	v.SetDefault("tools.webanalyze_apps", "")
	v.SetDefault("tools.webanalyze_workers", 4)
	v.SetDefault("tools.webanalyze_crawl", 0)
	v.SetDefault("tools.webanalyze_batch_size", 500)
	v.SetDefault("tools.nuclei_bin", "nuclei")
	v.SetDefault("tools.nuclei_template_dir", "")
	v.SetDefault("tools.nuclei_update_templates", true)
	v.SetDefault("tools.nuclei_from_cves", true)
	v.SetDefault("tools.nuclei_tags", "cve")
	v.SetDefault("tools.nuclei_severities", "medium,high,critical")
	v.SetDefault("tools.nuclei_template_ids", "")
	v.SetDefault("tools.nuclei_cve_limit", 100)
	v.SetDefault("tools.nuclei_rate", 80)
	v.SetDefault("tools.nuclei_c", 20)
	v.SetDefault("tools.nuclei_bulk_size", 5)
	v.SetDefault("tools.timeout", "20m")
	v.SetDefault("target_parallelism", 12)
	v.SetDefault("schedule.full", "0 15 3 */3 * *")
	v.SetDefault("schedule.scope_sync", "0 15 3 * * *")
	v.SetDefault("schedule.enum", "0 45 3 * * *")
	v.SetDefault("schedule.probe", "0 30 4 * * *")
	v.SetDefault("schedule.cve", "0 15 5 * * *")
	v.SetDefault("schedule.nuclei", "0 45 5 * * *")
	v.SetDefault("schedule.nuclei_templates", "0 5 3 * * *")
	v.SetDefault("api.addr", "127.0.0.1:8080")
	v.SetDefault("worker.run_on_startup", true)
	v.SetDefault("worker.recover_running_scans", true)
	v.SetDefault("database.auto_migrate", true)
	v.SetDefault("database.max_conns", 1)
	v.SetDefault("database.retries", 4)
	v.SetDefault("database.retry_wait", "3s")
	v.SetDefault("data.stale_after_hours", 168)
	v.SetDefault("intel.cve_min_year", 2018)
	v.SetDefault("intel.nvd_retries", 3)
	v.SetDefault("intel.nvd_retry_wait", "3s")

	_ = v.BindEnv("database_url", "ZERO_DATABASE_URL")
	_ = v.BindEnv("database_svc_key", "ZERO_DATABASE_SVC_KEY")
	_ = v.BindEnv("database.auto_migrate", "ZERO_AUTO_MIGRATE")
	_ = v.BindEnv("database.max_conns", "ZERO_DATABASE_MAX_CONNS")
	_ = v.BindEnv("database.retries", "ZERO_DATABASE_RETRIES")
	_ = v.BindEnv("database.retry_wait", "ZERO_DATABASE_RETRY_WAIT")
	_ = v.BindEnv("supabase_url", "ZERO_SUPABASE_URL")
	_ = v.BindEnv("supabase_anon_key", "ZERO_SUPABASE_ANON_KEY")
	_ = v.BindEnv("supabase_service_role_key", "ZERO_SUPABASE_SERVICE_ROLE_KEY")
	_ = v.BindEnv("h1.username", "ZERO_H1_USERNAME")
	_ = v.BindEnv("h1.token", "ZERO_H1_TOKEN")
	_ = v.BindEnv("scope.bounty_only", "ZERO_SCOPE_BOUNTY_ONLY")
	_ = v.BindEnv("scope.private_only", "ZERO_SCOPE_PRIVATE_ONLY")
	_ = v.BindEnv("scope.categories", "ZERO_SCOPE_CATEGORIES")
	_ = v.BindEnv("tools.subfinder_bin", "ZERO_SUBFINDER_BIN")
	_ = v.BindEnv("tools.subfinder_provider_config", "ZERO_SUBFINDER_PROVIDER_CONFIG", "SUBFINDER_PROVIDER_CONFIG")
	_ = v.BindEnv("tools.subfinder_sources", "ZERO_SUBFINDER_SOURCES")
	_ = v.BindEnv("tools.subfinder_rate_limits", "ZERO_SUBFINDER_RATE_LIMITS")
	_ = v.BindEnv("tools.dnsx_bin", "ZERO_DNSX_BIN")
	_ = v.BindEnv("tools.dnsx_resolvers", "ZERO_DNSX_RESOLVERS")
	_ = v.BindEnv("tools.dnsx_rate", "ZERO_DNSX_RATE")
	_ = v.BindEnv("tools.httpx_bin", "ZERO_HTTPX_BIN")
	_ = v.BindEnv("tools.httpx_timeout", "ZERO_HTTPX_TIMEOUT")
	_ = v.BindEnv("tools.httpx_threads", "ZERO_HTTPX_THREADS")
	_ = v.BindEnv("tools.httpx_batch_size", "ZERO_HTTPX_BATCH_SIZE")
	_ = v.BindEnv("tools.httpx_batch_timeout", "ZERO_HTTPX_BATCH_TIMEOUT")
	_ = v.BindEnv("tools.httpx_pattern_min_group", "ZERO_HTTPX_PATTERN_MIN_GROUP")
	_ = v.BindEnv("tools.httpx_pattern_cap", "ZERO_HTTPX_PATTERN_CAP")
	_ = v.BindEnv("tools.httpx_tls_probe", "ZERO_HTTPX_TLS_PROBE")
	_ = v.BindEnv("tools.webanalyze_bin", "ZERO_WEBANALYZE_BIN")
	_ = v.BindEnv("tools.webanalyze_apps", "ZERO_WEBANALYZE_APPS")
	_ = v.BindEnv("tools.webanalyze_workers", "ZERO_WEBANALYZE_WORKERS")
	_ = v.BindEnv("tools.webanalyze_crawl", "ZERO_WEBANALYZE_CRAWL")
	_ = v.BindEnv("tools.webanalyze_batch_size", "ZERO_WEBANALYZE_BATCH_SIZE")
	_ = v.BindEnv("tools.nuclei_bin", "ZERO_NUCLEI_BIN")
	_ = v.BindEnv("tools.nuclei_template_dir", "ZERO_NUCLEI_TEMPLATE_DIR")
	_ = v.BindEnv("tools.nuclei_update_templates", "ZERO_NUCLEI_UPDATE_TEMPLATES_ON_STARTUP")
	_ = v.BindEnv("tools.nuclei_from_cves", "ZERO_NUCLEI_FROM_CVES")
	_ = v.BindEnv("tools.nuclei_tags", "ZERO_NUCLEI_TAGS")
	_ = v.BindEnv("tools.nuclei_severities", "ZERO_NUCLEI_SEVERITIES")
	_ = v.BindEnv("tools.nuclei_template_ids", "ZERO_NUCLEI_TEMPLATE_IDS")
	_ = v.BindEnv("tools.nuclei_cve_limit", "ZERO_NUCLEI_CVE_LIMIT")
	_ = v.BindEnv("tools.nuclei_rate", "ZERO_NUCLEI_RATE")
	_ = v.BindEnv("tools.nuclei_c", "ZERO_NUCLEI_CONCURRENCY")
	_ = v.BindEnv("tools.nuclei_bulk_size", "ZERO_NUCLEI_BULK_SIZE")
	_ = v.BindEnv("tools.timeout", "ZERO_TOOL_TIMEOUT")
	_ = v.BindEnv("target_parallelism", "ZERO_TARGET_PARALLELISM")
	_ = v.BindEnv("schedule.full", "ZERO_SCHEDULE_FULL")
	_ = v.BindEnv("schedule.scope_sync", "ZERO_SCHEDULE_SCOPE_SYNC")
	_ = v.BindEnv("schedule.enum", "ZERO_SCHEDULE_ENUM")
	_ = v.BindEnv("schedule.probe", "ZERO_SCHEDULE_PROBE")
	_ = v.BindEnv("schedule.cve", "ZERO_SCHEDULE_CVE")
	_ = v.BindEnv("schedule.nuclei", "ZERO_SCHEDULE_NUCLEI")
	_ = v.BindEnv("schedule.nuclei_templates", "ZERO_SCHEDULE_NUCLEI_TEMPLATES")
	_ = v.BindEnv("api.addr", "ZERO_API_ADDR")
	_ = v.BindEnv("api.token", "ZERO_API_TOKEN")
	_ = v.BindEnv("notify.discord_webhook_url", "ZERO_DISCORD_WEBHOOK_URL")
	_ = v.BindEnv("notify.discord_passive_webhook_url", "ZERO_DISCORD_PASSIVE_WEBHOOK_URL")
	_ = v.BindEnv("notify.discord_validated_webhook_url", "ZERO_DISCORD_VALIDATED_WEBHOOK_URL")
	_ = v.BindEnv("notify.discord_alert_webhook_url", "ZERO_DISCORD_ALERT_WEBHOOK_URL")
	_ = v.BindEnv("worker.run_on_startup", "ZERO_RUN_ON_STARTUP")
	_ = v.BindEnv("worker.recover_running_scans", "ZERO_RECOVER_RUNNING_SCANS")
	_ = v.BindEnv("intel.nvd_api_key", "ZERO_NVD_API_KEY")
	_ = v.BindEnv("intel.tech_aliases_file", "ZERO_TECH_ALIASES_FILE")
	_ = v.BindEnv("intel.cve_min_year", "ZERO_CVE_MIN_YEAR")
	_ = v.BindEnv("intel.nvd_retries", "ZERO_NVD_RETRIES")
	_ = v.BindEnv("intel.nvd_retry_wait", "ZERO_NVD_RETRY_WAIT")
	_ = v.BindEnv("data.stale_after_hours", "ZERO_STALE_AFTER_HOURS")

	return Config{
		DatabaseURL:       v.GetString("database_url"),
		DatabaseMaxConns:  clampInt(v.GetInt("database.max_conns"), 1, 10),
		DatabaseRetries:   clampInt(v.GetInt("database.retries"), 1, 10),
		DatabaseRetryWait: v.GetDuration("database.retry_wait"),
		AutoMigrate:       v.GetBool("database.auto_migrate"),
		TargetParallelism: clampInt(v.GetInt("target_parallelism"), 1, 16),
		Supabase: SupabaseConfig{
			URL:            v.GetString("supabase_url"),
			AnonKey:        v.GetString("supabase_anon_key"),
			ServiceRoleKey: firstNonEmpty(v.GetString("supabase_service_role_key"), v.GetString("database_svc_key")),
		},
		HackerOne: HackerOneConfig{
			Username: v.GetString("h1.username"),
			Token:    v.GetString("h1.token"),
		},
		Scope: ScopeConfig{
			BountyOnly:  v.GetBool("scope.bounty_only"),
			PrivateOnly: v.GetBool("scope.private_only"),
			Categories:  v.GetString("scope.categories"),
		},
		Tools: ToolConfig{
			SubfinderBin:            v.GetString("tools.subfinder_bin"),
			SubfinderProviderConfig: v.GetString("tools.subfinder_provider_config"),
			SubfinderSources:        v.GetString("tools.subfinder_sources"),
			SubfinderRateLimits:     v.GetString("tools.subfinder_rate_limits"),
			DNSXBin:                 v.GetString("tools.dnsx_bin"),
			DNSXResolvers:           v.GetString("tools.dnsx_resolvers"),
			DNSXRate:                v.GetInt("tools.dnsx_rate"),
			HTTPXBin:                v.GetString("tools.httpx_bin"),
			HTTPXTimeout:            clampInt(v.GetInt("tools.httpx_timeout"), 1, 60),
			HTTPXThreads:            clampInt(v.GetInt("tools.httpx_threads"), 1, 200),
			HTTPXBatchSize:          clampInt(v.GetInt("tools.httpx_batch_size"), 50, 10000),
			HTTPXBatchTimeout:       v.GetDuration("tools.httpx_batch_timeout"),
			HTTPXPatternMinGroup:    clampInt(v.GetInt("tools.httpx_pattern_min_group"), 0, 100000),
			HTTPXPatternCap:         clampInt(v.GetInt("tools.httpx_pattern_cap"), 0, 100000),
			HTTPXTLSProbe:           v.GetBool("tools.httpx_tls_probe"),
			WebanalyzeBin:           v.GetString("tools.webanalyze_bin"),
			WebanalyzeApps:          v.GetString("tools.webanalyze_apps"),
			WebanalyzeWorkers:       v.GetInt("tools.webanalyze_workers"),
			WebanalyzeCrawl:         v.GetInt("tools.webanalyze_crawl"),
			WebanalyzeBatchSize:     clampInt(v.GetInt("tools.webanalyze_batch_size"), 50, 5000),
			NucleiBin:               v.GetString("tools.nuclei_bin"),
			NucleiTemplateDir:       v.GetString("tools.nuclei_template_dir"),
			NucleiUpdateTemplates:   v.GetBool("tools.nuclei_update_templates"),
			NucleiFromCVEs:          v.GetBool("tools.nuclei_from_cves"),
			NucleiTags:              v.GetString("tools.nuclei_tags"),
			NucleiSeverities:        v.GetString("tools.nuclei_severities"),
			NucleiTemplateIDs:       v.GetString("tools.nuclei_template_ids"),
			NucleiCVELimit:          v.GetInt("tools.nuclei_cve_limit"),
			NucleiRate:              v.GetInt("tools.nuclei_rate"),
			NucleiC:                 v.GetInt("tools.nuclei_c"),
			NucleiBulkSize:          v.GetInt("tools.nuclei_bulk_size"),
			ToolTimeout:             v.GetDuration("tools.timeout"),
		},
		Schedule: ScheduleConfig{
			Full:            v.GetString("schedule.full"),
			ScopeSync:       v.GetString("schedule.scope_sync"),
			Enum:            v.GetString("schedule.enum"),
			Probe:           v.GetString("schedule.probe"),
			CVE:             v.GetString("schedule.cve"),
			Nuclei:          v.GetString("schedule.nuclei"),
			NucleiTemplates: v.GetString("schedule.nuclei_templates"),
		},
		API: APIConfig{
			Addr:  v.GetString("api.addr"),
			Token: v.GetString("api.token"),
		},
		Notify: NotifyConfig{
			DiscordWebhookURL:          v.GetString("notify.discord_webhook_url"),
			DiscordPassiveWebhookURL:   firstNonEmpty(v.GetString("notify.discord_passive_webhook_url"), v.GetString("notify.discord_webhook_url")),
			DiscordValidatedWebhookURL: firstNonEmpty(v.GetString("notify.discord_validated_webhook_url"), v.GetString("notify.discord_webhook_url")),
			DiscordAlertWebhookURL:     firstNonEmpty(v.GetString("notify.discord_alert_webhook_url"), v.GetString("notify.discord_webhook_url")),
		},
		Worker: WorkerConfig{
			RunOnStartup:        v.GetBool("worker.run_on_startup"),
			RecoverRunningScans: v.GetBool("worker.recover_running_scans"),
		},
		Intel: IntelConfig{
			NVDAPIKey:       v.GetString("intel.nvd_api_key"),
			TechAliasesFile: v.GetString("intel.tech_aliases_file"),
			CVEMinYear:      clampInt(v.GetInt("intel.cve_min_year"), 0, 9999),
			NVDRetries:      clampInt(v.GetInt("intel.nvd_retries"), 1, 10),
			NVDRetryWait:    v.GetDuration("intel.nvd_retry_wait"),
		},
		Data: DataConfig{
			StaleAfterHours: v.GetInt("data.stale_after_hours"),
		},
	}, nil
}

func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.TrimPrefix(key, "\ufeff"))
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

func DefaultCommandTimeout() time.Duration {
	return 30 * time.Minute
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
