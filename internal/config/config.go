package config

import (
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	DatabaseURL string
	Supabase    SupabaseConfig

	HackerOne HackerOneConfig
	Scope     ScopeConfig
	Tools     ToolConfig
	Schedule  ScheduleConfig
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
	HTTPXBin                string
	NucleiBin               string
	NucleiRate              int
	NucleiC                 int
}

type ScheduleConfig struct {
	ScopeSync string
	Enum      string
	Probe     string
	CVE       string
	Nuclei    string
}

func Load() (Config, error) {
	_ = godotenv.Load()

	v := viper.New()
	v.SetEnvPrefix("ZERO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	v.SetDefault("scope.bounty_only", true)
	v.SetDefault("scope.private_only", true)
	v.SetDefault("scope.categories", "url,wildcard")
	v.SetDefault("tools.subfinder_bin", "subfinder")
	v.SetDefault("tools.subfinder_provider_config", "")
	v.SetDefault("tools.subfinder_sources", "shodan,bevigil,virustotal,securitytrails")
	v.SetDefault("tools.subfinder_rate_limits", "shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s")
	v.SetDefault("tools.httpx_bin", "httpx")
	v.SetDefault("tools.nuclei_bin", "nuclei")
	v.SetDefault("tools.nuclei_rate", 80)
	v.SetDefault("tools.nuclei_c", 20)
	v.SetDefault("schedule.scope_sync", "0 15 3 * * *")
	v.SetDefault("schedule.enum", "0 45 3 * * *")
	v.SetDefault("schedule.probe", "0 30 4 * * *")
	v.SetDefault("schedule.cve", "0 15 5 * * *")
	v.SetDefault("schedule.nuclei", "0 45 5 * * *")

	_ = v.BindEnv("tools.subfinder_bin", "ZERO_SUBFINDER_BIN")
	_ = v.BindEnv("tools.subfinder_provider_config", "ZERO_SUBFINDER_PROVIDER_CONFIG", "SUBFINDER_PROVIDER_CONFIG")
	_ = v.BindEnv("tools.subfinder_sources", "ZERO_SUBFINDER_SOURCES")
	_ = v.BindEnv("tools.subfinder_rate_limits", "ZERO_SUBFINDER_RATE_LIMITS")
	_ = v.BindEnv("tools.httpx_bin", "ZERO_HTTPX_BIN")
	_ = v.BindEnv("tools.nuclei_bin", "ZERO_NUCLEI_BIN")
	_ = v.BindEnv("tools.nuclei_rate", "ZERO_NUCLEI_RATE")
	_ = v.BindEnv("tools.nuclei_c", "ZERO_NUCLEI_CONCURRENCY")

	return Config{
		DatabaseURL: v.GetString("database_url"),
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
			HTTPXBin:                v.GetString("tools.httpx_bin"),
			NucleiBin:               v.GetString("tools.nuclei_bin"),
			NucleiRate:              v.GetInt("tools.nuclei_rate"),
			NucleiC:                 v.GetInt("tools.nuclei_c"),
		},
		Schedule: ScheduleConfig{
			ScopeSync: v.GetString("schedule.scope_sync"),
			Enum:      v.GetString("schedule.enum"),
			Probe:     v.GetString("schedule.probe"),
			CVE:       v.GetString("schedule.cve"),
			Nuclei:    v.GetString("schedule.nuclei"),
		},
	}, nil
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
