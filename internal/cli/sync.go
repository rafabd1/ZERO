package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/scope"
	"github.com/spf13/cobra"
)

func newSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize scope sources.",
	}
	cmd.AddCommand(scopeSyncCommand("all", "Synchronize all configured scope providers.", nil))
	cmd.AddCommand(scopeSyncCommand("h1", "Synchronize HackerOne scopes through the bbscope poller.", []string{"h1"}))
	cmd.AddCommand(scopeSyncCommand("bugcrowd", "Synchronize Bugcrowd scopes through the bbscope poller.", []string{"bugcrowd"}))
	cmd.AddCommand(scopeSyncCommand("bc", "Synchronize Bugcrowd scopes through the bbscope poller.", []string{"bugcrowd"}))
	cmd.AddCommand(scopeSyncCommand("intigriti", "Synchronize Intigriti scopes through the bbscope poller.", []string{"intigriti"}))
	cmd.AddCommand(scopeSyncCommand("it", "Synchronize Intigriti scopes through the bbscope poller.", []string{"intigriti"}))
	return cmd
}

func scopeSyncCommand(use, short string, providers []string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			selected := providers
			if len(selected) == 0 {
				selected = scopeProviders(cfg.Scope.Providers)
			}
			return runScopeSync(cmd, cfg, selected)
		},
	}
}

func runScopeSyncIfDue(parent *cobra.Command, cfg config.Config) error {
	ctx := commandContext()
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()
	last, err := repo.LastSuccessfulScopeSync(ctx)
	if err != nil {
		return err
	}
	maxAge := cfg.Scope.SyncMaxAge
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	if !scopeSyncDueFromLast(last, maxAge, time.Now().UTC()) {
		fmt.Fprintf(parent.OutOrStdout(), "scope sync skipped: last successful sync is newer than %s\n", maxAge)
		return nil
	}
	fmt.Fprintf(parent.OutOrStdout(), "scope sync due: last successful sync is older than %s\n", maxAge)
	return runScopeSync(parent, cfg, scopeProviders(cfg.Scope.Providers))
}

func scopeSyncDueFromLast(last *time.Time, maxAge time.Duration, now time.Time) bool {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	if last == nil {
		return true
	}
	return !last.After(now.Add(-maxAge))
}

func runScopeSync(parent *cobra.Command, cfg config.Config, providers []string) error {
	ctx := commandContext()
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()

	providers = normalizeScopeProviders(providers)
	if len(providers) == 0 {
		return fmt.Errorf("no scope providers configured")
	}
	scanID, err := startScanRun(ctx, parent, repo, "scope", "")
	if err != nil {
		return err
	}

	svc := scope.NewService(repo)
	total := scope.SyncResult{}
	stats := map[string]any{
		"providers": providers,
		"sources":   map[string]any{},
	}
	for _, provider := range providers {
		result, err := syncScopeProvider(ctx, svc, cfg, scanID, provider)
		if err != nil {
			if finishErr := finishScanRun(ctx, repo, scanID, err, total.Programs, total.Assets, stats); finishErr != nil {
				return finishErr
			}
			return err
		}
		total.Programs += result.Programs
		total.Assets += result.Assets
		stats["sources"].(map[string]any)[provider] = map[string]any{
			"programs": result.Programs,
			"assets":   result.Assets,
		}
		fmt.Fprintf(parent.OutOrStdout(), "synced %d %s programs and %d scope assets\n", result.Programs, provider, result.Assets)
	}
	stats["programs"] = total.Programs
	stats["assets"] = total.Assets
	stats["source"] = strings.Join(providers, ",")
	if err := finishScanRun(ctx, repo, scanID, nil, total.Programs, total.Assets, stats); err != nil {
		return err
	}
	fmt.Fprintf(parent.OutOrStdout(), "synced %d total programs and %d scope assets from %s\n", total.Programs, total.Assets, strings.Join(providers, ","))
	return nil
}

func syncScopeProvider(ctx context.Context, svc *scope.Service, cfg config.Config, scanID, provider string) (scope.SyncResult, error) {
	switch provider {
	case "h1":
		if cfg.HackerOne.Username == "" || cfg.HackerOne.Token == "" {
			return scope.SyncResult{}, fmt.Errorf("ZERO_H1_USERNAME and ZERO_H1_TOKEN are required")
		}
		return svc.SyncHackerOne(ctx, scope.HackerOneOptions{
			Username:    cfg.HackerOne.Username,
			Token:       cfg.HackerOne.Token,
			ScanRunID:   scanID,
			BountyOnly:  cfg.Scope.BountyOnly,
			PrivateOnly: cfg.Scope.PrivateOnly,
			Categories:  cfg.Scope.Categories,
		})
	case "bugcrowd":
		return svc.SyncBugcrowd(ctx, scope.BugcrowdOptions{
			Token:       cfg.Bugcrowd.Token,
			Email:       cfg.Bugcrowd.Email,
			Password:    cfg.Bugcrowd.Password,
			OTPSecret:   cfg.Bugcrowd.OTPSecret,
			Proxy:       cfg.Bugcrowd.Proxy,
			PublicOnly:  cfg.Bugcrowd.PublicOnly,
			ScanRunID:   scanID,
			BountyOnly:  cfg.Scope.BountyOnly,
			PrivateOnly: cfg.Scope.PrivateOnly,
			Categories:  cfg.Scope.Categories,
		})
	case "intigriti":
		if cfg.Intigriti.Token == "" {
			return scope.SyncResult{}, fmt.Errorf("ZERO_INTIGRITI_TOKEN is required")
		}
		return svc.SyncIntigriti(ctx, scope.IntigritiOptions{
			Token:       cfg.Intigriti.Token,
			ScanRunID:   scanID,
			BountyOnly:  cfg.Scope.BountyOnly,
			PrivateOnly: cfg.Scope.PrivateOnly,
			Categories:  cfg.Scope.Categories,
		})
	default:
		return scope.SyncResult{}, fmt.Errorf("unsupported scope provider %q", provider)
	}
}

func scopeProviders(raw string) []string {
	return normalizeScopeProviders(strings.Split(raw, ","))
}

func normalizeScopeProviders(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		provider := strings.ToLower(strings.TrimSpace(value))
		switch provider {
		case "hackerone", "h1":
			provider = "h1"
		case "bugcrowd", "bc":
			provider = "bugcrowd"
		case "intigriti", "it":
			provider = "intigriti"
		case "", "none":
			continue
		}
		if !seen[provider] {
			seen[provider] = true
			out = append(out, provider)
		}
	}
	return out
}
