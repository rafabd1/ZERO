package scope

import (
	"context"
	"fmt"
	"sync"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	bcplatform "github.com/sw33tLie/bbscope/v2/pkg/platforms/bugcrowd"
	h1platform "github.com/sw33tLie/bbscope/v2/pkg/platforms/hackerone"
	itplatform "github.com/sw33tLie/bbscope/v2/pkg/platforms/intigriti"
	bbscope "github.com/sw33tLie/bbscope/v2/pkg/scope"
)

type Service struct {
	repo *db.Repository
}

type HackerOneOptions struct {
	Username    string
	Token       string
	ScanRunID   string
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
	Concurrency int
}

type BugcrowdOptions struct {
	Token       string
	Email       string
	Password    string
	OTPSecret   string
	Proxy       string
	PublicOnly  bool
	ScanRunID   string
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
	Concurrency int
}

type IntigritiOptions struct {
	Token       string
	ScanRunID   string
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
	Concurrency int
}

type SyncResult struct {
	Programs int
	Assets   int
}

func NewService(repo *db.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) SyncHackerOne(ctx context.Context, opts HackerOneOptions) (SyncResult, error) {
	poller := h1platform.NewPoller(opts.Username, opts.Token)
	return s.syncPlatform(ctx, platformSyncOptions{
		Platform:    "h1",
		Source:      "bbscope",
		Poller:      poller,
		Auth:        platforms.AuthConfig{Username: opts.Username, Token: opts.Token},
		ScanRunID:   opts.ScanRunID,
		BountyOnly:  opts.BountyOnly,
		PrivateOnly: opts.PrivateOnly,
		Categories:  opts.Categories,
		Concurrency: opts.Concurrency,
	})
}

func (s *Service) SyncBugcrowd(ctx context.Context, opts BugcrowdOptions) (SyncResult, error) {
	var poller platforms.PlatformPoller
	if opts.PublicOnly && opts.Token == "" && opts.Email == "" {
		poller = bcplatform.NewPollerPublicOnly()
	} else {
		poller = bcplatform.NewPollerFromToken(opts.Token)
	}
	return s.syncPlatform(ctx, platformSyncOptions{
		Platform:    "bugcrowd",
		Source:      "bbscope",
		Poller:      poller,
		Auth:        platforms.AuthConfig{Token: opts.Token, Email: opts.Email, Password: opts.Password, OtpSecret: opts.OTPSecret, Proxy: opts.Proxy},
		ScanRunID:   opts.ScanRunID,
		BountyOnly:  opts.BountyOnly,
		PrivateOnly: opts.PrivateOnly,
		Categories:  opts.Categories,
		Concurrency: opts.Concurrency,
	})
}

func (s *Service) SyncIntigriti(ctx context.Context, opts IntigritiOptions) (SyncResult, error) {
	poller := itplatform.NewPoller()
	return s.syncPlatform(ctx, platformSyncOptions{
		Platform:    "intigriti",
		Source:      "bbscope",
		Poller:      poller,
		Auth:        platforms.AuthConfig{Token: opts.Token},
		ScanRunID:   opts.ScanRunID,
		BountyOnly:  opts.BountyOnly,
		PrivateOnly: opts.PrivateOnly,
		Categories:  opts.Categories,
		Concurrency: opts.Concurrency,
	})
}

type platformSyncOptions struct {
	Platform    string
	Source      string
	Poller      platforms.PlatformPoller
	Auth        platforms.AuthConfig
	ScanRunID   string
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
	Concurrency int
}

func (s *Service) syncPlatform(ctx context.Context, opts platformSyncOptions) (SyncResult, error) {
	if opts.Poller == nil {
		return SyncResult{}, fmt.Errorf("scope poller is required")
	}
	if err := opts.Poller.Authenticate(ctx, opts.Auth); err != nil {
		return SyncResult{}, fmt.Errorf("authenticate %s: %w", opts.Platform, err)
	}
	pollOpts := platforms.PollOptions{
		BountyOnly:  opts.BountyOnly,
		PrivateOnly: opts.PrivateOnly,
		Categories:  opts.Categories,
	}

	handles, err := opts.Poller.ListProgramHandles(ctx, pollOpts)
	if err != nil {
		return SyncResult{}, fmt.Errorf("list %s programs: %w", opts.Platform, err)
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	handleCh := make(chan string)
	errCh := make(chan error, len(handles))
	var mu sync.Mutex
	result := SyncResult{}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for handle := range handleCh {
				programCount, assetCount, err := s.syncPlatformProgram(ctx, opts, pollOpts, handle)
				if err != nil {
					errCh <- err
					continue
				}
				mu.Lock()
				result.Programs += programCount
				result.Assets += assetCount
				mu.Unlock()
			}
		}()
	}

	for _, handle := range handles {
		select {
		case handleCh <- handle:
		case err := <-errCh:
			close(handleCh)
			wg.Wait()
			return result, err
		case <-ctx.Done():
			close(handleCh)
			wg.Wait()
			return result, ctx.Err()
		}
	}
	close(handleCh)
	wg.Wait()

	select {
	case err := <-errCh:
		return result, err
	default:
	}

	return result, nil
}

func (s *Service) syncPlatformProgram(ctx context.Context, opts platformSyncOptions, pollOpts platforms.PollOptions, handle string) (int, int, error) {
	program, err := opts.Poller.FetchProgramScope(ctx, handle, fetchScopeOptions(pollOpts))
	if err != nil {
		return 0, 0, fmt.Errorf("fetch %s scope for %s: %w", opts.Platform, handle, err)
	}

	programID, err := s.repo.UpsertProgram(ctx, opts.Platform, handle, program.Url, map[string]any{
		"source":       opts.Source,
		"bbscope_name": opts.Poller.Name(),
	})
	if err != nil {
		return 0, 0, err
	}

	inScope, bountyExcluded := splitBountyScope(program.InScope, pollOpts.BountyOnly)

	assets := make([]db.ScopeAsset, 0, len(program.InScope)+len(program.OutOfScope))
	assets = append(assets, buildAssets(programID, opts.ScanRunID, opts.Platform, handle, inScope, true)...)
	assets = append(assets, buildAssets(programID, opts.ScanRunID, opts.Platform, handle, bountyExcluded, false)...)
	assets = append(assets, buildAssets(programID, opts.ScanRunID, opts.Platform, handle, program.OutOfScope, false)...)

	count, err := s.repo.UpsertScopeAssets(ctx, assets)
	if err != nil {
		return 0, 0, err
	}
	return 1, count, nil
}

func fetchScopeOptions(pollOpts platforms.PollOptions) platforms.PollOptions {
	pollOpts.BountyOnly = false
	return pollOpts
}

func splitBountyScope(elements []bbscope.ScopeElement, bountyOnly bool) ([]bbscope.ScopeElement, []bbscope.ScopeElement) {
	if !bountyOnly {
		return elements, nil
	}
	inScope := make([]bbscope.ScopeElement, 0, len(elements))
	outOfScope := make([]bbscope.ScopeElement, 0)
	for _, element := range elements {
		if element.IsBBP {
			inScope = append(inScope, element)
			continue
		}
		outOfScope = append(outOfScope, element)
	}
	return inScope, outOfScope
}

func buildAssets(programID, scanRunID, platform, handle string, elements []bbscope.ScopeElement, inScope bool) []db.ScopeAsset {
	assets := make([]db.ScopeAsset, 0, len(elements))
	for _, element := range elements {
		target := element.Target
		normalized := db.NormalizeTarget(target)
		if normalized == "" {
			continue
		}
		assets = append(assets, db.ScopeAsset{
			ProgramID:         programID,
			LastScanRunID:     scanRunID,
			Platform:          platform,
			Handle:            handle,
			AssetType:         element.Category,
			TargetRaw:         target,
			TargetNormalized:  normalized,
			Description:       element.Description,
			InScope:           inScope,
			EligibleForBounty: element.IsBBP,
			Source:            "bbscope",
		})
	}
	return assets
}
