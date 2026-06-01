package scope

import (
	"context"
	"fmt"
	"sync"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	h1platform "github.com/sw33tLie/bbscope/v2/pkg/platforms/hackerone"
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

type SyncResult struct {
	Programs int
	Assets   int
}

func NewService(repo *db.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) SyncHackerOne(ctx context.Context, opts HackerOneOptions) (SyncResult, error) {
	poller := h1platform.NewPoller(opts.Username, opts.Token)
	pollOpts := platforms.PollOptions{
		BountyOnly:  opts.BountyOnly,
		PrivateOnly: opts.PrivateOnly,
		Categories:  opts.Categories,
	}

	handles, err := poller.ListProgramHandles(ctx, pollOpts)
	if err != nil {
		return SyncResult{}, fmt.Errorf("list HackerOne programs: %w", err)
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
				programCount, assetCount, err := s.syncHackerOneProgram(ctx, poller, pollOpts, opts.ScanRunID, handle)
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

func (s *Service) syncHackerOneProgram(ctx context.Context, poller *h1platform.Poller, pollOpts platforms.PollOptions, scanRunID, handle string) (int, int, error) {
	program, err := poller.FetchProgramScope(ctx, handle, fetchScopeOptions(pollOpts))
	if err != nil {
		return 0, 0, fmt.Errorf("fetch HackerOne scope for %s: %w", handle, err)
	}

	programID, err := s.repo.UpsertProgram(ctx, "h1", handle, program.Url, map[string]any{
		"source":       "bbscope",
		"bbscope_name": poller.Name(),
	})
	if err != nil {
		return 0, 0, err
	}

	inScope, bountyExcluded := splitBountyScope(program.InScope, pollOpts.BountyOnly)

	assets := make([]db.ScopeAsset, 0, len(program.InScope)+len(program.OutOfScope))
	assets = append(assets, buildAssets(programID, scanRunID, "h1", handle, inScope, true)...)
	assets = append(assets, buildAssets(programID, scanRunID, "h1", handle, bountyExcluded, false)...)
	assets = append(assets, buildAssets(programID, scanRunID, "h1", handle, program.OutOfScope, false)...)

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
