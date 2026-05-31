package scope

import (
	"context"
	"fmt"

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
	BountyOnly  bool
	PrivateOnly bool
	Categories  string
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

	result := SyncResult{}
	for _, handle := range handles {
		program, err := poller.FetchProgramScope(ctx, handle, pollOpts)
		if err != nil {
			return result, fmt.Errorf("fetch HackerOne scope for %s: %w", handle, err)
		}

		programID, err := s.repo.UpsertProgram(ctx, "h1", handle, program.Url, map[string]any{
			"source":       "bbscope",
			"bbscope_name": poller.Name(),
		})
		if err != nil {
			return result, err
		}
		result.Programs++

		count, err := s.upsertElements(ctx, programID, "h1", handle, program.InScope, true)
		if err != nil {
			return result, err
		}
		result.Assets += count

		count, err = s.upsertElements(ctx, programID, "h1", handle, program.OutOfScope, false)
		if err != nil {
			return result, err
		}
		result.Assets += count
	}

	return result, nil
}

func (s *Service) upsertElements(ctx context.Context, programID, platform, handle string, elements []bbscope.ScopeElement, inScope bool) (int, error) {
	count := 0
	for _, element := range elements {
		target := element.Target
		normalized := db.NormalizeTarget(target)
		if normalized == "" {
			continue
		}
		_, err := s.repo.UpsertScopeAsset(ctx, db.ScopeAsset{
			ProgramID:         programID,
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
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
