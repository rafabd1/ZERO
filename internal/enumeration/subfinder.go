package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
	"github.com/rafabd1/ZERO/internal/tools"
)

type SubfinderRunner struct {
	repo           *db.Repository
	bin            string
	providerConfig string
	sources        string
	rateLimits     string
	scanRunID      string
	programID      string
	limit          int
}

type SubfinderResult struct {
	Roots      int
	Subdomains int
}

func NewSubfinderRunner(repo *db.Repository, bin string) *SubfinderRunner {
	if bin == "" {
		bin = "subfinder"
	}
	return &SubfinderRunner{repo: repo, bin: bin}
}

func (r *SubfinderRunner) WithProviderConfig(path string) *SubfinderRunner {
	r.providerConfig = path
	return r
}

func (r *SubfinderRunner) WithSources(sources string) *SubfinderRunner {
	r.sources = sources
	return r
}

func (r *SubfinderRunner) WithRateLimits(rateLimits string) *SubfinderRunner {
	r.rateLimits = rateLimits
	return r
}

func (r *SubfinderRunner) WithLimit(limit int) *SubfinderRunner {
	r.limit = limit
	return r
}

func (r *SubfinderRunner) WithProgramID(programID string) *SubfinderRunner {
	r.programID = strings.TrimSpace(programID)
	return r
}

func (r *SubfinderRunner) WithScanRunID(scanRunID string) *SubfinderRunner {
	r.scanRunID = strings.TrimSpace(scanRunID)
	return r
}

func (r *SubfinderRunner) Run(ctx context.Context) (SubfinderResult, error) {
	roots, err := r.repo.ListDomainRoots(ctx, r.programID)
	if err != nil {
		return SubfinderResult{}, err
	}
	exclusions, err := r.repo.ListOutOfScopeDomainRules(ctx, r.programID)
	if err != nil {
		return SubfinderResult{}, err
	}
	if r.limit > 0 && len(roots) > r.limit {
		roots = roots[:r.limit]
	}

	result := SubfinderResult{Roots: len(roots)}
	for _, root := range roots {
		args := []string{"-silent", "-d", root.RootDomain}
		if r.providerConfig != "" {
			args = append(args, "-pc", r.providerConfig)
		}
		if r.sources != "" {
			args = append(args, "-sources", r.sources)
		}
		if r.rateLimits != "" {
			args = append(args, "-rls", r.rateLimits)
		}
		err := tools.RunLines(ctx, r.bin, args, nil, func(line string) error {
			fqdn, ok := sanitize.CanonicalDomain(strings.TrimSpace(line))
			if !ok || !sanitize.MatchesWildcard(fqdn, root.RootDomain) || excluded(exclusions, root.ProgramID, fqdn) {
				return nil
			}
			_, err := r.repo.UpsertSubdomain(ctx, db.Subdomain{
				ProgramID:     root.ProgramID,
				ScopeAssetID:  root.ScopeAssetID,
				LastScanRunID: r.scanRunID,
				RootDomain:    root.RootDomain,
				FQDN:          fqdn,
				Source:        "subfinder",
			})
			if err != nil {
				return err
			}
			result.Subdomains++
			return nil
		})
		if err != nil {
			return result, fmt.Errorf("subfinder %s: %w", root.RootDomain, err)
		}
	}
	return result, nil
}

func excluded(rules []db.DomainScopeRule, programID, host string) bool {
	for _, rule := range rules {
		if rule.ProgramID != programID {
			continue
		}
		switch rule.MatchMode {
		case db.ProbeMatchWildcard:
			if sanitize.MatchesWildcard(host, rule.Host) {
				return true
			}
		case db.ProbeMatchExact:
			if host == rule.Host {
				return true
			}
		}
	}
	return false
}
