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

func (r *SubfinderRunner) Run(ctx context.Context) (SubfinderResult, error) {
	roots, err := r.repo.ListDomainRoots(ctx)
	if err != nil {
		return SubfinderResult{}, err
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
			if !ok || !sanitize.IsWithinRoot(fqdn, root.RootDomain) {
				return nil
			}
			_, err := r.repo.UpsertSubdomain(ctx, db.Subdomain{
				ProgramID:    root.ProgramID,
				ScopeAssetID: root.ScopeAssetID,
				RootDomain:   root.RootDomain,
				FQDN:         fqdn,
				Source:       "subfinder",
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
