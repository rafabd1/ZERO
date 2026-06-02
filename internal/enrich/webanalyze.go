package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/tools"
)

type WebanalyzeRunner struct {
	repo      *db.Repository
	bin       string
	apps      string
	workers   int
	crawl     int
	scanRunID string
	programID string
	limit     int
	timeout   time.Duration
	batchSize int
}

type WebanalyzeResult struct {
	Targets       int
	Matches       int
	Inserted      int
	Versioned     int
	SkippedOutput int
}

func NewWebanalyzeRunner(repo *db.Repository, bin string) *WebanalyzeRunner {
	if bin == "" {
		bin = "webanalyze"
	}
	return &WebanalyzeRunner{repo: repo, bin: bin, workers: 4}
}

func (r *WebanalyzeRunner) WithApps(path string) *WebanalyzeRunner {
	r.apps = strings.TrimSpace(path)
	return r
}

func (r *WebanalyzeRunner) WithWorkers(workers int) *WebanalyzeRunner {
	if workers > 0 {
		r.workers = workers
	}
	return r
}

func (r *WebanalyzeRunner) WithCrawl(crawl int) *WebanalyzeRunner {
	if crawl >= 0 {
		r.crawl = crawl
	}
	return r
}

func (r *WebanalyzeRunner) WithScanRunID(scanRunID string) *WebanalyzeRunner {
	r.scanRunID = strings.TrimSpace(scanRunID)
	return r
}

func (r *WebanalyzeRunner) WithProgramID(programID string) *WebanalyzeRunner {
	r.programID = strings.TrimSpace(programID)
	return r
}

func (r *WebanalyzeRunner) WithLimit(limit int) *WebanalyzeRunner {
	r.limit = limit
	return r
}

func (r *WebanalyzeRunner) WithTimeout(timeout time.Duration) *WebanalyzeRunner {
	if timeout > 0 {
		r.timeout = timeout
	}
	return r
}

func (r *WebanalyzeRunner) WithBatchSize(batchSize int) *WebanalyzeRunner {
	if batchSize > 0 {
		r.batchSize = batchSize
	}
	return r
}

func (r *WebanalyzeRunner) Run(ctx context.Context) (WebanalyzeResult, error) {
	targets, err := r.repo.ListWebTechTargets(ctx, r.programID, r.limit)
	if err != nil {
		return WebanalyzeResult{}, err
	}
	result := WebanalyzeResult{Targets: len(targets)}
	if len(targets) == 0 {
		return result, nil
	}
	batchSize := r.batchSize
	if batchSize <= 0 {
		batchSize = len(targets)
	}
	for start := 0; start < len(targets); start += batchSize {
		end := start + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		if err := r.runBatch(ctx, targets[start:end], &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (r *WebanalyzeRunner) runBatch(ctx context.Context, targets []db.WebTechTarget, result *WebanalyzeResult) error {
	index := make(map[string][]db.WebTechTarget, len(targets))
	hostFile, err := os.CreateTemp("", "zero-webanalyze-hosts-*.txt")
	if err != nil {
		return err
	}
	hostPath := hostFile.Name()
	defer os.Remove(hostPath)
	for _, target := range targets {
		if target.URL == "" {
			continue
		}
		if _, err := fmt.Fprintln(hostFile, target.URL); err != nil {
			hostFile.Close()
			return err
		}
		index[normalizeURLKey(target.URL)] = append(index[normalizeURLKey(target.URL)], target)
	}
	if err := hostFile.Close(); err != nil {
		return err
	}

	args := []string{
		"-hosts", hostPath,
		"-output", "json",
		"-silent",
		"-worker", strconv.Itoa(r.workers),
		"-crawl", strconv.Itoa(r.crawl),
		"-search=false",
		"-redirect=false",
	}
	if r.apps != "" {
		args = append(args, "-apps", r.apps)
	}

	return tools.RunLinesWithTimeout(ctx, r.timeout, r.bin, args, nil, func(line string) error {
		parsed, err := parseWebanalyzeLine(line)
		if err != nil {
			result.SkippedOutput++
			return nil
		}
		candidates := index[normalizeURLKey(parsed.Hostname)]
		if len(candidates) == 0 {
			result.SkippedOutput++
			return nil
		}
		for _, target := range candidates {
			for _, match := range parsed.Matches {
				if strings.TrimSpace(match.AppName) == "" {
					continue
				}
				_, inserted, err := r.repo.UpsertTechnologyObservation(ctx, db.TechnologyObservation{
					ProgramID:     target.ProgramID,
					HTTPServiceID: target.HTTPServiceID,
					LastScanRunID: firstNonEmpty(r.scanRunID, target.LastScanRunID),
					Name:          match.AppName,
					Version:       match.Version,
					Source:        "webanalyze",
					Confidence:    75,
					Evidence: map[string]any{
						"url":        target.URL,
						"categories": match.Categories,
						"source":     "webanalyze",
					},
				})
				if err != nil {
					return err
				}
				result.Matches++
				if inserted {
					result.Inserted++
				}
				if strings.TrimSpace(match.Version) != "" {
					result.Versioned++
				}
			}
		}
		return nil
	})
}

type webanalyzeLine struct {
	Hostname string                `json:"hostname"`
	Matches  []webanalyzeMatchJSON `json:"matches"`
}

type webanalyzeMatchJSON struct {
	AppName  string   `json:"app_name"`
	Version  string   `json:"version"`
	CatNames []string `json:"cat_names"`
}

type webanalyzeMatch struct {
	AppName    string
	Version    string
	Categories []string
}

type parsedWebanalyzeLine struct {
	Hostname string
	Matches  []webanalyzeMatch
}

func parseWebanalyzeLine(line string) (parsedWebanalyzeLine, error) {
	var raw webanalyzeLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return parsedWebanalyzeLine{}, err
	}
	parsed := parsedWebanalyzeLine{Hostname: raw.Hostname}
	for _, match := range raw.Matches {
		categories := match.CatNames
		parsed.Matches = append(parsed.Matches, webanalyzeMatch{
			AppName:    match.AppName,
			Version:    match.Version,
			Categories: categories,
		})
	}
	return parsed, nil
}

func normalizeURLKey(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), "/")
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.ToLower(parsed.String())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
