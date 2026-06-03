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
	repo          *db.Repository
	bin           string
	apps          []string
	probePaths    []string
	workers       int
	crawl         int
	scanRunID     string
	programID     string
	limit         int
	timeout       time.Duration
	batchSize     int
	authoritative bool
	onBatchDone   func(batch, totalBatches, processed, totalTargets, size int)
}

type WebanalyzeResult struct {
	Targets       int
	Matches       int
	Inserted      int
	Versioned     int
	SkippedOutput int
	Deactivated   int
}

func NewWebanalyzeRunner(repo *db.Repository, bin string) *WebanalyzeRunner {
	if bin == "" {
		bin = "webanalyze"
	}
	return &WebanalyzeRunner{repo: repo, bin: bin, workers: 4}
}

func (r *WebanalyzeRunner) WithApps(paths []string) *WebanalyzeRunner {
	r.apps = normalizePathList(paths)
	return r
}

func (r *WebanalyzeRunner) WithProbePaths(paths []string) *WebanalyzeRunner {
	r.probePaths = normalizeProbePaths(paths)
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

func (r *WebanalyzeRunner) WithAuthoritative(authoritative bool) *WebanalyzeRunner {
	r.authoritative = authoritative
	return r
}

func (r *WebanalyzeRunner) WithBatchProgress(onBatchDone func(batch, totalBatches, processed, totalTargets, size int)) *WebanalyzeRunner {
	r.onBatchDone = onBatchDone
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
	targets = expandWebTechTargets(targets, r.probePaths)
	result.Targets = len(targets)
	batchSize := r.batchSize
	if batchSize <= 0 {
		batchSize = len(targets)
	}
	totalBatches := (len(targets) + batchSize - 1) / batchSize
	appsPath, cleanup, err := prepareWebanalyzeApps(r.apps)
	if err != nil {
		return result, err
	}
	defer cleanup()
	batch := 0
	for start := 0; start < len(targets); start += batchSize {
		end := start + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		batch++
		if err := r.runBatch(ctx, targets[start:end], appsPath, &result); err != nil {
			return result, err
		}
		if r.onBatchDone != nil {
			r.onBatchDone(batch, totalBatches, end, len(targets), end-start)
		}
	}
	if r.authoritative && strings.TrimSpace(r.scanRunID) != "" {
		ids := uniqueWebTechServiceIDs(targets)
		deactivated, err := r.repo.MarkMissingTechnologyObservationsInactive(ctx, r.programID, r.scanRunID, "webanalyze", ids)
		if err != nil {
			return result, err
		}
		result.Deactivated = deactivated
	}
	return result, nil
}

func normalizeProbePaths(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if strings.Contains(path, "://") {
			parsed, err := url.Parse(path)
			if err != nil || !parsed.IsAbs() {
				continue
			}
		}
		if parsed, err := url.Parse(path); err == nil && parsed.IsAbs() {
			path = parsed.EscapedPath()
			if parsed.RawQuery != "" {
				path += "?" + parsed.RawQuery
			}
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		parsed, err := url.Parse(path)
		if err != nil || parsed.Host != "" || parsed.Scheme != "" {
			continue
		}
		parsed.Fragment = ""
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		path = parsed.RequestURI()
		if path == "" {
			path = "/"
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func expandWebTechTargets(targets []db.WebTechTarget, probePaths []string) []db.WebTechTarget {
	probePaths = normalizeProbePaths(probePaths)
	if len(probePaths) == 0 {
		return targets
	}
	out := make([]db.WebTechTarget, 0, len(targets)*(len(probePaths)+1))
	seen := map[string]struct{}{}
	for _, target := range targets {
		addWebTechTarget(&out, seen, target)
		for _, path := range probePaths {
			expanded, ok := targetWithProbePath(target, path)
			if !ok {
				continue
			}
			addWebTechTarget(&out, seen, expanded)
		}
	}
	return out
}

func addWebTechTarget(out *[]db.WebTechTarget, seen map[string]struct{}, target db.WebTechTarget) {
	key := target.HTTPServiceID + "\x00" + normalizeURLKey(target.URL)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, target)
}

func targetWithProbePath(target db.WebTechTarget, probePath string) (db.WebTechTarget, bool) {
	parsed, err := url.Parse(strings.TrimSpace(target.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return db.WebTechTarget{}, false
	}
	pathURL, err := url.Parse(probePath)
	if err != nil || pathURL.Scheme != "" || pathURL.Host != "" {
		return db.WebTechTarget{}, false
	}
	parsed.Path = pathURL.Path
	parsed.RawPath = pathURL.RawPath
	parsed.RawQuery = pathURL.RawQuery
	parsed.Fragment = ""
	target.URL = parsed.String()
	return target, true
}

func (r *WebanalyzeRunner) runBatch(ctx context.Context, targets []db.WebTechTarget, appsPath string, result *WebanalyzeResult) error {
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
	if appsPath != "" {
		args = append(args, "-apps", appsPath)
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

type webanalyzeAppsFile struct {
	Technologies map[string]json.RawMessage `json:"technologies,omitempty"`
	Categories   map[string]json.RawMessage `json:"categories,omitempty"`
	Apps         map[string]json.RawMessage `json:"apps,omitempty"`
}

func prepareWebanalyzeApps(paths []string) (string, func(), error) {
	paths = normalizePathList(paths)
	if len(paths) == 0 {
		return "", func() {}, nil
	}
	if len(paths) == 1 {
		return paths[0], func() {}, nil
	}
	merged := webanalyzeAppsFile{
		Technologies: map[string]json.RawMessage{},
		Categories:   map[string]json.RawMessage{},
		Apps:         map[string]json.RawMessage{},
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", func() {}, fmt.Errorf("read Webanalyze apps %s: %w", path, err)
		}
		var parsed webanalyzeAppsFile
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", func() {}, fmt.Errorf("parse Webanalyze apps %s: %w", path, err)
		}
		for name, raw := range parsed.Technologies {
			merged.Technologies[name] = raw
		}
		for name, raw := range parsed.Categories {
			merged.Categories[name] = raw
		}
		for name, raw := range parsed.Apps {
			merged.Apps[name] = raw
		}
	}
	if len(merged.Technologies) == 0 && len(merged.Apps) == 0 {
		return "", func() {}, fmt.Errorf("merged Webanalyze apps contain no technologies")
	}
	if len(merged.Categories) == 0 {
		merged.Categories = nil
	}
	if len(merged.Apps) == 0 {
		merged.Apps = nil
	}
	file, err := os.CreateTemp("", "zero-webanalyze-apps-*.json")
	if err != nil {
		return "", func() {}, err
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(merged); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", func() {}, err
	}
	return file.Name(), func() { _ = os.Remove(file.Name()) }, nil
}

func normalizePathList(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		for _, path := range splitList(value) {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

func splitList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
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

func uniqueWebTechServiceIDs(targets []db.WebTechTarget) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		id := strings.TrimSpace(target.HTTPServiceID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
