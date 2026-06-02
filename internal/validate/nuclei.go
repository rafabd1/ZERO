package validate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/tools"
)

type NucleiRunner struct {
	repo        *db.Repository
	bin         string
	tags        string
	severities  string
	templateIDs string
	templates   string
	templateDir string
	rate        int
	concurrency int
	bulkSize    int
	retries     int
	timeout     int
	scanRunID   string
	programID   string
	limit       int
	toolTimeout time.Duration
}

type NucleiResult struct {
	Targets          int
	Results          int
	Inserted         int
	FindingsInserted int
	Skipped          string
}

func NewNucleiRunner(repo *db.Repository, bin string) *NucleiRunner {
	if bin == "" {
		bin = "nuclei"
	}
	return &NucleiRunner{
		repo:        repo,
		bin:         bin,
		tags:        "cve",
		severities:  "medium,high,critical",
		rate:        80,
		concurrency: 20,
		bulkSize:    5,
		retries:     1,
		timeout:     8,
	}
}

func (r *NucleiRunner) WithPolicy(tags, severities, templateIDs string, rate, concurrency, bulkSize int) *NucleiRunner {
	if tags != "" {
		r.tags = tags
	}
	if severities != "" {
		r.severities = severities
	}
	if templateIDs != "" {
		r.templateIDs = templateIDs
	}
	if rate > 0 {
		r.rate = rate
	}
	if concurrency > 0 {
		r.concurrency = concurrency
	}
	if bulkSize > 0 {
		r.bulkSize = bulkSize
	}
	return r
}

func (r *NucleiRunner) WithTemplates(templates string) *NucleiRunner {
	if strings.TrimSpace(templates) != "" {
		r.templates = strings.TrimSpace(templates)
	}
	return r
}

func (r *NucleiRunner) WithTemplateDir(templateDir string) *NucleiRunner {
	if strings.TrimSpace(templateDir) != "" {
		r.templateDir = strings.TrimSpace(templateDir)
	}
	return r
}

func (r *NucleiRunner) WithRuntime(retries, timeout int) *NucleiRunner {
	if retries >= 0 {
		r.retries = retries
	}
	if timeout > 0 {
		r.timeout = timeout
	}
	return r
}

func (r *NucleiRunner) WithLimit(limit int) *NucleiRunner {
	r.limit = limit
	return r
}

func (r *NucleiRunner) WithToolTimeout(timeout time.Duration) *NucleiRunner {
	if timeout > 0 {
		r.toolTimeout = timeout
	}
	return r
}

func (r *NucleiRunner) WithProgramID(programID string) *NucleiRunner {
	r.programID = strings.TrimSpace(programID)
	return r
}

func (r *NucleiRunner) WithScanRunID(scanRunID string) *NucleiRunner {
	r.scanRunID = strings.TrimSpace(scanRunID)
	return r
}

func (r *NucleiRunner) Run(ctx context.Context) (NucleiResult, error) {
	targets, err := r.repo.ListNucleiTargets(ctx, r.programID)
	if err != nil {
		return NucleiResult{}, err
	}
	if r.limit > 0 && len(targets) > r.limit {
		targets = targets[:r.limit]
	}
	result := NucleiResult{Targets: len(targets)}
	if len(targets) == 0 {
		result.Skipped = "no active HTTP services"
		return result, nil
	}

	var input bytes.Buffer
	for _, target := range targets {
		input.WriteString(target.URL)
		input.WriteByte('\n')
	}

	index := newTargetIndex(targets)
	args := []string{
		"-silent",
		"-j",
		"-duc",
		"-ni",
		"-pt", "http",
		"-severity", r.severities,
		"-rate-limit", strconv.Itoa(r.rate),
		"-c", strconv.Itoa(r.concurrency),
		"-bs", strconv.Itoa(r.bulkSize),
		"-retries", strconv.Itoa(r.retries),
		"-timeout", strconv.Itoa(r.timeout),
		"-or",
		"-ot",
	}
	if r.templates != "" {
		args = append(args, "-t", r.templates)
	} else if r.templateDir != "" {
		args = append(args, "-t", r.templateDir)
	}
	if r.templateIDs != "" {
		args = append(args, "-id", r.templateIDs)
	} else {
		args = append(args, "-tags", r.tags)
	}

	err = tools.RunLinesWithTimeout(ctx, r.toolTimeout, r.bin, args, bufio.NewReader(&input), func(line string) error {
		parsed, err := parseNucleiLine(line)
		if err != nil {
			return err
		}
		target, ok := index.match(parsed.MatchedAt)
		if !ok {
			return nil
		}
		parsed.ProgramID = target.ProgramID
		parsed.HTTPServiceID = target.HTTPServiceID
		parsed.ScanRunID = r.scanRunID
		nucleiID, inserted, err := r.repo.UpsertNucleiResult(ctx, parsed)
		if err != nil {
			return err
		}
		_, findingInserted, err := r.repo.UpsertCandidateFindingFromNuclei(ctx, nucleiID, parsed)
		if err != nil {
			return err
		}
		result.Results++
		if inserted {
			result.Inserted++
		}
		if findingInserted {
			result.FindingsInserted++
		}
		return nil
	})
	if err != nil && isNoTemplatesError(err) {
		result.Skipped = "no matching local Nuclei templates"
		return result, nil
	}
	return result, err
}

func isNoTemplatesError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(stripANSI(err.Error()))
	return strings.Contains(msg, "no templates provided for scan")
}

func stripANSI(value string) string {
	var out strings.Builder
	inEscape := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if inEscape {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b {
			inEscape = true
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

type nucleiJSON struct {
	TemplateID    string          `json:"template-id"`
	TemplatePath  string          `json:"template-path"`
	MatchedAt     string          `json:"matched-at"`
	Type          string          `json:"type"`
	ExtractorName string          `json:"extractor-name"`
	Info          nucleiInfo      `json:"info"`
	Raw           json.RawMessage `json:"-"`
}

type nucleiInfo struct {
	Severity       string         `json:"severity"`
	Tags           any            `json:"tags"`
	Classification map[string]any `json:"classification"`
	Metadata       map[string]any `json:"metadata"`
}

func parseNucleiLine(line string) (db.NucleiResult, error) {
	var parsed nucleiJSON
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		return db.NucleiResult{}, fmt.Errorf("parse nuclei json: %w", err)
	}
	raw := json.RawMessage(append([]byte(nil), line...))
	cves := stringSliceFromAny(parsed.Info.Classification["cve-id"])
	if len(cves) == 0 {
		cves = stringSliceFromAny(parsed.Info.Metadata["cve"])
	}
	if cves == nil {
		cves = []string{}
	}
	tags := stringSliceFromAny(parsed.Info.Tags)
	if tags == nil {
		tags = []string{}
	}
	evidenceHash := hashParts(parsed.TemplateID, parsed.MatchedAt, parsed.Type, parsed.ExtractorName, strings.Join(cves, ","))
	return db.NucleiResult{
		TemplateID:    parsed.TemplateID,
		TemplatePath:  parsed.TemplatePath,
		MatchedAt:     parsed.MatchedAt,
		Severity:      strings.ToLower(parsed.Info.Severity),
		CVEs:          cves,
		Tags:          tags,
		Type:          parsed.Type,
		ExtractorName: parsed.ExtractorName,
		EvidenceHash:  evidenceHash,
		Raw:           raw,
	}, nil
}

func stringSliceFromAny(value any) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return splitCSV(v)
	case []string:
		return cleanStrings(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return cleanStrings(out)
	default:
		return nil
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	return cleanStrings(parts)
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func hashParts(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type targetIndex struct {
	targets []db.NucleiTarget
	byHost  map[string][]db.NucleiTarget
}

func newTargetIndex(targets []db.NucleiTarget) targetIndex {
	idx := targetIndex{
		targets: targets,
		byHost:  make(map[string][]db.NucleiTarget),
	}
	for _, target := range targets {
		host := hostOf(target.URL)
		if host != "" {
			idx.byHost[host] = append(idx.byHost[host], target)
		}
	}
	return idx
}

func (idx targetIndex) match(matchedAt string) (db.NucleiTarget, bool) {
	for _, target := range idx.targets {
		if matchedAt == target.URL || strings.HasPrefix(matchedAt, strings.TrimRight(target.URL, "/")+"/") {
			return target, true
		}
	}
	host := hostOf(matchedAt)
	if host == "" {
		return db.NucleiTarget{}, false
	}
	matches := idx.byHost[host]
	if len(matches) == 1 {
		return matches[0], true
	}
	return db.NucleiTarget{}, false
}

func hostOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
