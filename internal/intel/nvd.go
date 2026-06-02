package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
)

type NVDRunner struct {
	repo      *db.Repository
	apiKey    string
	programID string
	scanRunID string
	aliases   TechnologyAliases
	limit     int
	perQuery  int
	minYear   int
	retries   int
	retryWait time.Duration
	client    *http.Client
}

type NVDResult struct {
	Technologies     int
	CVEs             int
	Inserted         int
	Matches          int
	InsertedMatches  int
	TemplateEligible int
}

func NewNVDRunner(repo *db.Repository, apiKey string) *NVDRunner {
	return &NVDRunner{
		repo:      repo,
		apiKey:    strings.TrimSpace(apiKey),
		aliases:   DefaultTechnologyAliases(),
		limit:     25,
		perQuery:  20,
		minYear:   2018,
		retries:   3,
		retryWait: 3 * time.Second,
		client:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (r *NVDRunner) WithAliases(aliases TechnologyAliases) *NVDRunner {
	if len(aliases) > 0 {
		r.aliases = aliases
	}
	return r
}

func (r *NVDRunner) WithProgramID(programID string) *NVDRunner {
	r.programID = strings.TrimSpace(programID)
	return r
}

func (r *NVDRunner) WithScanRunID(scanRunID string) *NVDRunner {
	r.scanRunID = strings.TrimSpace(scanRunID)
	return r
}

func (r *NVDRunner) WithLimit(limit int) *NVDRunner {
	if limit > 0 {
		r.limit = limit
	}
	return r
}

func (r *NVDRunner) WithMinYear(year int) *NVDRunner {
	if year >= 0 {
		r.minYear = year
	}
	return r
}

func (r *NVDRunner) WithRetry(retries int, wait time.Duration) *NVDRunner {
	if retries > 0 {
		r.retries = retries
	}
	if wait > 0 {
		r.retryWait = wait
	}
	return r
}

func (r *NVDRunner) Run(ctx context.Context) (NVDResult, error) {
	techs, err := r.repo.ListVersionedTechnologies(ctx, r.programID, r.limit)
	if err != nil {
		return NVDResult{}, err
	}
	result := NVDResult{Technologies: len(techs)}
	for i, tech := range techs {
		query := tech.Name + " " + tech.Version
		candidates, err := r.search(ctx, tech, query)
		if err != nil {
			return result, err
		}
		for _, candidate := range candidates {
			vulnerabilityID, inserted, err := r.repo.UpsertVulnerabilityRecord(ctx, candidate.Record)
			if err != nil {
				return result, err
			}
			result.CVEs++
			if inserted {
				result.Inserted++
			}
			_, matchInserted, err := r.repo.UpsertTechnologyVulnerabilityMatch(ctx, db.TechnologyVulnerabilityMatch{
				ProgramID:         tech.ProgramID,
				HTTPServiceID:     tech.HTTPServiceID,
				VulnerabilityID:   vulnerabilityID,
				LastScanRunID:     firstNonEmpty(r.scanRunID, tech.LastScanRunID),
				TechnologyName:    tech.Name,
				TechnologyVersion: tech.Version,
				SourceObservation: tech.Source,
				SourceQuery:       query,
				Confidence:        candidate.Confidence,
				Evidence:          candidate.Evidence,
			})
			if err != nil {
				return result, err
			}
			result.Matches++
			if matchInserted {
				result.InsertedMatches++
			}
			if candidate.Confidence >= 50 && candidate.Record.Severity != "low" && candidate.Record.Severity != "unknown" {
				result.TemplateEligible++
			}
		}
		if r.apiKey == "" && i+1 < len(techs) {
			select {
			case <-time.After(6 * time.Second):
			case <-ctx.Done():
				return result, ctx.Err()
			}
		}
	}
	return result, nil
}

type nvdCandidate struct {
	Record     db.VulnerabilityRecord
	Confidence int
	Evidence   map[string]any
}

func (r *NVDRunner) search(ctx context.Context, tech db.VersionedTechnology, keyword string) ([]nvdCandidate, error) {
	endpoint := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	q := url.Values{}
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", fmt.Sprint(r.perQuery))
	q.Set("noRejected", "")
	var parsed nvdResponse
	var lastErr error
	for attempt := 1; attempt <= r.retries; attempt++ {
		parsed, lastErr = r.fetch(ctx, endpoint+"?"+q.Encode(), keyword)
		if lastErr == nil {
			break
		}
		if attempt == r.retries || !retryableNVDError(lastErr) {
			return nil, lastErr
		}
		wait := time.Duration(attempt) * r.retryWait
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	candidates := make([]nvdCandidate, 0, len(parsed.Vulnerabilities))
	for _, item := range parsed.Vulnerabilities {
		if r.minYear > 0 && cveYear(item.CVE.ID) < r.minYear {
			continue
		}
		confidence, evidence := matchConfidence(tech, item.CVE, keyword, r.aliases)
		if confidence < 40 {
			continue
		}
		raw, _ := json.Marshal(item.CVE)
		candidates = append(candidates, nvdCandidate{
			Confidence: confidence,
			Evidence:   evidence,
			Record: db.VulnerabilityRecord{
				VulnID:     item.CVE.ID,
				Source:     "nvd",
				Summary:    firstEnglishDescription(item.CVE.Descriptions),
				Severity:   item.CVE.severity(),
				CVSSScore:  item.CVE.score(),
				References: item.CVE.references(),
				Raw:        raw,
			},
		})
	}
	return candidates, nil
}

func (r *NVDRunner) fetch(ctx context.Context, rawURL, keyword string) (nvdResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nvdResponse{}, err
	}
	if r.apiKey != "" {
		req.Header.Set("apiKey", r.apiKey)
	}
	res, err := r.client.Do(req)
	if err != nil {
		return nvdResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nvdResponse{}, nvdStatusError{keyword: keyword, status: res.StatusCode}
	}
	var parsed nvdResponse
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return nvdResponse{}, err
	}
	return parsed, nil
}

type nvdStatusError struct {
	keyword string
	status  int
}

func (e nvdStatusError) Error() string {
	return fmt.Sprintf("nvd search %q failed with status %d", e.keyword, e.status)
}

func retryableNVDError(err error) bool {
	if statusErr, ok := err.(nvdStatusError); ok {
		return statusErr.status == http.StatusTooManyRequests || statusErr.status >= 500
	}
	return true
}

func cveYear(id string) int {
	id = strings.ToUpper(strings.TrimSpace(id))
	if !strings.HasPrefix(id, "CVE-") || len(id) < 9 {
		return 0
	}
	year, err := strconv.Atoi(id[4:8])
	if err != nil {
		return 0
	}
	return year
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	References   []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []nvdConfiguration `json:"configurations"`
	Metrics        struct {
		CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
		CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
		CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Nodes    []nvdNode     `json:"nodes"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseSeverity string   `json:"baseSeverity"`
		BaseScore    *float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

func (c nvdCVE) severity() string {
	for _, metrics := range [][]nvdMetric{c.Metrics.CVSSMetricV40, c.Metrics.CVSSMetricV31, c.Metrics.CVSSMetricV30, c.Metrics.CVSSMetricV2} {
		if len(metrics) == 0 {
			continue
		}
		severity := firstNonEmpty(metrics[0].CVSSData.BaseSeverity, metrics[0].BaseSeverity)
		if severity != "" {
			return strings.ToLower(severity)
		}
	}
	return "unknown"
}

func (c nvdCVE) score() *float64 {
	for _, metrics := range [][]nvdMetric{c.Metrics.CVSSMetricV40, c.Metrics.CVSSMetricV31, c.Metrics.CVSSMetricV30, c.Metrics.CVSSMetricV2} {
		if len(metrics) > 0 && metrics[0].CVSSData.BaseScore != nil {
			return metrics[0].CVSSData.BaseScore
		}
	}
	return nil
}

func (c nvdCVE) references() []string {
	refs := make([]string, 0, len(c.References))
	for _, ref := range c.References {
		if strings.TrimSpace(ref.URL) != "" {
			refs = append(refs, ref.URL)
		}
	}
	return refs
}

func matchConfidence(tech db.VersionedTechnology, cve nvdCVE, query string, aliases TechnologyAliases) (int, map[string]any) {
	cpeScore, cpeEvidence := cve.cpeConfidence(tech, aliases)
	if cve.hasVulnerableCPEs() && cpeScore == 0 {
		return 0, map[string]any{"reason": "cpe-present-without-product-version-match"}
	}
	textScore, textEvidence := textConfidence(tech, cve)
	if cpeScore >= textScore {
		cpeEvidence["query"] = query
		cpeEvidence["strategy"] = "nvd-cpe"
		return cpeScore, cpeEvidence
	}
	textEvidence["query"] = query
	textEvidence["strategy"] = "nvd-keyword"
	return textScore, textEvidence
}

func (c nvdCVE) hasVulnerableCPEs() bool {
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, match := range flattenCPEMatches(node) {
				if match.Vulnerable && strings.TrimSpace(match.Criteria) != "" {
					return true
				}
			}
		}
	}
	return false
}

func (c nvdCVE) cpeConfidence(tech db.VersionedTechnology, aliases TechnologyAliases) (int, map[string]any) {
	bestScore := 0
	best := map[string]any{}
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, match := range flattenCPEMatches(node) {
				if !match.Vulnerable {
					continue
				}
				parsed, ok := parseCPE23(match.Criteria)
				if !ok {
					continue
				}
				productText := normalizeText(parsed.Vendor + " " + parsed.Product)
				if !productMatchesTech(productText, tech.Name, aliases) {
					continue
				}
				score, relation := cpeVersionScore(tech.Version, parsed.Version, match)
				if score > bestScore {
					bestScore = score
					best = map[string]any{
						"criteria":       match.Criteria,
						"version_match":  relation,
						"cpe_vendor":     parsed.Vendor,
						"cpe_product":    parsed.Product,
						"cpe_version":    parsed.Version,
						"match_criteria": match.MatchCriteriaID,
					}
				}
			}
		}
	}
	bestScore = applyPassiveCPEGates(tech, c, bestScore, best)
	return bestScore, best
}

func flattenCPEMatches(node nvdNode) []nvdCPEMatch {
	out := append([]nvdCPEMatch{}, node.CPEMatch...)
	for _, child := range node.Nodes {
		out = append(out, flattenCPEMatches(child)...)
	}
	return out
}

type cpe23 struct {
	Vendor  string
	Product string
	Version string
}

func parseCPE23(criteria string) (cpe23, bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return cpe23{}, false
	}
	return cpe23{
		Vendor:  strings.ReplaceAll(parts[3], `\`, ""),
		Product: strings.ReplaceAll(parts[4], `\`, ""),
		Version: strings.ReplaceAll(parts[5], `\`, ""),
	}, true
}

func productMatchesTech(productText, techName string, aliases TechnologyAliases) bool {
	techText := normalizeText(techName)
	if techText == "" || productText == "" {
		return false
	}
	tokens := significantTokens(techName)
	if len(tokens) == 1 {
		if singleTokenProductMatch(productText, tokens[0]) {
			return true
		}
	} else if strings.Contains(productText, techText) || strings.Contains(techText, productText) {
		return true
	}
	for _, alias := range aliases.MatchAliases(techName) {
		if strings.Contains(productText, alias) {
			return true
		}
	}
	hits := 0
	for _, token := range tokens {
		if strings.Contains(productText, token) {
			hits++
		}
	}
	if len(tokens) <= 1 {
		return false
	}
	return hits >= 2
}

func singleTokenProductMatch(productText, token string) bool {
	productTokens := significantTokens(productText)
	if len(productTokens) == 0 {
		return false
	}
	if len(productTokens) > 2 {
		return false
	}
	for _, productToken := range productTokens {
		if productToken == token {
			return true
		}
	}
	return false
}

func applyPassiveCPEGates(tech db.VersionedTechnology, cve nvdCVE, score int, evidence map[string]any) int {
	if score < 80 {
		return score
	}
	if conditionalCVEText(firstEnglishDescription(cve.Descriptions)) {
		evidence["passive_gate"] = "conditional_configuration_or_module"
		return minInt(score, 75)
	}
	if majorOnlyVersion(tech.Version) && majorOnlySensitiveProduct(tech.Name) {
		evidence["passive_gate"] = "major_only_version"
		return minInt(score, 75)
	}
	return score
}

var conditionalCVERE = regexp.MustCompile(`(?i)(^|[^[:alnum:]_])(if|when|requires|required|configuration|configured|enabled|module|mod_|cgi|ssi|suexec|vcl|proxy protocol|tls termination|http/2)([^[:alnum:]_]|$)|built with`)

func conditionalCVEText(summary string) bool {
	return conditionalCVERE.MatchString(summary)
}

func majorOnlyVersion(version string) bool {
	return len(versionPartRE.FindAllString(version, -1)) == 1
}

func majorOnlySensitiveProduct(name string) bool {
	text := normalizeText(name)
	return text == "drupal" || text == "wordpress" || text == "joomla"
}

func cpeVersionScore(version, cpeVersion string, match nvdCPEMatch) (int, string) {
	version = strings.TrimSpace(version)
	cpeVersion = strings.TrimSpace(cpeVersion)
	if version == "" {
		return 55, "product-only"
	}
	if cpeVersion != "" && cpeVersion != "*" && cpeVersion != "-" {
		if equalVersion(version, cpeVersion) {
			return 95, "exact"
		}
		return 0, "different"
	}
	if ok, comparable := versionInRange(version, match); comparable {
		if ok {
			return 90, "range"
		}
		return 0, "outside-range"
	}
	return 65, "product-wildcard"
}

func textConfidence(tech db.VersionedTechnology, cve nvdCVE) (int, map[string]any) {
	summary := firstEnglishDescription(cve.Descriptions)
	raw, _ := json.Marshal(cve)
	text := normalizeText(summary + " " + string(raw))
	tokens := significantTokens(tech.Name)
	if weakTextFallbackTech(tokens) {
		return 0, map[string]any{"reason": "weak-keyword-only-technology"}
	}
	hits := []string{}
	for _, token := range tokens {
		if strings.Contains(text, token) {
			hits = append(hits, token)
		}
	}
	if len(hits) == 0 {
		return 0, map[string]any{"reason": "no-product-token"}
	}
	score := 35 + minInt(len(hits)*10, 25)
	versionRelation := "none"
	version := normalizeText(tech.Version)
	if version != "" && strings.Contains(text, version) {
		score += 30
		versionRelation = "exact-text"
	} else if majorMinor := majorMinorVersion(tech.Version); majorMinor != "" && strings.Contains(text, normalizeText(majorMinor)) {
		score += 15
		versionRelation = "major-minor-text"
	}
	if versionRelation == "none" && tech.Version != "" && score > 55 {
		score = 55
	}
	return score, map[string]any{
		"matched_tokens":  hits,
		"version_match":   versionRelation,
		"summary_excerpt": truncate(summary, 240),
	}
}

func weakTextFallbackTech(tokens []string) bool {
	if len(tokens) != 1 {
		return false
	}
	weak := map[string]struct{}{
		"iis":     {},
		"openssl": {},
		"apache":  {},
		"nginx":   {},
	}
	_, ok := weak[tokens[0]]
	return ok
}

func versionInRange(version string, match nvdCPEMatch) (bool, bool) {
	type bound struct {
		value     string
		inclusive bool
		isStart   bool
	}
	bounds := []bound{}
	if match.VersionStartIncluding != "" {
		bounds = append(bounds, bound{value: match.VersionStartIncluding, inclusive: true, isStart: true})
	}
	if match.VersionStartExcluding != "" {
		bounds = append(bounds, bound{value: match.VersionStartExcluding, inclusive: false, isStart: true})
	}
	if match.VersionEndIncluding != "" {
		bounds = append(bounds, bound{value: match.VersionEndIncluding, inclusive: true})
	}
	if match.VersionEndExcluding != "" {
		bounds = append(bounds, bound{value: match.VersionEndExcluding, inclusive: false})
	}
	if len(bounds) == 0 {
		return false, false
	}
	for _, b := range bounds {
		cmp, ok := compareVersions(version, b.value)
		if !ok {
			return false, false
		}
		if b.isStart {
			if cmp < 0 || (!b.inclusive && cmp == 0) {
				return false, true
			}
			continue
		}
		if cmp > 0 || (!b.inclusive && cmp == 0) {
			return false, true
		}
	}
	return true, true
}

func equalVersion(a, b string) bool {
	cmp, ok := compareVersions(a, b)
	if ok {
		return cmp == 0
	}
	return normalizeText(a) == normalizeText(b)
}

var versionPartRE = regexp.MustCompile(`\d+`)

func compareVersions(a, b string) (int, bool) {
	left := numericParts(a)
	right := numericParts(b)
	if len(left) == 0 || len(right) == 0 {
		return 0, false
	}
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		lv, rv := 0, 0
		if i < len(left) {
			lv = left[i]
		}
		if i < len(right) {
			rv = right[i]
		}
		if lv < rv {
			return -1, true
		}
		if lv > rv {
			return 1, true
		}
	}
	return 0, true
}

func numericParts(version string) []int {
	raw := versionPartRE.FindAllString(version, -1)
	out := make([]int, 0, len(raw))
	for _, part := range raw {
		n, err := strconv.Atoi(part)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

func majorMinorVersion(version string) string {
	parts := versionPartRE.FindAllString(version, -1)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func significantTokens(value string) []string {
	stop := map[string]struct{}{
		"app": {}, "cms": {}, "http": {}, "https": {}, "server": {}, "web": {},
	}
	raw := strings.Fields(normalizeText(value))
	out := []string{}
	seen := map[string]struct{}{}
	for _, token := range raw {
		if len(token) < 3 {
			continue
		}
		if _, ok := stop[token]; ok {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out
}

var nonWordRE = regexp.MustCompile(`[^a-z0-9.]+`)

func normalizeText(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	value = nonWordRE.ReplaceAllString(value, " ")
	return strings.Join(strings.Fields(value), " ")
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func firstEnglishDescription(descriptions []nvdDescription) string {
	for _, description := range descriptions {
		if description.Lang == "en" {
			return description.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
