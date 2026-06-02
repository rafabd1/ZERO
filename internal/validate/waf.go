package validate

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/tools"
)

type WAFDiagnostic struct {
	Enabled           bool     `json:"enabled"`
	Suspected         bool     `json:"suspected"`
	Confidence        int      `json:"confidence"`
	Reason            string   `json:"reason,omitempty"`
	Reasons           []string `json:"reasons,omitempty"`
	SampleSize        int      `json:"sample_size"`
	BaselineBlocked   int      `json:"baseline_blocked"`
	PostBlocked       int      `json:"post_blocked"`
	BaselineWAFLike   int      `json:"baseline_waf_like"`
	PostWAFLike       int      `json:"post_waf_like"`
	ProbeErrors       int      `json:"probe_errors"`
	NucleiHadError    bool     `json:"nuclei_had_error"`
	NucleiTimedOut    bool     `json:"nuclei_timed_out"`
	NucleiHadResults  bool     `json:"nuclei_had_results"`
	Indicators        []string `json:"indicators,omitempty"`
	SampledURLPreview []string `json:"sampled_url_preview,omitempty"`
}

type wafProbeResult struct {
	blocked    int
	wafLike    int
	errors     int
	indicators map[string]struct{}
}

type wafBaseline struct {
	diag     WAFDiagnostic
	sample   []db.NucleiTarget
	headers  []string
	timeout  time.Duration
	baseline wafProbeResult
}

func startWAFDiagnostic(ctx context.Context, targets []db.NucleiTarget, headers []string, sampleSize, timeoutSeconds int) wafBaseline {
	diag := WAFDiagnostic{
		Enabled: true,
	}
	sample := sampleWAFProbeTargets(targets, sampleSize)
	diag.SampleSize = len(sample)
	for _, target := range sample {
		if len(diag.SampledURLPreview) >= 3 {
			break
		}
		diag.SampledURLPreview = append(diag.SampledURLPreview, target.URL)
	}
	if len(sample) == 0 {
		diag.Reason = "no_sample_targets"
		return wafBaseline{diag: diag, headers: normalizeHeaders(headers)}
	}

	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := wafHTTPClient(timeout)
	return wafBaseline{
		diag:     diag,
		sample:   sample,
		headers:  normalizeHeaders(headers),
		timeout:  timeout,
		baseline: probeWAFSample(ctx, client, sample, headers),
	}
}

func finishWAFDiagnostic(ctx context.Context, baseline wafBaseline, nucleiErr error, nucleiResults int) WAFDiagnostic {
	diag := baseline.diag
	diag.NucleiHadError = nucleiErr != nil
	diag.NucleiTimedOut = tools.IsTimeout(nucleiErr)
	diag.NucleiHadResults = nucleiResults > 0
	if !diag.Enabled || len(baseline.sample) == 0 {
		return diag
	}

	timeout := baseline.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := wafHTTPClient(timeout)
	post := probeWAFSample(ctx, client, baseline.sample, baseline.headers)

	diag.BaselineBlocked = baseline.baseline.blocked
	diag.PostBlocked = post.blocked
	diag.BaselineWAFLike = baseline.baseline.wafLike
	diag.PostWAFLike = post.wafLike
	diag.ProbeErrors = baseline.baseline.errors + post.errors
	diag.Indicators = sortedIndicators(baseline.baseline.indicators, post.indicators)
	diag.Reasons, diag.Confidence = wafReasonsAndConfidence(diag)
	if len(diag.Reasons) > 0 {
		diag.Suspected = true
		diag.Reason = diag.Reasons[0]
	}
	return diag
}

func sampleWAFProbeTargets(targets []db.NucleiTarget, sampleSize int) []db.NucleiTarget {
	if sampleSize <= 0 || sampleSize > 50 {
		sampleSize = 8
	}
	out := []db.NucleiTarget{}
	seenHosts := map[string]struct{}{}
	for _, target := range targets {
		host := hostKey(target.URL)
		if host == "" {
			continue
		}
		if _, ok := seenHosts[host]; ok {
			continue
		}
		seenHosts[host] = struct{}{}
		out = append(out, target)
		if len(out) >= sampleSize {
			return out
		}
	}
	for _, target := range targets {
		if len(out) >= sampleSize {
			break
		}
		out = append(out, target)
	}
	return out
}

func wafHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func probeWAFSample(ctx context.Context, client *http.Client, sample []db.NucleiTarget, headers []string) wafProbeResult {
	result := wafProbeResult{indicators: map[string]struct{}{}}
	for _, target := range sample {
		blocked, wafLike, indicators, err := probeWAFURL(ctx, client, target.URL, headers)
		if err != nil {
			result.errors++
			continue
		}
		if blocked {
			result.blocked++
		}
		if wafLike {
			result.wafLike++
		}
		for _, indicator := range indicators {
			result.indicators[indicator] = struct{}{}
		}
	}
	return result
}

func probeWAFURL(ctx context.Context, client *http.Client, targetURL string, headers []string) (bool, bool, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false, false, nil, err
	}
	for _, header := range normalizeHeaders(headers) {
		name, value, _ := strings.Cut(header, ":")
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, false, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	blocked, wafLike, indicators := classifyWAFResponse(resp.StatusCode, resp.Header, string(body))
	return blocked, wafLike, indicators, nil
}

func classifyWAFResponse(status int, headers http.Header, body string) (blocked bool, wafLike bool, indicators []string) {
	lowerBody := strings.ToLower(body)
	switch status {
	case 403, 406, 407, 408, 409, 429, 451, 503:
		blocked = true
		indicators = append(indicators, fmt.Sprintf("status_%d", status))
	}
	for name, values := range headers {
		lowerName := strings.ToLower(name)
		joined := strings.ToLower(strings.Join(values, " "))
		switch {
		case lowerName == "cf-ray":
			wafLike = true
			indicators = append(indicators, "cloudflare_header")
		case strings.Contains(lowerName, "datadome") || strings.Contains(joined, "datadome"):
			wafLike = true
			indicators = append(indicators, "datadome_header")
		case strings.Contains(lowerName, "sucuri") || strings.Contains(joined, "sucuri"):
			wafLike = true
			indicators = append(indicators, "sucuri_header")
		case strings.Contains(lowerName, "incap") || strings.Contains(joined, "incap_ses") || lowerName == "x-iinfo":
			wafLike = true
			indicators = append(indicators, "imperva_header")
		case strings.Contains(joined, "akamai") || strings.Contains(joined, "ak_bmsc") || strings.Contains(joined, "bm_sv"):
			wafLike = true
			indicators = append(indicators, "akamai_header")
		}
	}
	for _, pattern := range []struct {
		needle    string
		indicator string
	}{
		{"access denied", "access_denied_body"},
		{"request blocked", "request_blocked_body"},
		{"attention required", "attention_required_body"},
		{"checking your browser", "browser_check_body"},
		{"captcha", "captcha_body"},
		{"cloudflare", "cloudflare_body"},
		{"akamai", "akamai_body"},
		{"imperva", "imperva_body"},
		{"incapsula", "imperva_body"},
		{"datadome", "datadome_body"},
		{"perimeterx", "perimeterx_body"},
		{"sucuri", "sucuri_body"},
		{"bot protection", "bot_protection_body"},
		{"temporarily blocked", "temporarily_blocked_body"},
	} {
		if strings.Contains(lowerBody, pattern.needle) {
			wafLike = true
			indicators = append(indicators, pattern.indicator)
		}
	}
	if blocked && wafLike {
		return true, true, cleanStrings(indicators)
	}
	if wafLike && (status >= 400 || status == 0) {
		return true, true, cleanStrings(indicators)
	}
	return blocked, wafLike, cleanStrings(indicators)
}

func wafReasonsAndConfidence(diag WAFDiagnostic) ([]string, int) {
	reasons := []string{}
	confidence := 0
	if diag.PostBlocked > diag.BaselineBlocked {
		reasons = append(reasons, "post_scan_blocking_increased")
		confidence = maxInt(confidence, 85)
	}
	if diag.PostWAFLike > diag.BaselineWAFLike {
		reasons = append(reasons, "post_scan_waf_indicators_increased")
		confidence = maxInt(confidence, 80)
	}
	if diag.NucleiTimedOut && diag.PostBlocked > 0 {
		reasons = append(reasons, "nuclei_timeout_with_blocked_probe")
		confidence = maxInt(confidence, 75)
	}
	if diag.NucleiHadError && diag.PostWAFLike > 0 {
		reasons = append(reasons, "nuclei_error_with_waf_indicators")
		confidence = maxInt(confidence, 70)
	}
	if !diag.NucleiHadResults && diag.PostBlocked >= majority(diag.SampleSize) && diag.PostWAFLike > 0 {
		reasons = append(reasons, "no_nuclei_results_with_waf_like_responses")
		confidence = maxInt(confidence, 65)
	}
	if !diag.NucleiHadResults && diag.BaselineBlocked >= majority(diag.SampleSize) && diag.BaselineWAFLike > 0 {
		reasons = append(reasons, "baseline_waf_like_responses")
		confidence = maxInt(confidence, 55)
	}
	return cleanStrings(reasons), confidence
}

func majority(total int) int {
	if total <= 0 {
		return 1
	}
	return total/2 + 1
}

func sortedIndicators(groups ...map[string]struct{}) []string {
	seen := map[string]struct{}{}
	for _, group := range groups {
		for indicator := range group {
			seen[indicator] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for indicator := range seen {
		out = append(out, indicator)
	}
	sort.Strings(out)
	return out
}

func hostKey(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if before, _, ok := strings.Cut(rawURL, "://"); ok && before != "" {
		rawURL = strings.TrimPrefix(rawURL, before+"://")
	}
	host := strings.Split(rawURL, "/")[0]
	host = strings.Split(host, ":")[0]
	return strings.ToLower(strings.TrimSpace(host))
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
