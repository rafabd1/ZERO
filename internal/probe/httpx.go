package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
	"github.com/rafabd1/ZERO/internal/tools"
)

type HTTPXRunner struct {
	repo       *db.Repository
	bin        string
	scanRunID  string
	programID  string
	limit      int
	timeout    time.Duration
	reqTimeout int
	threads    int
	batchSize  int
	batchTO    time.Duration
	patternMin int
	patternCap int
	tlsProbe   bool
}

type HTTPXResult struct {
	Hosts            int
	Services         int
	Deactivated      int
	SkippedByPattern int
	PriorityKept     int
	BudgetedRoots    int
}

type httpxLine struct {
	Input        string          `json:"input"`
	URL          string          `json:"url"`
	Scheme       string          `json:"scheme"`
	Host         string          `json:"host"`
	Port         string          `json:"port"`
	StatusCode   int             `json:"status_code"`
	Title        string          `json:"title"`
	Webserver    string          `json:"webserver"`
	Technologies []string        `json:"tech"`
	FaviconHash  string          `json:"favicon_hash"`
	TLS          json.RawMessage `json:"tls"`
}

func NewHTTPXRunner(repo *db.Repository, bin string) *HTTPXRunner {
	if bin == "" {
		bin = "httpx"
	}
	return &HTTPXRunner{repo: repo, bin: bin}
}

func (r *HTTPXRunner) WithLimit(limit int) *HTTPXRunner {
	r.limit = limit
	return r
}

func (r *HTTPXRunner) WithTimeout(timeout time.Duration) *HTTPXRunner {
	if timeout > 0 {
		r.timeout = timeout
	}
	return r
}

func (r *HTTPXRunner) WithRequestPolicy(reqTimeout, threads int) *HTTPXRunner {
	if reqTimeout > 0 {
		r.reqTimeout = reqTimeout
	}
	if threads > 0 {
		r.threads = threads
	}
	return r
}

func (r *HTTPXRunner) WithBatchSize(batchSize int) *HTTPXRunner {
	if batchSize > 0 {
		r.batchSize = batchSize
	}
	return r
}

func (r *HTTPXRunner) WithBatchTimeout(timeout time.Duration) *HTTPXRunner {
	if timeout > 0 {
		r.batchTO = timeout
	}
	return r
}

func (r *HTTPXRunner) WithPatternBudget(minGroup, cap int) *HTTPXRunner {
	r.patternMin = minGroup
	r.patternCap = cap
	return r
}

func (r *HTTPXRunner) WithTLSProbe(enabled bool) *HTTPXRunner {
	r.tlsProbe = enabled
	return r
}

func (r *HTTPXRunner) WithProgramID(programID string) *HTTPXRunner {
	r.programID = programID
	return r
}

func (r *HTTPXRunner) WithScanRunID(scanRunID string) *HTTPXRunner {
	r.scanRunID = scanRunID
	return r
}

func (r *HTTPXRunner) Run(ctx context.Context) (HTTPXResult, error) {
	targets, err := r.repo.ListProbeTargets(ctx, r.programID)
	if err != nil {
		return HTTPXResult{}, err
	}

	byHost := make(map[string][]db.ProbeTarget, len(targets))
	hosts := make([]string, 0, len(targets))
	for _, target := range targets {
		fqdn, ok := sanitize.CanonicalDomain(target.FQDN)
		if !ok || !targetAllowsHost(target, fqdn) {
			continue
		}
		target.FQDN = fqdn
		if _, ok := byHost[fqdn]; !ok {
			hosts = append(hosts, fqdn)
		}
		byHost[fqdn] = append(byHost[fqdn], target)
	}

	budgeted := applyHostBudget(hosts, byHost, hostBudgetPolicy{
		MinGroup: r.patternMin,
		Cap:      r.patternCap,
	})
	hosts = budgeted.Hosts
	if r.limit > 0 && len(hosts) > r.limit {
		budgeted.Skipped += len(hosts) - r.limit
		hosts = hosts[:r.limit]
	}
	result := HTTPXResult{
		Hosts:            len(hosts),
		SkippedByPattern: budgeted.Skipped,
		PriorityKept:     budgeted.PriorityKept,
		BudgetedRoots:    budgeted.BudgetedRoot,
	}
	args := buildHTTPXArgs(r.reqTimeout, r.threads, r.tlsProbe)
	batchSize := r.batchSize
	if batchSize <= 0 {
		batchSize = len(hosts)
	}
	batchTimeout := r.timeout
	if r.batchTO > 0 && (batchTimeout <= 0 || r.batchTO < batchTimeout) {
		batchTimeout = r.batchTO
	}
	for start := 0; start < len(hosts); start += batchSize {
		end := start + batchSize
		if end > len(hosts) {
			end = len(hosts)
		}
		if err := r.runBatch(ctx, batchTimeout, args, hosts[start:end], byHost, &result); err != nil {
			return result, err
		}
	}
	if r.scanRunID != "" && r.limit <= 0 {
		deactivated, err := r.deactivateMissingServices(ctx, hosts, byHost)
		if err != nil {
			return result, err
		}
		result.Deactivated = deactivated
	}
	return result, nil
}

func (r *HTTPXRunner) deactivateMissingServices(ctx context.Context, hosts []string, byHost map[string][]db.ProbeTarget) (int, error) {
	hostsByProgram := map[string]map[string]struct{}{}
	for _, host := range hosts {
		for _, target := range byHost[host] {
			if target.ProgramID == "" {
				continue
			}
			if _, ok := hostsByProgram[target.ProgramID]; !ok {
				hostsByProgram[target.ProgramID] = map[string]struct{}{}
			}
			hostsByProgram[target.ProgramID][host] = struct{}{}
		}
	}
	total := 0
	for programID, hostSet := range hostsByProgram {
		programHosts := make([]string, 0, len(hostSet))
		for host := range hostSet {
			programHosts = append(programHosts, host)
		}
		count, err := r.repo.MarkMissingHTTPServicesInactiveForHosts(ctx, programID, r.scanRunID, programHosts)
		if err != nil {
			return total, err
		}
		total += count
	}
	return total, nil
}

func (r *HTTPXRunner) runBatch(ctx context.Context, timeout time.Duration, args []string, hosts []string, byHost map[string][]db.ProbeTarget, result *HTTPXResult) error {
	var input bytes.Buffer
	for _, host := range hosts {
		input.WriteString(host)
		input.WriteByte('\n')
	}
	return tools.RunLinesWithTimeout(ctx, timeout, r.bin, args, bufio.NewReader(&input), func(line string) error {
		var parsed httpxLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			return fmt.Errorf("parse httpx json: %w", err)
		}
		services, err := parsed.toServices(byHost, r.scanRunID)
		if err != nil {
			return err
		}
		for _, service := range services {
			_, err = r.repo.UpsertHTTPService(ctx, service)
			if err != nil {
				return err
			}
			result.Services++
		}
		return nil
	})
}

func buildHTTPXArgs(reqTimeout, threads int, tlsProbe bool) []string {
	args := []string{
		"-silent",
		"-json",
		"-tech-detect",
		"-status-code",
		"-title",
		"-web-server",
		"-favicon",
	}
	if tlsProbe {
		args = append(args, "-tls-probe")
	}
	if reqTimeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(reqTimeout))
	}
	if threads > 0 {
		args = append(args, "-threads", strconv.Itoa(threads))
	}
	return args
}

func (h httpxLine) toServices(byHost map[string][]db.ProbeTarget, scanRunID string) ([]db.HTTPService, error) {
	if h.URL == "" {
		return nil, fmt.Errorf("httpx output without url")
	}
	u, err := url.Parse(h.URL)
	if err != nil {
		return nil, err
	}
	host, ok := sanitize.CanonicalDomain(u.Hostname())
	if !ok {
		return nil, nil
	}
	var port *int
	if h.Port != "" {
		if p, err := strconv.Atoi(h.Port); err == nil {
			port = &p
		}
	}
	var status *int
	if h.StatusCode != 0 {
		status = &h.StatusCode
	}
	raw, _ := json.Marshal(h)
	candidates := append([]db.ProbeTarget{}, byHost[host]...)
	if h.Input != "" {
		inputHost, inputOK := sanitize.CanonicalDomain(h.Input)
		if inputOK && inputHost != host {
			candidates = append(candidates, byHost[inputHost]...)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	services := make([]db.HTTPService, 0, len(candidates))
	seen := map[string]bool{}
	for _, target := range candidates {
		if target.ProgramID == "" || !targetAllowsHost(target, host) {
			continue
		}
		key := target.ProgramID + "\x00" + target.SubdomainID + "\x00" + h.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		services = append(services, db.HTTPService{
			ProgramID:     target.ProgramID,
			SubdomainID:   target.SubdomainID,
			LastScanRunID: scanRunID,
			URL:           h.URL,
			Scheme:        firstNonEmpty(h.Scheme, u.Scheme),
			Host:          host,
			Port:          port,
			StatusCode:    status,
			Title:         h.Title,
			Webserver:     h.Webserver,
			Technologies:  h.Technologies,
			FaviconHash:   h.FaviconHash,
			TLS:           h.TLS,
			Raw:           raw,
		})
	}
	return services, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func targetAllowsHost(target db.ProbeTarget, host string) bool {
	switch target.MatchMode {
	case db.ProbeMatchWildcard:
		return sanitize.MatchesWildcard(host, target.RootDomain)
	case db.ProbeMatchExact:
		root, ok := sanitize.CanonicalDomain(target.RootDomain)
		return ok && host == root
	default:
		return false
	}
}
