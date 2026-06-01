package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
	"github.com/rafabd1/ZERO/internal/tools"
)

type HTTPXRunner struct {
	repo  *db.Repository
	bin   string
	limit int
}

type HTTPXResult struct {
	Hosts    int
	Services int
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

func (r *HTTPXRunner) Run(ctx context.Context) (HTTPXResult, error) {
	targets, err := r.repo.ListProbeTargets(ctx)
	if err != nil {
		return HTTPXResult{}, err
	}
	if r.limit > 0 && len(targets) > r.limit {
		targets = targets[:r.limit]
	}

	var input bytes.Buffer
	byHost := make(map[string][]db.ProbeTarget, len(targets))
	for _, target := range targets {
		fqdn, ok := sanitize.CanonicalDomain(target.FQDN)
		if !ok || !targetAllowsHost(target, fqdn) {
			continue
		}
		target.FQDN = fqdn
		if _, ok := byHost[fqdn]; !ok {
			input.WriteString(fqdn)
			input.WriteByte('\n')
		}
		byHost[fqdn] = append(byHost[fqdn], target)
	}

	result := HTTPXResult{Hosts: len(byHost)}
	args := []string{
		"-silent",
		"-json",
		"-tech-detect",
		"-status-code",
		"-title",
		"-web-server",
		"-favicon",
		"-tls-probe",
	}
	err = tools.RunLines(ctx, r.bin, args, bufio.NewReader(&input), func(line string) error {
		var parsed httpxLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			return fmt.Errorf("parse httpx json: %w", err)
		}
		services, err := parsed.toServices(byHost)
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
	return result, err
}

func (h httpxLine) toServices(byHost map[string][]db.ProbeTarget) ([]db.HTTPService, error) {
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
			ProgramID:    target.ProgramID,
			SubdomainID:  target.SubdomainID,
			URL:          h.URL,
			Scheme:       firstNonEmpty(h.Scheme, u.Scheme),
			Host:         host,
			Port:         port,
			StatusCode:   status,
			Title:        h.Title,
			Webserver:    h.Webserver,
			Technologies: h.Technologies,
			FaviconHash:  h.FaviconHash,
			TLS:          h.TLS,
			Raw:          raw,
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
