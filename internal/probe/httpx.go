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
	repo *db.Repository
	bin  string
}

type HTTPXResult struct {
	Hosts    int
	Services int
}

type httpxLine struct {
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

func (r *HTTPXRunner) Run(ctx context.Context) (HTTPXResult, error) {
	subdomains, err := r.repo.ListSubdomains(ctx)
	if err != nil {
		return HTTPXResult{}, err
	}

	var input bytes.Buffer
	for _, sub := range subdomains {
		fqdn, ok := sanitize.CanonicalDomain(sub.FQDN)
		if !ok || !sanitize.IsWithinRoot(fqdn, sub.RootDomain) {
			continue
		}
		input.WriteString(fqdn)
		input.WriteByte('\n')
	}

	byHost := make(map[string]db.Subdomain, len(subdomains))
	for _, sub := range subdomains {
		fqdn, ok := sanitize.CanonicalDomain(sub.FQDN)
		if !ok || !sanitize.IsWithinRoot(fqdn, sub.RootDomain) {
			continue
		}
		sub.FQDN = fqdn
		byHost[fqdn] = sub
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
		service, err := parsed.toService(byHost)
		if err != nil {
			return err
		}
		_, err = r.repo.UpsertHTTPService(ctx, service)
		if err != nil {
			return err
		}
		result.Services++
		return nil
	})
	return result, err
}

func (h httpxLine) toService(byHost map[string]db.Subdomain) (db.HTTPService, error) {
	if h.URL == "" {
		return db.HTTPService{}, fmt.Errorf("httpx output without url")
	}
	u, err := url.Parse(h.URL)
	if err != nil {
		return db.HTTPService{}, err
	}
	host, ok := sanitize.CanonicalDomain(u.Hostname())
	if !ok {
		return db.HTTPService{}, fmt.Errorf("httpx output host %q is not a valid domain", u.Hostname())
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
	sub, ok := byHost[host]
	if !ok || sub.ProgramID == "" {
		return db.HTTPService{}, fmt.Errorf("httpx output host %q is not linked to a known program", host)
	}
	return db.HTTPService{
		ProgramID:    sub.ProgramID,
		SubdomainID:  sub.ID,
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
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
