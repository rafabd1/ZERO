package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
	"github.com/rafabd1/ZERO/internal/tools"
)

type DNSXRunner struct {
	repo      *db.Repository
	bin       string
	resolvers string
	rate      int
	batchSize int
	batchTO   time.Duration
	scanRunID string
	programID string
	limit     int
	timeout   time.Duration
}

type DNSXResult struct {
	Hosts    int
	Resolved int
	Updated  int
}

type dnsxLine struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
}

func NewDNSXRunner(repo *db.Repository, bin string) *DNSXRunner {
	if bin == "" {
		bin = "dnsx"
	}
	return &DNSXRunner{repo: repo, bin: bin, rate: 200}
}

func (r *DNSXRunner) WithResolvers(resolvers string) *DNSXRunner {
	r.resolvers = strings.TrimSpace(resolvers)
	return r
}

func (r *DNSXRunner) WithRate(rate int) *DNSXRunner {
	if rate > 0 {
		r.rate = rate
	}
	return r
}

func (r *DNSXRunner) WithBatchSize(batchSize int) *DNSXRunner {
	if batchSize > 0 {
		r.batchSize = batchSize
	}
	return r
}

func (r *DNSXRunner) WithBatchTimeout(timeout time.Duration) *DNSXRunner {
	if timeout > 0 {
		r.batchTO = timeout
	}
	return r
}

func (r *DNSXRunner) WithLimit(limit int) *DNSXRunner {
	r.limit = limit
	return r
}

func (r *DNSXRunner) WithTimeout(timeout time.Duration) *DNSXRunner {
	if timeout > 0 {
		r.timeout = timeout
	}
	return r
}

func (r *DNSXRunner) WithProgramID(programID string) *DNSXRunner {
	r.programID = strings.TrimSpace(programID)
	return r
}

func (r *DNSXRunner) WithScanRunID(scanRunID string) *DNSXRunner {
	r.scanRunID = strings.TrimSpace(scanRunID)
	return r
}

func (r *DNSXRunner) Run(ctx context.Context) (DNSXResult, error) {
	targets, err := r.repo.ListDNSValidationTargets(ctx, r.programID, r.limit)
	if err != nil {
		return DNSXResult{}, err
	}
	known := map[string]db.Subdomain{}
	byProgram := map[string]map[string]bool{}
	hosts := []string{}
	for _, target := range targets {
		fqdn, ok := sanitize.CanonicalDomain(target.FQDN)
		if !ok {
			continue
		}
		target.FQDN = fqdn
		key := target.ProgramID + "\x00" + fqdn
		if _, ok := known[key]; ok {
			continue
		}
		known[key] = target
		if _, ok := byProgram[target.ProgramID]; !ok {
			byProgram[target.ProgramID] = map[string]bool{}
		}
		byProgram[target.ProgramID][fqdn] = false
		hosts = append(hosts, fqdn)
	}
	result := DNSXResult{Hosts: len(known)}
	if result.Hosts == 0 {
		return result, nil
	}

	args := []string{"-silent", "-json", "-a", "-aaaa", "-cname", "-rl", strconv.Itoa(r.rate)}
	if r.resolvers != "" {
		args = append(args, "-r", r.resolvers)
	}
	batchSize := r.batchSize
	if batchSize <= 0 {
		batchSize = len(hosts)
	}
	batchTimeout := r.timeout
	if r.batchTO > 0 {
		batchTimeout = r.batchTO
	}
	for start := 0; start < len(hosts); start += batchSize {
		end := start + batchSize
		if end > len(hosts) {
			end = len(hosts)
		}
		if err := r.runBatch(ctx, batchTimeout, args, hosts[start:end], known, byProgram, &result); err != nil {
			return result, err
		}
	}
	for programID, resolved := range byProgram {
		updated, err := r.repo.UpdateSubdomainResolution(ctx, programID, resolved, r.scanRunID)
		if err != nil {
			return result, err
		}
		result.Updated += updated
	}
	return result, nil
}

func (r *DNSXRunner) runBatch(ctx context.Context, timeout time.Duration, args []string, hosts []string, known map[string]db.Subdomain, byProgram map[string]map[string]bool, result *DNSXResult) error {
	var input bytes.Buffer
	for _, host := range hosts {
		input.WriteString(host)
		input.WriteByte('\n')
	}
	return tools.RunLinesWithTimeout(ctx, timeout, r.bin, args, bufio.NewReader(&input), func(line string) error {
		var parsed dnsxLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			return fmt.Errorf("parse dnsx json: %w", err)
		}
		fqdn, ok := sanitize.CanonicalDomain(parsed.Host)
		if !ok {
			return nil
		}
		resolved := len(parsed.A) > 0 || len(parsed.AAAA) > 0 || len(parsed.CNAME) > 0
		for _, target := range known {
			if target.FQDN == fqdn {
				byProgram[target.ProgramID][fqdn] = resolved
			}
		}
		if resolved {
			result.Resolved++
		}
		return nil
	})
}
