package probe

import (
	"sort"
	"strings"
	"unicode"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
)

type hostBudgetPolicy struct {
	MinGroup  int
	Cap       int
	FamilyCap int
}

type hostBudgetResult struct {
	Hosts            []string
	Skipped          int
	PriorityKept     int
	BudgetedRoot     int
	BudgetedFamilies int
}

func applyHostBudget(hosts []string, byHost map[string][]db.ProbeTarget, policy hostBudgetPolicy) hostBudgetResult {
	out := hostBudgetResult{Hosts: append([]string(nil), hosts...)}
	if policy.MinGroup <= 0 || policy.Cap <= 0 || len(hosts) == 0 {
		sort.Strings(out.Hosts)
		return out
	}

	byRoot := map[string][]string{}
	for _, host := range hosts {
		root := hostBudgetRoot(host, byHost[host])
		byRoot[root] = append(byRoot[root], host)
	}

	kept := make([]string, 0, len(hosts))
	for root, group := range byRoot {
		sort.Strings(group)
		if root == "" || len(group) < policy.MinGroup {
			kept = append(kept, group...)
			continue
		}
		if !hostBudgetLooksMassive(root, group, byHost) {
			kept = append(kept, group...)
			continue
		}
		out.BudgetedRoot++
		tenantKept := 0
		for _, host := range group {
			if hostBudgetAlwaysKeep(host, root, byHost[host]) {
				kept = append(kept, host)
				out.PriorityKept++
				continue
			}
			if tenantKept < policy.Cap {
				kept = append(kept, host)
				tenantKept++
				continue
			}
			out.Skipped++
		}
	}
	sort.Strings(kept)
	out.Hosts = kept
	if policy.FamilyCap > 0 {
		out.applyFamilyBudget(byHost, policy.FamilyCap)
	}
	return out
}

func (r *hostBudgetResult) applyFamilyBudget(byHost map[string][]db.ProbeTarget, familyCap int) {
	if familyCap <= 0 || len(r.Hosts) == 0 {
		return
	}
	byFamily := map[string][]string{}
	passThrough := []string{}
	for _, host := range r.Hosts {
		signature := hostFamilySignature(host, byHost[host])
		if signature == "" {
			passThrough = append(passThrough, host)
			continue
		}
		byFamily[signature] = append(byFamily[signature], host)
	}
	kept := append([]string{}, passThrough...)
	for _, group := range byFamily {
		sort.Slice(group, func(i, j int) bool {
			return hostFamilyRank(group[i], byHost[group[i]]) < hostFamilyRank(group[j], byHost[group[j]])
		})
		if len(group) <= familyBudgetThreshold(familyCap) {
			kept = append(kept, group...)
			continue
		}
		r.BudgetedFamilies++
		tenantKept := 0
		for _, host := range group {
			root := hostBudgetRoot(host, byHost[host])
			if hostBudgetAlwaysKeep(host, root, byHost[host]) {
				kept = append(kept, host)
				r.PriorityKept++
				continue
			}
			if tenantKept < familyCap {
				kept = append(kept, host)
				tenantKept++
				continue
			}
			r.Skipped++
		}
	}
	sort.Strings(kept)
	r.Hosts = kept
}

func familyBudgetThreshold(familyCap int) int {
	if familyCap < 4 {
		return familyCap + 2
	}
	return familyCap * 2
}

func hostBudgetLooksMassive(root string, group []string, byHost map[string][]db.ProbeTarget) bool {
	if len(group) >= 1000 {
		return true
	}
	tenantLike := 0
	plainTenant := 0
	for _, host := range group {
		if hostBudgetAlwaysKeep(host, root, byHost[host]) {
			continue
		}
		if tenantLikeHostLabel(host, root) {
			tenantLike++
		}
		if oneLabelUnderRoot(host, root) {
			plainTenant++
		}
	}
	if len(group) >= 500 && plainTenant*100/len(group) >= 70 {
		return true
	}
	return tenantLike >= 80 && tenantLike*100/len(group) >= 35
}

func hostBudgetRoot(host string, targets []db.ProbeTarget) string {
	for _, target := range targets {
		root, ok := sanitize.CanonicalDomain(target.RootDomain)
		if ok && root != "" {
			return root
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func hostFamilySignature(host string, targets []db.ProbeTarget) string {
	root := hostBudgetRoot(host, targets)
	if root == "" {
		return ""
	}
	left := strings.TrimSuffix(host, "."+root)
	left = strings.Trim(left, ".")
	if left == "" {
		return ""
	}
	rootLabels := strings.Split(root, ".")
	if len(rootLabels) == 0 {
		return ""
	}
	programID := ""
	if len(targets) > 0 {
		programID = targets[0].ProgramID
	}
	brand := rootLabels[0]
	labels := strings.Split(left, ".")
	normalized := make([]string, 0, len(labels))
	changed := false
	for _, label := range labels {
		next := normalizeFamilyLabel(label)
		if next != label {
			changed = true
		}
		normalized = append(normalized, next)
	}
	if !changed && !rootLooksLocaleVariant(root) && !leftLooksReplicatedFamily(labels) {
		return ""
	}
	return programID + "\x00" + strings.Join(normalized, ".") + "." + brand
}

func leftLooksReplicatedFamily(labels []string) bool {
	if len(labels) == 0 || len(labels) > 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || priorityHostLabel(label) {
			return false
		}
	}
	return true
}

func normalizeFamilyLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return label
	}
	if isLocaleLabel(label) {
		return "{locale}"
	}
	parts := strings.FieldsFunc(label, func(r rune) bool {
		return r == '-' || r == '_'
	})
	if len(parts) <= 1 {
		if looksNumericOrGenerated(label) {
			return "{id}"
		}
		return label
	}
	changed := false
	for i, part := range parts {
		switch {
		case isLocaleLabel(part):
			parts[i] = "{locale}"
			changed = true
		case looksNumericOrGenerated(part):
			parts[i] = "{id}"
			changed = true
		}
	}
	if !changed {
		return label
	}
	return strings.Join(parts, "-")
}

func isLocaleLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if len(label) == 2 && allLetters(label) {
		return true
	}
	parts := strings.FieldsFunc(label, func(r rune) bool {
		return r == '-' || r == '_'
	})
	if len(parts) == 2 && len(parts[0]) == 2 && len(parts[1]) == 2 && allLetters(parts[0]) && allLetters(parts[1]) {
		return true
	}
	return false
}

func looksNumericOrGenerated(label string) bool {
	if label == "" {
		return false
	}
	digits := 0
	hex := 0
	for _, r := range label {
		if unicode.IsDigit(r) {
			digits++
		}
		if unicode.IsDigit(r) || (r >= 'a' && r <= 'f') {
			hex++
		}
	}
	if digits > 0 && digits*100/len(label) >= 30 {
		return true
	}
	return len(label) >= 16 && hex == len(label)
}

func rootLooksLocaleVariant(root string) bool {
	labels := strings.Split(root, ".")
	if len(labels) < 2 {
		return false
	}
	if len(labels[len(labels)-1]) == 2 && allLetters(labels[len(labels)-1]) {
		return true
	}
	if len(labels) >= 3 && len(labels[len(labels)-2]) == 2 && allLetters(labels[len(labels)-2]) {
		return true
	}
	return false
}

func hostFamilyRank(host string, targets []db.ProbeTarget) int {
	root := hostBudgetRoot(host, targets)
	rank := len(host)
	if strings.HasSuffix(root, ".com") {
		rank -= 1000
	}
	if strings.HasPrefix(host, "www.") {
		rank -= 100
	}
	return rank
}

func allLetters(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func hostBudgetAlwaysKeep(host, root string, targets []db.ProbeTarget) bool {
	for _, target := range targets {
		if target.MatchMode == db.ProbeMatchExact && strings.HasPrefix(target.Source, "scope:") {
			return true
		}
	}
	left := strings.TrimSuffix(host, "."+root)
	left = strings.Trim(left, ".")
	if left == "" {
		return true
	}
	labels := strings.Split(left, ".")
	for _, label := range labels {
		if priorityHostLabel(label) {
			return true
		}
	}
	if len(labels) >= 3 {
		return true
	}
	return false
}

func tenantLikeHostLabel(host, root string) bool {
	left := strings.TrimSuffix(host, "."+root)
	left = strings.Trim(left, ".")
	if left == "" {
		return false
	}
	label := strings.Split(left, ".")[0]
	if len(label) <= 2 {
		return true
	}
	digits := 0
	letters := 0
	other := 0
	for _, r := range label {
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsLetter(r):
			letters++
		default:
			other++
		}
	}
	if digits > 0 && digits*100/len(label) >= 25 {
		return true
	}
	if len(label) >= 24 && digits > 0 && letters > 0 {
		return true
	}
	if len(label) >= 12 && other > 0 && digits > 0 {
		return true
	}
	return false
}

func oneLabelUnderRoot(host, root string) bool {
	left := strings.TrimSuffix(host, "."+root)
	left = strings.Trim(left, ".")
	return left != "" && !strings.Contains(left, ".")
}

func priorityHostLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return false
	}
	priorityTokens := []string{
		"api", "admin", "auth", "oauth", "oidc", "saml", "sso", "login", "account",
		"payment", "pay", "checkout", "billing", "wallet", "secure", "security",
		"app", "portal", "console", "dashboard", "developer", "dev", "docs", "doc",
		"staging", "stage", "test", "testing", "qa", "uat", "preprod", "prod",
		"vpn", "jira", "jenkins", "grafana", "kibana", "status", "support",
		"cdn", "static", "assets", "upload", "uploads", "files", "mail", "mx",
		"mobile", "internal", "corp", "idp",
	}
	parts := splitHostLabel(label)
	for _, part := range parts {
		for _, token := range priorityTokens {
			if part == token {
				return true
			}
		}
	}
	return false
}

func splitHostLabel(label string) []string {
	fields := strings.FieldsFunc(label, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimFunc(field, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}
