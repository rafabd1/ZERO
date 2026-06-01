package sanitize

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func DomainFromScopeTarget(raw string) (string, bool) {
	host := strings.TrimSpace(strings.ToLower(raw))
	if host == "" {
		return "", false
	}

	host = strings.TrimPrefix(host, "*.")
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return "", false
		}
		host = parsed.Hostname()
	} else {
		host = strings.Split(host, "/")[0]
		host = strings.Split(host, ":")[0]
	}

	return CanonicalDomain(host)
}

func CanonicalDomain(raw string) (string, bool) {
	host := strings.TrimSpace(strings.ToLower(raw))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, "/\\") {
		return "", false
	}
	if strings.Contains(host, "*") || strings.Contains(host, "_") {
		return "", false
	}
	if net.ParseIP(host) != nil {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
		return "", false
	}
	return ascii, true
}

func IsWithinRoot(domain, root string) bool {
	d, ok := CanonicalDomain(domain)
	if !ok {
		return false
	}
	r, ok := CanonicalDomain(root)
	if !ok {
		return false
	}
	return d == r || strings.HasSuffix(d, "."+r)
}

func WildcardRegex(root string) (*regexp.Regexp, bool) {
	r, ok := CanonicalDomain(root)
	if !ok {
		return nil, false
	}
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	pattern := `^(?:` + label + `\.)+` + regexp.QuoteMeta(r) + `$`
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	return compiled, true
}

func MatchesWildcard(domain, root string) bool {
	d, ok := CanonicalDomain(domain)
	if !ok {
		return false
	}
	re, ok := WildcardRegex(root)
	if !ok {
		return false
	}
	return re.MatchString(d)
}
