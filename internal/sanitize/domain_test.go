package sanitize

import "testing"

func TestDomainFromScopeTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "wildcard", raw: "*.example.com", want: "example.com", ok: true},
		{name: "url", raw: "https://App.Example.com/path", want: "app.example.com", ok: true},
		{name: "domain", raw: "api.example.com.", want: "api.example.com", ok: true},
		{name: "cidr", raw: "10.0.0.0/24", ok: false},
		{name: "path-only", raw: "/admin", ok: false},
		{name: "underscore", raw: "bad_host.example.com", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DomainFromScopeTarget(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("DomainFromScopeTarget(%q) = %q, %v; want %q, %v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestWildcardRootFromScopeTargetRequiresExplicitWildcard(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "wildcard root", raw: "*.example.com", want: "example.com", ok: true},
		{name: "wildcard url", raw: "https://*.apps.example.com/path", want: "apps.example.com", ok: true},
		{name: "provider subdomain is not collapsed", raw: "*.sub.heroku.com", want: "sub.heroku.com", ok: true},
		{name: "plain domain cannot enumerate children", raw: "sub.heroku.com", ok: false},
		{name: "normalized wildcard without marker rejected", raw: "example.com", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := WildcardRootFromScopeTarget(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("WildcardRootFromScopeTarget(%q) = %q, %v; want %q, %v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRegisteredDomain(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "normal root", raw: "api.example.com", want: "example.com"},
		{name: "multi part suffix", raw: "a.b.example.co.uk", want: "example.co.uk"},
		{name: "private suffix", raw: "app.herokuapp.com", want: "app.herokuapp.com"},
		{name: "provider subdomain", raw: "sub.heroku.com", want: "heroku.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := RegisteredDomain(tt.raw)
			if !ok || got != tt.want {
				t.Fatalf("RegisteredDomain(%q) = %q, %v; want %q, true", tt.raw, got, ok, tt.want)
			}
		})
	}
}

func TestIsWithinRoot(t *testing.T) {
	if !IsWithinRoot("a.b.example.com", "example.com") {
		t.Fatal("expected subdomain to be inside root")
	}
	if !IsWithinRoot("example.com", "example.com") {
		t.Fatal("expected root to be inside itself")
	}
	if IsWithinRoot("example.com.evil.test", "example.com") {
		t.Fatal("expected suffix lookalike to be rejected")
	}
}

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		root   string
		want   bool
	}{
		{name: "one label", domain: "app.example.com", root: "example.com", want: true},
		{name: "many labels", domain: "a.b.example.com", root: "example.com", want: true},
		{name: "apex is not wildcard match", domain: "example.com", root: "example.com", want: false},
		{name: "sibling rejected", domain: "app.other.com", root: "example.com", want: false},
		{name: "suffix lookalike rejected", domain: "example.com.evil.test", root: "example.com", want: false},
		{name: "bad label rejected", domain: "-bad.example.com", root: "example.com", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesWildcard(tt.domain, tt.root); got != tt.want {
				t.Fatalf("MatchesWildcard(%q, %q) = %v; want %v", tt.domain, tt.root, got, tt.want)
			}
		})
	}
}
