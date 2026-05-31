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
