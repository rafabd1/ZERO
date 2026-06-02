package db

import "testing"

func TestScanCampaignChildParamsForcesProgramAndSkipSync(t *testing.T) {
	raw := []byte(`{"ProgramID":"old","SkipSync":false,"NucleiTemplate":"/tmp/custom.yaml"}`)
	got, err := scanCampaignChildParams(raw, "new-program")
	if err != nil {
		t.Fatalf("scanCampaignChildParams returned error: %v", err)
	}
	if string(got) == "" {
		t.Fatal("expected non-empty child params")
	}
	if want := `"ProgramID":"new-program"`; !containsJSONFragment(string(got), want) {
		t.Fatalf("child params = %s; missing %s", got, want)
	}
	if want := `"SkipSync":true`; !containsJSONFragment(string(got), want) {
		t.Fatalf("child params = %s; missing %s", got, want)
	}
	if want := `"NucleiTemplate":"/tmp/custom.yaml"`; !containsJSONFragment(string(got), want) {
		t.Fatalf("child params = %s; missing %s", got, want)
	}
}

func containsJSONFragment(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func TestDomainExcludedAppliesExactAndWildcardRulesPerProgram(t *testing.T) {
	rules := []DomainScopeRule{
		{ProgramID: "p1", Host: "admin.example.com", MatchMode: ProbeMatchExact},
		{ProgramID: "p1", Host: "excluded.example.com", MatchMode: ProbeMatchWildcard},
		{ProgramID: "p2", Host: "other.example.com", MatchMode: ProbeMatchWildcard},
	}

	tests := []struct {
		name      string
		programID string
		host      string
		want      bool
	}{
		{name: "exact excluded", programID: "p1", host: "admin.example.com", want: true},
		{name: "exact does not exclude children", programID: "p1", host: "x.admin.example.com", want: false},
		{name: "wildcard excludes children", programID: "p1", host: "api.excluded.example.com", want: true},
		{name: "wildcard does not exclude apex", programID: "p1", host: "excluded.example.com", want: false},
		{name: "rules are program scoped", programID: "p1", host: "api.other.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domainExcluded(rules, tt.programID, tt.host); got != tt.want {
				t.Fatalf("domainExcluded(%q, %q) = %v; want %v", tt.programID, tt.host, got, tt.want)
			}
		})
	}
}

func TestBuildDomainRootsUsesOnlyAuthorizedOwnedRoots(t *testing.T) {
	assets := []domainRootAsset{
		{ScopeAssetID: "wild-owned", ProgramID: "p1", AssetType: "wildcard", TargetRaw: "*.example.com"},
		{ScopeAssetID: "wild-nested", ProgramID: "p1", AssetType: "wildcard", TargetRaw: "*.api.example.com"},
		{ScopeAssetID: "wild-provider", ProgramID: "p1", AssetType: "wildcard", TargetRaw: "*.sub.heroku.com"},
		{ScopeAssetID: "wild-owned-by-domain", ProgramID: "p2", AssetType: "wildcard", TargetRaw: "*.api.acme.com"},
		{ScopeAssetID: "domain-owned", ProgramID: "p2", AssetType: "domain", TargetRaw: "acme.com"},
		{ScopeAssetID: "wild-not-authorized", ProgramID: "p3", AssetType: "wildcard", TargetRaw: "*.api.vendor.com"},
		{ScopeAssetID: "domain-subdomain-only", ProgramID: "p3", AssetType: "domain", TargetRaw: "api.vendor.com"},
	}

	roots := buildDomainRootsFromAssets(assets)
	got := map[string]DomainRoot{}
	for _, root := range roots {
		got[root.ScopeAssetID] = root
	}

	if root, ok := got["wild-owned"]; !ok || root.RootDomain != "example.com" || root.QueryDomain != "example.com" {
		t.Fatalf("wild-owned root = %#v; want scope/query example.com", root)
	}
	if root, ok := got["wild-nested"]; !ok || root.RootDomain != "api.example.com" || root.QueryDomain != "example.com" {
		t.Fatalf("wild-nested root = %#v; want scope api.example.com and query example.com", root)
	}
	if root, ok := got["wild-owned-by-domain"]; !ok || root.RootDomain != "api.acme.com" || root.QueryDomain != "acme.com" {
		t.Fatalf("wild-owned-by-domain root = %#v; want scope api.acme.com and query acme.com", root)
	}
	if _, ok := got["wild-provider"]; ok {
		t.Fatalf("provider subdomain wildcard should not be sent to subfinder: %#v", got["wild-provider"])
	}
	if _, ok := got["wild-not-authorized"]; ok {
		t.Fatalf("nested wildcard without owned root authorization should not be sent to subfinder: %#v", got["wild-not-authorized"])
	}
}

func TestScopedSubdomainAssetSelectionRules(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "root domain skipped", raw: "example.com", want: false},
		{name: "subdomain included", raw: "app.example.com", want: true},
		{name: "url subdomain included", raw: "https://login.example.com/path", want: true},
		{name: "provider subdomain still included as exact scope", raw: "sub.heroku.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, ok := scopedSubdomainHost(tt.raw)
			if ok != tt.want {
				t.Fatalf("scopedSubdomainHost(%q) ok = %v; want %v (host %q)", tt.raw, ok, tt.want, host)
			}
		})
	}
}
