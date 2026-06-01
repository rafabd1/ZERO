package db

import "testing"

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
