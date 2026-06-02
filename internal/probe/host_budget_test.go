package probe

import (
	"fmt"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
)

func TestHostBudgetCapsTenantLikeRootButKeepsPriorityHosts(t *testing.T) {
	hosts := []string{
		"api.example.com",
		"admin.example.com",
		"login.example.com",
		"exact.example.com",
	}
	byHost := map[string][]db.ProbeTarget{}
	for _, host := range hosts {
		byHost[host] = []db.ProbeTarget{{RootDomain: "example.com", MatchMode: db.ProbeMatchWildcard}}
	}
	byHost["exact.example.com"] = []db.ProbeTarget{{RootDomain: "exact.example.com", MatchMode: db.ProbeMatchExact, Source: "scope:url"}}
	for i := 0; i < 240; i++ {
		host := fmt.Sprintf("tenant-%04d.example.com", i)
		hosts = append(hosts, host)
		byHost[host] = []db.ProbeTarget{{RootDomain: "example.com", MatchMode: db.ProbeMatchWildcard}}
	}

	result := applyHostBudget(hosts, byHost, hostBudgetPolicy{MinGroup: 100, Cap: 25})
	got := set(result.Hosts)

	for _, want := range []string{"api.example.com", "admin.example.com", "login.example.com", "exact.example.com"} {
		if !got[want] {
			t.Fatalf("expected priority/exact host %q to be kept; result=%#v", want, result)
		}
	}
	if result.Skipped == 0 {
		t.Fatalf("expected tenant-like hosts to be skipped; result=%#v", result)
	}
	if result.BudgetedRoot != 1 {
		t.Fatalf("expected one budgeted root; result=%#v", result)
	}
}

func TestHostBudgetDoesNotCapSmallerSemanticRoot(t *testing.T) {
	hosts := []string{}
	byHost := map[string][]db.ProbeTarget{}
	for _, label := range []string{"account", "checkout", "billing", "docs", "support", "portal", "static", "cdn", "app", "developer"} {
		host := label + ".example.com"
		hosts = append(hosts, host)
		byHost[host] = []db.ProbeTarget{{RootDomain: "example.com", MatchMode: db.ProbeMatchWildcard}}
	}

	result := applyHostBudget(hosts, byHost, hostBudgetPolicy{MinGroup: 100, Cap: 5})
	if len(result.Hosts) != len(hosts) || result.Skipped != 0 {
		t.Fatalf("expected semantic small root to pass unchanged; result=%#v", result)
	}
}

func set(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}
