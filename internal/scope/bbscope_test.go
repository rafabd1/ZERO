package scope

import (
	"testing"

	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	bbscope "github.com/sw33tLie/bbscope/v2/pkg/scope"
)

func TestSplitBountyScopeMovesNonBountyAssetsOutOfScope(t *testing.T) {
	elements := []bbscope.ScopeElement{
		{Target: "*.paid.example.com", IsBBP: true},
		{Target: "*.vdp.example.com", IsBBP: false},
	}

	inScope, outOfScope := splitBountyScope(elements, true)
	if len(inScope) != 1 || inScope[0].Target != "*.paid.example.com" {
		t.Fatalf("inScope = %#v; want only paid asset", inScope)
	}
	if len(outOfScope) != 1 || outOfScope[0].Target != "*.vdp.example.com" {
		t.Fatalf("outOfScope = %#v; want non-bounty asset", outOfScope)
	}
}

func TestSplitBountyScopeKeepsAllWhenBountyOnlyDisabled(t *testing.T) {
	elements := []bbscope.ScopeElement{{Target: "*.vdp.example.com", IsBBP: false}}
	inScope, outOfScope := splitBountyScope(elements, false)
	if len(inScope) != 1 || len(outOfScope) != 0 {
		t.Fatalf("got %d in-scope and %d out-of-scope; want all in-scope", len(inScope), len(outOfScope))
	}
}

func TestFetchScopeOptionsKeepsFullAssetSet(t *testing.T) {
	opts := fetchScopeOptions(platforms.PollOptions{
		BountyOnly:  true,
		PrivateOnly: true,
		Categories:  "url,wildcard",
	})
	if opts.BountyOnly {
		t.Fatal("fetch scope options must disable bounty filtering so non-bounty assets can be stored out-of-scope")
	}
	if !opts.PrivateOnly || opts.Categories != "url,wildcard" {
		t.Fatalf("fetch scope options changed unrelated filters: %#v", opts)
	}
}
