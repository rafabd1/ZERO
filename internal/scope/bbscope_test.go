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

func TestBuildAssetsFiltersConfiguredCategories(t *testing.T) {
	elements := []bbscope.ScopeElement{
		{Target: "https://app.example.com", Category: "Url", IsBBP: true},
		{Target: "*.example.com", Category: "Wildcard", IsBBP: true},
		{Target: "com.example.mobile", Category: "Android", IsBBP: true},
		{Target: "repository", Category: "SourceCode", IsBBP: true},
	}

	assets := buildAssets("program-id", "scan-id", "intigriti", "example/example", elements, true, "url,wildcard")
	if len(assets) != 2 {
		t.Fatalf("got %d assets; want only url and wildcard assets: %#v", len(assets), assets)
	}
	if assets[0].TargetNormalized != "app.example.com" || assets[1].TargetNormalized != "example.com" {
		t.Fatalf("unexpected filtered assets: %#v", assets)
	}
	if assets[0].AssetType != "url" || assets[1].AssetType != "wildcard" {
		t.Fatalf("asset categories were not normalized: %#v", assets)
	}
}

func TestCanonicalCategorySet(t *testing.T) {
	got := canonicalCategorySet("url,wildcard")
	want := map[string]bool{"url": false, "wildcard": false}
	for _, category := range got {
		if _, ok := want[category]; ok {
			want[category] = true
		}
	}
	for category, seen := range want {
		if !seen {
			t.Fatalf("canonicalCategorySet missing %q in %#v", category, got)
		}
	}
}
