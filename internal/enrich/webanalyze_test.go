package enrich

import "testing"

func TestParseWebanalyzeLine(t *testing.T) {
	parsed, err := parseWebanalyzeLine(`{"hostname":"https://app.example.com","matches":[{"app_name":"Hugo","version":"0.42.1","cat_names":["Static Site Generator"]}]}`)
	if err != nil {
		t.Fatalf("parseWebanalyzeLine returned error: %v", err)
	}
	if parsed.Hostname != "https://app.example.com" {
		t.Fatalf("Hostname = %q", parsed.Hostname)
	}
	if len(parsed.Matches) != 1 {
		t.Fatalf("matches = %d; want 1", len(parsed.Matches))
	}
	if parsed.Matches[0].AppName != "Hugo" || parsed.Matches[0].Version != "0.42.1" {
		t.Fatalf("match = %#v", parsed.Matches[0])
	}
}

func TestNormalizeURLKeyDropsQueryAndTrailingSlash(t *testing.T) {
	got := normalizeURLKey("https://APP.example.com/path/?x=1#frag")
	want := "https://app.example.com/path"
	if got != want {
		t.Fatalf("normalizeURLKey = %q; want %q", got, want)
	}
}
