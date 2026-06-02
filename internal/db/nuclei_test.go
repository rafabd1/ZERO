package db

import "testing"

func TestNucleiTechFilters(t *testing.T) {
	filters := nucleiTechFilters("CrushFTP, crushftp | Crush FTP")
	want := []string{"%crushftp%", "%crush ftp%"}
	if len(filters) != len(want) {
		t.Fatalf("filters = %#v", filters)
	}
	for i := range want {
		if filters[i] != want[i] {
			t.Fatalf("filters[%d] = %q; want %q", i, filters[i], want[i])
		}
	}
}
