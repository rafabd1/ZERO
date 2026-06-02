package intel

import (
	"errors"
	"fmt"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
)

func TestRetryableNVDError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{err: nvdStatusError{status: 429, keyword: "apache"}, want: true},
		{err: nvdStatusError{status: 503, keyword: "apache"}, want: true},
		{err: nvdStatusError{status: 400, keyword: "apache"}, want: false},
		{err: errors.New("lookup services.nvd.nist.gov: no such host"), want: true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.err), func(t *testing.T) {
			if got := retryableNVDError(tt.err); got != tt.want {
				t.Fatalf("retryableNVDError(%v) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestMatchConfidenceUsesCPERanges(t *testing.T) {
	tech := db.VersionedTechnology{
		ProgramID: "program-1",
		Name:      "Apache HTTP Server",
		Version:   "2.4.49",
		Source:    "webanalyze",
	}
	cve := nvdCVE{
		ID: "CVE-2021-41773",
		Descriptions: []nvdDescription{{
			Lang:  "en",
			Value: "A path traversal and file disclosure vulnerability exists in Apache HTTP Server 2.4.49.",
		}},
		Configurations: []nvdConfiguration{{
			Nodes: []nvdNode{{
				CPEMatch: []nvdCPEMatch{{
					Vulnerable:            true,
					Criteria:              "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
					VersionStartIncluding: "2.4.49",
					VersionEndExcluding:   "2.4.50",
				}},
			}},
		}},
	}

	confidence, evidence := matchConfidence(tech, cve, "Apache HTTP Server 2.4.49", DefaultTechnologyAliases())
	if confidence < 90 {
		t.Fatalf("expected strong CPE confidence, got %d with evidence %#v", confidence, evidence)
	}
	if evidence["strategy"] != "nvd-cpe" {
		t.Fatalf("expected cpe strategy, got %#v", evidence["strategy"])
	}
}

func TestMatchConfidenceRejectsUnrelatedCPE(t *testing.T) {
	tech := db.VersionedTechnology{Name: "nginx", Version: "1.18.0"}
	cve := nvdCVE{
		ID: "CVE-2021-41773",
		Configurations: []nvdConfiguration{{
			Nodes: []nvdNode{{
				CPEMatch: []nvdCPEMatch{{
					Vulnerable: true,
					Criteria:   "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
				}},
			}},
		}},
	}

	confidence, _ := matchConfidence(tech, cve, "nginx 1.18.0", DefaultTechnologyAliases())
	if confidence != 0 {
		t.Fatalf("expected unrelated CPE to be rejected, got %d", confidence)
	}
}

func TestProductMatchingAvoidsVendorOnlyCiscoMatches(t *testing.T) {
	if productMatchesTech("cisco ios xe", "Cisco ASA", DefaultTechnologyAliases()) {
		t.Fatal("expected Cisco vendor-only overlap to be rejected")
	}
	if !productMatchesTech("cisco adaptive security appliance", "Cisco ASA WebVPN", DefaultTechnologyAliases()) {
		t.Fatal("expected Cisco ASA alias to match adaptive security appliance CPE product")
	}
	if !productMatchesTech("cisco firepower threat defense", "Cisco FTD WebVPN", DefaultTechnologyAliases()) {
		t.Fatal("expected Cisco FTD alias to match firepower threat defense CPE product")
	}
}

func TestTextFallbackLinksVersionedTechnology(t *testing.T) {
	tech := db.VersionedTechnology{Name: "Struts", Version: "2.5.12"}
	cve := nvdCVE{
		ID: "CVE-2017-5638",
		Descriptions: []nvdDescription{{
			Lang:  "en",
			Value: "Apache Struts 2.5.12 is affected by an input validation issue.",
		}},
	}

	confidence, evidence := matchConfidence(tech, cve, "Struts 2.5.12", DefaultTechnologyAliases())
	if confidence < 40 {
		t.Fatalf("expected keyword fallback confidence, got %d with evidence %#v", confidence, evidence)
	}
	if evidence["strategy"] != "nvd-keyword" {
		t.Fatalf("expected keyword strategy, got %#v", evidence["strategy"])
	}
}

func TestTextFallbackRejectsWeakIISToken(t *testing.T) {
	tech := db.VersionedTechnology{Name: "IIS", Version: "10.0"}
	cve := nvdCVE{
		ID: "CVE-2012-4591",
		Descriptions: []nvdDescription{{
			Lang:  "en",
			Value: "About.aspx in the Portal in McAfee Enterprise Mobility Manager before 10.0 discloses the IIS worker process account.",
		}},
	}

	confidence, evidence := matchConfidence(tech, cve, "IIS 10.0", DefaultTechnologyAliases())
	if confidence != 0 {
		t.Fatalf("expected weak IIS text-only match to be rejected, got %d with evidence %#v", confidence, evidence)
	}
}

func TestCPEPresenceBlocksUnmatchedKeywordFallback(t *testing.T) {
	tech := db.VersionedTechnology{Name: "Apache HTTP Server", Version: "2.4.6"}
	cve := nvdCVE{
		ID: "CVE-FAKE-1",
		Descriptions: []nvdDescription{{
			Lang:  "en",
			Value: "Apache HTTP Server is mentioned in a broad advisory, but the vulnerable product is not httpd.",
		}},
		Configurations: []nvdConfiguration{{
			Nodes: []nvdNode{{
				CPEMatch: []nvdCPEMatch{{
					Vulnerable: true,
					Criteria:   "cpe:2.3:a:oracle:weblogic_server:12.2.1.4.0:*:*:*:*:*:*:*",
				}},
			}},
		}},
	}

	confidence, evidence := matchConfidence(tech, cve, "Apache HTTP Server 2.4.6", DefaultTechnologyAliases())
	if confidence != 0 {
		t.Fatalf("expected unmatched vulnerable CPE to block keyword fallback, got %d with evidence %#v", confidence, evidence)
	}
}

func TestCVEYear(t *testing.T) {
	tests := map[string]int{
		"CVE-2018-17199": 2018,
		"cve-2025-12345": 2025,
		"CVE-FAKE-1":     0,
		"":               0,
	}
	for id, want := range tests {
		if got := cveYear(id); got != want {
			t.Fatalf("cveYear(%q) = %d; want %d", id, got, want)
		}
	}
}
