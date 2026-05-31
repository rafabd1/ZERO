package db

import "encoding/json"

type ScopeAsset struct {
	ID                string
	ProgramID         string
	Platform          string
	Handle            string
	AssetType         string
	TargetRaw         string
	TargetNormalized  string
	Description       string
	InScope           bool
	EligibleForBounty bool
	Source            string
	Metadata          map[string]any
}

type DomainRoot struct {
	ScopeAssetID string
	ProgramID    string
	RootDomain   string
}

type Subdomain struct {
	ID           string
	ProgramID    string
	ScopeAssetID string
	RootDomain   string
	FQDN         string
	Source       string
}

type HTTPService struct {
	ID           string
	ProgramID    string
	SubdomainID  string
	URL          string
	Scheme       string
	Host         string
	Port         *int
	StatusCode   *int
	Title        string
	Webserver    string
	Technologies []string
	FaviconHash  string
	TLS          json.RawMessage
	Raw          json.RawMessage
}

type NucleiTarget struct {
	ProgramID     string
	HTTPServiceID string
	URL           string
}

type NucleiResult struct {
	ProgramID     string
	HTTPServiceID string
	TemplateID    string
	TemplatePath  string
	MatchedAt     string
	Severity      string
	CVEs          []string
	Tags          []string
	Type          string
	ExtractorName string
	EvidenceHash  string
	Raw           json.RawMessage
}
