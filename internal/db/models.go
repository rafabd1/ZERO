package db

import "encoding/json"

type ScopeAsset struct {
	ID                string
	ProgramID         string
	LastScanRunID     string
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

type Program struct {
	ID                string
	Platform          string
	Handle            string
	ProgramURL        string
	ScanIntervalHours int
}

type ScanRequest struct {
	ID        string
	ProgramID string
	Name      string
	Params    json.RawMessage
}

type DomainRoot struct {
	ScopeAssetID string
	ProgramID    string
	RootDomain   string
}

type DomainScopeRule struct {
	ScopeAssetID string
	ProgramID    string
	Host         string
	MatchMode    string
}

type Subdomain struct {
	ID            string
	ProgramID     string
	ScopeAssetID  string
	LastScanRunID string
	RootDomain    string
	FQDN          string
	Source        string
}

const (
	ProbeMatchExact    = "exact"
	ProbeMatchWildcard = "wildcard"
)

type ProbeTarget struct {
	SubdomainID  string
	ProgramID    string
	ScopeAssetID string
	RootDomain   string
	FQDN         string
	Source       string
	MatchMode    string
}

type HTTPService struct {
	ID            string
	ProgramID     string
	SubdomainID   string
	LastScanRunID string
	URL           string
	Scheme        string
	Host          string
	Port          *int
	StatusCode    *int
	Title         string
	Webserver     string
	Technologies  []string
	FaviconHash   string
	TLS           json.RawMessage
	Raw           json.RawMessage
}

type WebTechTarget struct {
	ProgramID     string
	HTTPServiceID string
	LastScanRunID string
	URL           string
}

type TechnologyObservation struct {
	ProgramID     string
	HTTPServiceID string
	LastScanRunID string
	Name          string
	Version       string
	Source        string
	Confidence    int
	Evidence      map[string]any
}

type VersionedTechnology struct {
	ProgramID     string
	HTTPServiceID string
	LastScanRunID string
	Name          string
	Version       string
	Source        string
}

type VulnerabilityRecord struct {
	VulnID     string
	Source     string
	Summary    string
	Severity   string
	CVSSScore  *float64
	References []string
	Raw        json.RawMessage
}

type TechnologyVulnerabilityMatch struct {
	ProgramID         string
	HTTPServiceID     string
	VulnerabilityID   string
	LastScanRunID     string
	TechnologyName    string
	TechnologyVersion string
	SourceObservation string
	SourceQuery       string
	Confidence        int
	Evidence          map[string]any
}

type NucleiTarget struct {
	ProgramID     string
	HTTPServiceID string
	URL           string
}

type NucleiResult struct {
	ProgramID     string
	HTTPServiceID string
	ScanRunID     string
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

type ReportFinding struct {
	ID            string
	ProgramID     string
	ProgramHandle string
	ProgramURL    string
	ServiceURL    string
	ServiceHost   string
	Severity      string
	Confidence    int
	Evidence      json.RawMessage
	FirstSeenAt   string
}

type ReportDraft struct {
	ProgramID  string
	ScanRunID  string
	ReportKey  string
	Title      string
	Severity   string
	Confidence int
	Body       string
	FindingIDs []string
	Metadata   map[string]any
}

type DiscordReport struct {
	ReportID      string
	ProgramID     string
	ProgramHandle string
	ProgramURL    string
	ReportKey     string
	Title         string
	Severity      string
	Confidence    int
	BodyMarkdown  string
	FindingIDs    []string
	CreatedAt     string
}
