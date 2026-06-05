package db

import (
	"encoding/json"
	"time"
)

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
	ID         string
	ProgramID  string
	CampaignID string
	Name       string
	Params     json.RawMessage
}

type ScanRequestRetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
}

type ScanRequestProgress struct {
	Stage   string
	Current int
	Total   int
	Message string
	Meta    map[string]any
}

type ScanCampaignCreateResult struct {
	ID       string
	Total    int
	Queued   int
	DueOnly  bool
	Limit    int
	Parallel int
}

type CancelScanResult struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Status           string `json:"status"`
	QueuedCanceled   int    `json:"queued_canceled"`
	RunningCanceled  int    `json:"running_canceled"`
	RequestsCanceled int    `json:"requests_canceled"`
}

type CleanupResult struct {
	ScopeAssets                 int `json:"scope_assets"`
	Subdomains                  int `json:"subdomains"`
	HTTPServices                int `json:"http_services"`
	TechnologyObservations      int `json:"technology_observations"`
	TechnologyVulnerabilityRows int `json:"technology_vulnerability_rows"`
	ChangeEvents                int `json:"change_events"`
	ScanRequests                int `json:"scan_requests"`
	ScanRuns                    int `json:"scan_runs"`
}

type DomainRoot struct {
	ScopeAssetID string
	ProgramID    string
	RootDomain   string
	QueryDomain  string
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
	ProgramID        string
	HTTPServiceID    string
	LastScanRunID    string
	URL              string
	Host             string
	StatusCode       int
	Title            string
	Webserver        string
	Technologies     []string
	FaviconHash      string
	RedirectLocation string
	CNAME            string
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
	TargetID      string
	TargetSource  string
	Input         string
}

type NucleiResult struct {
	ProgramID     string
	HTTPServiceID string
	ScanRunID     string
	TargetSource  string
	TargetID      string
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
	Confirmed     int
	Potential     int
	CreatedAt     string
}
