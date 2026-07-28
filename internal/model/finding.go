package model

// FindingRow is a normalized row shared by cloud-specific collectors.
type FindingRow struct {
	ControlID       string
	ResourceType    string
	ResourceID      string
	RemediationURL  string
	StandardVersion string
}
