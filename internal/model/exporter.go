package model

import "context"

// Exporter defines a cloud-specific collector contract.
type Exporter interface {
	Export(ctx context.Context) ([]FindingRow, error)
}
