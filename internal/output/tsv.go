package output

import (
	"encoding/csv"
	"fmt"
	"os"

	"oreno-sec-posture-report/internal/model"
)

func WriteTSV(outputPath string, rows []model.FindingRow) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	w := csv.NewWriter(f)
	w.Comma = '\t'

	if err := w.Write([]string{"ControlId", "ResourceType", "ResourceId", "RemediationUrl", "StandardVersion"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for _, row := range rows {
		if err := w.Write([]string{row.ControlID, row.ResourceType, row.ResourceID, row.RemediationURL, row.StandardVersion}); err != nil {
			return fmt.Errorf("write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush tsv writer: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}

	return nil
}
