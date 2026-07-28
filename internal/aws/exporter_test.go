package awsreport

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestFindingToRowsUsesEnabledCISVersion(t *testing.T) {
	finding := types.AwsSecurityFinding{
		GeneratorId: aws.String("security-control/test"),
		Compliance: &types.Compliance{
			AssociatedStandards: []types.AssociatedStandard{
				{StandardsId: aws.String(awsFoundationalStandardsID)},
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/3.0.0")},
			},
		},
		Resources: []types.Resource{{Id: aws.String("resource-1")}},
	}

	rows := findingToRows(finding, []string{"standards/cis-aws-foundations-benchmark/v/3.0.0"})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	if rows[0].ResourceID != "resource-1" {
		t.Fatalf("expected resource id resource-1, got %s", rows[0].ResourceID)
	}
	want := awsFoundationalStandardsID + ",standards/cis-aws-foundations-benchmark/v/3.0.0"
	if rows[0].StandardVersion != want {
		t.Fatalf("expected matched standards to be comma-separated, got %s", rows[0].StandardVersion)
	}
}

func TestFindingToRowsListsAllMatchedCISVersionsCommaSeparated(t *testing.T) {
	finding := types.AwsSecurityFinding{
		GeneratorId: aws.String("security-control/test"),
		Compliance: &types.Compliance{
			AssociatedStandards: []types.AssociatedStandard{
				{StandardsId: aws.String(awsFoundationalStandardsID)},
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/1.4.0")},
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/3.0.0")},
			},
		},
		Resources: []types.Resource{{Id: aws.String("resource-1")}},
	}

	rows := findingToRows(finding, []string{"standards/cis-aws-foundations-benchmark/v/1.4.0", "standards/cis-aws-foundations-benchmark/v/3.0.0"})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	want := awsFoundationalStandardsID + ",standards/cis-aws-foundations-benchmark/v/1.4.0,standards/cis-aws-foundations-benchmark/v/3.0.0"
	if rows[0].StandardVersion != want {
		t.Fatalf("expected all matched standards to be comma-separated, got %s", rows[0].StandardVersion)
	}
}

func TestFindingToRowsKeepsAWSFoundationalRowWhenCISVersionNotEnabled(t *testing.T) {
	finding := types.AwsSecurityFinding{
		GeneratorId: aws.String("security-control/test"),
		Compliance: &types.Compliance{
			AssociatedStandards: []types.AssociatedStandard{
				{StandardsId: aws.String(awsFoundationalStandardsID)},
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/3.0.0")},
			},
		},
		Resources: []types.Resource{{Id: aws.String("resource-1")}},
	}

	rows := findingToRows(finding, []string{"standards/cis-aws-foundations-benchmark/v/4.0.0"})
	if len(rows) != 1 {
		t.Fatalf("expected AWS foundational row to still be returned, got %d", len(rows))
	}
	if rows[0].StandardVersion != awsFoundationalStandardsID {
		t.Fatalf("expected StandardVersion to fall back to AWS FSBP when CIS version not enabled, got %s", rows[0].StandardVersion)
	}
}

func TestFindingToRowsKeepsAWSFoundationalRowWhenNoCISEnabled(t *testing.T) {
	finding := types.AwsSecurityFinding{
		GeneratorId: aws.String("security-control/test"),
		Compliance: &types.Compliance{
			AssociatedStandards: []types.AssociatedStandard{
				{StandardsId: aws.String(awsFoundationalStandardsID)},
			},
		},
		Resources: []types.Resource{{Id: aws.String("resource-1")}},
	}

	rows := findingToRows(finding, nil)
	if len(rows) != 1 {
		t.Fatalf("expected AWS foundational row to still be returned, got %d", len(rows))
	}
	if rows[0].StandardVersion != awsFoundationalStandardsID {
		t.Fatalf("expected StandardVersion to fall back to AWS FSBP when no CIS standard enabled, got %s", rows[0].StandardVersion)
	}
}

func TestFindingToRowsIgnoresFindingWithoutAWSFoundational(t *testing.T) {
	finding := types.AwsSecurityFinding{
		GeneratorId: aws.String("security-control/test"),
		Compliance: &types.Compliance{
			AssociatedStandards: []types.AssociatedStandard{
				{StandardsId: aws.String("standards/cis-aws-foundations-benchmark/v/3.0.0")},
			},
		},
		Resources: []types.Resource{{Id: aws.String("resource-1")}},
	}

	rows := findingToRows(finding, []string{"standards/cis-aws-foundations-benchmark/v/3.0.0"})
	if len(rows) != 0 {
		t.Fatalf("expected no rows without AWS foundational standard, got %d", len(rows))
	}
}

func TestCisStandardIDFromARN(t *testing.T) {
	arn := "arn:aws:securityhub:ap-northeast-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
	standardID, ok := cisStandardIDFromARN(arn)
	if !ok {
		t.Fatalf("expected ok=true for arn %s", arn)
	}
	if standardID != "standards/cis-aws-foundations-benchmark/v/1.4.0" {
		t.Fatalf("expected resource-only standard id, got %s", standardID)
	}
}

func TestCisStandardIDFromARNIgnoresOtherStandards(t *testing.T) {
	arn := "arn:aws:securityhub:ap-northeast-1::standards/aws-foundational-security-best-practices/v/1.0.0"
	if _, ok := cisStandardIDFromARN(arn); ok {
		t.Fatalf("expected ok=false for non-CIS arn %s", arn)
	}
}
