package awsreport

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"oreno-sec-posture-report/internal/model"
)

const (
	awsFoundationalStandardsID       = "standards/aws-foundational-security-best-practices/v/1.0.0"
	cisAwsFoundationsStandardsPrefix = "standards/cis-aws-foundations-benchmark/"
)

type Exporter struct {
	profile    string
	region     string
	onProgress func(Progress)
}

type Progress struct {
	Pages    int
	Findings int
	Rows     int
	Done     bool
}

func NewExporter(profile, region string, onProgress func(Progress)) *Exporter {
	return &Exporter{profile: profile, region: region, onProgress: onProgress}
}

func (e *Exporter) Export(ctx context.Context) ([]model.FindingRow, error) {
	cfgOptions := make([]func(*config.LoadOptions) error, 0, 2)
	if e.profile != "" {
		cfgOptions = append(cfgOptions, config.WithSharedConfigProfile(e.profile))
	}
	if e.region != "" {
		cfgOptions = append(cfgOptions, config.WithRegion(e.region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, cfgOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	client := securityhub.NewFromConfig(cfg)
	return e.collectRows(ctx, client)
}

func (e *Exporter) collectRows(ctx context.Context, client *securityhub.Client) ([]model.FindingRow, error) {
	enabledVersions, err := e.getEnabledCISVersions(ctx, client)
	if err != nil {
		return nil, err
	}

	rows := make([]model.FindingRow, 0, 128)
	pages := 0
	findings := 0
	outputRows := 0

	input := &securityhub.GetFindingsInput{
		Filters: &types.AwsSecurityFindingFilters{
			SeverityLabel: []types.StringFilter{
				{Value: aws.String("HIGH"), Comparison: types.StringFilterComparisonEquals},
				{Value: aws.String("CRITICAL"), Comparison: types.StringFilterComparisonEquals},
			},
			ComplianceStatus: []types.StringFilter{
				{Value: aws.String("FAILED"), Comparison: types.StringFilterComparisonEquals},
			},
			RecordState: []types.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: types.StringFilterComparisonEquals},
			},
		},
	}

	for {
		out, err := client.GetFindings(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("securityhub get-findings: %w", err)
		}
		pages++
		findings += len(out.Findings)

		for _, finding := range out.Findings {
			converted := findingToRows(finding, enabledVersions)
			outputRows += len(converted)
			rows = append(rows, converted...)
		}
		e.reportProgress(Progress{Pages: pages, Findings: findings, Rows: outputRows})

		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		input.NextToken = out.NextToken
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ControlID != rows[j].ControlID {
			return rows[i].ControlID < rows[j].ControlID
		}
		if rows[i].ResourceType != rows[j].ResourceType {
			return rows[i].ResourceType < rows[j].ResourceType
		}
		return rows[i].ResourceID < rows[j].ResourceID
	})

	e.reportProgress(Progress{Pages: pages, Findings: findings, Rows: outputRows, Done: true})

	return rows, nil
}

func (e *Exporter) reportProgress(p Progress) {
	if e.onProgress != nil {
		e.onProgress(p)
	}
}

func (e *Exporter) getEnabledCISVersions(ctx context.Context, client *securityhub.Client) ([]string, error) {
	out, err := client.GetEnabledStandards(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("securityhub get-enabled-standards: %w", err)
	}

	versions := make([]string, 0)
	seen := make(map[string]struct{})
	for _, subscription := range out.StandardsSubscriptions {
		arn := aws.ToString(subscription.StandardsArn)
		if arn == "" {
			arn = aws.ToString(subscription.StandardsSubscriptionArn)
		}

		standardID, ok := cisStandardIDFromARN(arn)
		if !ok {
			continue
		}

		if _, ok := seen[standardID]; ok {
			continue
		}
		seen[standardID] = struct{}{}
		versions = append(versions, standardID)
	}

	return versions, nil
}

// cisStandardIDFromARN extracts the resource portion of a CIS AWS Foundations
// Benchmark standard/subscription ARN (e.g. "standards/cis-aws-foundations-benchmark/v/1.4.0")
// since Compliance.AssociatedStandards[].StandardsId only contains that resource
// portion, not the full ARN (e.g. "arn:aws:securityhub:<region>::standards/cis-aws-foundations-benchmark/v/1.4.0").
func cisStandardIDFromARN(arn string) (string, bool) {
	idx := strings.Index(arn, cisAwsFoundationsStandardsPrefix)
	if idx == -1 {
		return "", false
	}
	return arn[idx:], true
}

func findingToRows(finding types.AwsSecurityFinding, enabledVersions []string) []model.FindingRow {
	generatorID := aws.ToString(finding.GeneratorId)
	if !strings.HasPrefix(generatorID, "security-control/") {
		return nil
	}

	if !hasStandards(finding.Compliance, awsFoundationalStandardsID) {
		return nil
	}

	matchedStandards := []string{awsFoundationalStandardsID}
	for _, version := range enabledVersions {
		if hasStandard(finding.Compliance, version) {
			matchedStandards = append(matchedStandards, version)
		}
	}
	standardVersion := strings.Join(matchedStandards, ",")

	controlID := strings.TrimPrefix(generatorID, "security-control/")
	remediationURL := ""
	if finding.Remediation != nil && finding.Remediation.Recommendation != nil {
		remediationURL = aws.ToString(finding.Remediation.Recommendation.Url)
	}

	rows := make([]model.FindingRow, 0, len(finding.Resources))
	for _, resource := range finding.Resources {
		rows = append(rows, model.FindingRow{
			ControlID:       controlID,
			ResourceType:    aws.ToString(resource.Type),
			ResourceID:      aws.ToString(resource.Id),
			RemediationURL:  remediationURL,
			StandardVersion: standardVersion,
		})
	}

	return rows
}

func hasStandard(compliance *types.Compliance, expectedStandardID string) bool {
	if compliance == nil {
		return false
	}

	have := make(map[string]struct{}, len(compliance.AssociatedStandards))
	for _, standard := range compliance.AssociatedStandards {
		have[aws.ToString(standard.StandardsId)] = struct{}{}
	}

	_, ok := have[expectedStandardID]
	return ok
}

func hasStandards(compliance *types.Compliance, expectedStandardIDs ...string) bool {
	if compliance == nil {
		return false
	}

	if len(expectedStandardIDs) == 0 {
		return true
	}

	have := make(map[string]struct{}, len(compliance.AssociatedStandards))
	for _, standard := range compliance.AssociatedStandards {
		have[aws.ToString(standard.StandardsId)] = struct{}{}
	}

	for _, expected := range expectedStandardIDs {
		if _, ok := have[expected]; !ok {
			return false
		}
	}

	return true
}
