package awscmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	awsreport "oreno-sec-posture-report/internal/aws"
	"oreno-sec-posture-report/internal/output"
)

func Run(args []string) error {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printHelp()
			return nil
		}
	}

	var outputPath string
	var profile string
	var region string
	var progress bool

	fs := flag.NewFlagSet("oreno-sec-posture-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&outputPath, "output", "get-findings.tsv", "TSV output file path")
	fs.StringVar(&profile, "profile", "", "AWS profile name")
	fs.StringVar(&region, "region", "", "AWS region")
	fs.BoolVar(&progress, "progress", true, "Show progress on stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var progressFn func(awsreport.Progress)
	if progress {
		progressFn = func(p awsreport.Progress) {
			fmt.Fprintf(os.Stderr, "\r\x1b[2KProgress pages=%d findings=%d outputRows=%d", p.Pages, p.Findings, p.Rows)
			if p.Done {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	exporter := awsreport.NewExporter(profile, region, progressFn)
	rows, err := exporter.Export(context.Background())
	if err != nil {
		return err
	}

	if err := output.WriteTSV(outputPath, rows); err != nil {
		return err
	}

	fmt.Printf("wrote %d rows to %s\n", len(rows), outputPath)
	return nil
}

func printHelp() {
	help := "Usage: oreno-sec-posture-report [options]\n\n" +
		"Options:\n" +
		"  -output string   TSV output file path (default: get-findings.tsv)\n" +
		"  -profile string  AWS profile name\n" +
		"  -region string   AWS region\n" +
		"  -progress bool   Show progress on stderr (default: true)\n\n" +
		"Examples:\n" +
		"  oreno-sec-posture-report -output get-findings.tsv\n" +
		"  oreno-sec-posture-report -profile dev -region ap-northeast-1\n" +
		"  oreno-sec-posture-report -progress=false\n"
	fmt.Print(help)
}
