package main

import (
	"fmt"
	"os"

	awscmd "oreno-sec-posture-report/cmd/aws"
)

var appVersion = "0.0.0"

func main() {
	args := os.Args[1:]
	for _, arg := range args {
		if arg == "-v" {
			fmt.Printf("oreno-sec-posture-report version %s\n", appVersion)
			os.Exit(0)
		}
	}

	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		printHelp()
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	return awscmd.Run(os.Args[1:])
}

func printHelp() {
	help := "Usage: oreno-sec-posture-report [options]\n\n" +
		"Global Options:\n" +
		"  -h, --help  Show this help\n" +
		"  -v          Show version\n\n" +
		"AWS Options:\n" +
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
