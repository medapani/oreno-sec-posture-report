# oreno-sec-posture-report

AWS Security Hubの診断結果を取得し、TSV出力するツールです。

## 前提条件

- Go 1.26以上
- AWS認証情報が設定済みであること
	- 例: IAM Identity Center / ~/.aws/credentials / 環境変数

## ディレクトリ構成

oreno-sec-posture-report/
	cmd/
		aws/main.go      AWS向けCLI
	internal/
		aws/exporter.go  AWS Security Hub取得と抽出ロジック
		model/
			finding.go     共通データモデル
			exporter.go    エクスポートインターフェース
		output/tsv.go    TSV出力
	main.go            エントリーポイント

## AWS 出力項目

- ControlId
- ResourceType
- ResourceId
- RemediationUrl
- StandardVersion

## AWS 抽出条件

- SeverityLabel: HIGH または CRITICAL
- ComplianceStatus: FAILED
- RecordState: ACTIVE
- GeneratorId が security-control/ で始まる
- Compliance.AssociatedStandards に standards/aws-foundational-security-best-practices/v/1.0.0 を含む
- StandardVersion には該当する標準の識別子(standards/aws-foundational-security-best-practices/v/1.0.0 と、有効かつ一致する CIS AWS Foundations Benchmark のバージョン)をカンマ区切りで記載する。CIS が無効、または一致しない場合は standards/aws-foundational-security-best-practices/v/1.0.0 のみを記載する

## 実行方法

go run . -output get-findings.tsv

AWSプロファイルとリージョンを指定:

go run . -output get-findings.tsv -profile my-profile -region ap-northeast-1

進捗表示を無効化する場合:

go run . -output get-findings.tsv -progress=false

Taskで実行:

task export-findings-tsv
