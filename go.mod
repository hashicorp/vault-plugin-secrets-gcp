module github.com/hashicorp/vault-plugin-secrets-gcp

go 1.12

require (
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-gcp-common v0.5.0
	github.com/hashicorp/go-hclog v0.12.0
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.5-0.20200215224050-f6547fa8e820
	github.com/hashicorp/vault/sdk v0.1.14-0.20200215224050-f6547fa8e820
	github.com/kr/pretty v0.2.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	google.golang.org/api v0.58.0
)

// hashicorp/go-gcp-common depends on google.golang.org/api 0.5.0 which does not include the impersonate GCP client.
// The impersonate client wasn't introduced until 0.46.0 but there was a breaking change in the oauth2 v2 client
// in 0.20.0. Therefore replacing hashicorp/go-gcp-common until that gets fixed.
//
// See https://github.com/hashicorp/go-gcp-common/pull/5
replace github.com/hashicorp/go-gcp-common => github.com/mdgreenfield/go-gcp-common v0.7.1-0.20211018231312-c5937153ab03
