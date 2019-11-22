module github.com/hashicorp/vault-plugin-secrets-gcp

go 1.12

require (
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-gcp-common v0.5.0
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault-plugin-auth-gcp v0.5.1
	github.com/hashicorp/vault/api v1.0.5-0.20191119221745-86341afaded0
	github.com/hashicorp/vault/sdk v0.1.14-0.20191108161836-82f2b5571044
	github.com/mitchellh/mapstructure v1.1.2
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/api v0.14.0
)
