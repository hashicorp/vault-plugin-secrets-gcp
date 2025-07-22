package gcpsecrets

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// @TODO can all be moved to common Vault SDK package
func pathMetrics(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "/metrics",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathImpersonatedAccountAccessToken,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "impersonated-account-access-token",
				},
			},
		},
		HelpSynopsis:    pathMetricsHelpSyn,
		HelpDescription: pathMetricsHelpDesc,
	}
}

const (
	pathMetricsHelpSyn  = `Get metrics for the plugin backend.`
	pathMetricsHelpDesc = `
This path will provide metrics for the plugin usage.

Please see backend documentation for more information:
https://www.vaultproject.io/docs/secrets/gcp/index.html
`
)
