// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathStaticAccountSecretServiceAccountKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s/key", staticAccountPathPrefix, framework.GenericNameRegex("name")),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixGoogleCloud,
			OperationVerb:   "generate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the static account.",
			},
			"key_algorithm": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key algorithm for service account key. Defaults to %s."`, keyAlgorithmRSA2k),
				Default:     keyAlgorithmRSA2k,
				Query:       true,
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key type for service account key. Defaults to %s."`, privateKeyTypeJson),
				Default:     privateKeyTypeJson,
				Query:       true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Lifetime of the service account key",
				Query:       true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticAccountSecretKey,
				Summary:  "Generate a service account key for a static account.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "static-account-key2",
				},
				Responses: map[int][]framework.Response{
					200: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"private_key_data": {
								Type:        framework.TypeString,
								Description: "Base64-encoded private key data for the service account key.",
							},
							"key_algorithm": {
								Type:        framework.TypeString,
								Description: "Algorithm used to generate the service account key.",
							},
							"key_type": {
								Type:        framework.TypeString,
								Description: "Private key type of the service account key.",
							},
						},
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathStaticAccountSecretKey,
				Summary:  "Generate a service account key for a static account.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "static-account-key",
				},
				Responses: map[int][]framework.Response{
					200: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"private_key_data": {
								Type:        framework.TypeString,
								Description: "Base64-encoded private key data for the service account key.",
							},
							"key_algorithm": {
								Type:        framework.TypeString,
								Description: "Algorithm used to generate the service account key.",
							},
							"key_type": {
								Type:        framework.TypeString,
								Description: "Private key type of the service account key.",
							},
						},
					}},
				},
			},
		},
		HelpSynopsis:    pathServiceAccountKeySyn,
		HelpDescription: pathServiceAccountKeyDesc,
	}
}

func pathStaticAccountSecretAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s/token", staticAccountPathPrefix, framework.GenericNameRegex("name")),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixGoogleCloud,
			OperationVerb:   "generate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the static account.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticAccountAccessToken,
				Summary:  "Generate an access token for a static account.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "static-account-access-token2",
				},
				Responses: map[int][]framework.Response{
					200: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"token": {
								Type:        framework.TypeString,
								Description: "OAuth2 access token.",
							},
							"token_ttl": {
								Type:        framework.TypeInt,
								Description: "Remaining lifetime of the token in seconds.",
							},
							"expires_at_seconds": {
								Type:        framework.TypeInt,
								Description: "Unix timestamp at which the token expires.",
							},
						},
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathStaticAccountAccessToken,
				Summary:  "Generate an access token for a static account.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "static-account-access-token",
				},
				Responses: map[int][]framework.Response{
					200: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"token": {
								Type:        framework.TypeString,
								Description: "OAuth2 access token.",
							},
							"token_ttl": {
								Type:        framework.TypeInt,
								Description: "Remaining lifetime of the token in seconds.",
							},
							"expires_at_seconds": {
								Type:        framework.TypeInt,
								Description: "Unix timestamp at which the token expires.",
							},
						},
					}},
				},
			},
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

func (b *backend) pathStaticAccountSecretKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	acctName := d.Get("name").(string)
	keyType := d.Get("key_type").(string)
	keyAlg := d.Get("key_algorithm").(string)
	ttl := d.Get("ttl").(int)

	acct, err := b.getStaticAccount(acctName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return logical.ErrorResponse("static account %q does not exists", acctName), nil
	}
	if acct.SecretType != SecretTypeKey {
		return logical.ErrorResponse("static account %q cannot generate service account keys (has secret type %s)", acctName, acct.SecretType), nil
	}

	params := secretKeyParams{
		keyType:      keyType,
		keyAlgorithm: keyAlg,
		ttl:          ttl,
		extraInternalData: map[string]interface{}{
			"static_account":          acct.Name,
			"static_account_bindings": acct.bindingHash(),
		},
	}

	return b.createServiceAccountKeySecret(ctx, req.Storage, &acct.ServiceAccountId, params)
}

func (b *backend) pathStaticAccountAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	acctName := d.Get("name").(string)

	acct, err := b.getStaticAccount(acctName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return logical.ErrorResponse("static account %q does not exists", acctName), nil
	}
	if acct.SecretType != SecretTypeAccessToken {
		return logical.ErrorResponse("static account %q cannot generate access tokens (has secret type %s)", acctName, acct.SecretType), nil
	}

	return b.secretAccessTokenResponse(ctx, req.Storage, acct.TokenGen)
}
