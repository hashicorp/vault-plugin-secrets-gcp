package gcpsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathStaticAccountSecretServiceAccountKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:    fmt.Sprintf("%s/%s/key", staticAccountPathPrefix, framework.GenericNameRegex("static_account")),
		Deprecated: true,
		Fields: map[string]*framework.FieldSchema{
			"static_account": {
				Type:        framework.TypeString,
				Description: "Required. Name of the static_account.",
			},
			"key_algorithm": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key algorithm for service account key - defaults to %s"`, keyAlgorithmRSA2k),
				Default:     keyAlgorithmRSA2k,
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf(`Private key type for service account key - defaults to %s"`, privateKeyTypeJson),
				Default:     privateKeyTypeJson,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Lifetime of the service account key",
			},
		},
		ExistenceCheck: b.pathStaticAccountExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticAccountSecretKey},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticAccountSecretKey},
		},
		HelpSynopsis:    pathServiceAccountKeySyn,
		HelpDescription: pathServiceAccountKeyDesc,
	}
}

func pathStaticAccountSecretAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:    fmt.Sprintf("%s/%s/token", staticAccountPathPrefix, framework.GenericNameRegex("static_account")),
		Deprecated: true,
		Fields: map[string]*framework.FieldSchema{
			"static_account": {
				Type:        framework.TypeString,
				Description: "Required. Name of the static_account.",
			},
		},
		ExistenceCheck: b.pathStaticAccountExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticAccountAccessToken},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticAccountAccessToken},
		},
		HelpSynopsis:    pathServiceAccountKeySyn,
		HelpDescription: pathServiceAccountKeyDesc,
	}
}

func (b *backend) pathStaticAccountSecretKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	acctName := d.Get("static_account").(string)
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
	acctName := d.Get("static_account").(string)

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
