package gcpsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

func pathImpersonatedAccountSecretAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s/token", impersonatedAccountPathPrefix, framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the impersonated account.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathImpersonatedAccountAccessToken},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathImpersonatedAccountAccessToken},
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

func (b *backend) pathImpersonatedAccountAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	acctName := d.Get("name").(string)

	acct, err := b.getImpersonatedAccount(acctName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return logical.ErrorResponse("impersonated account %q does not exists", acctName), nil
	}

	creds, err := b.credentials(req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	warnings := []string{}
	acctTtl := time.Duration(acct.Ttl) * time.Second
	if acctTtl > config.MaxTTL {
		warnings = append(warnings, fmt.Sprintf("using backend max ttl %q which is less than impersonated account ttl %q for token",
			config.MaxTTL.String(),
			acctTtl.String()))
		acctTtl = config.MaxTTL
	} else if acctTtl == 0 {
		warnings = append(warnings, fmt.Sprintf("using backend default ttl %q since impersonated account ttl not configured for token",
			config.TTL.String()))
		acctTtl = config.TTL
	}

	tokenSource, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: acct.EmailOrId,
		Scopes:          acct.TokenScopes,
		Lifetime:        acctTtl,
	}, option.WithCredentials(creds))
	if err != nil {
		return logical.ErrorResponse("unable to generate token source: %v", err), nil
	}
	token, err := tokenSource.Token()
	if err != nil {
		return logical.ErrorResponse("unable to generate token - make sure your service account and key are still valid: %v", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token":              token.AccessToken,
			"token_ttl":          token.Expiry.UTC().Sub(time.Now().UTC()) / (time.Second),
			"expires_at_seconds": token.Expiry.Unix(),
		},
		Warnings: warnings,
	}, nil
}
