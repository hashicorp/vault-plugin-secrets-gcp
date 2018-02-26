package gcpsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"net/http"
	"net/url"
	"time"
)

const (
	SecretTypeAccessToken     = "access_token"
	revokeAccessTokenEndpoint = "https://accounts.google.com/o/oauth2/revoke"
)

func secretAccessToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeAccessToken,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "OAuth2 token",
			},
		},
		Renew:  b.secretAccessTokenRenew,
		Revoke: secretAccessTokenRevoke,
	}
}

func pathSecretAccessToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("token/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role set.",
			},
			"scopes": {
				Type:        framework.TypeStringSlice,
				Description: `List of OAuth scopes to assign to access tokens generated under this role set`,
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathAccessToken,
			logical.UpdateOperation: b.pathAccessToken,
		},
		HelpSynopsis:    pathTokenHelpSyn,
		HelpDescription: pathTokenHelpDesc,
	}
}

func (b *backend) pathAccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rsName := d.Get("name").(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' does not exists", rsName)), nil
	}

	if rs.SecretType != SecretTypeAccessToken {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' cannot generate access tokens (has secret type %s)", rsName, rs.SecretType)), nil
	}

	scopes := d.Get("scopes").([]string)

	return b.getSecretAccessToken(ctx, req.Storage, rs, scopes)
}

func (b *backend) secretAccessTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Renewal not allowed
	return logical.ErrorResponse("short-term access tokens cannot be renewed - request new access token instead"), nil
}

func secretAccessTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenRaw, ok := req.Secret.InternalData["token"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token internal data")
	}

	resp, err := http.Get(revokeAccessTokenEndpoint + fmt.Sprintf("?token=%s", url.QueryEscape(tokenRaw.(string))))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("revoke returned error: %v", err)), nil
	}

	if err := googleapi.CheckResponse(resp); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

func (b *backend) getSecretAccessToken(ctx context.Context, s logical.Storage, rs *RoleSet, scopes []string) (*logical.Response, error) {
	iamC, err := newIamAdmin(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("could not create IAM Admin client: %v", err)
	}

	// Verify account still exists
	_, err = rs.getServiceAccount(iamC)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if rs.TokenGen == nil || rs.TokenGen.KeyName == "" {
		return logical.ErrorResponse(fmt.Sprintf("invalid role set has no service account key, must be updated (path roleset/%s/rotate-key) before generating new secrets", rs.Name)), nil
	}

	token, err := rs.TokenGen.getAccessToken(iamC, ctx, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	secretD := map[string]interface{}{
		"token": token.AccessToken,
	}
	internalD := map[string]interface{}{
		"token":             token.AccessToken,
		"key_name":          rs.TokenGen.KeyName,
		"role_set":          rs.Name,
		"role_set_bindings": rs.bindingHash(),
	}
	resp := b.Secret(SecretTypeKey).Response(secretD, internalD)
	resp.Secret.LeaseOptions.TTL = token.Expiry.Sub(time.Now())
	resp.Secret.LeaseOptions.Renewable = false

	return resp, err
}

func (tg *TokenGenerator) getAccessToken(iamAdmin *iam.Service, ctx context.Context, scopes []string) (*oauth2.Token, error) {
	key, err := iamAdmin.Projects.ServiceAccounts.Keys.Get(tg.KeyName).Do()
	if err != nil {
		return nil, fmt.Errorf("could not verify key used to generate tokens: %v", err)
	}
	if key == nil {
		return nil, fmt.Errorf("could not find key used to generate tokens, must update role set")
	}

	if len(scopes) == 0 {
		scopes = tg.DefaultScopes
	}

	cfg, err := google.JWTConfigFromJSON([]byte(tg.KeyJSON), scopes...)
	if err != nil {
		return nil, err
	}

	return cfg.TokenSource(ctx).Token()
}
