package gcpsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	stsTokenURL                = "https://sts.googleapis.com/v1/token"
	defaultJWTSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
)

func pathConfig(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"credentials": {
				Type:        framework.TypeString,
				Description: `GCP IAM service account credentials JSON with permissions to create new service accounts and set IAM policies`,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease for generated keys. If <= 0, will use system default.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum time a service account key is valid for. If <= 0, will use system default.",
			},
			"project_id": {
				Type:        framework.TypeString,
				Description: `Project ID for the Google Project.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
	pluginidentityutil.AddPluginIdentityTokenFields(p.Fields)

	return p
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	configData := map[string]interface{}{
		"ttl":     int64(cfg.TTL / time.Second),
		"max_ttl": int64(cfg.MaxTTL / time.Second),
	}

	cfg.PopulatePluginIdentityTokenData(configData)

	return &logical.Response{
		Data: configData,
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	credentialsRaw, setNewCreds := data.GetOk("credentials")
	if setNewCreds {
		_, err := gcputil.Credentials(credentialsRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid credentials JSON file: %v", err)), nil
		}
		cfg.CredentialsRaw = credentialsRaw.(string)
	}

	// set namespace to config
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to get namespace from context: %v", err)), nil
	}
	cfg.Namespace = ns

	// set plugin identity token fields
	if err := cfg.ParsePluginIdentityTokenFields(data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// set project ID
	projectID, ok := data.GetOk("project_id")
	if ok {
		cfg.ProjectID = projectID.(string)
	}

	// Update token TTL.
	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		cfg.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	// Update token Max TTL.
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if ok {
		cfg.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if setNewCreds {
		b.ClearCaches()
	}
	return nil, nil
}

type config struct {
	CredentialsRaw string
	Namespace      *namespace.Namespace

	TTL    time.Duration
	MaxTTL time.Duration

	pluginidentityutil.PluginIdentityTokenParams
	ProjectID             string
	SubjectTokenType      string
	TokenURL              string
	WorkloadIdentityToken string
}

func (c *config) GetExternalAccountConfig() *gcputil.ExternalAccountCredential {
	cred := &gcputil.ExternalAccountCredential{
		Audience:              c.IdentityTokenAudience,
		ProjectID:             c.ProjectID,
		SubjectTokenType:      c.SubjectTokenType,
		TokenURL:              c.TokenURL,
		Scopes:                []string{"https://www.googleapis.com/auth/cloud-platform"},
		WorkloadIdentityToken: c.WorkloadIdentityToken,
	}

	return cred
}

func getConfig(ctx context.Context, s logical.Storage) (*config, error) {
	var cfg config
	cfgRaw, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if cfgRaw == nil {
		return nil, nil
	}

	if err := cfgRaw.DecodeJSON(&cfg); err != nil {
		return nil, err
	}

	return &cfg, err
}

const pathConfigHelpSyn = `
Configure the GCP backend.
`

const pathConfigHelpDesc = `
The GCP backend requires credentials for managing IAM service accounts and keys
and IAM policies on various GCP resources. This endpoint is used to configure
those credentials as well as default values for the backend in general.
`
