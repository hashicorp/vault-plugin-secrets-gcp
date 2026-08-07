// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixGoogleCloud,
		},

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
			"service_account_email": {
				Type:        framework.TypeString,
				Description: `Email ID for the Service Account to impersonate for Workload Identity Federation.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Return the GCP secrets engine configuration.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "configuration",
				},
				Responses: map[int][]framework.Response{
					200: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"ttl": {
								Type:        framework.TypeInt,
								Description: "Default lease for generated keys, in seconds.",
							},
							"max_ttl": {
								Type:        framework.TypeInt,
								Description: "Maximum lifetime of generated keys, in seconds.",
							},
							"service_account_email": {
								Type:        framework.TypeString,
								Description: "Email ID of the service account used for Workload Identity Federation.",
							},
							"identity_token_audience": {
								Type:        framework.TypeString,
								Description: "Audience of plugin identity tokens.",
							},
							"identity_token_ttl": {
								Type:        framework.TypeInt,
								Description: "Time-to-live of plugin identity tokens, in seconds.",
							},
							"rotation_schedule": {
								Type:        framework.TypeString,
								Description: "CRON-style schedule for automated root credential rotation.",
							},
							"rotation_window": {
								Type:        framework.TypeInt,
								Description: "Time window in seconds for automated rotation to complete.",
							},
							"rotation_period": {
								Type:        framework.TypeInt,
								Description: "Period in seconds between automated root credential rotations.",
							},
							"disable_automated_rotation": {
								Type:        framework.TypeBool,
								Description: "Whether automated rotation is disabled.",
							},
							"rotation_policy": {
								Type:        framework.TypeString,
								Description: "Name of the rotation policy for automated root credential rotation.",
							},
						},
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the GCP secrets engine.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
				Responses: map[int][]framework.Response{
					204: {{Description: "No Content"}},
				},
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}

	pluginidentityutil.AddPluginIdentityTokenFields(p.Fields)
	automatedrotationutil.AddAutomatedRotationFields(p.Fields)

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
		"ttl":                   int64(cfg.TTL / time.Second),
		"max_ttl":               int64(cfg.MaxTTL / time.Second),
		"service_account_email": cfg.ServiceAccountEmail,
	}

	cfg.PopulatePluginIdentityTokenData(configData)
	cfg.PopulateAutomatedRotationData(configData)

	return &logical.Response{
		Data: configData,
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Check for existing config.
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

	// set plugin identity token fields
	if err := cfg.ParsePluginIdentityTokenFields(data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// set Service Account email
	saEmail, ok := data.GetOk("service_account_email")
	if ok {
		cfg.ServiceAccountEmail = saEmail.(string)
	}

	if cfg.IdentityTokenAudience != "" && cfg.CredentialsRaw != "" {
		return logical.ErrorResponse("only one of 'credentials' or 'identity_token_audience' can be set"), nil
	}

	if cfg.IdentityTokenAudience != "" && cfg.ServiceAccountEmail == "" {
		return logical.ErrorResponse("missing required 'service_account_email' when 'identity_token_audience' is set"), nil
	}

	// generate token to check if WIF is enabled on this edition of Vault
	if cfg.IdentityTokenAudience != "" {
		_, err := b.System().GenerateIdentityToken(ctx, &pluginutil.IdentityTokenRequest{
			Audience: cfg.IdentityTokenAudience,
		})
		if err != nil {
			if errors.Is(err, pluginidentityutil.ErrPluginWorkloadIdentityUnsupported) {
				return logical.ErrorResponse(err.Error()), nil
			}
			return nil, err
		}
	}

	// if token audience or TTL is being updated, ensure cached credentials are cleared
	_, audOk := data.GetOk("identity_token_audience")
	_, ttlOk := data.GetOk("identity_token_ttl")
	if audOk || ttlOk {
		setNewCreds = true
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

	rotationResp, err := cfg.HandleRotationJob(ctx, b.Backend, data, req)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	cfg.SetRotationInfo(rotationResp.RotationInfo)

	err = writeConfig(ctx, req.Storage, *cfg)
	_ = rotationResp.HandleStorageErrorAfterRotationJob(req, err)

	if setNewCreds {
		b.ClearCaches()
	}
	return nil, nil
}

type config struct {
	CredentialsRaw string

	TTL    time.Duration
	MaxTTL time.Duration

	ServiceAccountEmail string
	pluginidentityutil.PluginIdentityTokenParams
	automatedrotationutil.AutomatedRotationParams
	automatedrotationutil.RotationInfoResponseParams
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

func writeConfig(ctx context.Context, storage logical.Storage, config config) (err error) {
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}
	err = storage.Put(ctx, entry)
	if err != nil {
		return err
	}
	return nil
}

const pathConfigHelpSyn = `Configure the GCP secrets engine.`

const pathConfigHelpDesc = `
The GCP backend requires credentials for managing IAM service accounts and keys
and IAM policies on various GCP resources. This endpoint is used to configure
those credentials as well as default values for the backend in general.
`
