package gcpsecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"credentials": {
				Type: framework.TypeString,
				Description: strings.TrimSpace(`
Optional Google Cloud service account key credentials JSON.
`),
			},
			"ttl": {
				Type:       framework.TypeDurationSecond,
				Deprecated: true,
				Description: strings.TrimSpace(`
Default lease duration for secrets that support leasing. Setting this value is
deprecated and will be removed in a future release. Use "vault secrets tune"
instead.
`),
			},
			"max_ttl": {
				Type:       framework.TypeDurationSecond,
				Deprecated: true,
				Description: strings.TrimSpace(`
Default maximum duration for secrets that support leasing. Setting this value is
deprecated and will be removed in a future release. Use "vault secrets tune"
instead.
`),
			},
		},
		ExistenceCheck: b.configExistenceCheck(),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
		},
		HelpSynopsis: strings.TrimSpace(`
Configure the Google Cloud secrets engine.
`),
		HelpDescription: strings.TrimSpace(`
This path configures the Google Cloud secrets engine. When running on Google
Cloud or a platform that supports Workload Identity Federation, the Vault server
will automatically use the underlying service account attached to the machine
identity. In these circumstances, specifying the service account key credentials
JSON is unnecessary.
`),
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ttl":     int64(cfg.TTL / time.Second),
			"max_ttl": int64(cfg.MaxTTL / time.Second),
		},
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

func (b *backend) configExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
		cfg, err := getConfig(ctx, req.Storage)
		if err != nil {
			return false, err
		}
		return cfg != nil, nil
	}
}

type config struct {
	CredentialsRaw string

	// TTL and MaxTTL are the default backend TTLs.
	//
	// Deprecated: Use "vault secrets tune" instead.
	TTL    time.Duration
	MaxTTL time.Duration
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

// adjustTTLsFromConfig extracts the current configuration and caps the ttl and
// max_ttl on the provided secret at the max value in the configuration. If the
// config has a value for the TTLs, it adds a warning to the response to push
// the caller to use "vault secrets tune" instead.
//
// TODO(sethvargo): remove this in a future release.
func adjustTTLsFromConfig(ctx context.Context, storage logical.Storage, resp *logical.Response) error {
	cfg, err := getConfig(ctx, storage)
	if err != nil {
		return err
	}
	cfg.adjustTTLs(resp)
	return nil
}

// adjustTTLs adjusts the TTLs on the secret against the provided response. See
// adjustTTLsFromConfig for more information.
//
// TODO(sethvargo): remove this in a future release.
func (c *config) adjustTTLs(resp *logical.Response) {
	if c == nil || resp == nil || resp.Secret == nil {
		return
	}

	if ttl := c.TTL; ttl > 0 {
		resp.AddWarning(`The Google Cloud secrets engine is using a ttl set via ` +
			`the /config path. This approach is deprecated and will be removed in ` +
			`a future release. Use "vault secrets tune" to set the ttl.`)

		if resp.Secret.TTL > ttl {
			resp.Secret.TTL = ttl
		}
	}

	if ttl := c.MaxTTL; ttl > 0 {
		resp.AddWarning(`The Google Cloud secrets engine is using a max_ttl set ` +
			`via the /config path. This approach is deprecated and will be removed ` +
			`in a future release. Use "vault secrets tune" to set the max_ttl.`)

		if resp.Secret.MaxTTL > ttl {
			resp.Secret.MaxTTL = ttl
		}
	}
}
