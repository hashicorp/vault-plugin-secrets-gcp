// Copyright IBM Corp. 2018, 2026
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/cache"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
)

const userAgentPluginName = "secrets-gcp"

const (
	// cacheTime is the duration for which to cache clients and credentials. This
	// must be less than 60 minutes.
	cacheTime = 30 * time.Minute

	// operationPrefixGoogleCloud is used as a prefix for OpenAPI operation id's.
	operationPrefixGoogleCloud = "google-cloud"
)

type backend struct {
	*framework.Backend

	// cache stores credentials and other cached objects. Authenticated API
	// clients are bound to the credentials object used to create them.
	cache                *cache.Cache
	credentialClientLock sync.Mutex
	credentialClient     *credentialClient
	identityLock         sync.RWMutex
	// mountServiceAccountIdentityLock protects the resolved identity for an
	// impersonated service account whose credentials use a numeric ID.
	mountServiceAccountIdentityLock  sync.Mutex
	mountServiceAccountIdentityID    string
	mountServiceAccountIdentityEmail string

	// pluginEnv contains Vault version information. It is used in user-agent headers.
	pluginEnv *logical.PluginEnvironment

	resources iamutil.ResourceParser

	rolesetLock             sync.Mutex
	staticAccountLock       sync.Mutex
	impersonatedAccountLock sync.Mutex
}

type credentialClient struct {
	credentials *google.Credentials
	state       *credentialState
	httpClient  *http.Client
	iamClient   *iam.Service
}

// credentialState keeps the WIF identity paired with the credentials loaded
// from the same config snapshot.
type credentialState struct {
	credentials                 *google.Credentials
	mountServiceAccountIdentity string
	identityFromWIFConfig       bool
	identityFromMetadata        bool
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	b := &backend{
		cache:     cache.New(),
		resources: iamutil.GetEnabledResources(),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathConfigRotateRoot(b),
				// Roleset
				pathRoleSet(b),
				pathRoleSetList(b),
				pathRoleSetRotateAccount(b),
				pathRoleSetRotateKey(b),
				pathRoleSetSecretAccessToken(b),
				pathRoleSetSecretServiceAccountKey(b),
				deprecatedPathRoleSetSecretAccessToken(b),
				deprecatedPathRoleSetSecretServiceAccountKey(b),
				// Static Account
				pathStaticAccount(b),
				pathStaticAccountList(b),
				pathStaticAccountRotateKey(b),
				pathStaticAccountSecretAccessToken(b),
				pathStaticAccountSecretServiceAccountKey(b),
				// Impersonate
				pathImpersonatedAccount(b),
				pathImpersonatedAccountList(b),
				pathImpersonatedAccountSecretAccessToken(b),
			},
		),
		Secrets: []*framework.Secret{
			secretAccessToken(b),
			secretServiceAccountKey(b),
		},

		InitializeFunc:   b.initialize,
		Invalidate:       b.invalidate,
		RotateCredential: b.rotateRootCredential,

		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,
	}

	return b
}

func (b *backend) initialize(ctx context.Context, _ *logical.InitializationRequest) error {
	pluginEnv, err := b.System().PluginEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to read plugin environment: %w", err)
	}
	b.pluginEnv = pluginEnv

	return nil
}

// IAMAdminClient returns the IAM client bound to the current credentials.
func (b *backend) IAMAdminClient(s logical.Storage) (*iam.Service, error) {
	clients, err := b.credentialClients(s)
	if err != nil {
		return nil, errwrap.Wrapf("failed to create IAM HTTP client: {{err}}", err)
	}

	return b.iamAdminClient(clients)
}

func (b *backend) iamAdminClient(clients *credentialClient) (*iam.Service, error) {
	b.credentialClientLock.Lock()
	defer b.credentialClientLock.Unlock()

	if clients.iamClient == nil {
		client, err := iam.NewService(context.Background(), option.WithHTTPClient(clients.httpClient))
		if err != nil {
			return nil, errwrap.Wrapf("failed to create IAM client: {{err}}", err)
		}
		client.UserAgent = useragent.PluginString(b.pluginEnv, userAgentPluginName)
		clients.iamClient = client
	}

	return clients.iamClient, nil
}

// HTTPClient returns the HTTP client bound to the current credentials.
func (b *backend) HTTPClient(s logical.Storage) (*http.Client, error) {
	clients, err := b.credentialClients(s)
	if err != nil {
		return nil, errwrap.Wrapf("failed to create oauth2 http client: {{err}}", err)
	}

	return clients.httpClient, nil
}

func (b *backend) credentialClients(s logical.Storage) (*credentialClient, error) {
	state, err := b.credentialState(s)
	if err != nil {
		return nil, err
	}

	b.credentialClientLock.Lock()
	defer b.credentialClientLock.Unlock()

	if b.credentialClient == nil || b.credentialClient.state != state {
		b.Logger().Debug("creating oauth2 http client")
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())
		b.credentialClient = &credentialClient{
			credentials: state.credentials,
			state:       state,
			httpClient:  oauth2.NewClient(ctx, state.credentials.TokenSource),
		}
	}

	return b.credentialClient, nil
}

// credentials returns the credentials which were specified in the
// configuration. If no credentials were given during configuration, this uses
// default application credentials. If no default application credentials are
// found, this function returns an error. The credentials are cached in-memory
// for performance.
func (b *backend) credentials(s logical.Storage) (*google.Credentials, error) {
	state, err := b.credentialState(s)
	if err != nil {
		return nil, err
	}
	return state.credentials, nil
}

func (b *backend) credentialState(s logical.Storage) (*credentialState, error) {
	cachedState, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) {
		b.Logger().Debug("loading credentials")

		ctx := context.Background()

		cfg, err := getConfig(ctx, s)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = &config{}
		}
		// Get creds from the config
		credBytes := []byte(cfg.CredentialsRaw)

		// If credentials were provided, use those. Otherwise fall back to the
		// default application credentials.
		var creds *google.Credentials
		if len(credBytes) > 0 {
			creds, err = google.CredentialsFromJSON(ctx, credBytes, iam.CloudPlatformScope)
			if err != nil {
				return nil, errwrap.Wrapf("failed to parse credentials: {{err}}", err)
			}
		} else if cfg.IdentityTokenAudience != "" {
			ts := &PluginIdentityTokenSupplier{
				sys:      b.System(),
				logger:   b.Logger(),
				audience: cfg.IdentityTokenAudience,
				ttl:      cfg.IdentityTokenTTL,
			}

			creds, err = b.GetExternalAccountConfig(cfg, ts).GetExternalAccountCredentials(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch external account credentials: %w", err)
			}
		} else {
			creds, err = google.FindDefaultCredentials(ctx, iam.CloudPlatformScope)
			if err != nil {
				return nil, errwrap.Wrapf("failed to get default credentials: {{err}}", err)
			}
		}

		var metadataIdentity string
		identityFromMetadata := len(credBytes) == 0 &&
			cfg.IdentityTokenAudience == "" &&
			len(creds.JSON) == 0
		if identityFromMetadata {
			metadataIdentity, err = metadata.EmailWithContext(ctx, "default")
			if err != nil {
				return nil, fmt.Errorf("failed to determine metadata service account identity: %w", err)
			}
			if metadataIdentity == "" {
				return nil, fmt.Errorf("failed to determine metadata service account identity: empty email")
			}
		}

		mountIdentity := cfg.ServiceAccountEmail
		if identityFromMetadata {
			mountIdentity = metadataIdentity
		}

		return &credentialState{
			credentials:                 creds,
			mountServiceAccountIdentity: mountIdentity,
			identityFromWIFConfig:       cfg.IdentityTokenAudience != "",
			identityFromMetadata:        identityFromMetadata,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	state, ok := cachedState.(*credentialState)
	if !ok {
		return nil, fmt.Errorf("cached credentials have unexpected type %T", cachedState)
	}
	return state, nil
}

func (b *backend) GetExternalAccountConfig(c *config, ts *PluginIdentityTokenSupplier) *gcputil.ExternalAccountConfig {
	b.Logger().Debug("adding web identity token fetcher")
	cfg := &gcputil.ExternalAccountConfig{
		ServiceAccountEmail: c.ServiceAccountEmail,
		Audience:            c.IdentityTokenAudience,
		TTL:                 c.IdentityTokenTTL,
		TokenSupplier:       ts,
	}

	return cfg
}

type PluginIdentityTokenSupplier struct {
	sys      logical.SystemView
	logger   hclog.Logger
	audience string
	ttl      time.Duration
}

var _ externalaccount.SubjectTokenSupplier = (*PluginIdentityTokenSupplier)(nil)

func (p *PluginIdentityTokenSupplier) SubjectToken(ctx context.Context, opts externalaccount.SupplierOptions) (string, error) {
	p.logger.Info("fetching new plugin identity token")
	resp, err := p.sys.GenerateIdentityToken(ctx, &pluginutil.IdentityTokenRequest{
		Audience: p.audience,
		TTL:      p.ttl,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate plugin identity token: %w", err)
	}

	if resp.TTL < p.ttl {
		p.logger.Debug("generated plugin identity token has shorter TTL than requested",
			"requested", p.ttl.Seconds(), "actual", resp.TTL)
	}

	return resp.Token.Token(), nil
}

// ClearCaches deletes all cached clients and credentials.
func (b *backend) ClearCaches() {
	b.identityLock.Lock()
	defer b.identityLock.Unlock()
	b.clearCaches()
}

func (b *backend) clearCaches() {
	b.cache.Clear()
	b.credentialClientLock.Lock()
	b.credentialClient = nil
	b.credentialClientLock.Unlock()
}

// invalidate resets the plugin. This is called when a key is updated via
// replication.
func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.ClearCaches()
	}
}

const backendHelp = `
The GCP secrets engine dynamically generates Google Cloud service account keys
and OAuth access tokens based on predefined Cloud IAM policies. This enables
users to gain access to Google Cloud resources without needing to create or
manage a dedicated Google Cloud service account.

After mounting this secrets engine, you can configure the credentials using the
"config/" endpoints. You can generate rolesets using the "rolesets/" endpoints.
`
