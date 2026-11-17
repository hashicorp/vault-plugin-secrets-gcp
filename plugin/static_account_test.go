// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

const (
	staticIdentityProject     = "test-project"
	staticIdentityRootEmail   = "mount@test-project.iam.gserviceaccount.com"
	staticIdentityRootID      = "123456789012345678901"
	staticIdentityOtherEmail  = "other@test-project.iam.gserviceaccount.com"
	staticIdentityOtherID     = "987654321098765432109"
	staticIdentitySourceEmail = "source@test-project.iam.gserviceaccount.com"

	staticIdentityImpersonationURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + staticIdentityRootEmail + ":generateAccessToken"
	staticIdentityTokenURL         = "https://oauth2.googleapis.com/token"
	staticIdentityIssuedToken      = "issued-access-token"

	staticIdentitySelfTargetError = "static account cannot target the GCP secrets engine's own service account"
)

// staticIdentityConfigs returns mount configurations whose service account
// (staticIdentityRootEmail) can be determined from config alone.
func staticIdentityConfigs(t *testing.T) []struct {
	name string
	cfg  config
} {
	t.Helper()
	return []struct {
		name string
		cfg  config
	}{
		{"service_account credentials", config{CredentialsRaw: staticIdentityJSON(t, map[string]interface{}{
			"type": "service_account", "project_id": staticIdentityProject,
			"client_email": staticIdentityRootEmail, "client_id": staticIdentityRootID,
			"private_key_id": "fake-key-id", "private_key": "fake-key", "token_uri": staticIdentityTokenURL,
		})}},
		{"impersonated_service_account credentials", config{CredentialsRaw: staticIdentityJSON(t, map[string]interface{}{
			"type":                              "impersonated_service_account",
			"service_account_impersonation_url": staticIdentityImpersonationURL,
			"source_credentials": map[string]interface{}{
				"type": "service_account", "client_email": staticIdentitySourceEmail,
				"private_key_id": "fake-key-id", "private_key": "fake-key", "token_uri": staticIdentityTokenURL,
			},
		})}},
		{"external_account credentials with impersonation", config{CredentialsRaw: staticIdentityJSON(t, map[string]interface{}{
			"type":                              "external_account",
			"audience":                          "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider",
			"subject_token_type":                "urn:ietf:params:oauth:token-type:jwt",
			"token_url":                         "https://sts.googleapis.com/v1/token",
			"service_account_impersonation_url": staticIdentityImpersonationURL,
			"credential_source":                 map[string]interface{}{"file": "/dev/null"},
		})}},
		{"plugin workload identity federation", config{
			PluginIdentityTokenParams: pluginidentityutil.PluginIdentityTokenParams{
				IdentityTokenAudience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/vault",
			},
			ServiceAccountEmail: staticIdentityRootEmail,
		}},
	}
}

func TestStaticAccountIdentity_Create(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		for _, target := range []string{staticIdentityRootEmail, staticIdentityRootID} {
			for _, secretType := range []string{SecretTypeKey, SecretTypeAccessToken} {
				t.Run(fmt.Sprintf("%s/%s/%s", mount.name, target, secretType), func(t *testing.T) {
					b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)

					resp, err := b.HandleRequest(ctx, &logical.Request{
						Operation: logical.CreateOperation,
						Path:      "static-account/self-test",
						Storage:   storage,
						Data: map[string]interface{}{
							"service_account_email": target,
							"secret_type":           secretType,
							"token_scopes":          []string{iam.CloudPlatformScope},
						},
					})

					assertStaticAccountIdentityRejected(t, resp, err, transport)
					entry, err := storage.Get(ctx, "static-account/self-test")
					require.NoError(t, err)
					assert.Nil(t, entry, "must not persist a static account targeting the mount identity")
				})
			}
		}
	}
}

func TestStaticAccountIdentity_MetadataCredentials(t *testing.T) {
	t.Run("create/no-config", func(t *testing.T) {
		b, storage, transport, ctx := setupStaticAccountMetadataTest(t, staticIdentityRootEmail)
		require.NoError(t, storage.Delete(ctx, "config"))

		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "static-account/self-test",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_email": staticIdentityRootEmail,
				"secret_type":           SecretTypeKey,
			},
		})

		assertStaticAccountIdentityRejected(t, resp, err, transport)
		entry, err := storage.Get(ctx, "static-account/self-test")
		require.NoError(t, err)
		assert.Nil(t, entry, "must not persist a static account targeting the mount identity")
	})

	for _, target := range []string{staticIdentityRootEmail, staticIdentityRootID} {
		for _, secretType := range []string{SecretTypeKey, SecretTypeAccessToken} {
			t.Run(fmt.Sprintf("create/%s/%s", target, secretType), func(t *testing.T) {
				b, storage, transport, ctx := setupStaticAccountMetadataTest(t, staticIdentityRootEmail)

				resp, err := b.HandleRequest(ctx, &logical.Request{
					Operation: logical.CreateOperation,
					Path:      "static-account/self-test",
					Storage:   storage,
					Data: map[string]interface{}{
						"service_account_email": target,
						"secret_type":           secretType,
						"token_scopes":          []string{iam.CloudPlatformScope},
					},
				})

				assertStaticAccountIdentityRejected(t, resp, err, transport)
				entry, err := storage.Get(ctx, "static-account/self-test")
				require.NoError(t, err)
				assert.Nil(t, entry, "must not persist a static account targeting the mount identity")
			})
		}
	}

	for _, target := range []gcputil.ServiceAccountId{
		{Project: "-", EmailOrId: staticIdentityRootEmail},
		{Project: staticIdentityProject, EmailOrId: staticIdentityRootID},
	} {
		for _, tc := range []struct {
			name       string
			suffix     string
			operation  logical.Operation
			secretType string
		}{
			{"read-key", "/key", logical.ReadOperation, SecretTypeKey},
			{"write-key", "/key", logical.UpdateOperation, SecretTypeKey},
			{"read-token", "/token", logical.ReadOperation, SecretTypeAccessToken},
			{"write-token", "/token", logical.UpdateOperation, SecretTypeAccessToken},
			{"update-key-account", "", logical.UpdateOperation, SecretTypeKey},
			{"update-token-account", "", logical.UpdateOperation, SecretTypeAccessToken},
			{"rotate-key", "/rotate-key", logical.UpdateOperation, SecretTypeAccessToken},
		} {
			t.Run(fmt.Sprintf("existing/%s/%s", target.ResourceName(), tc.name), func(t *testing.T) {
				b, storage, transport, ctx := setupStaticAccountMetadataTest(t, staticIdentityRootEmail)
				account := &StaticAccount{
					Name:             "self-test",
					SecretType:       tc.secretType,
					ServiceAccountId: target,
				}
				if tc.secretType == SecretTypeAccessToken {
					account.TokenGen = &TokenGenerator{
						KeyName:    target.ResourceName() + "/keys/old",
						B64KeyJSON: staticIdentityKeyData(t, staticIdentityRootEmail),
						Scopes:     []string{iam.CloudPlatformScope},
					}
				}
				require.NoError(t, account.save(ctx, storage))
				before, err := storage.Get(ctx, "static-account/self-test")
				require.NoError(t, err)

				req := &logical.Request{
					Operation: tc.operation,
					Path:      "static-account/self-test" + tc.suffix,
					Storage:   storage,
				}
				if tc.suffix == "" {
					req.Data = map[string]interface{}{
						"service_account_email": target.EmailOrId,
						"secret_type":           tc.secretType,
					}
				}
				resp, err := b.HandleRequest(ctx, req)

				assertStaticAccountIdentityRejected(t, resp, err, transport)
				after, err := storage.Get(ctx, "static-account/self-test")
				require.NoError(t, err)
				require.NotNil(t, after)
				assert.True(t, bytes.Equal(before.Value, after.Value), "rejected requests must not change the stored account")
			})
		}
	}

	for _, secretType := range []string{SecretTypeKey, SecretTypeAccessToken} {
		t.Run("other-account/"+secretType, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountMetadataTest(t, staticIdentityRootEmail)
			createStaticIdentityAccount(t, ctx, b, storage, "other", secretType)

			if secretType == SecretTypeKey {
				for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
					resp := handleStaticIdentityRequest(t, ctx, b, storage, op, "static-account/other/key", nil)
					assert.NotEmpty(t, resp.Data["private_key_data"])
					require.NotNil(t, resp.Secret)
				}
			} else {
				for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
					resp := handleStaticIdentityRequest(t, ctx, b, storage, op, "static-account/other/token", nil)
					assert.Equal(t, staticIdentityIssuedToken, resp.Data["token"])
				}
				handleStaticIdentityRequest(t, ctx, b, storage, logical.UpdateOperation, "static-account/other/rotate-key", nil)
			}
			assert.Equal(t, []string{staticIdentityOtherID, staticIdentityOtherID}, transport.keyCreates)
		})
	}
}

func TestStaticAccountIdentity_ADCCredentialsFile(t *testing.T) {
	for _, tc := range []struct {
		name                string
		fileEmail           string
		metadataEmail       string
		rejectStaticAccount bool
	}{
		{
			name:                "file identity matches target",
			fileEmail:           staticIdentityRootEmail,
			metadataEmail:       staticIdentityOtherEmail,
			rejectStaticAccount: true,
		},
		{
			name:          "metadata identity matches target but file does not",
			fileEmail:     staticIdentityOtherEmail,
			metadataEmail: staticIdentityRootEmail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountMetadataTestWithADCFile(t, tc.metadataEmail, tc.fileEmail)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "static-account/target",
				Storage:   storage,
				Data: map[string]interface{}{
					"service_account_email": staticIdentityRootEmail,
					"secret_type":           SecretTypeKey,
				},
			})

			if tc.rejectStaticAccount {
				assertStaticAccountIdentityRejected(t, resp, err, transport)
				entry, err := storage.Get(ctx, "static-account/target")
				require.NoError(t, err)
				assert.Nil(t, entry, "must not persist a static account targeting the ADC identity")
				return
			}

			require.NoError(t, err)
			if resp != nil {
				require.False(t, resp.IsError(), "targeting metadata identity must be allowed when ADC uses another account")
			}
			entry, err := storage.Get(ctx, "static-account/target")
			require.NoError(t, err)
			assert.NotNil(t, entry, "must persist a static account that does not target the ADC identity")
			assert.Empty(t, transport.keyCreates)
		})
	}
}

// TestStaticAccountIdentity_ExistingAccount models static accounts saved before
// the protection existed, so each credential-producing path must check again.
func TestStaticAccountIdentity_ExistingAccount(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		for _, target := range []gcputil.ServiceAccountId{
			{Project: "-", EmailOrId: staticIdentityRootEmail},
			{Project: staticIdentityProject, EmailOrId: staticIdentityRootID},
		} {
			for _, tc := range []struct {
				name       string
				suffix     string
				operation  logical.Operation
				secretType string
			}{
				{"read-key", "/key", logical.ReadOperation, SecretTypeKey},
				{"write-key", "/key", logical.UpdateOperation, SecretTypeKey},
				{"read-token", "/token", logical.ReadOperation, SecretTypeAccessToken},
				{"write-token", "/token", logical.UpdateOperation, SecretTypeAccessToken},
				{"update-key-account", "", logical.UpdateOperation, SecretTypeKey},
				{"update-token-account", "", logical.UpdateOperation, SecretTypeAccessToken},
				{"rotate-key", "/rotate-key", logical.UpdateOperation, SecretTypeAccessToken},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", mount.name, target.ResourceName(), tc.name), func(t *testing.T) {
					b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)

					account := &StaticAccount{
						Name:             "self-test",
						SecretType:       tc.secretType,
						ServiceAccountId: target,
					}
					if tc.secretType == SecretTypeAccessToken {
						account.TokenGen = &TokenGenerator{
							KeyName:    target.ResourceName() + "/keys/old",
							B64KeyJSON: staticIdentityKeyData(t, staticIdentityRootEmail),
							Scopes:     []string{iam.CloudPlatformScope},
						}
					}
					require.NoError(t, account.save(ctx, storage))
					before, err := storage.Get(ctx, "static-account/self-test")
					require.NoError(t, err)

					req := &logical.Request{
						Operation: tc.operation,
						Path:      "static-account/self-test" + tc.suffix,
						Storage:   storage,
					}
					if tc.suffix == "" {
						req.Data = map[string]interface{}{
							"service_account_email": target.EmailOrId,
							"secret_type":           tc.secretType,
						}
					}
					resp, err := b.HandleRequest(ctx, req)

					assertStaticAccountIdentityRejected(t, resp, err, transport)
					after, err := storage.Get(ctx, "static-account/self-test")
					require.NoError(t, err)
					require.NotNil(t, after)
					assert.True(t, bytes.Equal(before.Value, after.Value), "rejected requests must not change the stored account")
				})
			}
		}
	}
}

// TestStaticAccountIdentity_OtherAccount makes sure the protection does not
// block static accounts for other service accounts.
func TestStaticAccountIdentity_OtherAccount(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		t.Run(mount.name+"/"+SecretTypeKey, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)
			createStaticIdentityAccount(t, ctx, b, storage, "other", SecretTypeKey)

			for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
				resp := handleStaticIdentityRequest(t, ctx, b, storage, op, "static-account/other/key", nil)
				assert.NotEmpty(t, resp.Data["private_key_data"])
				require.NotNil(t, resp.Secret)
				assert.Equal(t, "other", resp.Secret.InternalData["static_account"])
			}
			handleStaticIdentityRequest(t, ctx, b, storage, logical.UpdateOperation, "static-account/other", map[string]interface{}{
				"service_account_email": staticIdentityOtherEmail,
				"secret_type":           SecretTypeKey,
			})
			assert.Equal(t, []string{staticIdentityOtherID, staticIdentityOtherID}, transport.keyCreates)
		})

		t.Run(mount.name+"/"+SecretTypeAccessToken, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)
			createStaticIdentityAccount(t, ctx, b, storage, "other", SecretTypeAccessToken)

			for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
				resp := handleStaticIdentityRequest(t, ctx, b, storage, op, "static-account/other/token", nil)
				assert.Equal(t, staticIdentityIssuedToken, resp.Data["token"])
			}
			handleStaticIdentityRequest(t, ctx, b, storage, logical.UpdateOperation, "static-account/other/rotate-key", nil)
			handleStaticIdentityRequest(t, ctx, b, storage, logical.UpdateOperation, "static-account/other", map[string]interface{}{
				"service_account_email": staticIdentityOtherEmail,
				"secret_type":           SecretTypeAccessToken,
			})
			assert.Equal(t, []string{staticIdentityOtherID, staticIdentityOtherID}, transport.keyCreates)
			assert.Equal(t, 2, transport.tokensIssued)
		})
	}
}

func createStaticIdentityAccount(t *testing.T, ctx context.Context, b *backend, storage logical.Storage, name, secretType string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-account/" + name,
		Storage:   storage,
		Data: map[string]interface{}{
			"service_account_email": staticIdentityOtherEmail,
			"secret_type":           secretType,
			"token_scopes":          []string{iam.CloudPlatformScope},
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.IsError(), "creating a static account for another service account must succeed: %v", resp.Error())
}

func handleStaticIdentityRequest(t *testing.T, ctx context.Context, b *backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage, Data: data})
	require.NoError(t, err)
	if resp == nil {
		return &logical.Response{}
	}
	require.False(t, resp.IsError(), "%s %s must succeed: %v", op, path, resp.Error())
	return resp
}

func assertStaticAccountIdentityRejected(t *testing.T, resp *logical.Response, err error, transport *staticAccountIdentityTransport) {
	t.Helper()
	if err == nil && resp != nil {
		err = resp.Error()
	}
	require.Error(t, err, "must reject the mount's own service account")
	assert.Contains(t, err.Error(), staticIdentitySelfTargetError)
	if resp != nil {
		assert.NotContains(t, resp.Data, "private_key_data", "must not return a key for the mount identity")
		assert.NotContains(t, resp.Data, "token", "must not return a token for the mount identity")
		assert.Nil(t, resp.Secret, "must not issue a secret for the mount identity")
	}
	assert.Empty(t, transport.keyCreates, "must not create keys for the mount identity")
	assert.Zero(t, transport.tokensIssued, "must not issue tokens for the mount identity")
}

// setupStaticAccountIdentityTest returns a backend whose credentials and HTTP
// clients are mocked so no request can reach GCP. The returned context also
// routes service account key token exchanges through the mock.
func setupStaticAccountIdentityTest(t *testing.T, cfg config) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	b, storage := getTestBackend(t)
	require.NoError(t, writeConfig(context.Background(), storage, cfg))

	transport := &staticAccountIdentityTransport{t: t}
	creds := &google.Credentials{
		ProjectID:   staticIdentityProject,
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"}),
	}
	if cfg.CredentialsRaw != "" {
		creds.JSON = []byte(cfg.CredentialsRaw)
	}
	_, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return creds, nil })
	require.NoError(t, err)
	client := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: transport}}
	_, err = b.cache.Fetch("HTTPClient", cacheTime, func() (interface{}, error) { return client, nil })
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport})
	return b, storage, transport, ctx
}

func setupStaticAccountMetadataTest(t *testing.T, email string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/email" ||
			r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("unexpected metadata request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected metadata request", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, email)
	}))
	t.Cleanup(metadataServer.Close)
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(metadataServer.URL, "http://"))
	return setupStaticAccountIdentityTest(t, config{})
}

func setupStaticAccountMetadataTestWithADCFile(t *testing.T, metadataEmail, fileEmail string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	b, storage, transport, ctx := setupStaticAccountMetadataTest(t, metadataEmail)
	creds := &google.Credentials{
		ProjectID: staticIdentityProject,
		JSON: []byte(staticIdentityJSON(t, map[string]string{
			"type": "service_account", "project_id": staticIdentityProject,
			"client_email": fileEmail, "client_id": staticIdentityRootID,
			"private_key_id": "fake-key-id", "private_key": "fake-key",
			"token_uri": staticIdentityTokenURL,
		})),
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"}),
	}
	b.cache.Expire("credentials")
	_, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return creds, nil })
	require.NoError(t, err)
	return b, storage, transport, ctx
}

var staticIdentityPrivateKeyPEM = sync.OnceValue(func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
})

// staticIdentityKeyData returns base64 service account key JSON that can be
// exchanged for an access token through the mocked token endpoint.
func staticIdentityKeyData(t *testing.T, email string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(staticIdentityJSON(t, map[string]interface{}{
		"type": "service_account", "project_id": staticIdentityProject, "client_email": email,
		"private_key_id": "test-key-id", "private_key": staticIdentityPrivateKeyPEM(), "token_uri": staticIdentityTokenURL,
	})))
}

func staticIdentityJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

type staticAccountIdentityTransport struct {
	t            *testing.T
	mu           sync.Mutex
	keyCreates   []string
	tokensIssued int
}

func (tr *staticAccountIdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	var response interface{}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/"), "/")
	switch {
	case req.Method == http.MethodPost && req.URL.String() == staticIdentityTokenURL:
		tr.tokensIssued++
		response = map[string]interface{}{"access_token": staticIdentityIssuedToken, "token_type": "Bearer", "expires_in": 3600}
	case req.URL.Host == "iam.googleapis.com" && len(parts) >= 4 &&
		parts[0] == "projects" && (parts[1] == "-" || parts[1] == staticIdentityProject) && parts[2] == "serviceAccounts":
		account := &iam.ServiceAccount{ProjectId: staticIdentityProject}
		switch parts[3] {
		case staticIdentityRootEmail, staticIdentityRootID:
			account.Email, account.UniqueId = staticIdentityRootEmail, staticIdentityRootID
		case staticIdentityOtherEmail, staticIdentityOtherID:
			account.Email, account.UniqueId = staticIdentityOtherEmail, staticIdentityOtherID
		default:
			return tr.unexpected(req)
		}
		account.Name = "projects/" + staticIdentityProject + "/serviceAccounts/" + account.UniqueId
		switch {
		case req.Method == http.MethodGet && len(parts) == 4:
			response = account
		case req.Method == http.MethodPost && len(parts) == 5 && parts[4] == "keys":
			tr.keyCreates = append(tr.keyCreates, account.UniqueId)
			response = &iam.ServiceAccountKey{
				Name:           fmt.Sprintf("%s/keys/key-%d", account.Name, len(tr.keyCreates)),
				PrivateKeyData: staticIdentityKeyData(tr.t, account.Email),
				PrivateKeyType: privateKeyTypeJson,
				KeyAlgorithm:   keyAlgorithmRSA2k,
			}
		case req.Method == http.MethodDelete && len(parts) == 6 && parts[4] == "keys":
			response = struct{}{}
		default:
			return tr.unexpected(req)
		}
	default:
		return tr.unexpected(req)
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func (tr *staticAccountIdentityTransport) unexpected(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	tr.t.Errorf("unexpected HTTP request: %s %s%s", req.Method, req.URL.Host, req.URL.Path)
	return nil, fmt.Errorf("unexpected mocked HTTP request")
}
