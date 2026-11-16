// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

const (
	staticIdentityProject    = "test-project"
	staticIdentityRootEmail  = "mount@test-project.iam.gserviceaccount.com"
	staticIdentityRootID     = "123456789012345678901"
	staticIdentityOtherEmail = "other@test-project.iam.gserviceaccount.com"
	staticIdentityOtherID    = "987654321098765432109"
)

func TestStaticAccountIdentity_Create(t *testing.T) {
	for _, configured := range []bool{true, false} {
		for _, target := range []string{staticIdentityRootEmail, staticIdentityRootID} {
			for _, secretType := range []string{SecretTypeKey, SecretTypeAccessToken} {
				t.Run(fmt.Sprintf("configured=%t/%s/%s", configured, target, secretType), func(t *testing.T) {
					b, storage, transport := setupStaticAccountIdentityTest(t, configured)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

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
					assert.True(t, entry == nil, "must not persist a static account targeting the mount identity")
				})
			}
		}
	}
}

func TestStaticAccountIdentity_ExistingAccount(t *testing.T) {
	for _, configured := range []bool{true, false} {
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
				{"update-account", "", logical.UpdateOperation, SecretTypeKey},
				{"rotate-token-key", "/rotate-key", logical.UpdateOperation, SecretTypeAccessToken},
			} {
				t.Run(fmt.Sprintf("configured=%t/%s/%s", configured, target.ResourceName(), tc.name), func(t *testing.T) {
					b, storage, transport := setupStaticAccountIdentityTest(t, configured)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					// Seed storage directly to model entries created before the protection exists.
					account := &StaticAccount{
						Name:             "self-test",
						SecretType:       tc.secretType,
						ServiceAccountId: target,
					}
					if tc.secretType == SecretTypeAccessToken {
						account.TokenGen = &TokenGenerator{
							KeyName:    target.ResourceName() + "/keys/old",
							B64KeyJSON: base64.StdEncoding.EncodeToString([]byte("fake-key")),
							Scopes:     []string{iam.CloudPlatformScope},
						}
					}
					require.NoError(t, account.save(ctx, storage))
					before, err := storage.Get(ctx, "static-account/self-test")
					require.NoError(t, err)

					resp, err := b.HandleRequest(ctx, &logical.Request{
						Operation: tc.operation,
						Path:      "static-account/self-test" + tc.suffix,
						Storage:   storage,
						Data: map[string]interface{}{
							"service_account_email": target.EmailOrId,
							"secret_type":           tc.secretType,
						},
					})

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

func TestStaticAccountIdentity_OtherAccount(t *testing.T) {
	for _, configured := range []bool{true, false} {
		for _, secretType := range []string{SecretTypeKey, SecretTypeAccessToken} {
			t.Run(fmt.Sprintf("configured=%t/%s", configured, secretType), func(t *testing.T) {
				b, storage, transport := setupStaticAccountIdentityTest(t, configured)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				resp, err := b.HandleRequest(ctx, &logical.Request{
					Operation: logical.CreateOperation,
					Path:      "static-account/other",
					Storage:   storage,
					Data: map[string]interface{}{
						"service_account_email": staticIdentityOtherEmail,
						"secret_type":           secretType,
						"token_scopes":          []string{iam.CloudPlatformScope},
					},
				})
				require.NoError(t, err)
				require.False(t, resp.IsError(), "ordinary account creation must succeed")

				if secretType == SecretTypeKey {
					for _, op := range []logical.Operation{logical.ReadOperation, logical.UpdateOperation} {
						resp, err = b.HandleRequest(ctx, &logical.Request{
							Operation: op, Path: "static-account/other/key", Storage: storage,
						})
						require.NoError(t, err)
						require.NotNil(t, resp)
						require.False(t, resp.IsError())
						assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("fake-key")), resp.Data["private_key_data"])
						require.NotNil(t, resp.Secret)
						assert.Equal(t, "other", resp.Secret.InternalData["static_account"])
					}
				} else {
					resp, err = b.HandleRequest(ctx, &logical.Request{
						Operation: logical.UpdateOperation, Path: "static-account/other/rotate-key", Storage: storage,
					})
					require.NoError(t, err)
					require.False(t, resp.IsError(), "ordinary token key rotation must succeed")
				}
				assert.Equal(t, []string{staticIdentityOtherID, staticIdentityOtherID}, transport.keyCreates)
			})
		}
	}
}

func assertStaticAccountIdentityRejected(t *testing.T, resp *logical.Response, err error, transport *staticAccountIdentityTransport) {
	t.Helper()
	assert.True(t, err != nil || resp.IsError(), "must reject the mount's own service account")
	if resp != nil {
		_, hasPrivateKey := resp.Data["private_key_data"]
		assert.False(t, hasPrivateKey, "must not return private key data for the mount identity")
		assert.True(t, resp.Secret == nil, "must not issue a secret for the mount identity")
	}
	assert.Zero(t, len(transport.keyCreates), "must reject the protected identity before requesting a key from IAM")
}

func setupStaticAccountIdentityTest(t *testing.T, configured bool) (*backend, logical.Storage, *staticAccountIdentityTransport) {
	t.Helper()
	b, storage := getTestBackend(t)
	credentialsJSON, err := json.Marshal(map[string]string{
		"type": "service_account", "project_id": staticIdentityProject,
		"client_email": staticIdentityRootEmail, "client_id": staticIdentityRootID,
		"private_key_id": "fake-key-id", "private_key": "fake-key",
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	if configured {
		require.NoError(t, writeConfig(context.Background(), storage, config{CredentialsRaw: string(credentialsJSON)}))
	}

	transport := &staticAccountIdentityTransport{t: t}
	creds := &google.Credentials{
		ProjectID:   staticIdentityProject,
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"}),
	}
	if configured {
		creds.JSON = credentialsJSON
	}
	// Inject both caches so neither ADC discovery nor authenticated requests can reach GCP.
	_, err = b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return creds, nil })
	require.NoError(t, err)
	client := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: transport}}
	_, err = b.cache.Fetch("HTTPClient", cacheTime, func() (interface{}, error) { return client, nil })
	require.NoError(t, err)
	return b, storage, transport
}

type staticAccountIdentityTransport struct {
	t          *testing.T
	keyCreates []string
}

func (tr *staticAccountIdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var response interface{}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/"), "/")
	switch {
	case req.Method == http.MethodGet && req.URL.Host == "www.googleapis.com" && req.URL.Path == "/oauth2/v2/tokeninfo":
		response = map[string]string{"issued_to": staticIdentityRootID, "audience": staticIdentityRootID}
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
				PrivateKeyData: base64.StdEncoding.EncodeToString([]byte("fake-key")),
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
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    req,
	}, nil
}

func (tr *staticAccountIdentityTransport) unexpected(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	tr.t.Errorf("unexpected HTTP request: %s %s%s", req.Method, req.URL.Host, req.URL.Path)
	return nil, fmt.Errorf("unexpected mocked HTTP request")
}
