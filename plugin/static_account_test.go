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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/helper/pluginidentityutil"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
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

type staticIdentityTestSetup func(*testing.T) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context)

var staticAccountIdentityExistingPaths = []struct {
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
}

func testExistingStaticAccountIdentity(t *testing.T, setup staticIdentityTestSetup) {
	t.Helper()
	for _, target := range []gcputil.ServiceAccountId{
		{Project: "-", EmailOrId: staticIdentityRootEmail},
		{Project: staticIdentityProject, EmailOrId: staticIdentityRootID},
		{Project: "-", EmailOrId: strings.ToUpper(staticIdentityRootEmail)},
	} {
		for _, tc := range staticAccountIdentityExistingPaths {
			t.Run(fmt.Sprintf("%s/%s", target.ResourceName(), tc.name), func(t *testing.T) {
				b, storage, transport, ctx := setup(t)
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

func TestStaticAccountIdentity_Create(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		for _, target := range []string{staticIdentityRootEmail, staticIdentityRootID, strings.ToUpper(staticIdentityRootEmail)} {
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

// TestStaticAccountIdentity_MixedCaseMountIdentity makes sure a mount identity
// configured with a different email case still matches the canonical target.
func TestStaticAccountIdentity_MixedCaseMountIdentity(t *testing.T) {
	upperEmail := strings.ToUpper(staticIdentityRootEmail)
	for _, mount := range []struct {
		name string
		cfg  config
	}{
		{"service_account credentials", config{CredentialsRaw: staticIdentityJSON(t, map[string]interface{}{
			"type": "service_account", "project_id": staticIdentityProject,
			"client_email": upperEmail, "client_id": staticIdentityRootID,
			"private_key_id": "fake-key-id", "private_key": "fake-key", "token_uri": staticIdentityTokenURL,
		})}},
		{"plugin workload identity federation", config{
			PluginIdentityTokenParams: pluginidentityutil.PluginIdentityTokenParams{
				IdentityTokenAudience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/vault",
			},
			ServiceAccountEmail: upperEmail,
		}},
	} {
		for _, target := range []string{staticIdentityRootEmail, staticIdentityRootID} {
			t.Run(mount.name+"/"+target, func(t *testing.T) {
				b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)

				resp, err := b.HandleRequest(ctx, &logical.Request{
					Operation: logical.CreateOperation,
					Path:      "static-account/self-test",
					Storage:   storage,
					Data: map[string]interface{}{
						"service_account_email": target,
						"secret_type":           SecretTypeKey,
					},
				})

				assertStaticAccountIdentityRejected(t, resp, err, transport)
				entry, err := storage.Get(ctx, "static-account/self-test")
				require.NoError(t, err)
				assert.Nil(t, entry)
			})
		}
	}
}

// TestStaticAccountIdentity_ResourceNameRejected makes sure a full service
// account resource name is not accepted as service_account_email, so it cannot
// be used to reach the mount identity.
func TestStaticAccountIdentity_ResourceNameRejected(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		for _, target := range []string{
			"projects/" + staticIdentityProject + "/serviceAccounts/" + staticIdentityRootEmail,
			"projects/-/serviceAccounts/" + staticIdentityRootID,
		} {
			t.Run(mount.name+"/"+target, func(t *testing.T) {
				b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)
				// Create retries failed service account lookups until the request
				// deadline, so keep the deadline short.
				reqCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()

				resp, err := b.HandleRequest(reqCtx, &logical.Request{
					Operation: logical.CreateOperation,
					Path:      "static-account/self-test",
					Storage:   storage,
					Data: map[string]interface{}{
						"service_account_email": target,
						"secret_type":           SecretTypeKey,
					},
				})
				if err == nil && resp != nil {
					err = resp.Error()
				}
				require.Error(t, err)
				if resp != nil {
					assert.Nil(t, resp.Secret)
				}
				assert.Empty(t, transport.keyCreates)
				assert.Zero(t, transport.tokensIssued)
				entry, err := storage.Get(ctx, "static-account/self-test")
				require.NoError(t, err)
				assert.Nil(t, entry)
			})
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

	t.Run("existing", func(t *testing.T) {
		testExistingStaticAccountIdentity(t, func(t *testing.T) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
			return setupStaticAccountMetadataTest(t, staticIdentityRootEmail)
		})
	})

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

func TestStaticAccountIdentity_UnresolvedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name        string
		credentials string
	}{
		{
			name:        "unsupported type",
			credentials: staticIdentityJSON(t, map[string]string{"type": "gdch_service_account"}),
		},
		{
			name: "service account without client email",
			credentials: staticIdentityJSON(t, map[string]string{
				"type": "service_account",
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, tc.credentials)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "static-account/target",
				Storage:   storage,
				Data: map[string]interface{}{
					"service_account_email": staticIdentityRootEmail,
					"secret_type":           SecretTypeKey,
				},
			})

			assertStaticAccountIdentityUndetermined(t, resp, err, transport)
			entry, err := storage.Get(ctx, "static-account/target")
			require.NoError(t, err)
			assert.Nil(t, entry, "must not persist an account when the mount identity cannot be determined")
		})
	}
}

func TestStaticAccountIdentity_UnresolvedIAMEmail(t *testing.T) {
	credentials := staticIdentityJSON(t, map[string]interface{}{
		"type": "impersonated_service_account",
		"service_account_impersonation_url": strings.Replace(
			staticIdentityImpersonationURL, staticIdentityRootEmail, staticIdentityRootID, 1,
		),
	})
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, credentials)
	transport.omitEmail = true
	account := &StaticAccount{
		Name:             "target",
		SecretType:       SecretTypeKey,
		ServiceAccountId: gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail},
	}
	require.NoError(t, account.save(ctx, storage))

	resp := handleStaticIdentityRequestError(t, ctx, b, storage, logical.ReadOperation, "static-account/target/key")
	assert.Contains(t, resp.Error().Error(), "unable to determine GCP secrets engine identity")
	assert.Empty(t, transport.keyCreates, "must not create a key if IAM cannot resolve the mount identity")
}

func TestStaticAccountIdentity_ConfigChangesWaitForKeyCreation(t *testing.T) {
	mount := staticIdentityConfigs(t)[0]
	b, storage, transport, ctx := setupStaticAccountIdentityTest(t, mount.cfg)
	createStaticIdentityAccount(t, ctx, b, storage, "other", SecretTypeKey)

	transport.keyCreateEntered = make(chan struct{}, 1)
	transport.releaseKeyCreate = make(chan struct{})
	keyDone := make(chan error, 1)
	go func() {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "static-account/other/key",
			Storage:   storage,
		})
		if err == nil && (resp == nil || resp.IsError()) {
			if resp == nil {
				err = fmt.Errorf("key request returned no response")
			} else {
				err = resp.Error()
			}
		}
		keyDone <- err
	}()

	select {
	case <-transport.keyCreateEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("key request did not reach the mocked key creation")
	}

	configStarted := make(chan struct{})
	configDone := make(chan error, 1)
	newCredentials := staticIdentityJSON(t, map[string]interface{}{
		"type": "service_account", "project_id": staticIdentityProject,
		"client_email": staticIdentityOtherEmail, "client_id": staticIdentityOtherID,
		"private_key_id": "new-key-id", "private_key": "new-key",
		"token_uri": staticIdentityTokenURL,
	})
	go func() {
		close(configStarted)
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data:      map[string]interface{}{"credentials": newCredentials},
		})
		if err == nil && resp != nil && resp.IsError() {
			err = resp.Error()
		}
		configDone <- err
	}()
	<-configStarted

	select {
	case err := <-configDone:
		t.Fatalf("config update completed before key creation finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(transport.releaseKeyCreate)
	require.NoError(t, <-keyDone)
	require.NoError(t, <-configDone)
	require.Equal(t, []string{staticIdentityOtherID}, transport.keyCreates)
}

func TestStaticAccountIdentity_ImpersonatedServiceAccountByID(t *testing.T) {
	credentials := staticIdentityImpersonatedCredentials(t, staticIdentityRootID)
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, credentials)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "static-account/target",
		Storage:   storage,
		Data: map[string]interface{}{
			"service_account_email": staticIdentityRootEmail,
			"secret_type":           SecretTypeKey,
		},
	})

	assertStaticAccountIdentityRejected(t, resp, err, transport)
	entry, err := storage.Get(ctx, "static-account/target")
	require.NoError(t, err)
	assert.Nil(t, entry, "must not persist a static account targeting the impersonated identity")
}

func TestStaticAccountIdentity_ImpersonatedServiceAccountEmailReused(t *testing.T) {
	credentials := staticIdentityImpersonatedCredentials(t, staticIdentityRootID)
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, credentials)
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	for i := 0; i < 2; i++ {
		_, err := b.checkStaticAccountTarget(ctx, storage, target)
		require.EqualError(t, err, staticIdentitySelfTargetError)
	}

	require.Equal(t, []string{staticIdentityRootID}, transport.accountLookups,
		"the numeric impersonation ID should be resolved only once")
}

func TestStaticAccountIdentity_ImpersonatedServiceAccountEmailSurvivesCredentialReload(t *testing.T) {
	credentials := staticIdentityImpersonatedCredentials(t, staticIdentityRootID)
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, credentials)
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	_, err := b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, staticIdentitySelfTargetError)
	require.Equal(t, []string{staticIdentityRootID}, transport.accountLookups)

	injectStaticAccountCredentialsJSON(t, b, transport, credentials)
	_, err = b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, staticIdentitySelfTargetError)
	assert.Equal(t, []string{staticIdentityRootID}, transport.accountLookups,
		"credential reload with the same numeric ID should reuse the resolved email")
}

func TestStaticAccountIdentity_ImpersonatedServiceAccountEmailRefreshesForNewID(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	_, err := b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, staticIdentitySelfTargetError)

	injectStaticAccountCredentialsJSON(t, b, transport,
		staticIdentityImpersonatedCredentials(t, staticIdentityOtherID))
	_, err = b.checkStaticAccountTarget(ctx, storage, target)
	require.NoError(t, err, "the old service-account email must not be used for a different ID")
	_, err = b.checkStaticAccountTarget(ctx, storage, target)
	require.NoError(t, err)

	assert.Equal(t, []string{staticIdentityRootID, staticIdentityOtherID}, transport.accountLookups,
		"the new numeric ID should be resolved once and then reused")
}

func TestStaticAccountIdentity_FailedImpersonationLookupPreservesCachedEmail(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	_, err := b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, staticIdentitySelfTargetError)

	transport.omitEmailIDs = map[string]bool{staticIdentityOtherID: true}
	injectStaticAccountCredentialsJSON(t, b, transport,
		staticIdentityImpersonatedCredentials(t, staticIdentityOtherID))
	_, err = b.checkStaticAccountTarget(ctx, storage, target)
	require.ErrorContains(t, err, "unable to determine GCP secrets engine identity")

	injectStaticAccountCredentialsJSON(t, b, transport,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	_, err = b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, staticIdentitySelfTargetError)
	assert.Equal(t, []string{staticIdentityRootID, staticIdentityOtherID}, transport.accountLookups,
		"a failed lookup must leave the previously cached ID/email pair unchanged")
}

func TestStaticAccountIdentity_ImpersonationLookupHonorsCancellation(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	transport.stallLookups = true
	transport.lookupStalled = make(chan struct{}, 1)
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	reqCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := b.checkStaticAccountTarget(reqCtx, storage, target)
		done <- err
	}()

	<-transport.lookupStalled
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("canceling the request did not cancel the IAM lookup")
	}
}

// TestStaticAccountIdentity_CancelledIAMCallsReleaseIdentityLock makes sure a
// stalled IAM call made while holding identityLock stops when the request is
// canceled, so it cannot block configuration writes or root rotation.
func TestStaticAccountIdentity_CancelledIAMCallsReleaseIdentityLock(t *testing.T) {
	for _, tc := range []struct {
		name      string
		existing  bool
		operation logical.Operation
		path      string
		data      map[string]interface{}
		stallKey  bool
	}{
		{
			name:      "create-account-lookup",
			operation: logical.CreateOperation,
			path:      "static-account/other",
			data:      map[string]interface{}{"service_account_email": staticIdentityOtherEmail, "secret_type": SecretTypeKey},
		},
		{
			name:      "update-account-lookup",
			existing:  true,
			operation: logical.UpdateOperation,
			path:      "static-account/other",
			data:      map[string]interface{}{"service_account_email": staticIdentityOtherEmail, "secret_type": SecretTypeKey},
		},
		{
			name:      "key-creation",
			existing:  true,
			operation: logical.UpdateOperation,
			path:      "static-account/other/key",
			stallKey:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountIdentityTest(t, staticIdentityConfigs(t)[0].cfg)
			if tc.existing {
				require.NoError(t, (&StaticAccount{
					Name:             "other",
					SecretType:       SecretTypeKey,
					ServiceAccountId: gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityOtherEmail},
				}).save(ctx, storage))
			}
			stalled := make(chan struct{}, 1)
			if tc.stallKey {
				transport.stallKeyCreates = true
				transport.keyCreateStalled = stalled
			} else {
				transport.stallLookups = true
				transport.lookupStalled = stalled
			}

			reqCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan struct{})
			var resp *logical.Response
			var err error
			go func() {
				defer close(done)
				resp, err = b.HandleRequest(reqCtx, &logical.Request{
					Operation: tc.operation,
					Path:      tc.path,
					Storage:   storage,
					Data:      tc.data,
				})
			}()

			select {
			case <-stalled:
			case <-done:
				t.Fatalf("request finished before reaching the stalled IAM call: resp=%v err=%v", resp, err)
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach the stalled IAM call")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("canceling the request did not stop the stalled IAM call")
			}

			if err == nil && resp != nil {
				err = resp.Error()
			}
			require.Error(t, err)
			if resp != nil {
				assert.Nil(t, resp.Secret)
			}
			assert.Empty(t, transport.keyCreates)
			require.True(t, b.identityLock.TryLock(), "a canceled request must release identityLock")
			b.identityLock.Unlock()
		})
	}
}

func TestStaticAccountIdentity_CancelledMetadataRebuildReleasesIdentityLock(t *testing.T) {
	b, storage, _, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	require.NoError(t, (&StaticAccount{
		Name:             "other",
		SecretType:       SecretTypeKey,
		ServiceAccountId: gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityOtherEmail},
	}).save(ctx, storage))
	b.cache.Expire("credentials")

	stalled := make(chan struct{}, 1)
	release := make(chan struct{})
	md.mu.Lock()
	md.stallEmail = true
	md.emailStalled = stalled
	md.releaseEmail = release
	md.mu.Unlock()
	t.Cleanup(func() { close(release) })

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	var resp *logical.Response
	var err error
	go func() {
		defer close(done)
		resp, err = b.HandleRequest(reqCtx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "static-account/other/key",
			Storage:   storage,
		})
	}()

	select {
	case <-stalled:
	case <-done:
		t.Fatalf("request finished before reaching the stalled metadata lookup: resp=%v err=%v", resp, err)
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the stalled metadata lookup")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("canceling the request did not stop the metadata lookup")
	}
	if err == nil && resp != nil {
		err = resp.Error()
	}
	require.Error(t, err)
	assert.ErrorContains(t, err, context.Canceled.Error())
	require.True(t, b.identityLock.TryLock(), "a canceled request must release identityLock")
	b.identityLock.Unlock()

	md.mu.Lock()
	md.stallEmail = false
	md.mu.Unlock()
	_, err = b.credentialState(storage)
	require.NoError(t, err, "a canceled rebuild must release the credential cache lock")
}

func TestStaticAccountIdentity_StalledImpersonationLookupDoesNotBlockOtherRequests(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	transport.stallLookups = true
	transport.lookupStalled = make(chan struct{}, 2)
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}

	firstCtx, cancelFirst := context.WithCancel(ctx)
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		_, err := b.checkStaticAccountTarget(firstCtx, storage, target)
		firstDone <- err
	}()
	<-transport.lookupStalled

	secondCtx, cancelSecond := context.WithCancel(ctx)
	secondDone := make(chan error, 1)
	go func() {
		_, err := b.checkStaticAccountTarget(secondCtx, storage, target)
		secondDone <- err
	}()

	select {
	case <-transport.lookupStalled:
	case <-time.After(5 * time.Second):
		t.Fatal("second request waited behind the first request's stalled IAM lookup")
	}
	cancelSecond()
	select {
	case err := <-secondDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("second request could not be canceled while the first lookup was stalled")
	}

	select {
	case err := <-firstDone:
		t.Fatalf("first request finished before it was canceled: %v", err)
	default:
	}
	cancelFirst()
	require.ErrorIs(t, <-firstDone, context.Canceled)
}

func TestStaticAccountIdentity_ConcurrentImpersonationLookups(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, staticIdentityRootID))
	self := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail}
	other := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityOtherEmail}

	const workers = 20
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		target, wantSelf := other, false
		if i%2 == 0 {
			target, wantSelf = self, true
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.checkStaticAccountTarget(ctx, storage, target)
			switch {
			case wantSelf && (err == nil || err.Error() != staticIdentitySelfTargetError):
				errs <- fmt.Errorf("self target: got %v, want %q", err, staticIdentitySelfTargetError)
			case !wantSelf && err != nil:
				errs <- fmt.Errorf("other target: unexpected error: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	transport.mu.Lock()
	lookups := len(transport.accountLookups)
	transport.mu.Unlock()
	assert.GreaterOrEqual(t, lookups, 1)
	assert.LessOrEqual(t, lookups, workers)

	transport.mu.Lock()
	transport.accountLookups = nil
	transport.mu.Unlock()
	_, err := b.checkStaticAccountTarget(ctx, storage, self)
	require.EqualError(t, err, staticIdentitySelfTargetError)
	assert.Empty(t, transport.accountLookups, "the resolved email should be cached after concurrent lookups")
}

func TestStaticAccountIdentity_NonNumericImpersonationIdentifierRejected(t *testing.T) {
	b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t,
		staticIdentityImpersonatedCredentials(t, "not-an-email-or-id"))
	target := &gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityOtherEmail}

	_, err := b.checkStaticAccountTarget(ctx, storage, target)
	require.EqualError(t, err, "unable to determine GCP secrets engine identity: invalid service account identifier")
	assert.Empty(t, transport.accountLookups, "non-numeric identifiers must not be looked up or cached")
}

func staticIdentityImpersonatedCredentials(t *testing.T, targetID string) string {
	t.Helper()
	return staticIdentityJSON(t, map[string]interface{}{
		"type": "impersonated_service_account",
		"service_account_impersonation_url": strings.Replace(
			staticIdentityImpersonationURL, staticIdentityRootEmail, targetID, 1,
		),
		"source_credentials": map[string]interface{}{
			"type": "service_account", "client_email": staticIdentitySourceEmail,
			"private_key_id": "fake-key-id", "private_key": "fake-key", "token_uri": staticIdentityTokenURL,
		},
	})
}

type supportedPluginIdentitySystemView struct {
	testSystemView
}

func (s supportedPluginIdentitySystemView) GenerateIdentityToken(context.Context, *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	return &pluginutil.IdentityTokenResponse{}, nil
}

func TestStaticAccountIdentity_WIFEmailChangeClearsClients(t *testing.T) {
	conf := logical.TestBackendConfig()
	conf.StorageView = new(logical.InmemStorage)
	conf.System = supportedPluginIdentitySystemView{}
	b := Backend()
	require.NoError(t, b.Setup(context.Background(), conf))
	s := conf.StorageView
	require.NoError(t, writeConfig(context.Background(), s, config{
		PluginIdentityTokenParams: pluginidentityutil.PluginIdentityTokenParams{
			IdentityTokenAudience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/vault",
		},
		ServiceAccountEmail: staticIdentityRootEmail,
	}))

	oldClients, err := b.credentialClients(s)
	require.NoError(t, err)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   s,
		Data:      map[string]interface{}{"service_account_email": staticIdentityOtherEmail},
	})
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError())
	}
	require.Nil(t, b.credentialClient, "changing the WIF target must invalidate clients built for the old target")

	newClients, err := b.credentialClients(s)
	require.NoError(t, err)
	require.NotSame(t, oldClients, newClients)
	require.NotSame(t, oldClients.credentials, newClients.credentials)

	_, err = b.checkStaticAccountTarget(context.Background(), s, &gcputil.ServiceAccountId{
		Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail,
	})
	require.NoError(t, err, "the old WIF target should be allowed after configuration switches to another account")
}

func TestStaticAccountIdentity_WIFReplicationKeepsIdentityBoundToCachedClient(t *testing.T) {
	conf := logical.TestBackendConfig()
	conf.StorageView = new(logical.InmemStorage)
	conf.System = supportedPluginIdentitySystemView{}
	b := Backend()
	require.NoError(t, b.Setup(context.Background(), conf))
	s := conf.StorageView

	wifConfig := func(email string) config {
		return config{
			PluginIdentityTokenParams: pluginidentityutil.PluginIdentityTokenParams{
				IdentityTokenAudience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/vault",
			},
			ServiceAccountEmail: email,
		}
	}
	require.NoError(t, writeConfig(context.Background(), s, wifConfig(staticIdentityRootEmail)))
	transport := &staticAccountIdentityTransport{t: t}
	creds := &google.Credentials{
		ProjectID:   staticIdentityProject,
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"}),
	}
	oldState := &credentialState{
		credentials:                 creds,
		mountServiceAccountIdentity: staticIdentityRootEmail,
		identityFromWIFConfig:       true,
	}
	_, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return oldState, nil })
	require.NoError(t, err)
	oldClient := &credentialClient{
		credentials: creds,
		state:       oldState,
		httpClient: &http.Client{Transport: &oauth2.Transport{
			Source: creds.TokenSource,
			Base:   transport,
		}},
	}
	b.credentialClientLock.Lock()
	b.credentialClient = oldClient
	b.credentialClientLock.Unlock()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport})

	oldAccount := &StaticAccount{
		Name:             "old-target",
		SecretType:       SecretTypeKey,
		ServiceAccountId: gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityRootEmail},
	}
	require.NoError(t, oldAccount.save(ctx, s))

	// Replication writes the new config to storage before asynchronously
	// invalidating the cached credential client on this node.
	require.NoError(t, writeConfig(context.Background(), s, wifConfig(staticIdentityOtherEmail)))
	require.Same(t, oldClient, b.credentialClient)

	resp := handleStaticIdentityRequestError(t, ctx, b, s, logical.ReadOperation, "static-account/old-target/key")
	require.Contains(t, resp.Error().Error(), staticIdentitySelfTargetError,
		"the cached client for the old WIF target must not be allowed to create its own key")
	require.Empty(t, transport.keyCreates, "the /key endpoint must not create a key for the cached WIF identity")
	require.Same(t, oldClient, b.credentialClient)

	b.invalidate(ctx, "config")
	require.Nil(t, b.credentialClient, "replication invalidation must clear the old credential client")
	newClients, err := b.credentialClients(s)
	require.NoError(t, err)
	require.NotSame(t, oldClient, newClients)
	require.Equal(t, staticIdentityOtherEmail, newClients.state.mountServiceAccountIdentity)

	_, err = b.checkStaticAccountTarget(ctx, s, &oldAccount.ServiceAccountId)
	require.NoError(t, err, "the old WIF target should be allowed once the client is rebuilt for the new target")

	newAccount := &StaticAccount{
		Name:             "new-target",
		SecretType:       SecretTypeKey,
		ServiceAccountId: gcputil.ServiceAccountId{Project: staticIdentityProject, EmailOrId: staticIdentityOtherEmail},
	}
	require.NoError(t, newAccount.save(ctx, s))
	resp = handleStaticIdentityRequestError(t, ctx, b, s, logical.ReadOperation, "static-account/new-target/key")
	require.Contains(t, resp.Error().Error(), staticIdentitySelfTargetError,
		"the rebuilt client must protect its new WIF target")
	require.Empty(t, transport.keyCreates, "neither WIF identity may have a key created during the test")
}

// The metadata server can start reporting a different service account while
// Vault keeps running, for example after a GKE Workload Identity annotation
// change. The cached credentials can still hold a token for the previous
// account, so they must be rebuilt before the new email is trusted.

func TestStaticAccountIdentity_MetadataChangeDoesNotUseStaleCredentials(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secretType string
		operation  logical.Operation
		suffix     string
	}{
		{"read-key", SecretTypeKey, logical.ReadOperation, "/key"},
		{"write-key", SecretTypeKey, logical.UpdateOperation, "/key"},
		{"rotate-key", SecretTypeAccessToken, logical.UpdateOperation, "/rotate-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
			stale := b.credentialClient
			saveStaticIdentityAccount(t, ctx, storage, "previous", tc.secretType, staticIdentityRootEmail)

			md.setEmail(staticIdentityOtherEmail)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: tc.operation,
				Path:      "static-account/previous" + tc.suffix,
				Storage:   storage,
			})

			// The test metadata server never issues tokens, so the request fails
			// once rebuilt credentials try to reach GCP.
			if err == nil && resp != nil {
				err = resp.Error()
			}
			assert.Error(t, err)
			assert.Empty(t, transport.keyCreates, "must not create a key with credentials cached for the previous metadata identity")
			assertStaticIdentityCredentialsRebuilt(t, b, stale, staticIdentityOtherEmail)
			assert.Positive(t, md.tokenRequests(), "the IAM call must use credentials rebuilt for the new metadata identity")
		})
	}
}

func TestStaticAccountIdentity_MetadataChangeRebuildsCredentialsInSameRequest(t *testing.T) {
	b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	stale := b.credentialClient

	md.setEmail(staticIdentityOtherEmail)
	// The previous identity is no longer the engine's own account, so the
	// request succeeds without the caller having to retry.
	handleStaticIdentityRequest(t, ctx, b, storage, logical.CreateOperation, "static-account/previous", map[string]interface{}{
		"service_account_email": staticIdentityRootEmail,
		"secret_type":           SecretTypeKey,
	})

	assertStaticIdentityCredentialsRebuilt(t, b, stale, staticIdentityOtherEmail)
	assert.Empty(t, transport.keyCreates)
	assert.Zero(t, md.tokenRequests(), "creating a key-type static account makes no IAM calls after the identity check")
}

func TestStaticAccountIdentity_MetadataChangeProtectsNewIdentity(t *testing.T) {
	t.Run("existing", func(t *testing.T) {
		b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
		stale := b.credentialClient
		saveStaticIdentityAccount(t, ctx, storage, "current", SecretTypeKey, staticIdentityOtherEmail)

		md.setEmail(staticIdentityOtherEmail)
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "static-account/current/key",
			Storage:   storage,
		})

		assertStaticAccountIdentityRejected(t, resp, err, transport)
		assertStaticIdentityCredentialsRebuilt(t, b, stale, staticIdentityOtherEmail)
	})

	t.Run("create", func(t *testing.T) {
		b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
		stale := b.credentialClient

		md.setEmail(staticIdentityOtherEmail)
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "static-account/current",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_account_email": staticIdentityOtherEmail,
				"secret_type":           SecretTypeKey,
			},
		})

		assertStaticAccountIdentityRejected(t, resp, err, transport)
		entry, err := storage.Get(ctx, "static-account/current")
		require.NoError(t, err)
		assert.Nil(t, entry, "must not persist a static account targeting the new mount identity")
		assertStaticIdentityCredentialsRebuilt(t, b, stale, staticIdentityOtherEmail)
	})
}

func TestStaticAccountIdentity_MetadataChangeRebuildsOnce(t *testing.T) {
	b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	saveStaticIdentityAccount(t, ctx, storage, "other", SecretTypeKey, staticIdentityOtherEmail)

	n := 0
	md.setEmailFunc(func() string {
		n++
		return fmt.Sprintf("changing-%d@%s.iam.gserviceaccount.com", n, staticIdentityProject)
	})
	readsBefore := md.emailReads()
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-account/other/key",
		Storage:   storage,
	})

	if err == nil && resp != nil {
		err = resp.Error()
	}
	assert.Error(t, err, "a metadata identity that keeps changing must fail closed")
	assert.Empty(t, transport.keyCreates)
	assert.LessOrEqual(t, md.emailReads()-readsBefore, 4, "credentials must be rebuilt at most once per request")
}

func TestCredentialStateRecordsMetadataIdentity(t *testing.T) {
	b, storage, _, _, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	b.cache.Expire("credentials")

	state, err := b.credentialState(storage)

	require.NoError(t, err)
	assert.True(t, state.identityFromMetadata)
	assert.Equal(t, staticIdentityRootEmail, state.mountServiceAccountIdentity)
	assert.Positive(t, md.emailReads())
}

func TestStaticAccountIdentity_MetadataUnchangedReusesCredentials(t *testing.T) {
	b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	cached := b.credentialClient
	createStaticIdentityAccount(t, ctx, b, storage, "other", SecretTypeKey)

	for i := 0; i < 2; i++ {
		handleStaticIdentityRequest(t, ctx, b, storage, logical.ReadOperation, "static-account/other/key", nil)
	}

	b.credentialClientLock.Lock()
	current := b.credentialClient
	b.credentialClientLock.Unlock()
	assert.Same(t, cached, current, "credentials must not be rebuilt while the metadata identity is unchanged")
	assert.Zero(t, md.tokenRequests())
	assert.Equal(t, []string{staticIdentityOtherID, staticIdentityOtherID}, transport.keyCreates)
}

func TestStaticAccountIdentity_MetadataFederatedIdentityIsNotServiceAccount(t *testing.T) {
	b, storage, _, ctx, _ := setupStaticAccountMetadataServerTest(t, "test-project.svc.id.goog[namespace/service-account]")
	clients, err := b.credentialClients(storage)
	require.NoError(t, err)

	identity, err := b.mountServiceAccountIdentity(ctx, clients)
	require.NoError(t, err)
	require.Empty(t, identity, "GKE workload federation identities are not IAM service accounts")
}

// TestStaticAccountIdentity_MetadataTokenBoundToCheckedIdentity makes sure
// metadata credentials only use tokens for the identity the target check saw.
func TestStaticAccountIdentity_MetadataTokenBoundToCheckedIdentity(t *testing.T) {
	t.Run("identity-changes-after-check", func(t *testing.T) {
		b, storage, transport, ctx, md := setupStaticAccountMetadataTokenTest(t)
		saveStaticIdentityAccount(t, ctx, storage, "target", SecretTypeKey, staticIdentityOtherEmail)

		// The identity check still sees the original account, but the metadata
		// server switches to the target account before a token is fetched.
		md.setEmailFunc(func() string {
			md.tokenIdentity = staticIdentityOtherEmail
			return staticIdentityRootEmail
		})
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "static-account/target/key",
			Storage:   storage,
		})

		if err == nil && resp != nil {
			err = resp.Error()
		}
		require.Error(t, err)
		if resp != nil {
			assert.Nil(t, resp.Secret)
			assert.NotContains(t, resp.Data, "private_key_data")
		}
		assert.Empty(t, transport.keyCreates, "the target account must not create its own key")
		assert.NotContains(t, md.tokenAccounts(), "default", "tokens must not be fetched for whichever account metadata currently reports")
		assert.Contains(t, md.tokenAccounts(), staticIdentityRootEmail)
	})

	t.Run("identity-unchanged", func(t *testing.T) {
		b, storage, transport, ctx, md := setupStaticAccountMetadataTokenTest(t)
		saveStaticIdentityAccount(t, ctx, storage, "target", SecretTypeKey, staticIdentityOtherEmail)

		handleStaticIdentityRequest(t, ctx, b, storage, logical.ReadOperation, "static-account/target/key", nil)

		assert.Equal(t, []string{staticIdentityOtherID}, transport.keyCreates)
		assert.Equal(t, []string{staticIdentityRootEmail}, md.tokenAccounts())
	})
}

// setupStaticAccountMetadataTokenTest builds real metadata credentials for
// staticIdentityRootEmail against a token-issuing fake metadata server, and
// routes their IAM traffic through the mock transport.
func setupStaticAccountMetadataTokenTest(t *testing.T) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context, *staticIdentityMetadataServer) {
	t.Helper()
	b, storage, transport, ctx, md := setupStaticAccountMetadataServerTest(t, staticIdentityRootEmail)
	md.mu.Lock()
	md.issueTokens = true
	md.mu.Unlock()

	b.cache.Expire("credentials")
	state, err := b.credentialState(storage)
	require.NoError(t, err)
	require.True(t, state.identityFromMetadata)
	require.Equal(t, staticIdentityRootEmail, state.mountServiceAccountIdentity)

	b.credentialClientLock.Lock()
	b.credentialClient = &credentialClient{
		credentials: state.credentials,
		state:       state,
		httpClient:  &http.Client{Transport: &oauth2.Transport{Source: state.credentials.TokenSource, Base: transport}},
	}
	b.credentialClientLock.Unlock()
	return b, storage, transport, ctx, md
}

func assertStaticIdentityCredentialsRebuilt(t *testing.T, b *backend, stale *credentialClient, email string) {
	t.Helper()
	b.credentialClientLock.Lock()
	current := b.credentialClient
	b.credentialClientLock.Unlock()
	require.NotNil(t, current, "credentials must be rebuilt in the same request")
	assert.NotSame(t, stale, current, "credentials cached for the previous metadata identity must be replaced")
	require.NotNil(t, current.state)
	assert.Equal(t, email, current.state.mountServiceAccountIdentity,
		"rebuilt credentials must record the metadata identity they were built for")
}

func saveStaticIdentityAccount(t *testing.T, ctx context.Context, storage logical.Storage, name, secretType, email string) {
	t.Helper()
	account := &StaticAccount{
		Name:             name,
		SecretType:       secretType,
		ServiceAccountId: gcputil.ServiceAccountId{Project: "-", EmailOrId: email},
	}
	if secretType == SecretTypeAccessToken {
		account.TokenGen = &TokenGenerator{
			KeyName:    account.ServiceAccountId.ResourceName() + "/keys/old",
			B64KeyJSON: staticIdentityKeyData(t, email),
			Scopes:     []string{iam.CloudPlatformScope},
		}
	}
	require.NoError(t, account.save(ctx, storage))
}

func TestCredentialClientsTrackADCRefresh(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "credentials.json")
	writeCredentials := func(email string) {
		credentials := staticIdentityJSON(t, map[string]string{
			"type": "service_account", "project_id": staticIdentityProject,
			"client_email": email, "client_id": staticIdentityRootID,
			"private_key_id": "fake-key-id", "private_key": staticIdentityPrivateKeyPEM(),
			"token_uri": staticIdentityTokenURL,
		})
		require.NoError(t, os.WriteFile(credentialsPath, []byte(credentials), 0600))
	}
	writeCredentials(staticIdentityRootEmail)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentialsPath)

	b, storage := getTestBackend(t)
	require.NoError(t, writeConfig(context.Background(), storage, config{}))
	oldClients, err := b.credentialClients(storage)
	require.NoError(t, err)
	require.Contains(t, string(oldClients.credentials.JSON), staticIdentityRootEmail)

	writeCredentials(staticIdentityOtherEmail)
	b.cache.Expire("credentials")
	newClients, err := b.credentialClients(storage)
	require.NoError(t, err)
	require.NotSame(t, oldClients, newClients)
	require.NotSame(t, oldClients.credentials, newClients.credentials)
	require.Contains(t, string(newClients.credentials.JSON), staticIdentityOtherEmail)

	iamClient, err := b.IAMAdminClient(storage)
	require.NoError(t, err)
	require.Same(t, newClients.iamClient, iamClient)
}

func TestStaticAccountIdentity_KnownNonServiceAccountCredentials(t *testing.T) {
	for _, tc := range []struct {
		name        string
		credentials string
	}{
		{
			name: "authorized user",
			credentials: staticIdentityJSON(t, map[string]string{
				"type": "authorized_user", "client_id": "fake-client-id",
				"client_secret": "fake-client-secret", "refresh_token": "fake-refresh-token",
			}),
		},
		{
			name: "external account without impersonation",
			credentials: staticIdentityJSON(t, map[string]interface{}{
				"type":               "external_account",
				"audience":           "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider",
				"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
				"token_url":          "https://sts.googleapis.com/v1/token",
				"credential_source":  map[string]interface{}{"file": "/dev/null"},
			}),
		},
		{
			name: "external account authorized user",
			credentials: staticIdentityJSON(t, map[string]string{
				"type":          "external_account_authorized_user",
				"audience":      "//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider",
				"refresh_token": "fake-refresh-token",
			}),
		},
		{
			name: "OAuth client credentials",
			credentials: staticIdentityJSON(t, map[string]interface{}{
				"installed": map[string]interface{}{
					"client_id": "fake-client-id", "redirect_uris": []string{"http://localhost"},
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, transport, ctx := setupStaticAccountCredentialsJSONTest(t, tc.credentials)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "static-account/target",
				Storage:   storage,
				Data: map[string]interface{}{
					"service_account_email": staticIdentityRootEmail,
					"secret_type":           SecretTypeKey,
				},
			})

			require.NoError(t, err)
			if resp != nil {
				require.False(t, resp.IsError(), "credentials that do not represent a service account should be allowed")
			}
			entry, err := storage.Get(ctx, "static-account/target")
			require.NoError(t, err)
			assert.NotNil(t, entry)
			assert.Empty(t, transport.keyCreates)
		})
	}
}

// TestStaticAccountIdentity_ExistingAccount models static accounts saved before
// the protection existed, so each credential-producing path must check again.
func TestStaticAccountIdentity_ExistingAccount(t *testing.T) {
	for _, mount := range staticIdentityConfigs(t) {
		t.Run(mount.name, func(t *testing.T) {
			testExistingStaticAccountIdentity(t, func(t *testing.T) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
				return setupStaticAccountIdentityTest(t, mount.cfg)
			})
		})
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

func handleStaticIdentityRequestError(t *testing.T, ctx context.Context, b *backend, storage logical.Storage, op logical.Operation, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
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

func assertStaticAccountIdentityUndetermined(t *testing.T, resp *logical.Response, err error, transport *staticAccountIdentityTransport) {
	t.Helper()
	if err == nil && resp != nil {
		err = resp.Error()
	}
	require.Error(t, err, "must reject when the mount identity cannot be determined")
	if resp != nil {
		assert.NotContains(t, resp.Data, "private_key_data")
		assert.NotContains(t, resp.Data, "token")
		assert.Nil(t, resp.Secret)
	}
	assert.Empty(t, transport.keyCreates)
	assert.Zero(t, transport.tokensIssued)
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
	state := &credentialState{
		credentials:                 creds,
		mountServiceAccountIdentity: cfg.ServiceAccountEmail,
		identityFromWIFConfig:       cfg.IdentityTokenAudience != "",
	}
	_, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return state, nil })
	require.NoError(t, err)
	client := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: transport}}
	b.credentialClientLock.Lock()
	b.credentialClient = &credentialClient{credentials: creds, state: state, httpClient: client}
	b.credentialClientLock.Unlock()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport})
	return b, storage, transport, ctx
}

func setupStaticAccountMetadataTest(t *testing.T, email string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	b, storage, transport, ctx, _ := setupStaticAccountMetadataServerTest(t, email)
	return b, storage, transport, ctx
}

// setupStaticAccountMetadataServerTest returns a backend whose cached
// credentials were built while the metadata server reported email.
func setupStaticAccountMetadataServerTest(t *testing.T, email string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context, *staticIdentityMetadataServer) {
	t.Helper()
	md := newStaticIdentityMetadataServer(t, email)
	b, storage, transport, ctx := setupStaticAccountIdentityTest(t, config{})
	b.credentialClient.state.mountServiceAccountIdentity = email
	b.credentialClient.state.identityFromMetadata = true
	return b, storage, transport, ctx, md
}

// staticIdentityMetadataServer is a fake GCE metadata server. It reports a
// configurable service account email and records token requests. It issues
// tokens only when issueTokens is set, and then only for "default" or the
// currently reported email, like a real metadata server.
type staticIdentityMetadataServer struct {
	mu           sync.Mutex
	email        func() string
	reads        int
	tokenReqs    int
	tokenPaths   []string
	issueTokens  bool
	stallEmail   bool
	emailStalled chan struct{}
	releaseEmail chan struct{}
	// tokenIdentity is the account the server currently issues tokens for.
	tokenIdentity string
}

func newStaticIdentityMetadataServer(t *testing.T, email string) *staticIdentityMetadataServer {
	t.Helper()
	md := &staticIdentityMetadataServer{}
	md.setEmail(email)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("metadata request without Metadata-Flavor header: %s %s", r.Method, r.URL.Path)
			http.Error(w, "missing Metadata-Flavor header", http.StatusForbidden)
			return
		}
		const accountsPrefix = "/computeMetadata/v1/instance/service-accounts/"
		if r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/email" {
			md.mu.Lock()
			md.reads++
			email := md.email()
			stallEmail, emailStalled, releaseEmail := md.stallEmail, md.emailStalled, md.releaseEmail
			md.mu.Unlock()
			if stallEmail {
				select {
				case emailStalled <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
					return
				case <-releaseEmail:
				}
			}
			_, _ = io.WriteString(w, email)
			return
		}
		md.mu.Lock()
		defer md.mu.Unlock()
		if account, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, accountsPrefix), "/token"); ok &&
			strings.HasPrefix(r.URL.Path, accountsPrefix) && !strings.Contains(account, "/") {
			md.tokenReqs++
			md.tokenPaths = append(md.tokenPaths, account)
			if !md.issueTokens || (account != "default" && account != md.tokenIdentity) {
				http.Error(w, "no token for this service account", http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"metadata-token-for-`+md.tokenIdentity+`","expires_in":3600,"token_type":"Bearer"}`)
			return
		}
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			_, _ = io.WriteString(w, staticIdentityProject)
		case "/computeMetadata/v1/universe/universe_domain":
			http.Error(w, "not defined", http.StatusNotFound)
		default:
			t.Errorf("unexpected metadata request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected metadata request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(server.URL, "http://"))
	// Rebuilt default credentials must come from this server, not from a
	// developer's local application default credentials.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())
	return md
}

func (md *staticIdentityMetadataServer) setEmail(email string) {
	md.setEmailFunc(func() string { return email })
	md.mu.Lock()
	defer md.mu.Unlock()
	md.tokenIdentity = email
}

func (md *staticIdentityMetadataServer) setEmailFunc(email func() string) {
	md.mu.Lock()
	defer md.mu.Unlock()
	md.email = email
}

func (md *staticIdentityMetadataServer) emailReads() int {
	md.mu.Lock()
	defer md.mu.Unlock()
	return md.reads
}

func (md *staticIdentityMetadataServer) tokenAccounts() []string {
	md.mu.Lock()
	defer md.mu.Unlock()
	return append([]string(nil), md.tokenPaths...)
}

func (md *staticIdentityMetadataServer) tokenRequests() int {
	md.mu.Lock()
	defer md.mu.Unlock()
	return md.tokenReqs
}

func setupStaticAccountMetadataTestWithADCFile(t *testing.T, metadataEmail, fileEmail string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	credentialsPath := filepath.Join(t.TempDir(), "credentials.json")
	credentials := staticIdentityJSON(t, map[string]string{
		"type": "service_account", "project_id": staticIdentityProject,
		"client_email": fileEmail, "client_id": staticIdentityRootID,
		"private_key_id": "fake-key-id", "private_key": staticIdentityPrivateKeyPEM(),
		"token_uri": staticIdentityTokenURL,
	})
	require.NoError(t, os.WriteFile(credentialsPath, []byte(credentials), 0600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentialsPath)

	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/email" ||
			r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("unexpected metadata request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected metadata request", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, metadataEmail)
	}))
	t.Cleanup(metadataServer.Close)
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(metadataServer.URL, "http://"))
	b, storage, transport, ctx := setupStaticAccountIdentityTest(t, config{})
	b.cache.Expire("credentials")
	state, err := b.credentialState(storage)
	require.NoError(t, err)
	creds := state.credentials
	creds.TokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"})
	b.credentialClientLock.Lock()
	b.credentialClient = &credentialClient{
		credentials: creds,
		state:       state,
		httpClient: &http.Client{Transport: &oauth2.Transport{
			Source: creds.TokenSource,
			Base:   transport,
		}},
	}
	b.credentialClientLock.Unlock()
	return b, storage, transport, ctx
}

func setupStaticAccountCredentialsJSONTest(t *testing.T, credentialJSON string) (*backend, logical.Storage, *staticAccountIdentityTransport, context.Context) {
	t.Helper()
	b, storage, transport, ctx := setupStaticAccountIdentityTest(t, config{})
	injectStaticAccountCredentialsJSON(t, b, transport, credentialJSON)
	return b, storage, transport, ctx
}

func injectStaticAccountCredentialsJSON(t *testing.T, b *backend, transport *staticAccountIdentityTransport, credentialJSON string) {
	t.Helper()
	creds := &google.Credentials{
		ProjectID:   staticIdentityProject,
		JSON:        []byte(credentialJSON),
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-access-token"}),
	}
	b.cache.Expire("credentials")
	state := &credentialState{credentials: creds}
	_, err := b.cache.Fetch("credentials", cacheTime, func() (interface{}, error) { return state, nil })
	require.NoError(t, err)
	b.credentialClientLock.Lock()
	b.credentialClient = &credentialClient{
		credentials: creds,
		state:       state,
		httpClient: &http.Client{Transport: &oauth2.Transport{
			Source: creds.TokenSource,
			Base:   transport,
		}},
	}
	b.credentialClientLock.Unlock()
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
	t                *testing.T
	mu               sync.Mutex
	keyCreates       []string
	accountLookups   []string
	tokensIssued     int
	omitEmail        bool
	omitEmailIDs     map[string]bool
	keyCreateEntered chan struct{}
	releaseKeyCreate chan struct{}
	// stallLookups makes service account lookups wait until their request is
	// canceled. Each stalled lookup is announced on lookupStalled.
	stallLookups  bool
	lookupStalled chan struct{}
	// stallKeyCreates makes key creation wait until its request is canceled,
	// announcing each stalled request on keyCreateStalled.
	stallKeyCreates  bool
	keyCreateStalled chan struct{}
}

func (tr *staticAccountIdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.mu.Lock()
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/"), "/")
	if tr.stallKeyCreates && req.Method == http.MethodPost && req.URL.Host == "iam.googleapis.com" &&
		len(parts) == 5 && parts[4] == "keys" {
		tr.mu.Unlock()
		select {
		case tr.keyCreateStalled <- struct{}{}:
		default:
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	if tr.stallLookups && req.Method == http.MethodGet && req.URL.Host == "iam.googleapis.com" && len(parts) == 4 {
		tr.accountLookups = append(tr.accountLookups, parts[3])
		tr.mu.Unlock()
		select {
		case tr.lookupStalled <- struct{}{}:
		default:
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	defer tr.mu.Unlock()

	var response interface{}
	switch {
	case req.Method == http.MethodPost && req.URL.String() == staticIdentityTokenURL:
		tr.tokensIssued++
		response = map[string]interface{}{"access_token": staticIdentityIssuedToken, "token_type": "Bearer", "expires_in": 3600}
	case req.URL.Host == "iam.googleapis.com" && len(parts) >= 4 &&
		parts[0] == "projects" && (parts[1] == "-" || parts[1] == staticIdentityProject) && parts[2] == "serviceAccounts":
		account := &iam.ServiceAccount{ProjectId: staticIdentityProject}
		// IAM rejects service account names that are themselves resource names.
		if req.Method == http.MethodGet && parts[3] == "projects" {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":404,"message":"not found"}}`)),
				Request:    req,
			}, nil
		}
		// IAM resolves service account emails case-insensitively and returns the
		// canonical lowercase email.
		switch strings.ToLower(parts[3]) {
		case staticIdentityRootEmail, staticIdentityRootID:
			account.Email, account.UniqueId = staticIdentityRootEmail, staticIdentityRootID
		case staticIdentityOtherEmail, staticIdentityOtherID:
			account.Email, account.UniqueId = staticIdentityOtherEmail, staticIdentityOtherID
		default:
			return tr.unexpected(req)
		}
		if tr.omitEmail || tr.omitEmailIDs[parts[3]] {
			account.Email = ""
		}
		account.Name = "projects/" + staticIdentityProject + "/serviceAccounts/" + account.UniqueId
		switch {
		case req.Method == http.MethodGet && len(parts) == 4:
			tr.accountLookups = append(tr.accountLookups, parts[3])
			response = account
		case req.Method == http.MethodPost && len(parts) == 5 && parts[4] == "keys":
			if tr.keyCreateEntered != nil {
				tr.keyCreateEntered <- struct{}{}
				<-tr.releaseKeyCreate
			}
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
