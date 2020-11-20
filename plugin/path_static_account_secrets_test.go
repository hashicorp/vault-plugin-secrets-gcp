package gcpsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

func TestStaticSecrets_GetAccessToken(t *testing.T) {
	staticName := "test-static-token"
	testGetStaticAccessToken(t, staticName)
}

func TestStaticSecrets_GetKey(t *testing.T) {
	staticName := "test-static-key"
	testGetStaticKey(t, staticName, 0)
}

func TestStaticSecrets_GetKeyTTLOverride(t *testing.T) {
	staticName := "test-static-key-ttl"
	testGetStaticKey(t, staticName, 1200)
}

func testGetStaticAccessToken(t *testing.T, staticName string) {
	secretType := SecretTypeAccessToken

	td := setupTest(t, "0s", "2h")
	defer cleanupStatic(t, td, staticName, testRoles)

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

	expectedBinds := ResourceBindings{projRes: testRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
			"secret_type":           secretType,
			"bindings":              bindsRaw,
		})

	// expect error for trying to read key from token
	testGetKeyFail(t, td, fmt.Sprintf("%s/%s/key", staticAccountPathPrefix, staticName))

	token := testGetToken(t, fmt.Sprintf("%s/%s/token", staticAccountPathPrefix, staticName), td)

	callC := oauth2.NewClient(
		context.Background(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	)
	checkSecretPermissions(t, td, callC)

	// Cleanup
	testStaticDelete(t, td, staticName)
	verifyProjectBindingsRemoved(t, td, sa.Email, testRoles)
}

func testGetStaticKey(t *testing.T, staticName string, ttl uint64) {
	secretType := SecretTypeKey

	td := setupTest(t, "60s", "2h")
	defer cleanupStatic(t, td, staticName, testRoles)

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

	expectedBinds := ResourceBindings{projRes: testRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"secret_type":           secretType,
			"bindings":              bindsRaw,
		})

	// expect error for trying to read token
	testGetTokenFail(t, td, fmt.Sprintf("%s/%s/token", staticAccountPathPrefix, staticName))

	var creds *google.Credentials
	var resp *logical.Response
	if ttl == 0 {
		creds, resp = testGetKey(t, fmt.Sprintf("%s/%s/key", staticAccountPathPrefix, staticName), td)
		if uint(resp.Secret.LeaseTotal().Seconds()) != 60 {
			t.Fatalf("expected lease duration %d, got %d", 60, int(resp.Secret.LeaseTotal().Seconds()))
		}
	} else {
		// call the POST endpoint of /gcp/key/:roleset:/key with TTL
		creds, resp = testPostKey(t, td, fmt.Sprintf("%s/%s/key", staticAccountPathPrefix, staticName), fmt.Sprintf("%ds", ttl))
		if uint64(resp.Secret.LeaseTotal().Seconds()) != ttl {
			t.Fatalf("expected lease duration %d, got %d", ttl, int(resp.Secret.LeaseTotal().Seconds()))
		}
	}

	if int(resp.Secret.LeaseOptions.MaxTTL.Hours()) != 2 {
		t.Fatalf("expected max lease %d, got %d", 2, int(resp.Secret.LeaseOptions.MaxTTL.Hours()))
	}

	secret := resp.Secret
	// Confirm calls with key work
	keyHttpC := oauth2.NewClient(context.Background(), creds.TokenSource)
	checkSecretPermissions(t, td, keyHttpC)

	keyName := secret.InternalData["key_name"].(string)
	if keyName == "" {
		t.Fatalf("expected internal data to include key name")
	}

	_, err = td.IamAdmin.Projects.ServiceAccounts.Keys.Get(keyName).Do()
	if err != nil {
		t.Fatalf("could not get key from given internal 'key_name': %v", err)
	}

	testRenewSecretKey(t, td, secret)
	testRevokeSecretKey(t, td, secret)

	k, err := td.IamAdmin.Projects.ServiceAccounts.Keys.Get(keyName).Do()
	if err == nil || !isGoogleAccountKeyNotFoundErr(err) {
		t.Fatalf("expected 404 error from getting deleted key, instead got error: %v", err)
	}
	if k != nil {
		t.Fatalf("expected error as revoked key was deleted, instead got key: %v", k)
	}

	// Cleanup
	testStaticDelete(t, td, staticName)
	verifyProjectBindingsRemoved(t, td, sa.Email, testRoles)
}
