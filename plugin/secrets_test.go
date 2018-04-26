package gcpsecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
)

var testRoles = util.StringSet{
	// PERMISSIONS for roles/iam.roleViewer:
	// 		iam.roles.get
	// 		iam.roles.list
	// 		resourcemanager.projects.get
	// 		resourcemanager.projects.getIamPolicy
	"roles/iam.roleViewer": struct{}{},
}

func TestSecrets_GenerateAccessToken(t *testing.T) {
	secretType := SecretTypeAccessToken
	rsName := "test-gentoken"

	td := setupTest(t)
	defer cleanup(t, td, rsName, testRoles)

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create new role set
	expectedBinds := ResourceBindings{projRes: testRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"secret_type":  secretType,
			"project":      td.Project,
			"bindings":     bindsRaw,
			"token_scopes": []string{iam.CloudPlatformScope},
		})
	sa := getRoleSetAccount(t, td, rsName)

	// expect error for trying to read key from token roleset
	testGetKey(t, td, rsName, nil, true)

	resp := testGetToken(t, td, rsName, nil, false) // !expectError

	if time.Now().Sub(resp.Secret.ExpirationTime()) > time.Hour {
		t.Fatalf("expected token to expire within an hour")
	}

	tokenRaw, ok := resp.Data["token"]
	if !ok {
		t.Fatalf("expected 'token' field to be returned")
	}

	if resp.Secret.TTL >= time.Hour {
		t.Fatalf("expected token to expire within an hour")
	}

	token := tokenRaw.(string)
	callC := oauth2.NewClient(
		context.Background(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	)
	checkSecretPermissions(t, td, callC)

	testRenewSecret(t, td, resp.Secret)

	// OAuth token revocation is delayed so we can't really
	// test permissions are removed. Revocation shouldn't fail though.
	testRevokeSecret(t, td, resp.Secret, true) // isToken

	// Cleanup: Delete role set
	testRoleSetDelete(t, td, rsName, sa.Name)
	verifyProjectBindingsRemoved(t, td, sa.Email, testRoles)
}

func TestSecrets_GenerateKey(t *testing.T) {
	secretType := SecretTypeKey
	rsName := "test-genkey"

	td := setupTest(t)
	defer cleanup(t, td, rsName, testRoles)

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create new role set
	expectedBinds := ResourceBindings{projRes: testRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"secret_type": secretType,
			"project":     td.Project,
			"bindings":    bindsRaw,
		})
	sa := getRoleSetAccount(t, td, rsName)

	// expect error for trying to read token from key roleset
	testGetToken(t, td, rsName, nil, true)

	resp := testGetKey(t, td, rsName, nil, false) // !expectError

	// Confirm lease data
	if resp.Secret.ExpirationTime().Sub(resp.Secret.IssueTime) > defaultLeaseTTLHr*time.Hour {
		t.Fatalf("unexpected lease duration is longer than backend default")
	}

	// Confirm calls with key work
	callC := getKeyJWTConfig(t, resp.Data).Client(context.Background())
	checkSecretPermissions(t, td, callC)

	keyName := resp.Secret.InternalData["key_name"].(string)
	if keyName == "" {
		t.Fatalf("expected internal data to include key name")
	}

	_, err = td.IamAdmin.Projects.ServiceAccounts.Keys.Get(keyName).Do()
	if err != nil {
		t.Fatalf("could not get key from given internal 'key_name': %v", err)
	}

	testRenewSecret(t, td, resp.Secret)
	testRevokeSecret(t, td, resp.Secret, false) // !isToken

	k, err := td.IamAdmin.Projects.ServiceAccounts.Keys.Get(keyName).Do()

	if k != nil {
		t.Fatalf("expected error as revoked key was deleted, instead got key: %v", k)
	}
	if err == nil || !isGoogleApi404Error(err) {
		t.Fatalf("expected 404 error from getting deleted key, instead got error: %v", err)
	}

	// Cleanup: Delete role set
	testRoleSetDelete(t, td, rsName, sa.Name)
	verifyProjectBindingsRemoved(t, td, sa.Email, testRoles)
}

func getRoleSetAccount(t *testing.T, td *testData, rsName string) *iam.ServiceAccount {
	rs, err := getRoleSet(rsName, context.Background(), td.S)
	if err != nil {
		t.Fatalf("unable to get role set: %v", err)
	}
	if rs == nil || rs.AccountId == nil {
		t.Fatalf("role set not found")
	}

	sa, err := td.IamAdmin.Projects.ServiceAccounts.Get(rs.AccountId.ResourceName()).Do()
	if err != nil {
		t.Fatalf("unable to get service account: %v", err)
	}
	return sa
}

func testGetToken(t *testing.T, td *testData, rsName string, d map[string]interface{}, expectError bool) (resp *logical.Response) {
	return testGetSecret("token", t, td, rsName, d, expectError)
}

func testGetKey(t *testing.T, td *testData, rsName string, d map[string]interface{}, expectError bool) (resp *logical.Response) {
	return testGetSecret("key", t, td, rsName, d, expectError)
}

func testGetSecret(pathPrefix string, t *testing.T, td *testData, rsName string, d map[string]interface{}, expectError bool) (resp *logical.Response) {
	var err error
	if len(d) > 0 {
		resp, err = td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      fmt.Sprintf("%s/%s", pathPrefix, rsName),
			Storage:   td.S,
		})
	} else {
		resp, err = td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("%s/%s", pathPrefix, rsName),
			Data:      d,
			Storage:   td.S,
		})
	}
	if !expectError {
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}
		if resp == nil || resp.Secret == nil {
			t.Fatalf("expected response with secret, got response: %v", resp)
		}
		return resp
	}

	if err == nil && !resp.IsError() {
		t.Fatalf("expected error, instead got valid response (data: %v)", resp.Data)
	}
	return nil
}

func testRenewSecret(t *testing.T, td *testData, sec *logical.Secret) {
	sec.IssueTime = time.Now()
	sec.Increment = time.Hour
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    sec,
		Storage:   td.S,
	})

	if sec.Renewable {
		if err != nil {
			t.Fatalf("got error while trying to renew: %v", err)
		} else if resp.IsError() {
			t.Fatalf("got error while trying to renew: %v", resp.Error())
		}
	} else if err == nil && !resp.IsError() {
		t.Fatal("expected error for attempting to renew non-renewable token")
	}
}

func testRevokeSecret(t *testing.T, td *testData, sec *logical.Secret, isToken bool) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    sec,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if isToken {
		if resp == nil || len(resp.Warnings) == 0 {
			t.Fatal("expected non-nil response with warning on revoking access tokens")
		}
	}
}

func checkSecretPermissions(t *testing.T, td *testData, callClient *http.Client) {
	iamAdmin, err := iam.New(callClient)
	if err != nil {
		t.Fatalf("could not construct new IAM Admin Service client from given token: %v", err)
	}

	// Should succeed: List roles
	_, err = iamAdmin.Projects.Roles.List(fmt.Sprintf("projects/%s", td.Project)).Do()
	if err != nil {
		gErr, ok := err.(*googleapi.Error)
		if !ok {
			t.Fatalf("could not verify secret has permissions - got error %v", err)
		}
		if gErr.Code == 403 {
			t.Fatalf("expected call using secret to be authorized, got 403: %v", err)
		}
	}

	// Should fail: List service accounts
	_, err = iamAdmin.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", td.Project)).Do()
	if err != nil {
		gErr, ok := err.(*googleapi.Error)
		if !ok {
			t.Fatalf("could not verify secret has permissions - got error %v", err)
		}
		if gErr.Code != 403 {
			t.Fatalf("expected call using unauthorized secret to be denied with 403, instead got error: %v", err)
		}
	} else {
		t.Fatalf("expected call using unauthorized secret to be denied with 403, instead succeeded")
	}
}

func getKeyJWTConfig(t *testing.T, d map[string]interface{}) *jwt.Config {
	kAlg, ok := d["key_algorithm"]
	if !ok {
		t.Fatalf("expected 'key_algorithm' field to be returned")
	}
	if kAlg.(string) != keyAlgorithmRSA2k {
		t.Fatalf("expected 'key_algorithm' %s, got %v", keyAlgorithmRSA2k, kAlg)
	}

	kType, ok := d["key_type"]
	if !ok {
		t.Fatalf("expected 'key_type' field to be returned")
	}
	if kType.(string) != privateKeyTypeJson {
		t.Fatalf("expected 'key_type' %s, got %v", privateKeyTypeJson, kType)
	}

	keyDataRaw, ok := d["private_key_data"]
	if !ok {
		t.Fatalf("expected 'private_key_data' field to be returned")
	}
	keyJSON, err := base64.StdEncoding.DecodeString(keyDataRaw.(string))
	if err != nil {
		t.Fatalf("could not b64 decode 'private_key_data' field: %v", err)
	}
	cfg, err := google.JWTConfigFromJSON([]byte(keyJSON), iam.CloudPlatformScope)
	if err != nil {
		t.Fatalf("could not get JWT config from given 'private_key_data': %v", err)
	}
	return cfg
}
