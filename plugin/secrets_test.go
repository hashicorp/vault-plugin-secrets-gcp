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

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

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
	testGetKeyFail(t, td, rsName)

	token := testGetToken(t, td, rsName)

	callC := oauth2.NewClient(
		context.Background(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	)
	checkSecretPermissions(t, td, callC)

	// Cleanup: Delete role set
	testRoleSetDelete(t, td, rsName, sa.Name)
	verifyProjectBindingsRemoved(t, td, sa.Email, testRoles)
}

func TestSecrets_GenerateKey(t *testing.T) {
	secretType := SecretTypeKey
	rsName := "test-genkey"

	td := setupTest(t)
	defer cleanup(t, td, rsName, testRoles)

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

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
	testGetTokenFail(t, td, rsName)

	oauthCfg, secret := testGetKey(t, td, rsName)

	// Confirm calls with key work
	keyHttpC := oauthCfg.Client(context.Background())
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

func testGetTokenFail(t *testing.T, td *testData, rsName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("token/%s", rsName),
		Data:      make(map[string]interface{}),
		Storage:   td.S,
	})
	if err == nil && !resp.IsError() {
		t.Fatalf("expected error, instead got valid response (data: %v)", resp.Data)
	}
}

func testGetKeyFail(t *testing.T, td *testData, rsName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("key/%s", rsName),
		Data:      make(map[string]interface{}),
		Storage:   td.S,
	})
	if err == nil && !resp.IsError() {
		t.Fatalf("expected error, instead got valid response (data: %v)", resp.Data)
	}
}

func testGetToken(t *testing.T, td *testData, rsName string) (token string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("token/%s", rsName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp == nil || resp.Data == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}

	expiresAtRaw, ok := resp.Data["expires_at"]
	if !ok {
		t.Fatalf("expected 'expires_at' field to be returned")
	}
	expiresAt := expiresAtRaw.(time.Time)
	if time.Now().Sub(expiresAt) > time.Hour {
		t.Fatalf("expected token to expire within an hour")
	}

	tokenRaw, ok := resp.Data["token"]
	if !ok {
		t.Fatalf("expected 'token' field to be returned")
	}
	return tokenRaw.(string)
}

func testGetKey(t *testing.T, td *testData, rsName string) (*jwt.Config, *logical.Secret) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("key/%s", rsName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil || resp.Secret == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}
	if resp.Secret.ExpirationTime().Sub(resp.Secret.IssueTime) > defaultLeaseTTLHr*time.Hour {
		t.Fatalf("unexpected lease duration is longer than backend default")
	}

	cfg := getKeyJWTConfig(t, resp.Data)
	return cfg, resp.Secret
}

func testRenewSecretKey(t *testing.T, td *testData, sec *logical.Secret) {
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

func testRevokeSecretKey(t *testing.T, td *testData, sec *logical.Secret) {
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
