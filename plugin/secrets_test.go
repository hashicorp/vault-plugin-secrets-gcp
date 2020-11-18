package gcpsecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

const maxTokenTestCalls = 10

var testRoles = util.StringSet{
	// PERMISSIONS for roles/iam.roleViewer:
	// 		iam.roles.get
	// 		iam.roles.list
	// 		resourcemanager.projects.get
	// 		resourcemanager.projects.getIamPolicy
	"roles/iam.roleViewer": struct{}{},
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

func testGetTokenFail(t *testing.T, td *testData, path string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      make(map[string]interface{}),
		Storage:   td.S,
	})
	if err == nil && !resp.IsError() {
		t.Fatalf("expected error, instead got valid response (data: %v)", resp.Data)
	}

	error := resp.Error().Error()
	if !strings.Contains(error, "cannot generate access tokens (has secret type service_account_key)") {
		t.Fatalf("unexpected error: %s", error)
	}
}

func testGetKeyFail(t *testing.T, td *testData, path string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      make(map[string]interface{}),
		Storage:   td.S,
	})
	if err == nil && !resp.IsError() {
		t.Fatalf("expected error, instead got valid response (data: %v)", resp.Data)
	}

	error := resp.Error().Error()
	if !strings.Contains(error, "cannot generate service account keys (has secret type access_token)") {
		t.Fatalf("unexpected error: %s", error)
	}
}

func retryGetToken(td *testData, path string) (*logical.Response, error) {
	// Newly created key in backend is eventually consistent.
	// Might take up to 60s according to Google's docs
	rawResp, err := retryTestFunc(func() (interface{}, error) {
		resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   td.S,
		})

		if err != nil {
			return resp, err
		}

		if resp != nil && resp.IsError() {
			return resp, resp.Error()
		}
		return resp, err
	}, maxTokenTestCalls)

	resp := rawResp.(*logical.Response)
	return resp, err
}

func testGetToken(t *testing.T, path string, td *testData) (token string) {
	resp, err := retryGetToken(td, path)

	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp == nil || resp.Data == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}

	expiresAtRaw, ok := resp.Data["expires_at_seconds"]
	if !ok {
		t.Fatalf("expected 'expires_at' field to be returned")
	}
	expiresAt := time.Unix(expiresAtRaw.(int64), 0)
	if time.Now().Sub(expiresAt) > time.Hour {
		t.Fatalf("expected token to expire within an hour")
	}

	ttlRaw, ok := resp.Data["token_ttl"]
	if !ok {
		t.Fatalf("expected 'token_ttl' field to be returned")
	}
	tokenTtl := ttlRaw.(time.Duration)
	if tokenTtl > time.Hour || tokenTtl < 0 {
		t.Fatalf("expected token ttl to be less than one hour")
	}

	tokenRaw, ok := resp.Data["token"]
	if !ok {
		t.Fatalf("expected 'token' field to be returned")
	}
	return tokenRaw.(string)
}

// testPostKey enables the POST call to roleset|static/:name:/key
func testPostKey(t *testing.T, td *testData, path, ttl string) (*google.Credentials, *logical.Response) {
	data := map[string]interface{}{}
	if ttl != "" {
		data["ttl"] = ttl
	}

	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   td.S,
		Data:      data,
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

	creds := getGoogleCredentials(t, resp.Data)
	return creds, resp
}

func testGetKey(t *testing.T, path string, td *testData) (*google.Credentials, *logical.Response) {
	data := map[string]interface{}{}

	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   td.S,
		Data:      data,
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

	creds := getGoogleCredentials(t, resp.Data)
	return creds, resp
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

func retryTestFunc(f func() (interface{}, error), retries int) (interface{}, error) {
	var err error
	var value interface{}
	for i := 0; i < retries; i++ {
		if value, err = f(); err == nil {
			return value, nil
		}
		log.Printf("[DEBUG] test check failed with error %v (attempt %d), sleeping one second before trying again", err, i)
		time.Sleep(time.Second)
	}
	return value, err
}

func checkSecretPermissions(t *testing.T, td *testData, httpC *http.Client) {
	iamAdmin, err := iam.NewService(context.Background(), option.WithHTTPClient(httpC))
	if err != nil {
		t.Fatalf("could not construct new IAM Admin Service client from given token: %v", err)
	}

	// Should succeed: List roles
	_, err = retryTestFunc(func() (interface{}, error) {
		roles, err := iamAdmin.Projects.Roles.List(fmt.Sprintf("projects/%s", td.Project)).Do()
		return roles, err
	}, maxTokenTestCalls)
	if err != nil {
		t.Fatalf("expected call using authorized secret to succeed, instead got error: %v", err)
	}

	// Should fail (immediately): list service accounts
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

func getGoogleCredentials(t *testing.T, d map[string]interface{}) *google.Credentials {
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

	creds, err := google.CredentialsFromJSON(context.Background(), []byte(keyJSON), iam.CloudPlatformScope)
	if err != nil {
		t.Fatalf("could not get JWT config from given 'private_key_data': %v", err)
	}
	return creds
}
