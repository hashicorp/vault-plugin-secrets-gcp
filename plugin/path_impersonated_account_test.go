package gcpsecrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
)

const impersonateAccountDisplayNameTmpl = "Test Impersonated Account for Vault secrets backend %s"

func TestPathImpersonate_Basic(t *testing.T) {
	impersonateName := "test-impersonated-basic"

	td := setupTest(t, "0s", "2h")
	defer cleanupImpersonate(t, td, impersonateName, util.StringSet{})

	sa := createServiceAccount(t, td, impersonateName)
	defer deleteServiceAccount(t, td, sa)

	// 1. Read should return nothing
	respData := testImpersonateRead(t, td, impersonateName)
	if respData != nil {
		t.Fatalf("expected impersonate account to not exist initially")
	}

	// 2. Create new impersonate account
	testImpersonateCreate(t, td, impersonateName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read impersonated account
	respData = testImpersonateRead(t, td, impersonateName)
	if respData == nil {
		t.Fatalf("expected impersonate account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
	})
	// Test impersonate account is listed
	testImpersonateList(t, td, impersonateName)

	// 4. Delete impersonated account
	testImpersonateDelete(t, td, impersonateName)
}

func TestPathImpersonate_TTL(t *testing.T) {
	impersonateName := "test-impersonated-basic"

	td := setupTest(t, "0s", "2h")
	defer cleanupImpersonate(t, td, impersonateName, util.StringSet{})

	sa := createServiceAccount(t, td, impersonateName)
	defer deleteServiceAccount(t, td, sa)

	// 1. Read should return nothing
	respData := testImpersonateRead(t, td, impersonateName)
	if respData != nil {
		t.Fatalf("expected impersonate account to not exist initially")
	}

	// 2. Create new impersonated account with a TTL of 4 hours
	// (longer than MaxTTL of 2 horus)
	const ttl = 60 * 60 * 4
	testImpersonateCreate(t, td, impersonateName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
			"ttl":                   ttl,
		})

	// 3. Read impersonated account
	respData = testImpersonateRead(t, td, impersonateName)
	if respData == nil {
		t.Fatalf("expected impersonate account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"ttl":                     ttl,
	})
	// Test impersonate account is listed
	testImpersonateList(t, td, impersonateName)

	// 4. Delete impersonated account
	testImpersonateDelete(t, td, impersonateName)
}

// Tests that fields can be updated
func TestPathImpersonate_Update(t *testing.T) {
	impersonateName := "test-imp-update"

	td := setupTest(t, "0s", "2h")
	defer cleanupImpersonate(t, td, impersonateName, util.StringSet{})

	sa := createServiceAccount(t, td, impersonateName)
	defer deleteServiceAccount(t, td, sa)

	// 1. Read should return nothing
	respData := testImpersonateRead(t, td, impersonateName)
	if respData != nil {
		t.Fatalf("expected impersonate account to not exist initially")
	}

	// 2. Create new impersonated account
	testImpersonateCreate(t, td, impersonateName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read impersonated account
	respData = testImpersonateRead(t, td, impersonateName)
	if respData == nil {
		t.Fatalf("expected impersonate account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"token_scopes":            []string{iam.CloudPlatformScope},
	})

	// 4. Verify these updates:
	cases := []map[string]interface{}{
		{
			// Token scopes can be changed
			"token_scopes": []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
		},
	}
	for _, d := range cases {
		resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("%s/%s", impersonatedAccountPathPrefix, impersonateName),
			Data:      d,
			Storage:   td.S,
		})
		if err != nil || (resp != nil && !resp.IsError()) {
			t.Fatalf("expected update not to fail; data: %v", d)
		}

		verifyReadData(t, testImpersonateRead(t, td, impersonateName), map[string]interface{}{
			"service_account_email":   sa.Email,
			"service_account_project": sa.ProjectId,
			"token_scopes":            []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
		})
	}

	// 5. Delete impersonated account
	testImpersonateDelete(t, td, impersonateName)
}

// Tests that some fields cannot be updated
func TestPathImpersonate_UpdateDisallowed(t *testing.T) {
	impersonateName := "test-imp-update-fail"

	td := setupTest(t, "0s", "2h")
	defer cleanupImpersonate(t, td, impersonateName, util.StringSet{})

	sa := createServiceAccount(t, td, impersonateName)
	defer deleteServiceAccount(t, td, sa)

	saNew := createServiceAccount(t, td, impersonateName+"-new")
	defer cleanupImpersonate(t, td, impersonateName+"-new", util.StringSet{})
	defer deleteServiceAccount(t, td, saNew)

	// 1. Read should return nothing
	respData := testImpersonateRead(t, td, impersonateName)
	if respData != nil {
		t.Fatalf("expected impersonate account to not exist initially")
	}

	// 2. Create new impersonated account
	testImpersonateCreate(t, td, impersonateName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read impersonated account
	respData = testImpersonateRead(t, td, impersonateName)
	if respData == nil {
		t.Fatalf("expected impersonate account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"token_scopes":            []string{iam.CloudPlatformScope},
	})

	// 4. Verify these updates don't work:
	errCases := []map[string]interface{}{
		{
			// Token scopes cannot be empty
			"token_scopes": []string{},
		},
		{
			// Email cannot be changed
			"service_account_email": saNew.Email,
		},
	}
	for _, d := range errCases {
		resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("%s/%s", impersonatedAccountPathPrefix, impersonateName),
			Data:      d,
			Storage:   td.S,
		})
		if err == nil && (resp != nil && !resp.IsError()) {
			t.Fatalf("expected update to fail; data: %v", d)
		}
	}

	// 5. Delete impersonated account
	testImpersonateDelete(t, td, impersonateName)
}

func createServiceAccount(t *testing.T, td *testData, roleName string) *iam.ServiceAccount {
	intSuffix := fmt.Sprintf("%d", time.Now().Unix())
	fullName := fmt.Sprintf("%s-%s", roleName, intSuffix)
	if len(fullName) > 30 {
		fullName = fullName[0:30]
	}

	createSaReq := &iam.CreateServiceAccountRequest{
		AccountId: fullName,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf(impersonateAccountDisplayNameTmpl, roleName),
		},
	}

	sa, err := td.IamAdmin.Projects.ServiceAccounts.Create(fmt.Sprintf("projects/%s", td.Project), createSaReq).Do()
	if err != nil {
		t.Fatalf("could not create impersonated service account %q", err)
	}

	return sa
}

func deleteServiceAccount(t *testing.T, td *testData, sa *iam.ServiceAccount) {
	_, err := td.IamAdmin.Projects.ServiceAccounts.Delete(sa.Name).Do()

	if err != nil {
		t.Logf("[WARNING] Could not clean up test impersonated service account %s", sa.Name)
	}
}

func testImpersonateRead(t *testing.T, td *testData, roleName string) map[string]interface{} {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("%s/%s", impersonatedAccountPathPrefix, roleName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		return nil
	}

	return resp.Data
}

func testImpersonateCreate(t *testing.T, td *testData, roleName string, d map[string]interface{}) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("%s/%s", impersonatedAccountPathPrefix, roleName),
		Data:      d,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testImpersonateDelete(t *testing.T, td *testData, roleName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("%s/%s", impersonatedAccountPathPrefix, roleName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatalf("unable to delete impersonated account: %v", err)
	} else if resp != nil {
		if len(resp.Warnings) > 0 {
			t.Logf("warnings returned from impersonated account delete. Warnings:\n %s\n", strings.Join(resp.Warnings, ",\n"))
		}
		if resp.IsError() {
			t.Fatalf("unable to delete impersonated account: %v", resp.Error())
		}
	}
}

func testImpersonateList(t *testing.T, td *testData, roleName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      impersonatedAccountPathPrefix,
		Storage:   td.S,
	})

	if err != nil {
		t.Fatalf("unable to list impersonated accounts: %v", err)
	} else if resp != nil {
		if len(resp.Warnings) > 0 {
			t.Logf("warnings returned from impersonated account list. Warnings:\n %s\n", strings.Join(resp.Warnings, ",\n"))
		}
		if resp.IsError() {
			t.Fatalf("unable to list impersonated accounts: %v", resp.Error())
		}
		keys, ok := resp.Data["keys"].([]string)
		if !ok {
			t.Fatalf("expected response to contain data map with key 'key' of type []string keys")
		}
		found := false
		for _, s := range keys {
			if s == roleName {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected impersonated accounts listing to contain impersonated account but did not")
		}
	}
}
