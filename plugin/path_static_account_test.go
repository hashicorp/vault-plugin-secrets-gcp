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

const staticAccountDisplayNameTmpl = "Test Static Account for Vault secrets backend %s"

func TestPathStatic_Basic(t *testing.T) {
	staticName := "test-static-basic"

	td := setupTest(t, "0s", "2h")
	defer cleanupStatic(t, td, staticName, util.StringSet{})

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	// 1. Read should return nothing
	respData := testStaticRead(t, td, staticName)
	if respData != nil {
		t.Fatalf("expected static account to not exist initially")
	}

	// 2. Create new static account
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read static account
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                nil,
	})

	// 4. Delete static account
	testStaticDelete(t, td, staticName)
}

// Tests that some fields cannot be updated
func TestPathStatic_UpdateDisallowed(t *testing.T) {
	staticName := "test-static-update-fail"

	td := setupTest(t, "0s", "2h")
	defer cleanupStatic(t, td, staticName, util.StringSet{})

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	saNew := createStaticAccount(t, td, staticName+"-new")
	defer deleteStaticAccount(t, td, saNew)
	defer cleanupStatic(t, td, staticName+"-new", util.StringSet{})

	// 1. Read should return nothing
	respData := testStaticRead(t, td, staticName)
	if respData != nil {
		t.Fatalf("expected static account to not exist initially")
	}

	// 2. Create new static account
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"secret_type":           SecretTypeKey,
		})

	// 3. Read static account
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeKey,
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                nil,
	})

	// 4. Verify theses updates don't work:
	errCases := []map[string]interface{}{
		{
			// Email cannot be changed
			"service_account_email": saNew.Email,
		},
		{
			// Cannot change secret type
			"secret_type": SecretTypeAccessToken,
		},
	}
	for _, d := range errCases {
		resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("%s/%s", staticAccountPathPrefix, staticName),
			Data:      d,
			Storage:   td.S,
		})
		if err == nil && (resp != nil && !resp.IsError()) {
			t.Fatalf("expected update to fail; data: %v", d)
		}
	}

	// 5. Delete static account
	testStaticDelete(t, td, staticName)
}

func TestPathStatic_WithBindings(t *testing.T) {
	staticName := "test-static-binding"
	roles := util.StringSet{
		"roles/viewer": struct{}{},
	}

	td := setupTest(t, "0s", "2h")
	defer cleanupStatic(t, td, staticName, roles)

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

	// 1. Read should return nothing
	respData := testStaticRead(t, td, staticName)
	if respData != nil {
		t.Fatalf("expected static account to not exist initially")
	}

	// 2. Create new static account
	expectedBinds := ResourceBindings{projRes: roles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"bindings":              bindsRaw,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read static account
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                expectedBinds,
	})

	// Verify service account has given role on project
	verifyProjectBinding(t, td, sa.Email, roles)

	// 4. Delete static account
	testStaticDelete(t, td, staticName)
	verifyProjectBindingsRemoved(t, td, sa.Email, roles)
}

func TestPathStatic_UpdateBinding(t *testing.T) {
	staticName := "test-static-up-binding"

	initRoles := util.StringSet{
		"roles/viewer": struct{}{},
	}
	updatedRoles := util.StringSet{
		"roles/browser":         struct{}{},
		"roles/cloudsql.client": struct{}{},
	}

	td := setupTest(t, "0s", "2h")
	defer cleanupStatic(t, td, staticName, initRoles.Union(updatedRoles))

	sa := createStaticAccount(t, td, staticName)
	defer deleteStaticAccount(t, td, sa)

	projRes := fmt.Sprintf(testProjectResourceTemplate, td.Project)

	// 1. Read should return nothing
	respData := testStaticRead(t, td, staticName)
	if respData != nil {
		t.Fatalf("expected static account to not exist initially")
	}

	// 2. Create new static account
	testStaticCreate(t, td, staticName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	// 3. Read static account
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to have been created")
	}

	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                nil,
	})

	// Verify service account has no role on project
	verifyProjectBinding(t, td, sa.Email, util.StringSet{})

	// 4. Add Binding
	expectedBinds := ResourceBindings{projRes: initRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testStaticUpdate(t, td, staticName, map[string]interface{}{
		"service_account_email": sa.Email,
		"token_scopes":          []string{iam.CloudPlatformScope},
		"bindings":              bindsRaw,
	})

	// 5. Check Binding is added
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to still exist")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                expectedBinds,
	})
	// Verify service account has given role on project
	verifyProjectBinding(t, td, sa.Email, initRoles)

	// 6. Modify Binding
	expectedBinds = ResourceBindings{projRes: updatedRoles}
	bindsRaw, err = util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testStaticUpdate(t, td, staticName, map[string]interface{}{
		"service_account_email": sa.Email,
		"token_scopes":          []string{iam.CloudPlatformScope},
		"bindings":              bindsRaw,
	})

	// 7. Check Binding is modified
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to still exist")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                expectedBinds,
	})
	// Verify service account has given role on project
	verifyProjectBinding(t, td, sa.Email, updatedRoles)
	verifyProjectBindingsRemoved(t, td, sa.Email, initRoles)

	// 8. Remove Binding
	testStaticUpdate(t, td, staticName, map[string]interface{}{
		"service_account_email": sa.Email,
		"token_scopes":          []string{iam.CloudPlatformScope},
		"bindings":              "",
	})

	// 9. Check Binding is removed
	respData = testStaticRead(t, td, staticName)
	if respData == nil {
		t.Fatalf("expected static account to still exist")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_email":   sa.Email,
		"service_account_project": sa.ProjectId,
		"bindings":                nil,
	})
	verifyProjectBindingsRemoved(t, td, sa.Email, updatedRoles)

	// 10. Delete static account
	testStaticDelete(t, td, staticName)
}

func createStaticAccount(t *testing.T, td *testData, staticName string) *iam.ServiceAccount {
	intSuffix := fmt.Sprintf("%d", time.Now().Unix())
	fullName := fmt.Sprintf("%s-%s", staticName, intSuffix)
	if len(fullName) > 30 {
		fullName = fullName[0:30]
	}

	createSaReq := &iam.CreateServiceAccountRequest{
		AccountId: fullName,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf(staticAccountDisplayNameTmpl, staticName),
		},
	}

	sa, err := td.IamAdmin.Projects.ServiceAccounts.Create(fmt.Sprintf("projects/%s", td.Project), createSaReq).Do()
	if err != nil {
		t.Fatalf("could not create static service account %q", err)
	}

	return sa
}

func deleteStaticAccount(t *testing.T, td *testData, sa *iam.ServiceAccount) {
	_, err := td.IamAdmin.Projects.ServiceAccounts.Delete(sa.Name).Do()

	if err != nil {
		t.Logf("[WARNING] Could not clean up test static service account %s", sa.Name)
	}
}

func testStaticRead(t *testing.T, td *testData, staticName string) map[string]interface{} {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("%s/%s", staticAccountStoragePrefix, staticName),
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

func testStaticCreate(t *testing.T, td *testData, staticName string, d map[string]interface{}) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("%s/%s", staticAccountPathPrefix, staticName),
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

func testStaticUpdate(t *testing.T, td *testData, staticName string, d map[string]interface{}) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("%s/%s", staticAccountPathPrefix, staticName),
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

func testStaticDelete(t *testing.T, td *testData, staticName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("%s/%s", staticAccountPathPrefix, staticName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatalf("unable to delete role set: %v", err)
	} else if resp != nil {
		if len(resp.Warnings) > 0 {
			t.Logf("warnings returned from role set delete. Warnings:\n %s\n", strings.Join(resp.Warnings, ",\n"))
		}
		if resp.IsError() {
			t.Fatalf("unable to delete role set: %v", resp.Error())
		}
	}
}
