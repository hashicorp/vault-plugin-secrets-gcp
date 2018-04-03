package gcpsecrets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
)

func TestPathRoleSet_Basic(t *testing.T) {
	rsName := "test-basicrs"
	roles := util.StringSet{
		"roles/viewer": struct{}{},
	}

	td := setupTest(t)
	defer cleanup(t, td, rsName, roles)

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// 1. Read should return nothing
	respData := testRoleSetRead(t, td, rsName)
	if respData != nil {
		t.Fatalf("expected role set to not exist initially")
	}

	// 2. Create new role set
	expectedBinds := ResourceBindings{projRes: roles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"project":      td.Project,
			"bindings":     bindsRaw,
			"token_scopes": []string{iam.CloudPlatformScope},
		})

	// 3. Read role set
	respData = testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_project": td.Project,
		"bindings":                expectedBinds,
	})

	// Verify service account exists and has given role on project
	sa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, sa.Email, roles)

	// 4. Delete role set
	testRoleSetDelete(t, td, rsName, sa.Name)
	verifyProjectBindingsRemoved(t, td, sa.Email, roles)
}

func TestPathRoleSet_UpdateKeyRoleSet(t *testing.T) {
	rsName := "test-updatekeyrs"
	initRoles := util.StringSet{
		"roles/viewer": struct{}{},
	}
	updatedRoles := util.StringSet{
		"roles/browser":         struct{}{},
		"roles/cloudsql.client": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
	td := setupTest(t)
	defer cleanup(t, td, rsName, initRoles.Union(updatedRoles))

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create role set
	expectedBinds := ResourceBindings{projRes: initRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"project":     td.Project,
			"secret_type": SecretTypeKey,
			"bindings":    bindsRaw,
		})

	// Verify
	respData := testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeKey,
		"service_account_project": td.Project,
		"bindings":                expectedBinds,
	})

	initSa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, initSa.Email, initRoles)

	// Verify theses updates don't work:
	errCases := []map[string]interface{}{
		{
			// new project should not be allowed
			"project": "diff-proj",
		},
		{
			// Cannot be applied to key role sets
			"secret_type": SecretTypeAccessToken,
		},
	}
	for _, d := range errCases {
		resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("roleset/%s", rsName),
			Data:      d,
			Storage:   td.S,
		})
		if err == nil && (resp != nil && !resp.IsError()) {
			t.Fatalf("expected update to fail; data: %v", d)
		}
	}

	// Update role set
	expectedBinds = ResourceBindings{projRes: updatedRoles}
	bindsRaw, err = util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetUpdate(t, td, rsName,
		map[string]interface{}{
			"project":     td.Project,
			"secret_type": SecretTypeKey,
			"bindings":    bindsRaw,
		})

	// Verify
	respData = testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeKey, // default
		"service_account_project": td.Project,
		"bindings":                expectedBinds,
	})

	newSa := getServiceAccount(t, td.IamAdmin, respData)
	if newSa.Name == initSa.Name {
		t.Fatalf("expected role set to have new service account after update")
	}
	verifyProjectBinding(t, td, newSa.Email, updatedRoles)

	verifyServiceAccountDeleted(t, td.IamAdmin, initSa.Name)
	verifyProjectBindingsRemoved(t, td, initSa.Email, updatedRoles)

	// 4. Delete role set
	testRoleSetDelete(t, td, rsName, newSa.Name)
	verifyProjectBindingsRemoved(t, td, newSa.Email, updatedRoles)
}

func TestPathRoleSet_RotateKeyRoleSet(t *testing.T) {
	rsName := "test-rotatekeyrs"
	roles := util.StringSet{
		"roles/viewer": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
	td := setupTest(t)
	defer cleanup(t, td, rsName, roles)

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create role set
	expectedBinds := ResourceBindings{projRes: roles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"project":     td.Project,
			"secret_type": SecretTypeKey,
			"bindings":    bindsRaw,
		})

	// Verify initial role set.
	respData := testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	initSa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, initSa.Email, roles)

	// Rotate account and verify is new account.
	testRoleSetRotate(t, td, rsName)
	newSa := getServiceAccount(t, td.IamAdmin, testRoleSetRead(t, td, rsName))
	if newSa.Name == initSa.Name {
		t.Fatalf("expected role set to have new service account after rotation (update)")
	}
	verifyProjectBinding(t, td, newSa.Email, roles)

	// Verify old account/bindings deleted.
	verifyServiceAccountDeleted(t, td.IamAdmin, initSa.Name)
	verifyProjectBindingsRemoved(t, td, initSa.Email, roles)

	// Get RoleSet object for confirming key rotation:
	rs, err := getRoleSet(rsName, context.Background(), td.S)
	if rs.TokenGen != nil {
		t.Fatalf("expected no token gen to have been created for key role set")
	}

	// 4. Delete role set
	testRoleSetDelete(t, td, rsName, newSa.Name)
	verifyProjectBindingsRemoved(t, td, newSa.Email, roles)
}

func TestPathRoleSet_UpdateTokenRoleSet(t *testing.T) {
	rsName := "test-updatetokenrs"
	initRoles := util.StringSet{
		"roles/viewer": struct{}{},
	}
	updatedRoles := util.StringSet{
		"roles/browser":         struct{}{},
		"roles/cloudsql.client": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
	td := setupTest(t)
	defer cleanup(t, td, rsName, initRoles.Union(updatedRoles))

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create role set
	expectedBinds := ResourceBindings{projRes: initRoles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"project":      td.Project,
			"secret_type":  SecretTypeAccessToken,
			"bindings":     bindsRaw,
			"token_scopes": []string{"https://www.googleapis.com/auth/cloud-platform"},
		})

	// Verify
	respData := testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken,
		"service_account_project": td.Project,
		"bindings":                expectedBinds,
		"token_scopes":            []string{"https://www.googleapis.com/auth/cloud-platform"},
	})

	initSa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, initSa.Email, initRoles)

	initK := verifyRoleSetTokenKey(t, td, rsName)
	if !strings.HasPrefix(initK.Name, initSa.Name) {
		t.Fatalf("expected token key to have been generated under initial service account")
	}

	// Update role set
	expectedBinds = ResourceBindings{projRes: updatedRoles}
	bindsRaw, err = util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetUpdate(t, td, rsName,
		map[string]interface{}{
			"bindings": bindsRaw,
			"token_scopes": []string{
				"https://www.googleapis.com/auth/compute",
				"https://www.googleapis.com/auth/compute.readonly",
			},
		})

	// Verify
	respData = testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken,
		"service_account_project": td.Project,
		"bindings":                expectedBinds,
		"token_scopes": []string{
			"https://www.googleapis.com/auth/compute",
			"https://www.googleapis.com/auth/compute.readonly",
		},
	})
	newSa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, newSa.Email, updatedRoles)
	newK := verifyRoleSetTokenKey(t, td, rsName)
	if !strings.HasPrefix(newK.Name, newSa.Name) {
		t.Fatalf("expected token key to have been generated under new service account")
	}

	// Verify old account was deleted and is not being used anymore.
	if newSa.Name == initSa.Name {
		t.Fatalf("expected role set to have new service account after update")
	}
	verifyServiceAccountDeleted(t, td.IamAdmin, initSa.Name)
	verifyProjectBindingsRemoved(t, td, initSa.Email, updatedRoles)

	// 4. Delete role set
	testRoleSetDelete(t, td, rsName, newSa.Name)
	verifyProjectBindingsRemoved(t, td, newSa.Email, updatedRoles)
}

func TestPathRoleSet_RotateTokenRoleSet(t *testing.T) {
	rsName := "test-rotatetokenrs"
	roles := util.StringSet{
		"roles/viewer": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
	td := setupTest(t)
	defer cleanup(t, td, rsName, roles)

	projRes := fmt.Sprintf("projects/%s", td.Project)

	// Create role set
	expectedBinds := ResourceBindings{projRes: roles}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, td, rsName,
		map[string]interface{}{
			"project":      td.Project,
			"secret_type":  SecretTypeAccessToken,
			"bindings":     bindsRaw,
			"token_scopes": []string{"https://www.googleapis.com/auth/cloud-platform"},
		})

	// Verify initial role set.
	respData := testRoleSetRead(t, td, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	initSa := getServiceAccount(t, td.IamAdmin, respData)
	verifyProjectBinding(t, td, initSa.Email, roles)

	// Rotate account and verify is new account.
	testRoleSetRotate(t, td, rsName)
	newSa := getServiceAccount(t, td.IamAdmin, testRoleSetRead(t, td, rsName))
	if newSa.Name == initSa.Name {
		t.Fatalf("expected role set to have new service account after rotation (update)")
	}
	verifyProjectBinding(t, td, newSa.Email, roles)

	// Verify old account/bindings deleted.
	verifyServiceAccountDeleted(t, td.IamAdmin, initSa.Name)
	verifyProjectBindingsRemoved(t, td, initSa.Email, roles)

	// Get RoleSet object for confirming key rotation:
	oldK := verifyRoleSetTokenKey(t, td, rsName)

	// Rotate key only - should only change key, not service account
	testRoleSetRotateKey(t, td, rsName)
	saAfterRotate := getServiceAccount(t, td.IamAdmin, testRoleSetRead(t, td, rsName))
	if saAfterRotate.Name != newSa.Name {
		t.Fatalf("expected same service account (%s) after rotate key, instead got new account: %s", newSa.Name, saAfterRotate.Name)
	}

	// Verify old key was deleted
	result, err := td.IamAdmin.Projects.ServiceAccounts.Keys.Get(oldK.Name).Do()
	if err == nil && result != nil {
		t.Fatalf("old key was supposed to be deleted but get succeded")
	} else if err != nil && !isGoogleApi404Error(err) {
		t.Fatalf("got an error while trying to confirm service account key was deleted: %v", err)
	}

	// Verify new key != old key
	newK := verifyRoleSetTokenKey(t, td, rsName)
	if newK.Name == oldK.Name {
		t.Fatalf("expected new key to have been created in rotate")
	}
	if newK.PrivateKeyData == oldK.PrivateKeyData {
		t.Fatalf("expected new key data to have been created and saved in rotate")
	}

	// 4. Delete role set
	testRoleSetDelete(t, td, rsName, newSa.Name)
	verifyProjectBindingsRemoved(t, td, newSa.Email, roles)
}

// Helpers for calling backend methods
func testRoleSetCreate(t *testing.T, td *testData, rsName string, d map[string]interface{}) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
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

func testRoleSetRead(t *testing.T, td *testData, rsName string) map[string]interface{} {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
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

func testRoleSetUpdate(t *testing.T, td *testData, rsName string, d map[string]interface{}) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
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

func testRoleSetRotate(t *testing.T, td *testData, rsName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s/rotate", rsName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	return
}

func testRoleSetRotateKey(t *testing.T, td *testData, rsName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s/rotate-key", rsName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	return
}

func testRoleSetDelete(t *testing.T, td *testData, rsName, saName string) {
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Storage:   td.S,
	})

	if err != nil {
		t.Fatalf("unable to delete role set: %v", err)
	} else if resp != nil {
		if resp.IsError() {
			t.Fatalf("unable to delete role set: %v", resp.Error())
		} else if len(resp.Warnings) > 0 {
			t.Logf("warnings returned from role set delete. Warnings:\n %s\n", strings.Join(resp.Warnings, ",\n"))
		}
	}

	verifyServiceAccountDeleted(t, td.IamAdmin, saName)
}

// Test helpers
func verifyReadData(t *testing.T, actual map[string]interface{}, expected map[string]interface{}) {
	for k, v := range expected {
		actV, ok := actual[k]
		if !ok {
			t.Errorf("key '%s' not found, expected: %v", k, v)
		} else if k == "bindings" {
			verifyReadBindings(t, v.(ResourceBindings), actV)
		} else if k == "token_scopes" {
			if !strutil.EquivalentSlices(v.([]string), actV.([]string)) {
				t.Errorf("token scopes mismatch; expected: %v, actual: %v", v, actV)
			}
		} else if v != actV {
			t.Errorf("mismatch for key '%s'; expected: %v, actual: %v", k, v, actV)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

func verifyReadBindings(t *testing.T, expected ResourceBindings, actualRaw interface{}) {
	if actualRaw == nil && expected != nil {
		t.Fatalf("expected bindings")
	}
	actual := actualRaw.(map[string][]string)
	if len(actual) != len(expected) {
		t.Fatalf("expected %d bindings, got %d bindings in role set", len(expected), len(actual))
	}
	for res, v := range expected {
		actB, ok := actual[res]
		if !ok {
			t.Fatalf("expected bindings for resource %s", res)
		}
		if !util.ToSet(actB).Equals(v) {
			t.Fatalf("could not find same bindings; expected: %v, actual: %v", v.ToSlice(), actB)
		}
	}
}

func verifyRoleSetTokenKey(t *testing.T, td *testData, rsName string) *iam.ServiceAccountKey {
	rs, err := getRoleSet(rsName, context.Background(), td.S)
	if rs.TokenGen == nil || rs.TokenGen.KeyName == "" {
		t.Fatalf("expected token gen to have been created for access token role set")
	}
	keyData := rs.TokenGen.B64KeyJSON
	key, err := td.IamAdmin.Projects.ServiceAccounts.Keys.Get(rs.TokenGen.KeyName).Do()
	if err != nil {
		t.Fatalf("could not confirm key for role set service account to generate tokens: %v", err)
	}
	key.PrivateKeyData = keyData
	return key
}

func getServiceAccount(t *testing.T, iamAdmin *iam.Service, readData map[string]interface{}) *iam.ServiceAccount {
	emailRaw, ok := readData["service_account_email"]
	if !ok {
		t.Fatalf("expected role set to have service account email in returned read")
	}

	proj, ok := readData["service_account_project"]
	if !ok {
		t.Fatalf("expected role set to have service account email in returned read")
	}

	saName := fmt.Sprintf(gcputil.ServiceAccountTemplate, proj, emailRaw.(string))
	sa, err := iamAdmin.Projects.ServiceAccounts.Get(saName).Do()
	if err != nil && !isGoogleApi404Error(err) {
		t.Fatalf("could not verify role set service account '%s' exists: %v", saName, err)
	}
	if (err != nil && isGoogleApi404Error(err)) || sa == nil {
		t.Fatalf("expected role set service account '%s' exists", saName)
	}
	return sa
}

func verifyServiceAccountDeleted(t *testing.T, iamAdmin *iam.Service, saName string) {
	_, err := iamAdmin.Projects.ServiceAccounts.Get(saName).Do()
	if err == nil || !isGoogleApi404Error(err) {
		t.Fatalf("expected service account '%s' to have been deleted", saName)
	}
}

func verifyProjectBinding(t *testing.T, td *testData, email string, roleSet util.StringSet) {
	found := roleSubsetBoundOnProject(t, td.HttpClient, td.Project, email, roleSet)
	if len(roleSet) > len(found) {
		notFound := roleSet.Sub(found)
		for r := range notFound {
			t.Errorf("role (%s) not bound to member (%s) for project '%s'", r, email, td.Project)
		}
		t.FailNow()
	}
}

func verifyProjectBindingsRemoved(t *testing.T, td *testData, email string, roleSet util.StringSet) {
	found := roleSubsetBoundOnProject(t, td.HttpClient, td.Project, email, roleSet)
	for r := range found {
		t.Errorf("role (%s) still bound to service account (%s) for project '%s'", r, email, td.Project)
	}
	if t.Failed() {
		t.FailNow()
	}
}

func roleSubsetBoundOnProject(t *testing.T, httpC *http.Client, project, email string, roleSet util.StringSet) util.StringSet {
	if project == "" {
		t.Fatalf("expected project")
	}
	member := fmt.Sprintf("serviceAccount:%s", email)

	crm, err := cloudresourcemanager.New(httpC)
	if err != nil {
		t.Fatalf("[WARNING] Unable to ensure test project bindings deleted: %v", err)
	}

	p, err := crm.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		t.Fatalf("[WARNING] Unable to ensure test project bindings deleted, could not get policy: %v", err)
	}
	found := make(util.StringSet)
	for _, bind := range p.Bindings {
		if roleSet.Includes(bind.Role) {
			for _, m := range bind.Members {
				if m == member {
					found.Add(bind.Role)
				}
			}
		}
	}
	return found
}

// Set up/Teardown
type testData struct {
	B          logical.Backend
	S          logical.Storage
	Project    string
	HttpClient *http.Client
	IamAdmin   *iam.Service
}

func setupTest(t *testing.T) *testData {
	proj := util.GetTestProject(t)
	credsJson, creds := util.GetTestCredentials(t)
	httpC, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}

	iamAdmin, err := iam.New(httpC)
	if err != nil {
		t.Fatal(err)
	}

	b, reqStorage := getTestBackend(t)
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credsJson,
	})

	return &testData{
		B:          b,
		S:          reqStorage,
		Project:    proj,
		HttpClient: httpC,
		IamAdmin:   iamAdmin,
	}
}

func cleanup(t *testing.T, td *testData, rsName string, roles util.StringSet) {
	resp, err := td.IamAdmin.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", td.Project)).Do()
	if err != nil {
		t.Logf("[WARNING] Could not clean up test service accounts for role set %s or projects/%s IAM policy bindings (did test fail?)", rsName, td.Project)
		return
	}

	memberStrs := make(util.StringSet)
	for _, sa := range resp.Accounts {
		if sa.DisplayName == fmt.Sprintf(serviceAccountDisplayNameTmpl, rsName) {
			memberStrs.Add("serviceAccount:" + sa.Email)
			t.Logf("[WARNING] had to clean up service account %s, should have been deleted (did test fail?)", sa.Name)
			if _, err := td.IamAdmin.Projects.ServiceAccounts.Delete(sa.Name).Do(); err != nil {
				t.Logf("[WARNING] Auto-delete failed - manually clean up service account %s: %v", sa.Name, err)
			}
		}
	}

	crm, err := cloudresourcemanager.New(td.HttpClient)
	if err != nil {
		t.Logf("[WARNING] Unable to ensure test project bindings deleted: %v", err)
		return
	}

	p, err := crm.Projects.GetIamPolicy(td.Project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		t.Logf("[WARNING] Unable to ensure test project bindings deleted, could not get policy: %v", err)
		return
	}

	var changesMade bool
	found := make(util.StringSet)
	for idx, b := range p.Bindings {
		if roles.Includes(b.Role) {
			members := make([]string, 0, len(b.Members))
			for _, m := range b.Members {
				if memberStrs.Includes(m) {
					changesMade = true
					found.Add(b.Role)
				} else {
					members = append(members, m)
				}
			}
			p.Bindings[idx].Members = members
		}
	}

	if !changesMade {
		return
	}

	t.Logf("[WARNING] had to clean up some roles (%s) for test role set %s - should have been deleted (did test fail?)",
		strings.Join(found.ToSlice(), ","), rsName)
	if _, err := crm.Projects.SetIamPolicy(td.Project, &cloudresourcemanager.SetIamPolicyRequest{Policy: p}).Do(); err != nil {
		t.Logf("[WARNING] Auto-delete failed - manually remove bindings on project %s: %v", td.Project, err)
	}
}
