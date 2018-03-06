package gcpsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/logical"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"net/http"
	"strings"
	"testing"
)

const (
	readMismatchTmpl = "expected role set read data key '%s' to return '%v', instead got '%v'"
)

func TestPathRoleSet_Basic(t *testing.T) {
	rsName := "testrs"
	roleSet := util.StringSet{
		"roles/viewer": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
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

	projRes := fmt.Sprintf("projects/%s", proj)
	expectedBinds := ResourceBindings{projRes: roleSet}
	defer cleanupProjectBinding(t, httpC, proj, rsName, roleSet)

	// 1. Read should return nothing
	respData := testRoleSetRead(t, b, reqStorage, rsName)
	if respData != nil {
		t.Fatalf("expected role set to not exist initially")
	}

	// 2. Create new role set
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, b, reqStorage, rsName,
		map[string]interface{}{
			"project":      proj,
			"bindings":     bindsRaw,
			"token_scopes": []string{iam.CloudPlatformScope},
		})
	defer deleteRoleSet(t, b, reqStorage, rsName) //ensure we attempt to delete role set no matter what

	// 3. Read role set and verify a service account exists for it
	respData = testRoleSetRead(t, b, reqStorage, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeAccessToken, // default
		"service_account_project": proj,
	})

	compareBindings(t, expectedBinds, respData["bindings"])

	emailRaw, ok := respData["service_account_email"]
	if !ok {
		t.Fatalf("expected role set to have service account email in returned read")
	}
	saName := fmt.Sprintf(gcputil.ServiceAccountTemplate, proj, emailRaw.(string))
	sa := getServiceAccount(t, iamAdmin, saName)

	// 4. Delete role set
	deleteRoleSet(t, b, reqStorage, rsName)
	sa, err = iamAdmin.Projects.ServiceAccounts.Get(sa.Name).Do()
	if (err != nil && !isGoogleApi404Error(err)) || sa != nil {
		t.Fatalf("expected service account '%s' to have been deleted", sa.Name)
	}
}

func TestPathRoleSet_Update(t *testing.T) {
	rsName := "testrs"
	roleSet := util.StringSet{
		"roles/viewer": struct{}{},
	}
	newRoleSet := util.StringSet{
		"roles/browser":         struct{}{},
		"roles/cloudsql.client": struct{}{},
	}

	// Initial test set up - backend, initial config, test resources in project
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

	projRes := fmt.Sprintf("projects/%s", proj)
	defer cleanupProjectBinding(t, httpC, proj, rsName, roleSet)

	// Create role set
	expectedBinds := ResourceBindings{projRes: roleSet}
	bindsRaw, err := util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetCreate(t, b, reqStorage, rsName,
		map[string]interface{}{
			"project":     proj,
			"secret_type": SecretTypeKey,
			"bindings":    bindsRaw,
		})
	defer deleteRoleSet(t, b, reqStorage, rsName) //ensure we attempt to delete role set no matter what

	// Verify
	respData := testRoleSetRead(t, b, reqStorage, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	verifyReadData(t, respData, map[string]interface{}{
		"secret_type":             SecretTypeKey,
		"service_account_project": proj,
	})
	compareBindings(t, expectedBinds, respData["bindings"])
	emailRaw, ok := respData["service_account_email"]
	if !ok {
		t.Fatalf("expected role set to have service account email in returned read")
	}
	initSa := getServiceAccount(t, iamAdmin, fmt.Sprintf(gcputil.ServiceAccountTemplate, proj, emailRaw.(string)))

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
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("roleset/%s", rsName),
			Data:      d,
			Storage:   reqStorage,
		})
		if err == nil && (resp != nil && !resp.IsError()) {
			t.Fatalf("expected update to fail; data: %v", d)
		}
	}

	// Update role set
	expectedBinds = ResourceBindings{projRes: newRoleSet}
	bindsRaw, err = util.BindingsHCL(expectedBinds)
	if err != nil {
		t.Fatalf("unable to convert resource bindings to HCL string: %v", err)
	}
	testRoleSetUpdate(t, b, reqStorage, rsName,
		map[string]interface{}{
			"project":     proj,
			"secret_type": SecretTypeKey,
			"bindings":    bindsRaw,
		})

	// Verify
	respData = testRoleSetRead(t, b, reqStorage, rsName)
	if respData == nil {
		t.Fatalf("expected role set to have been created")
	}
	compareBindings(t, expectedBinds, respData["bindings"])
	emailRaw, ok = respData["service_account_email"]
	if !ok {
		t.Fatalf("expected role set to have service account email in returned read")
	}
	newSa := getServiceAccount(t, iamAdmin, fmt.Sprintf(gcputil.ServiceAccountTemplate, proj, emailRaw.(string)))
	if newSa.Name == initSa.Name {
		t.Fatalf("expected role set to have new service account after update")
	}
	// 4. Delete role set
	deleteRoleSet(t, b, reqStorage, rsName)
	newSa, err = iamAdmin.Projects.ServiceAccounts.Get(newSa.Name).Do()
	if (err != nil && !isGoogleApi404Error(err)) || newSa != nil {
		t.Fatalf("expected service account '%s' to have been deleted", newSa.Name)
	}
}

func verifyReadData(t *testing.T, actual map[string]interface{}, expected map[string]interface{}) {
	for k, v := range expected {
		actV, ok := actual[k]
		if !ok {
			t.Errorf("key '%s' not found, expected: %v", k, v)
		} else if v != actV {
			t.Errorf("mismatch for key '%s'; expected: %v, actual: %v", k, v, actV)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

func compareBindings(t *testing.T, expected ResourceBindings, actualRaw interface{}) {
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

func getServiceAccount(t *testing.T, iamAdmin *iam.Service, saName string) *iam.ServiceAccount {
	sa, err := iamAdmin.Projects.ServiceAccounts.Get(saName).Do()
	if err != nil && !isGoogleApi404Error(err) {
		t.Fatalf("could not verify role set service account '%s' exists: %v", saName, err)
	}
	if (err != nil && isGoogleApi404Error(err)) || sa == nil {
		t.Fatalf("expected role set service account '%s' exists", saName)
	}
	return sa
}

func testRoleSetCreate(t *testing.T, b logical.Backend, s logical.Storage, rsName string, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleSetUpdate(t *testing.T, b logical.Backend, s logical.Storage, rsName string, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleSetRead(t *testing.T, b logical.Backend, s logical.Storage, rsName string) map[string]interface{} {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Storage:   s,
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

func deleteRoleSet(t *testing.T, b logical.Backend, s logical.Storage, rsName string) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Storage:   s,
	})
	if err != nil {
		t.Logf("unable to delete role set: %v", err)
	} else if resp != nil && resp.IsError() {
		t.Logf("unable to delete role set: %v", resp.Error())
	}
}

func cleanupProjectBinding(t *testing.T, httpC *http.Client, project, rsName string, roles util.StringSet) {
	if project == "" {
		return
	}
	crm, err := cloudresourcemanager.New(httpC)
	if err != nil {
		t.Logf("[WARNING] Unable to ensure test project bindings deleted: %v", err)
		return
	}
	p, err := crm.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		t.Logf("[WARNING] Unable to ensure test project bindings deleted, could not get policy: %v", err)
		return
	}
	var changesMade bool
	for idx, b := range p.Bindings {
		if roles.Includes(b.Role) {
			members := make([]string, 0, len(b.Members))
			for _, m := range b.Members {
				if !strings.HasPrefix(m, fmt.Sprintf(
					iamutil.ServiceAccountMemberTmpl, fmt.Sprintf("vault%s", rsName))) {
					members = append(members, m)
				} else {
					changesMade = true
				}
			}
			p.Bindings[idx].Members = members
		}
	}

	if !changesMade {
		return
	}

	if _, err := crm.Projects.SetIamPolicy(project, &cloudresourcemanager.SetIamPolicyRequest{Policy: p}).Do(); err != nil {
		t.Logf("[WARNING] Unable to ensure test project bindings deleted, could not set policy: %v", err)
	}
}

func verifyRoleSetTokenGen(t *testing.T, httpC *http.Client, rs *RoleSet) {
	iamAdmin, err := iam.New(httpC)
	if err != nil {
		t.Fatal(err)
	}

	sa := getServiceAccount(t, iamAdmin, rs.AccountId.ResourceName())
	lsResp, err := iamAdmin.Projects.ServiceAccounts.Keys.List(sa.Name).KeyTypes("USER_MANAGED").Do()
	if err != nil {
		t.Fatalf("could not list keys under role set service account '%s': %v", rs.AccountId.ResourceName(), err)
	}
	keys := lsResp.Keys

	if rs.SecretType == SecretTypeAccessToken {
		if rs.TokenGen == nil {
			t.Fatal("expected service account key (token gen) to have been created for role set")
		}
		if len(keys) != 1 {
			t.Fatalf("expected only one key created under role set service account, got %d", len(keys))
		}
		if keys[0].Name != rs.TokenGen.KeyName {
			t.Fatalf("expected key %s created under role set service account, actual: %s", rs.TokenGen.KeyName, keys[0].Name)
		}
	} else {
		if len(keys) != 0 {
			t.Fatalf("expected no keys to have been created for role set service account %s", rs.AccountId.ResourceName())
		}
	}
}

func verifyRoleSetServiceAccountBindings(t *testing.T, httpC *http.Client, saEmail string, expectedBindings ResourceBindings) {
	iamHandle := iamutil.GetIamHandle(httpC, "")
	iamResources := iamutil.GetEnabledIamResources()
	memberStr := fmt.Sprintf(iamutil.ServiceAccountMemberTmpl, saEmail)

	for rName, roleSet := range expectedBindings {
		res, err := iamResources.Resource(rName)
		if err != nil {
			t.Fatalf("could not get IamResource for '%s': %v", rName, err)
		}
		p, err := iamHandle.GetIamPolicy(context.Background(), res)
		if err != nil {
			t.Fatalf("could not get policy for resource '%s': %v", rName, err)
		}

		foundRoles := make(util.StringSet)
		for _, b := range p.Bindings {
			memberSet := util.ToSet(b.Members)
			if memberSet.Includes(memberStr) {
				foundRoles.Add(b.Role)
			}
		}

		missing := roleSet.Sub(foundRoles).ToSlice()
		additional := foundRoles.Sub(roleSet).ToSlice()
		if len(missing) > 0 {
			t.Fatalf("member '%s' does not have some expected roles on resource '%s': %s", memberStr, rName, strings.Join(missing, ", "))
		}
		if len(additional) > 0 {
			t.Fatalf("member '%s' has some unexpected roles on resource '%s': %s", memberStr, rName, strings.Join(additional, ", "))
		}
	}
}

func testRoleSetRotateAccount(t *testing.T, b logical.Backend, s logical.Storage, rsName string) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s/rotate", rsName),
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRoleSetRotateAccountKey(t *testing.T, b logical.Backend, s logical.Storage, rsName string, isTokenRoleSet bool) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roleset/%s/rotate", rsName),
		Storage:   s,
	})
	if isTokenRoleSet {
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && resp.IsError() {
			t.Fatal(resp.Error())
		}
	} else if err == nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected error, instead got no error and valid response (%v)", resp)
	}
}
