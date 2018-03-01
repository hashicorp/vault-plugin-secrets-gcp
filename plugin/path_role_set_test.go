package gcpsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/logical"
	"google.golang.org/api/iam/v1"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPathRoleSet_TokenRoleSet(t *testing.T) {
	rsName := "testrs"

	proj := util.GetTestProject(t)
	credsJson, creds := util.GetTestCredentials(t)
	httpC, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}

	b, reqStorage := getTestBackend(t)
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credsJson,
	})

	testRoleSetRead(t, b, reqStorage, "testrs", nil)

	expectedBinds, cleanupF := createTestResources(t, httpC)
	defer cleanupF()

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

	rs, err := getRoleSet(rsName, context.Background(), reqStorage)
	if err != nil {
		t.Fatal(err)
	}

	defer tryDeleteServiceAccount(t, httpC, rs.AccountId)
	verifyCreatedRoleServiceAccount(t, httpC, rs, rsName, bindsRaw)
	verifyRoleSetServiceAccountBindings(t, httpC, rs.AccountId.EmailOrId, expectedBinds)

	testRoleSetDelete(t, b, reqStorage, rsName)
}

func tryDeleteServiceAccount(t *testing.T, httpC *http.Client, id *gcputil.ServiceAccountId) {
	if id == nil {
		return
	}
	iamAdmin, err := iam.New(httpC)
	if err != nil {
		t.Logf("[WARNING] Unable to ensure test role set service account deleted: %v", err)
	}
	if _, err := iamAdmin.Projects.ServiceAccounts.Delete(id.ResourceName()).Do(); err != nil && !isGoogleApi404Error(err) {
		t.Logf("[WARNING] Unable to ensure test role set service account deleted: %v", err)
	}
}

func verifyCreatedRoleServiceAccount(t *testing.T, httpC *http.Client, rs *RoleSet, rsName string, rawBindings string) {
	if rs.Name != rsName {
		t.Fatalf("role set names do not match, expected: %s, actual: %s", rsName, rs.Name)
	}
	if rs.RawBindings != rawBindings {
		t.Fatalf("role set raw bindings string does not match, expected: %s, actual: %s", rawBindings, rs.RawBindings)
	}
	if rs.AccountId == nil {
		t.Fatalf("expected role set to have account id")
	}

	iamAdmin, err := iam.New(httpC)
	if err != nil {
		t.Fatal(err)
	}

	sa, err := iamAdmin.Projects.ServiceAccounts.Get(rs.AccountId.ResourceName()).Do()
	if err != nil {
		t.Fatalf("could not convert role set service account '%s' exists: %v", rs.AccountId.ResourceName(), err)
	}
	if sa == nil {
		t.Fatalf("expected role set service account '%s' exists", rs.AccountId.ResourceName())
	}

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

func testRoleSetRead(t *testing.T, b logical.Backend, s logical.Storage, rsName string, expected map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp == nil && expected == nil {
		return
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if len(expected) != len(resp.Data) {
		t.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			t.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			t.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

func testRoleSetDelete(t *testing.T, b logical.Backend, s logical.Storage, rsName string) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roleset/%s", rsName),
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func createTestResources(t *testing.T, httpC *http.Client) (ResourceBindings, func()) {
	binds := make(ResourceBindings)

	proj := util.GetTestProject(t)
	projName := fmt.Sprintf("projects/%s", proj)
	//binds[projName] = util.ToSet(
	//	[]string{
	//		"roles/viewer",
	//		"roles/iam.securityReviewer",
	//	})

	iamAdmin, err := iam.New(httpC)
	if err != nil {
		t.Fatalf("unable to create IAM Admin service client: %v", err)
	}

	sa, err := iamAdmin.Projects.ServiceAccounts.Create(
		projName,
		&iam.CreateServiceAccountRequest{
			AccountId: fmt.Sprintf("testvault-%d", time.Now().Unix()),
			ServiceAccount: &iam.ServiceAccount{
				DisplayName: "test account for Vault secrets backend test",
			},
		}).Do()
	if err != nil {
		t.Fatalf("unable to create test service account: %v", err)
	}

	binds[sa.Name] = util.ToSet([]string{"roles/iam.serviceAccountAdmin"})
	cleanupF := func() {
		if _, err := iamAdmin.Projects.ServiceAccounts.Delete(sa.Name).Do(); err != nil {
			t.Logf("unable to cleanup test service account '%s': %v", sa.Name, err)
		}
	}

	return binds, cleanupF
}
