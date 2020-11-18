package gcpsecrets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

func getTestBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.New(nil)
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
		MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*backend), config.StorageView
}

// Set up/Teardown
type testData struct {
	B          logical.Backend
	S          logical.Storage
	Project    string
	HttpClient *http.Client
	IamAdmin   *iam.Service
}

func setupTest(t *testing.T, ttl, maxTTL string) *testData {
	proj := util.GetTestProject(t)
	credsJson, creds := util.GetTestCredentials(t)
	httpC, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}

	iamAdmin, err := iam.NewService(context.Background(), option.WithHTTPClient(httpC))
	if err != nil {
		t.Fatal(err)
	}

	b, reqStorage := getTestBackend(t)

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credsJson,
		"ttl":         ttl,
		"max_ttl":     maxTTL,
	})

	return &testData{
		B:          b,
		S:          reqStorage,
		Project:    proj,
		HttpClient: httpC,
		IamAdmin:   iamAdmin,
	}
}

func cleanup(t *testing.T, td *testData, saDisplayName string, roles util.StringSet) {
	resp, err := td.IamAdmin.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", td.Project)).Do()
	if err != nil {
		t.Logf("[WARNING] Could not clean up test service accounts %s or projects/%s IAM policy bindings (did test fail?)", saDisplayName, td.Project)
		return
	}

	memberStrs := make(util.StringSet)
	for _, sa := range resp.Accounts {
		if sa.DisplayName == saDisplayName {
			memberStrs.Add("serviceAccount:" + sa.Email)
			if _, err := td.IamAdmin.Projects.ServiceAccounts.Delete(sa.Name).Do(); err != nil {
				if isGoogleAccountNotFoundErr(err) {
					// Eventual consistency. We can ignore.
					continue
				}
				t.Logf("[WARNING] found test service account %s that should have been deleted, did test fail? Auto-delete failed - manually clean up service account: %v", sa.Name, err)
			}
			t.Logf("[WARNING] found test service account %s that should have been deleted, did test fail? Manually deleted", sa.Name)
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

	t.Logf("[WARNING] had to clean up some roles (%s) for test service account %s - should have been deleted (did test fail?)",
		strings.Join(found.ToSlice(), ","), saDisplayName)
	if _, err := crm.Projects.SetIamPolicy(td.Project, &cloudresourcemanager.SetIamPolicyRequest{Policy: p}).Do(); err != nil {
		t.Logf("[WARNING] Auto-delete failed - manually remove bindings on project %s: %v", td.Project, err)
	}
}

func cleanupRoleset(t *testing.T, td *testData, rsName string, roles util.StringSet) {
	cleanup(t, td, fmt.Sprintf(serviceAccountDisplayNameTmpl, rsName), roles)
}

func cleanupStatic(t *testing.T, td *testData, saName string, roles util.StringSet) {
	cleanup(t, td, fmt.Sprintf(staticAccountDisplayNameTmpl, saName), roles)
}
