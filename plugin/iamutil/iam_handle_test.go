package iamutil

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/helper/strutil"
	"google.golang.org/api/iam/v1"
	"net/http"
	"testing"
	"time"
)

func TestIamHandle_ServiceAccount(t *testing.T) {
	createServiceAccount := func(t *testing.T, httpC *http.Client) *iamResourceImpl {
		iamAdmin, err := iam.New(httpC)
		if err != nil {
			t.Fatal(err)
		}

		proj, err := util.GetTestProject()
		if err != nil {
			t.Fatal(err)
		}

		newSa, err := iamAdmin.Projects.ServiceAccounts.Create(
			fmt.Sprintf("projects/%s", proj),
			&iam.CreateServiceAccountRequest{
				AccountId: fmt.Sprintf("testvaultsa-%d", time.Now().Unix()),
				ServiceAccount: &iam.ServiceAccount{
					DisplayName: "test account for Vault IAM Handle test",
				},
			}).Do()
		if err != nil {
			t.Fatal(err)
		}

		relId, err := gcputil.ParseRelativeName(newSa.Name)
		if err != nil {
			t.Fatal(err)
		}

		return &iamResourceImpl{
			relativeId: relId,
			config:     generatedResources["projects/serviceAccounts"]["iam"]["v1"],
		}
	}

	deleteServiceAccount := func(t *testing.T, httpC *http.Client, r *iamResourceImpl) {
		saName := fmt.Sprintf("projects/%s/serviceAccounts/%s",
			r.relativeId.IdTuples["projects"],
			r.relativeId.IdTuples["serviceAccounts"])
		iamAdmin, err := iam.New(httpC)
		if err != nil {
			t.Logf("[WARNING] unable to delete test service account %s: %v", saName, err)
			return
		}
		if _, err := iamAdmin.Projects.ServiceAccounts.Delete(saName).Do(); err != nil {
			t.Logf("[WARNING] unable to delete test service account %s: %v", saName, err)
		}
	}

	verifyIamResource_GetSetPolicy(t, "projects/serviceAccounts", createServiceAccount, deleteServiceAccount)
}

func verifyIamResource_GetSetPolicy(t *testing.T, resourceType string,
	getF func(*testing.T, *http.Client) *iamResourceImpl,
	cleanupF func(*testing.T, *http.Client, *iamResourceImpl)) {
	creds, err := util.GetTestCredentials()
	if err != nil {
		t.Fatal(err)
	}

	httpC, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}

	r := getF(t, httpC)
	defer cleanupF(t, httpC, r)

	h := GetIamHandle(httpC, "")

	p, err := h.GetIamPolicy(context.Background(), r)
	if err != nil {
		t.Fatalf("could not get IAM Policy for resource type '%s': %v", resourceType, err)
	}

	_, newP := p.AddBindings(&PolicyDelta{
		Roles: util.StringSet{"roles/viewer": struct{}{}},
		Email: creds.ClientEmail,
	})

	if err != nil {
		t.Fatalf("could not get IAM Policy for resource type '%s': %v", resourceType, err)
	}

	changedP, err := h.SetIamPolicy(context.Background(), r, newP)
	if err != nil {
		t.Fatalf("could not set IAM Policy for resource type '%s': %v", resourceType, err)
	}

	actualP, err := h.GetIamPolicy(context.Background(), r)
	if err != nil {
		t.Fatalf("could not get updated IAM Policy for resource type '%s': %v", resourceType, err)
	}

	if actualP.Etag != changedP.Etag {
		t.Fatalf("etag mismatch, expected setIAMPolicy to generate new eTag %s, actual: %s", changedP.Etag, actualP.Etag)
	}
	for _, b := range actualP.Bindings {
		if b.Role == "roles/viewer" {
			if strutil.StrListContains(b.Members, fmt.Sprintf("serviceAccount:%s", creds.ClientEmail)) {
				return
			}
		}
	}
	t.Fatal("could not find added in new policy, set unsuccessful")
}
