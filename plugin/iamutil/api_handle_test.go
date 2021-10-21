package iamutil

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func TestIamResource_ServiceAccount(t *testing.T) {
	createServiceAccount := func(t *testing.T, httpC *http.Client) *IamResource {
		iamAdmin, err := iam.NewService(context.Background(), option.WithHTTPClient(httpC))
		if err != nil {
			t.Fatal(err)
		}

		newSa, err := iamAdmin.Projects.ServiceAccounts.Create(
			fmt.Sprintf("projects/%s", util.GetTestProject(t)),
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

		rConfig := generatedResources["projects/serviceAccounts"]["iam"]["v1"]

		return &IamResource{
			relativeId: relId,
			config:     &rConfig,
		}
	}

	deleteServiceAccount := func(t *testing.T, httpC *http.Client, r *IamResource) {
		saName := fmt.Sprintf("projects/%s/serviceAccounts/%s",
			r.relativeId.IdTuples["projects"],
			r.relativeId.IdTuples["serviceAccounts"])
		iamAdmin, err := iam.NewService(context.Background(), option.WithHTTPClient(httpC))
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
	getF func(*testing.T, *http.Client) *IamResource,
	cleanupF func(*testing.T, *http.Client, *IamResource)) {

	_, creds := util.GetTestCredentials(t)
	httpC, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
	if err != nil {
		t.Fatal(err)
	}

	r := getF(t, httpC)
	defer cleanupF(t, httpC, r)

	h := GetApiHandle(httpC, "")

	p, err := r.GetIamPolicy(context.Background(), h)
	if err != nil {
		t.Fatalf("could not get IAM Policy for resource type '%s': %v", resourceType, err)
	}

	_, newP := p.AddBindings(&PolicyDelta{
		Roles: util.StringSet{"roles/viewer": struct{}{}},
		Email: creds.ClientEmail,
	})

	if p.Version != newP.Version {
		t.Fatalf("expected policy version %d after adding bindings, got %d", p.Version, newP.Version)
	}

	if err != nil {
		t.Fatalf("could not get IAM Policy for resource type '%s': %v", resourceType, err)
	}

	changedP, err := r.SetIamPolicy(context.Background(), h, newP)
	if err != nil {
		t.Fatalf("could not set IAM Policy for resource type '%s': %v", resourceType, err)
	}

	actualP, err := r.GetIamPolicy(context.Background(), h)
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
