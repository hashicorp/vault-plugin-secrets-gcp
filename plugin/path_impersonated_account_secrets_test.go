package gcpsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func TestImpersonatedSecrets_GetAccessToken(t *testing.T) {
	roleName := "test-imp-token"
	testGetImpersonatedAccessToken(t, roleName)
}

func testGetImpersonatedAccessToken(t *testing.T, roleName string) {

	td := setupTest(t, "0s", "2h")
	defer cleanupImpersonate(t, td, roleName, util.StringSet{})

	sa := createServiceAccount(t, td, roleName)
	defer deleteServiceAccount(t, td, sa)

	testImpersonateCreate(t, td, roleName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
		})

	token := testGetToken(t, fmt.Sprintf("%s/%s/token", impersonatedAccountPathPrefix, roleName), td)

	goauth, err := oauth2.NewService(context.Background(), option.WithHTTPClient(td.HttpClient))
	if err != nil {
		t.Fatalf("error setting google oauth2 client %q", err)
	}

	info, err := goauth.Tokeninfo().AccessToken(token).Do()
	if err != nil {
		t.Fatalf("error getting token info %q", err)
	}

	if info.IssuedTo != sa.UniqueId {
		t.Fatalf("token email %q does not match service account email %q", info.Email, sa.Email)
	}

	// Cleanup
	testImpersonateDelete(t, td, roleName)
}
