package gcpsecrets

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func TestImpersonatedSecrets_GetDefaultAccessToken(t *testing.T) {
	roleName := "test-imp-token"
	td := setupTest(t, "0h", "12h")

	tests := map[string]struct {
		ttl_req time.Duration
		ttl_rcv time.Duration
	}{
		"unset ttl should be 1 hour": {
			ttl_req: 0,
			ttl_rcv: 1 * time.Hour,
		},
		"30 minutes requested and received": {
			ttl_req: 30 * time.Minute,
			ttl_rcv: 30 * time.Minute,
		},
		"1 hour requested and received": {
			ttl_req: 1 * time.Hour,
			ttl_rcv: 1 * time.Hour,
		},
	}

	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			ttl := testGetImpersonatedAccessToken(t, td, roleName, tt.ttl_req.String())
			if ttl.Round(1*time.Minute) != tt.ttl_rcv {
				t.Fatalf("expected access token to have a TTL of %v but got: %v", tt.ttl_rcv, ttl)
			}
		})
	}
}

func TestImpersonatedSecrets_GetExtendedAccessToken(t *testing.T) {

	roleName := "test-imp-token"
	td := setupTestCredentials(t)
	skipIfCredentialLifetimesNotExtended(t, td, roleName)

	setupTestBackend(t, td, "2h", "4h")

	tests := map[string]struct {
		ttl_req time.Duration
		ttl_rcv time.Duration
	}{
		"unset ttl should be 2 hours": {
			ttl_req: 0,
			ttl_rcv: 2 * time.Hour,
		},
		"account ttl below backend ttl should be allowed": {
			ttl_req: 1 * time.Hour,
			ttl_rcv: 1 * time.Hour,
		},
		"2 hours requested and received": {
			ttl_req: 2 * time.Hour,
			ttl_rcv: 2 * time.Hour,
		},
		"4 hours requested and received": {
			ttl_req: 4 * time.Hour,
			ttl_rcv: 4 * time.Hour,
		},
		"6 hours requested but clamped to backend TTL": {
			ttl_req: 6 * time.Hour,
			ttl_rcv: 4 * time.Hour,
		},
	}

	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			ttl := testGetImpersonatedAccessToken(t, td, roleName, tt.ttl_req.String())
			if ttl.Round(1*time.Minute) != tt.ttl_rcv {
				t.Fatalf("expected access token to have a TTL of %v but got: %v", tt.ttl_rcv, ttl)
			}
		})
	}

}

func skipIfCredentialLifetimesNotExtended(t *testing.T, td *testData, roleName string) {

	policyName := fmt.Sprintf("projects/%s/policies/iam.allowServiceAccountCredentialLifetimeExtension", td.Project)
	policy, err := td.OrgAdmin.Organizations.Policies.GetEffectivePolicy(policyName).Do()
	if policy == nil || err != nil {
		t.Skipf("credential lifetime extension policy not found %v", err)
	}

	allowed := false
	for _, rule := range policy.Spec.Rules {
		if rule.AllowAll {
			allowed = true
		}
	}
	if !allowed {
		t.Skipf("credential lifetime extension not allowed for %q", roleName)
	}

}

func testGetImpersonatedAccessToken(t *testing.T, td *testData, roleName string, ttl string) (tokenTtl time.Duration) {

	defer cleanupImpersonate(t, td, roleName, util.StringSet{})

	sa := createServiceAccount(t, td, roleName)
	defer deleteServiceAccount(t, td, sa)

	testImpersonateCreate(t, td, roleName,
		map[string]interface{}{
			"service_account_email": sa.Email,
			"token_scopes":          []string{iam.CloudPlatformScope},
			"ttl":                   ttl,
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

	return time.Duration(info.ExpiresIn) * time.Second
}
