package gcpsecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"google.golang.org/api/option"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

func TestConfigRotateRootUpdate(t *testing.T) {
	t.Parallel()

	t.Run("no_configuration", func(t *testing.T) {
		t.Parallel()

		b, storage := getTestBackend(t)
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "no configuration", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("config_with_no_credentials", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		b, storage := getTestBackend(t)

		entry, err := logical.StorageEntryJSON("config", &config{
			TTL: 5 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "does not have credentials", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("config_with_invalid_credentials", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		b, storage := getTestBackend(t)

		entry, err := logical.StorageEntryJSON("config", &config{
			CredentialsRaw: "baconbaconbacon",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if exp, act := "credentials are invalid", err.Error(); !strings.Contains(act, exp) {
			t.Errorf("expected %q to contain %q", act, exp)
		}
	})

	t.Run("rotate", func(t *testing.T) {
		t.Parallel()

		if testing.Short() {
			t.Skip("skipping integration test (short)")
		}

		ctx := context.Background()
		b, storage := getTestBackend(t)

		// Get user-supplied credentials
		credsPath := os.Getenv("GOOGLE_CREDENTIALS")
		credsBytes, err := ioutil.ReadFile(credsPath)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := google.CredentialsFromJSON(ctx, credsBytes, iam.CloudPlatformScope)
		if err != nil {
			t.Fatal(err)
		}
		parsedCreds, err := gcputil.Credentials(string(credsBytes))
		if err != nil {
			t.Fatal(err)
		}

		// Create http client
		clientCtx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())
		client := oauth2.NewClient(clientCtx, creds.TokenSource)

		// Create IAM client
		iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			t.Fatal(err)
		}

		// Create a new key, since this endpoint revokes the old key
		saName := "projects/-/serviceAccounts/" + parsedCreds.ClientEmail
		newKey, err := iamAdmin.Projects.ServiceAccounts.Keys.
			Create(saName, &iam.CreateServiceAccountKeyRequest{
				KeyAlgorithm:   keyAlgorithmRSA2k,
				PrivateKeyType: privateKeyTypeJson,
			}).
			Context(ctx).
			Do()
		if err != nil {
			t.Fatal(err)
		}

		// Base64-decode the private key data (it's the JSON file)
		newCredsJSON, err := base64.StdEncoding.DecodeString(newKey.PrivateKeyData)
		if err != nil {
			t.Fatal(err)
		}

		// Parse new creds
		newCreds, err := gcputil.Credentials(string(newCredsJSON))
		if err != nil {
			t.Fatal(err)
		}

		// If we made it this far, schedule a cleanup of the new key
		defer func() {
			newKeyName := fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s",
				newCreds.ProjectId,
				newCreds.ClientEmail,
				newCreds.PrivateKeyId)
			iamAdmin.Projects.ServiceAccounts.Keys.Delete(newKeyName)
		}()

		// Set config to the key
		entry, err := logical.StorageEntryJSON("config", &config{
			CredentialsRaw: string(newCredsJSON),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		// Rotate the key
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config/rotate-root",
			Storage:   storage,
		})
		if err != nil {
			t.Fatal(err)
		}

		privateKeyId := resp.Data["private_key_id"]
		if privateKeyId == "" {
			t.Errorf("missing private_key_id")
		}

		if privateKeyId == newCreds.PrivateKeyId {
			t.Errorf("creds were not rotated")
		}
	})
}
