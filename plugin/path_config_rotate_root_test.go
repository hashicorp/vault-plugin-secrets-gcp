package gcpsecrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"google.golang.org/api/option"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault/sdk/logical"
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
		_, creds := util.GetTestCredentials(t)
		client, err := gcputil.GetHttpClient(creds, iam.CloudPlatformScope)
		if err != nil {
			t.Fatal(err)
		}

		// Create IAM client
		iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			t.Fatal(err)
		}

		// Create a new key, since this endpoint will revoke the key given.
		saName := "projects/-/serviceAccounts/" + creds.ClientEmail
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

		// If we made it this far, schedule a cleanup of the key we just created.
		defer tryCleanupKey(t, iamAdmin, newKey.Name)

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

		// Make sure we delete the stored key, whether it was rotated or not (retry will not error)
		defer tryCleanupKey(t, iamAdmin, fmt.Sprintf(gcputil.ServiceAccountKeyTemplate,
			newCreds.ProjectId,
			newCreds.ClientEmail,
			privateKeyId))

		if privateKeyId == newCreds.PrivateKeyId {
			t.Errorf("creds were not rotated")
		}
	})
}

func tryCleanupKey(t *testing.T, iamAdmin *iam.Service, keyName string) {
	_, err := iamAdmin.Projects.ServiceAccounts.Keys.Delete(keyName).Do()
	if err != nil && !isGoogleAccountKeyNotFoundErr(err) {
		t.Logf("WARNING: failed to delete key created for test, clean up manually: %v", err)
	}
}
