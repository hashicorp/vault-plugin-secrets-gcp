package gcpsecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	b, reqStorage := getTestBackend(t)

	testConfigRead(t, b, reqStorage, nil)

	creds := map[string]interface{}{
		"client_email":   "testUser@google.com",
		"client_id":      "user123",
		"private_key_id": "privateKey123",
		"private_key":    "iAmAPrivateKey",
		"project_id":     "project123",
	}

	credJson, err := jsonutil.EncodeJSON(creds)
	if err != nil {
		t.Fatal(err)
	}

	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"credentials": credJson,
	})

	expected := map[string]interface{}{
		"ttl":     int64(0),
		"max_ttl": int64(0),
	}

	testConfigRead(t, b, reqStorage, expected)
	testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"ttl": "50s",
	})

	expected["ttl"] = int64(50)
	testConfigRead(t, b, reqStorage, expected)
}

func TestAdjustTTLsFromConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		config      *config
		resp        *logical.Response
		expWarnings int
		expTTL      time.Duration
		expMaxTTL   time.Duration
	}{
		{
			name:   "nil_config",
			config: nil,
			resp: &logical.Response{
				Secret: &logical.Secret{},
			},
			expWarnings: 0,
		},
		{
			name:        "nil_resp",
			config:      &config{},
			expWarnings: 0,
		},
		{
			name:   "nil_secret",
			config: &config{},
			resp: &logical.Response{
				Secret: nil,
			},
			expWarnings: 0,
		},
		{
			name: "config_ttl_higher",
			config: &config{
				TTL: 5 * time.Second,
			},
			resp: &logical.Response{
				Secret: &logical.Secret{
					LeaseOptions: logical.LeaseOptions{
						TTL: 1 * time.Second,
					},
				},
			},
			expWarnings: 1,
			expTTL:      1 * time.Second,
		},
		{
			name: "config_ttl_lower",
			config: &config{
				TTL: 5 * time.Second,
			},
			resp: &logical.Response{
				Secret: &logical.Secret{
					LeaseOptions: logical.LeaseOptions{
						TTL: 10 * time.Second,
					},
				},
			},
			expWarnings: 1,
			expTTL:      5 * time.Second,
		},
		{
			name: "config_max_ttl_higher",
			config: &config{
				MaxTTL: 5 * time.Second,
			},
			resp: &logical.Response{
				Secret: &logical.Secret{
					LeaseOptions: logical.LeaseOptions{
						MaxTTL: 1 * time.Second,
					},
				},
			},
			expWarnings: 1,
			expMaxTTL:   1 * time.Second,
		},
		{
			name: "config_max_ttl_lower",
			config: &config{
				MaxTTL: 5 * time.Second,
			},
			resp: &logical.Response{
				Secret: &logical.Secret{
					LeaseOptions: logical.LeaseOptions{
						MaxTTL: 10 * time.Second,
					},
				},
			},
			expWarnings: 1,
			expMaxTTL:   5 * time.Second,
		},
		{
			name: "warns_both",
			config: &config{
				TTL:    1 * time.Second,
				MaxTTL: 10 * time.Second,
			},
			resp: &logical.Response{
				Secret: &logical.Secret{},
			},
			expWarnings: 2,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.config.adjustTTLs(tc.resp)

			var warnings []string
			if tc.resp != nil {
				warnings = tc.resp.Warnings
			}

			if got, want := len(warnings), tc.expWarnings; got != want {
				t.Errorf("expected %d to be %d: %#v", got, want, warnings)
			}

			if want := tc.expTTL; want > 0 {
				secret := tc.resp.Secret
				if secret == nil {
					t.Fatal("expected ttl, but secret is nil")
				}
				if got := secret.TTL; got != want {
					t.Errorf("expected %s to be %s", got, want)
				}
			}

			if want := tc.expMaxTTL; want > 0 {
				secret := tc.resp.Secret
				if secret == nil {
					t.Fatal("expected max_ttl, but secret is nil")
				}
				if got := secret.MaxTTL; got != want {
					t.Errorf("expected %s to be %s", got, want)
				}
			}
		})
	}
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
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

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
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
