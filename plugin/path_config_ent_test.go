// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// TestConfig_PluginIdentityToken_ent tests parsing and validation of
// configuration used to set the secret engine up for web identity federation using
// plugin identity tokens.
func TestConfig_PluginIdentityToken_ent(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = &testSystemViewEnt{}

	b := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"identity_token_ttl":      int64(10),
		"identity_token_audience": "test-aud",
		"service_account_email":   "test-service_account",
	}

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config writing failed: resp:%#v\n err: %v", resp, err)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   config.StorageView,
		Path:      "config",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: config reading failed: resp:%#v\n err: %v", resp, err)
	}

	// Grab the subset of fields from the response we care to look at for this case
	got := map[string]interface{}{
		"identity_token_ttl":      resp.Data["identity_token_ttl"],
		"identity_token_audience": resp.Data["identity_token_audience"],
		"service_account_email":   resp.Data["service_account_email"],
	}

	if !reflect.DeepEqual(got, configData) {
		t.Errorf("bad: expected to read config root as %#v, got %#v instead", configData, resp.Data)
	}

	credJson, err := getTestCredentials()
	if err != nil {
		t.Fatalf("error getting test credentials: %s", err)
	}
	// mutually exclusive fields must result in an error
	configData = map[string]interface{}{
		"identity_token_audience": "test-aud",
		"credentials":             credJson,
	}

	configReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), configReq)
	if !resp.IsError() {
		t.Fatalf("expected an error but got nil")
	}
	expectedError := "only one of 'credentials' or 'identity_token_audience' can be set"
	if !strings.Contains(resp.Error().Error(), expectedError) {
		t.Fatalf("expected err %s, got %s", expectedError, resp.Error())
	}

	// erase storage so that no service account email is in config
	config.StorageView = &logical.InmemStorage{}
	// missing email with audience must result in an error
	configData = map[string]interface{}{
		"identity_token_audience": "test-aud",
	}

	configReq = &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Path:      "config",
		Data:      configData,
	}

	resp, err = b.HandleRequest(context.Background(), configReq)
	if !resp.IsError() {
		t.Fatalf("expected an error but got nil")
	}
	expectedError = "missing required 'service_account_email' when 'identity_token_audience' is set"
	if !strings.Contains(resp.Error().Error(), expectedError) {
		t.Fatalf("expected err %s, got %s", expectedError, resp.Error())
	}
}

type testSystemViewEnt struct {
	logical.StaticSystemView
}

func (d testSystemViewEnt) GenerateIdentityToken(_ context.Context, _ *pluginutil.IdentityTokenRequest) (*pluginutil.IdentityTokenResponse, error) {
	return &pluginutil.IdentityTokenResponse{}, nil
}
