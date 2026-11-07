// Copyright IBM Corp. 2018, 2026
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUsernameTemplate = `vlt-{{ .RoleName | lowercase | replace "_" "-" | replace "." "-" | truncate 16 }}-{{ random 6 | lowercase }}`

func writeUsernameTemplateConfig(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})
	require.NoError(t, err)
	return resp
}

func readUsernameTemplate(t *testing.T, b logical.Backend, s logical.Storage) string {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%v", resp.Error())
	return resp.Data["username_template"].(string)
}

func TestConfig_UsernameTemplate(t *testing.T) {
	t.Parallel()

	credJson, err := getTestCredentials()
	require.NoError(t, err)

	t.Run("unset on create reads empty", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp := writeUsernameTemplateConfig(t, b, s, map[string]interface{}{"credentials": credJson})
		assert.Nil(t, resp)
		assert.Empty(t, readUsernameTemplate(t, b, s))
	})

	t.Run("set, update, preserve on omission, and clear", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp := writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
			"credentials":       credJson,
			"username_template": testUsernameTemplate,
		})
		assert.Nil(t, resp)
		assert.Equal(t, testUsernameTemplate, readUsernameTemplate(t, b, s))

		updated := `vault-{{ .RoleName }}-{{ unix_time }}`
		resp = writeUsernameTemplateConfig(t, b, s, map[string]interface{}{"username_template": updated})
		assert.Nil(t, resp)
		assert.Equal(t, updated, readUsernameTemplate(t, b, s))

		resp = writeUsernameTemplateConfig(t, b, s, map[string]interface{}{"ttl": "50s"})
		assert.Nil(t, resp)
		assert.Equal(t, updated, readUsernameTemplate(t, b, s))

		resp = writeUsernameTemplateConfig(t, b, s, map[string]interface{}{"username_template": ""})
		assert.Nil(t, resp)
		assert.Empty(t, readUsernameTemplate(t, b, s))
	})

	t.Run("template without random or unix_time warns", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp := writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
			"credentials":       credJson,
			"username_template": `vault-{{ .RoleName }}`,
		})
		require.NotNil(t, resp)
		require.False(t, resp.IsError())
		require.Len(t, resp.Warnings, 1)
		assert.Contains(t, resp.Warnings[0], "random or unix_time")
		assert.Equal(t, `vault-{{ .RoleName }}`, readUsernameTemplate(t, b, s))
	})

	t.Run("stored config without template decodes to legacy naming", func(t *testing.T) {
		b, s := getTestBackend(t)
		entry, err := logical.StorageEntryJSON("config", map[string]interface{}{"CredentialsRaw": string(credJson)})
		require.NoError(t, err)
		require.NoError(t, s.Put(context.Background(), entry))
		assert.Empty(t, readUsernameTemplate(t, b, s))
	})

	invalid := map[string]string{
		"syntax":           `vault-{{ .RoleName `,
		"unknown field":    `vault-{{ .Project }}-{{ random 6 | lowercase }}`,
		"unknown function": `vault-{{ nope }}`,
		"function failure": `vault-{{ .RoleName | truncate 0 }}`,
		"empty output":     `{{ "" }}`,
		"too long":         `vault-{{ .RoleName }}-{{ .RoleName }}-{{ .RoleName }}`,
		"uppercase":        `Vault-{{ .RoleName }}`,
		"underscore":       `vault_{{ .RoleName }}`,
		"leading digit":    `1vault-{{ .RoleName }}`,
		"trailing hyphen":  `vault-{{ .RoleName }}-`,
		"random uppercase": `vault-{{ random 20 }}`,
	}

	for name, tmpl := range invalid {
		t.Run("invalid update preserves config: "+name, func(t *testing.T) {
			b, s := getTestBackend(t)
			writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
				"credentials":       credJson,
				"username_template": testUsernameTemplate,
			})

			resp := writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
				"username_template": tmpl,
				"ttl":               "50s",
			})
			require.NotNil(t, resp)
			require.True(t, resp.IsError())
			assert.True(t, strings.HasPrefix(resp.Error().Error(), "invalid username_template: "), resp.Error().Error())

			cfg, err := getConfig(context.Background(), s)
			require.NoError(t, err)
			assert.Equal(t, testUsernameTemplate, cfg.UsernameTemplate)
			assert.Zero(t, cfg.TTL)
		})

		t.Run("invalid create stores nothing: "+name, func(t *testing.T) {
			b, s := getTestBackend(t)
			resp := writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
				"credentials":       credJson,
				"username_template": tmpl,
			})
			require.NotNil(t, resp)
			require.True(t, resp.IsError())

			cfg, err := getConfig(context.Background(), s)
			require.NoError(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestRenderServiceAccountId_UsernameTemplate(t *testing.T) {
	t.Parallel()

	data := usernameTemplateData{DisplayName: "userpass-alice", RoleName: "my-roleset"}

	tests := map[string]struct {
		template string
		want     string
		wantErr  string
	}{
		"role and display name": {
			template: `{{ .RoleName }}-{{ .DisplayName }}`,
			want:     "my-roleset-userpass-alice",
		},
		"printf pipeline": {
			template: `{{ printf "vault-%s" .RoleName | truncate 12 }}`,
			want:     "vault-my-rol",
		},
		"6 characters": {
			template: `abcdef`,
			want:     "abcdef",
		},
		"30 characters": {
			template: strings.Repeat("a", 30),
			want:     strings.Repeat("a", 30),
		},
		"5 characters": {
			template: `abcde`,
			wantErr:  "must be 6 to 30 characters, got 5",
		},
		"31 characters": {
			template: strings.Repeat("a", 31),
			wantErr:  "must be 6 to 30 characters, got 31",
		},
		"uppercase": {
			template: `vault-{{ .RoleName | uppercase }}`,
			wantErr:  "must start with a lowercase letter",
		},
		"leading digit": {
			template: `1{{ .RoleName }}`,
			wantErr:  "must start with a lowercase letter",
		},
		"leading hyphen": {
			template: `-{{ .RoleName }}`,
			wantErr:  "must start with a lowercase letter",
		},
		"trailing hyphen": {
			template: `{{ .RoleName }}-`,
			wantErr:  "must start with a lowercase letter",
		},
		"underscore": {
			template: `vault_{{ .RoleName }}`,
			wantErr:  "must start with a lowercase letter",
		},
		"non-ascii": {
			template: `vault-{{ .RoleName }}-é`,
			wantErr:  "must start with a lowercase letter",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := renderServiceAccountId(tc.template, data)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("empty display name", func(t *testing.T) {
		got, err := renderServiceAccountId(`vault-{{ .RoleName }}{{ .DisplayName }}`, usernameTemplateData{RoleName: "my-roleset"})
		require.NoError(t, err)
		assert.Equal(t, "vault-my-roleset", got)
	})

	t.Run("design example is valid for any roleset name", func(t *testing.T) {
		for _, rsName := range []string{"a", "my-roleset", "My_Role.Name", "UPPER_CASE_ROLESET_NAME_THAT_IS_VERY_LONG"} {
			got, err := renderServiceAccountId(testUsernameTemplate, usernameTemplateData{RoleName: rsName})
			require.NoError(t, err, rsName)
			assert.True(t, strings.HasPrefix(got, "vlt-"), got)
		}
	})

	t.Run("random and unix_time", func(t *testing.T) {
		got, err := renderServiceAccountId(`vault-{{ unix_time }}-{{ random 6 | lowercase }}`, data)
		require.NoError(t, err)
		assert.Regexp(t, `^vault-[0-9]+-[a-z0-9]{6}$`, got)
	})
}

func TestServiceAccountIdForRoleSet_UsernameTemplate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	credJson, err := getTestCredentials()
	require.NoError(t, err)

	t.Run("no config uses legacy naming", func(t *testing.T) {
		b, s := getTestBackend(t)
		id, templated, err := b.serviceAccountIdForRoleSet(ctx, &logical.Request{Storage: s}, "my-roleset")
		require.NoError(t, err)
		assert.False(t, templated)
		assert.Regexp(t, `^vaultmy-roleset-[0-9]+$`, id)
	})

	t.Run("config without template uses legacy naming", func(t *testing.T) {
		b, s := getTestBackend(t)
		testConfigUpdate(t, b, s, map[string]interface{}{"credentials": credJson})
		id, templated, err := b.serviceAccountIdForRoleSet(ctx, &logical.Request{Storage: s}, "my-roleset")
		require.NoError(t, err)
		assert.False(t, templated)
		assert.Regexp(t, `^vaultmy-roleset-[0-9]+$`, id)
	})

	t.Run("template renders role and caller display name", func(t *testing.T) {
		b, s := getTestBackend(t)
		writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
			"credentials":       credJson,
			"username_template": `{{ .RoleName }}-{{ .DisplayName }}`,
		})
		id, templated, err := b.serviceAccountIdForRoleSet(ctx, &logical.Request{Storage: s, DisplayName: "token-admin"}, "rs")
		require.NoError(t, err)
		assert.True(t, templated)
		assert.Equal(t, "rs-token-admin", id)
	})

	t.Run("runtime render failure does not fall back", func(t *testing.T) {
		b, s := getTestBackend(t)
		writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
			"credentials":       credJson,
			"username_template": `vault-{{ .RoleName }}`,
		})
		_, _, err := b.serviceAccountIdForRoleSet(ctx, &logical.Request{Storage: s}, "My_Role")
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "error generating service account ID from username_template: "), err.Error())
	})
}

func TestSaveRoleSetWithNewAccount_UsernameTemplate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	credJson, err := getTestCredentials()
	require.NoError(t, err)

	b, s := getTestBackend(t)
	writeUsernameTemplateConfig(t, b, s, map[string]interface{}{
		"credentials":       credJson,
		"username_template": `vault-{{ .RoleName }}-{{ unix_time }}`,
	})

	req := &logical.Request{Storage: s}
	rs := &RoleSet{Name: "My_Role", SecretType: SecretTypeKey}
	_, err = b.saveRoleSetWithNewAccount(ctx, req, rs, "my-project", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error generating service account ID from username_template: ")

	walIds, err := framework.ListWAL(ctx, s)
	require.NoError(t, err)
	assert.Empty(t, walIds, "render failure must happen before any WAL entry")

	saved, err := getRoleSet(rs.Name, ctx, s)
	require.NoError(t, err)
	assert.Nil(t, saved)
}
