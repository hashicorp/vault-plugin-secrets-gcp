// Copyright IBM Corp. 2018, 2026
// SPDX-License-Identifier: MPL-2.0

package gcpsecrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	templateutil "github.com/hashicorp/vault/sdk/helper/template"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	serviceAccountMinLen = 6
	// Several renders make it unlikely that random output happens to pass validation.
	usernameTemplateSampleRenders = 5
)

// Google's documented accountId rule (RFC 1035).
var serviceAccountIdRegex = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])$`)

type usernameTemplateData struct {
	DisplayName string
	RoleName    string
}

var sampleUsernameTemplateData = usernameTemplateData{
	DisplayName: "token",
	RoleName:    "my-roleset",
}

// validateUsernameTemplate parses the template and checks that sample data renders a valid service account ID.
func validateUsernameTemplate(rawTemplate string) (warnings []string, err error) {
	for i := 0; i < usernameTemplateSampleRenders; i++ {
		if _, err := renderServiceAccountId(rawTemplate, sampleUsernameTemplateData); err != nil {
			return nil, err
		}
	}
	if !strings.Contains(rawTemplate, "random") && !strings.Contains(rawTemplate, "unix_time") {
		warnings = append(warnings, "username_template does not use random or unix_time; "+
			"service account IDs must be unique within a project, so roleset rotation and binding updates will fail")
	}
	return warnings, nil
}

func renderServiceAccountId(rawTemplate string, data usernameTemplateData) (string, error) {
	tmpl, err := templateutil.NewTemplate(templateutil.Template(rawTemplate))
	if err != nil {
		return "", err
	}
	id, err := tmpl.Generate(data)
	if err != nil {
		return "", err
	}
	if err := validateServiceAccountId(id); err != nil {
		return "", err
	}
	return id, nil
}

func validateServiceAccountId(id string) error {
	if len(id) < serviceAccountMinLen || len(id) > serviceAccountMaxLen {
		return fmt.Errorf("rendered service account ID %q must be %d to %d characters, got %d",
			id, serviceAccountMinLen, serviceAccountMaxLen, len(id))
	}
	if !serviceAccountIdRegex.MatchString(id) {
		return fmt.Errorf("rendered service account ID %q must start with a lowercase letter, "+
			"contain only lowercase letters, digits, and hyphens, and end with a letter or digit", id)
	}
	return nil
}

// serviceAccountIdForRoleSet returns the ID for a new roleset service account and whether it came from username_template.
func (b *backend) serviceAccountIdForRoleSet(ctx context.Context, req *logical.Request, rsName string) (id string, templated bool, err error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return "", false, err
	}
	if cfg == nil || cfg.UsernameTemplate == "" {
		return generateAccountNameForRoleSet(rsName), false, nil
	}

	id, err = renderServiceAccountId(cfg.UsernameTemplate, usernameTemplateData{
		DisplayName: req.DisplayName,
		RoleName:    rsName,
	})
	if err != nil {
		return "", true, fmt.Errorf("error generating service account ID from username_template: %w", err)
	}
	return id, true, nil
}
