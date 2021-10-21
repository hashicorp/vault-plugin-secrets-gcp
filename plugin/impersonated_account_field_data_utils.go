package gcpsecrets

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
)

type impersonatedAccountInputParams struct {
	name string

	project             string
	serviceAccountEmail string

	scopes []string
}

// parseOkInputServiceAccountEmail checks that when creating a static acocunt, a service account
// email is provided. A service account email can be provide while updating the static account
// but it must be the same as the one in the static account and cannot be updated.
func (input *impersonatedAccountInputParams) parseOkInputServiceAccountEmail(d *framework.FieldData) (warnings []string, err error) {
	email := d.Get("service_account_email").(string)
	if email == "" && input.serviceAccountEmail == "" {
		return nil, fmt.Errorf("email is required")
	}
	if input.serviceAccountEmail != "" && email != "" && input.serviceAccountEmail != email {
		return nil, fmt.Errorf("cannot update email")
	}

	input.serviceAccountEmail = email
	return nil, nil
}

func (input *impersonatedAccountInputParams) parseOkInputTokenScopes(d *framework.FieldData) (warnings []string, err error) {
	v, ok := d.GetOk("token_scopes")
	if ok {
		scopes, castOk := v.([]string)
		if !castOk {
			return nil, fmt.Errorf("scopes unexpected type %T, expected []string", v)
		}
		input.scopes = scopes
	}

	if len(input.scopes) == 0 {
		return nil, fmt.Errorf("non-empty token_scopes must be provided for generating secrets")
	}

	return
}
