package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesetStoragePrefix = "roleset"
)

func pathsRoleSet(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("roleset/%s", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Required. Name of the role.",
				},
				"secret_type": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("Type of secret generated for this role set. Defaults to '%s'", SecretTypeAccessToken),
					Default:     SecretTypeAccessToken,
				},
				"project": {
					Type:        framework.TypeString,
					Description: "Name of the GCP project that this roleset's service account will belong to.",
				},
				"bindings": {
					Type:        framework.TypeString,
					Description: "Bindings configuration string.",
				},
				"token_scopes": {
					Type:        framework.TypeCommaStringSlice,
					Description: `List of OAuth scopes to assign to credentials generated under this role set`,
				},
			},
			ExistenceCheck: b.pathRoleSetExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleSetDelete,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleSetRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleSetCreate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleSetUpdate,
				},
			},
			HelpSynopsis:    pathRoleSetHelpSyn,
			HelpDescription: pathRoleSetHelpDesc,
		},
		// Path to rotate role set service accounts
		{
			Pattern: fmt.Sprintf("roleset/%s/rotate", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
			},
			ExistenceCheck: b.pathRoleSetExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleSetRotateAccount,
				},
			},
			HelpSynopsis:    pathRoleSetRotateHelpSyn,
			HelpDescription: pathRoleSetRotateHelpDesc,
		},
		// Path to rotating role set service account key used to generate access tokens
		{
			Pattern: fmt.Sprintf("roleset/%s/rotate-key", framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
			},
			ExistenceCheck: b.pathRoleSetExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleSetRotateKey,
				},
			},
			HelpSynopsis:    pathRoleSetRotateKeyHelpSyn,
			HelpDescription: pathRoleSetRotateKeyHelpDesc,
		},
		// Paths for listing role sets
		{
			Pattern: "rolesets/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleSetList,
				},
			},

			HelpSynopsis:    pathListRoleSetHelpSyn,
			HelpDescription: pathListRoleSetHelpDesc,
		},
		{
			Pattern: "roleset/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleSetList,
				},
			},

			HelpSynopsis:    pathListRoleSetHelpSyn,
			HelpDescription: pathListRoleSetHelpDesc,
		},
	}
}

func (b *backend) pathRoleSetExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return false, errors.New("roleset name is required")
	}

	rs, err := getRoleSet(nameRaw.(string), ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return rs != nil, nil
}

func (b *backend) pathRoleSetRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}

	rs, err := getRoleSet(nameRaw.(string), ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"secret_type": rs.SecretType,
		"bindings":    rs.Bindings.asOutput(),
	}

	if rs.AccountId != nil {
		data["service_account_email"] = rs.AccountId.EmailOrId
		data["project"] = rs.AccountId.Project
	}

	if rs.TokenGen != nil && rs.SecretType == SecretTypeAccessToken {
		data["token_scopes"] = rs.TokenGen.Scopes
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRoleSetDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	rsName := nameRaw.(string)

	rs, err := getRoleSet(rsName, ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("unable to get role set %s: %v", rsName, err), nil
	}
	if rs == nil {
		return nil, nil
	}

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()

	// Add precautionary cleanup callbacks before attempting to delete roleset.
	err = b.addWalsForAllAccountResources(ctx, req.Storage, rsName, rs.AccountId, rs.Bindings, rs.TokenGen)
	if err != nil {
		return nil, err
	}

	// Delete roleset from storage
	if err := req.Storage.Delete(ctx, fmt.Sprintf("roleset/%s", nameRaw)); err != nil {
		return nil, err
	}

	// Now that roleset has been deleted, attempt to delete GCP resources. Since
	// eventual deletion is guaranteed by WAL, just warn if deletion fails.
	warnings := b.tryCleanAccountResources(ctx, req.Storage, rs.Name, rs.AccountId, rs.Bindings, rs.TokenGen)
	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}

	return nil, nil
}

func (b *backend) pathRoleSetCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var warnings []string
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	b.Logger().Debug("creating new roleset", "name", name)

	// Start param parsing
	// Secret type
	secretType := d.Get("secret_type").(string)
	switch secretType {
	case SecretTypeKey, SecretTypeAccessToken:
		// Valid secret type
		break
	default:
		return logical.ErrorResponse(fmt.Sprintf(`invalid "secret_type" value: "%s"`, secretType)), nil
	}

	// Project
	project := d.Get("project").(string)
	if len(project) == 0 {
		return logical.ErrorResponse("project argument is required for new role set"), nil
	}

	// Default token scopes
	var scopes []string
	if scopesRaw, ok := d.GetOk("token_scopes"); ok {
		scopes = scopesRaw.([]string)
		if len(scopes) == 0 {
			return logical.ErrorResponse("cannot provide empty token_scopes"), nil
		}
		if secretType != SecretTypeAccessToken {
			warnings = append(warnings, fmt.Sprintf("token_scopes will be ignored for roleset with secret_type %q", secretType))
		}
	}
	if secretType == SecretTypeAccessToken && len(scopes) == 0 {
		return logical.ErrorResponse("cannot provide no or empty token_scopes for secret_type %q", SecretTypeAccessToken), nil
	}

	// Bindings
	bRaw, bOk := d.GetOk("bindings")
	if !bOk {
		return logical.ErrorResponse("bindings are required for new role set - " +
			"explicitly set to empty string if you do not want to manage bindings"), nil
	}
	bindings, err := util.ParseBindings(bRaw.(string))
	if err != nil {
		return logical.ErrorResponse("unable to parse bindings: %v", err), nil
	}
	// End param parsing

	// Create new roleset with non-GCP-dependant values
	rs := &RoleSet{
		Name:        name,
		SecretType:  secretType,
		RawBindings: bRaw.(string),
		Bindings:    bindings,
	}

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()

	// Create new account resources and save to roleset
	saveWarn, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs,
		// Data used to create GCP resources
		project, randomServiceAccountName(name), rs.Bindings, scopes)
	if err != nil {
		return logical.ErrorResponse("unable to parse bindings: %v", err), nil
	}
	warnings = append(warnings, saveWarn...)
	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var warnings []string

	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()
	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse("update called but no roleset named %q found", name), nil
	}
	if rs.AccountId == nil {
		return logical.ErrorResponse("invalid roleset has no account id", name), nil
	}

	b.Logger().Debug("updating roleset", "name", name)

	// Reject non-updatable fields
	// Secret type is non-updatable to prevent confusion between keys used to generate access tokens and keys generated
	// as secret values.
	if v, ok := d.GetOk("secret_type"); ok && rs.SecretType != v.(string) {
		return logical.ErrorResponse("cannot update secret_type from %q to %q, recreate roleset to change", rs.SecretType, v), nil
	}

	// Project is non-updatable to simplify update.
	if v, ok := d.GetOk("project"); ok && rs.AccountId.Project != v.(string) {
		return logical.ErrorResponse("cannot update project from %q to %q, recreate roleset to change", rs.AccountId.Project, v), nil
	}

	// Scopes is updatable
	scopesRaw, ok := d.GetOk("token_scopes")
	if ok && rs.TokenGen != nil {
		scopes := scopesRaw.([]string)
		if len(scopes) == 0 {
			return logical.ErrorResponse("cannot provide empty token_scopes"), nil
		}
		rs.TokenGen.Scopes = scopesRaw.([]string)
	}
	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}

	// Bindings
	bindingsToSet := rs.Bindings
	bNewRaw, bindsOk := d.GetOk("bindings")
	if bindsOk {
		bindingsToSet, err = util.ParseBindings(bNewRaw.(string))
		if err != nil {
			return logical.ErrorResponse("unable to parse bindings: %v", err), nil
		}
	}

	// Check if we need to make changes to IAM resources
	hasNewBindings := bindsOk && rs.bindingHash() != getStringHash(bNewRaw.(string))
	if !hasNewBindings {
		// just save the roleset as there are no GCP changes required.
		if err := rs.save(ctx, req.Storage); err != nil {
			return logical.ErrorResponse("unable to save updated roleset %q to storage: %v", rs.Name, err), nil
		}
	}

	b.Logger().Debug("given new bindings, will need to recreate account")
	saveWarn, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs,
		rs.AccountId.Project, randomServiceAccountName(name), bindingsToSet, scopes)
	if err != nil {
		return logical.ErrorResponse("unable to save roleset %q with new account: %v", rs.Name, err), nil
	}
	warnings = append(warnings, saveWarn...)
	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolesets, err := req.Storage.List(ctx, "roleset/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(rolesets), nil
}

func (b *backend) pathRoleSetRotateAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()
	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("roleset '%s' not found", name)), nil
	}

	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}

	warnings, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs,
		rs.AccountId.Project, randomServiceAccountName(name), rs.Bindings, scopes)
	if err != nil {
		return logical.ErrorResponse("unable to parse bindings: %v", err), nil
	}
	if len(warnings) > 0 {
		return &logical.Response{
			Warnings: warnings,
		}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()
	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("roleset '%s' not found", name)), nil
	}
	if rs.SecretType != SecretTypeAccessToken {
		return logical.ErrorResponse("cannot rotate key for non-access-token role set"), nil
	}

	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}
	warnings, err := b.saveRolesetWithNewTokenGenerator(ctx, req.Storage, rs, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func getRoleSet(name string, ctx context.Context, s logical.Storage) (*RoleSet, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesetStoragePrefix, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	rs := &RoleSet{}
	if err := entry.DecodeJSON(rs); err != nil {
		return nil, err
	}
	return rs, nil
}

const pathRoleSetHelpSyn = `Read/write sets of IAM roles to be given to generated credentials for specified GCP resources.`
const pathListRoleSetHelpSyn = `List existing rolesets.`
const pathRoleSetRotateHelpSyn = `Rotate the service account (and key for access token roleset) created and used to generate secrets`
const pathRoleSetRotateKeyHelpSyn = `Rotate only the service account key used by an access token roleset to generate tokens`

const pathRoleSetRotateHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account used to
generate secrets for a given role set.`
const pathRoleSetRotateKeyHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account
key used to generate access tokens under a given role set. This
path only applies to role sets that generate access tokens `

const pathRoleSetHelpDesc = `
This path allows you create role sets, which bind sets of IAM roles
to specific GCP resources. Secrets (either service account keys or
access tokens) are generated under a role set and will have the
given set of roles on resources.

The specified binding file accepts an HCL (or JSON) string
with the following format:

resource "some/gcp/resource/uri" {
	roles = [
		"roles/role1",
		"roles/role2",
		"roles/role3",
		...
	]
}

The given resource can have the following

* Project-level self link
	Self-link for a resource under a given project
	(i.e. resource name starts with 'projects/...')
	Use if you need to provide a versioned object or
	are directly using resource.self_link.

	Example (Compute instance):
		http://www.googleapis.com/compute/v1/projects/$PROJECT/zones/$ZONE/instances/$INSTANCE_NAME

* Full Resource Name
	A scheme-less URI consisting of a DNS-compatible
	API service name and a resource path (i.e. the
	relative resource name). Useful if you need to
	specify what service this resource is under
	but just want the preferred supported API version.
	Note that if the resource you are using is for
	a non-preferred API with multiple service versions,
	you MUST specify the version.

	Example (IAM service account):
		//$SERVICE.googleapis.com/projects/my-project/serviceAccounts/myserviceaccount@...

* Relative Resource Name:
	A URI path (path-noscheme) without the leading "/".
	It identifies a resource within the API service.
	Use if there is only one service that your
	resource could belong to. If there are multiple
	API versions that support the resource, we will
	attempt to use the preferred version and ask
	for more specific format otherwise.

	Example (Pubsub subscription):
		projects/myproject/subscriptions/mysub
`
const pathListRoleSetHelpDesc = `List role sets by role set name`
