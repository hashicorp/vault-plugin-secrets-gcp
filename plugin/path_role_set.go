package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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
				"base64_encoded": {
					Type:        framework.TypeBool,
					Description: `Flag determining if bindings string is base64 encoded.`,
				},
				"default_scopes": {
					Type:        framework.TypeStringSlice,
					Description: `List of default scopes to assign to credentials generated under this role set`,
				},
			},
			ExistenceCheck: b.pathRoleSetExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.DeleteOperation: b.pathRoleSetDelete,
				logical.ReadOperation:   b.pathRoleSetRead,
				logical.CreateOperation: b.pathRoleSetCreateUpdate,
				logical.UpdateOperation: b.pathRoleSetCreateUpdate,
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
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleSetRotateAccount,
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
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleSetRotateKey,
			},
			HelpSynopsis:    pathRoleSetRotateKeyHelpSyn,
			HelpDescription: pathRoleSetRotateKeyHelpDesc,
		},
		// Paths for listing role sets
		{
			Pattern: "rolesets/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleSetList,
			},

			HelpSynopsis:    pathListRoleSetHelpSyn,
			HelpDescription: pathListRoleSetHelpDesc,
		},
		{
			Pattern: "roleset/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleSetList,
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

	data := map[string]interface{}{
		"bindings": rs.Bindings.asOutput(),
	}

	if rs.AccountId != nil {
		data["service_account_email"] = rs.AccountId.EmailOrId
		data["service_account_project"] = rs.AccountId.Project
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

	if err := req.Storage.Delete(ctx, fmt.Sprintf("roleset/%s", nameRaw)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleSetCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if rs == nil {
		rs = &RoleSet{
			Name: name,
		}
	}

	isCreate := req.Operation == logical.CreateOperation

	// Secret type
	secretType := d.Get("secret_type").(string)
	switch secretType {
	case SecretTypeKey:
	case SecretTypeAccessToken:
		if !isCreate && rs.SecretType != secretType {
			return logical.ErrorResponse("cannot change secret_type after roleset creation"), nil
		}
		rs.SecretType = secretType
	default:
		return logical.ErrorResponse(fmt.Sprintf(`invalid "secret_type" value: "%s"`, secretType)), nil
	}

	// Secret type
	var project string
	projectRaw, ok := d.GetOk("project")
	if ok {
		project := projectRaw.(string)
		if !isCreate && rs.AccountId.Project != project {
			return logical.ErrorResponse(fmt.Sprintf("cannot change project for existing role set (old: %s, new: %s)", rs.AccountId.Project, project)), nil
		}
		project = projectRaw.(string)
	} else {
		if isCreate {
			return logical.ErrorResponse("project argument is required for new role set"), nil
		}
		project = rs.AccountId.Project
	}

	// Default scopes
	var scopes []string
	scopesRaw, ok := d.GetOk("default_scopes")
	if ok {
		if rs.SecretType != SecretTypeAccessToken {
			return logical.ErrorResponse(fmt.Sprintf("default_scopes only valid for role set with '%s' secret type", SecretTypeAccessToken)), nil
		}
		scopes = scopesRaw.([]string)
	} else {
		if rs.TokenGen != nil {
			scopes = rs.TokenGen.DefaultScopes
		}
	}

	// Bindings
	b64ed := d.Get("base64_encoded").(bool)
	bRaw, newBindings := d.GetOk("bindings")
	if len(bRaw.(string)) == 0 {
		return logical.ErrorResponse("given empty bindings string"), nil
	}

	if isCreate && newBindings == false {
		return logical.ErrorResponse("bindings are required for new role set"), nil
	}

	if !newBindings {
		// Just save role with updated metadata:
		if err := rs.save(ctx, req.Storage); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		return nil, nil
	}

	// Only update service account if bindings are different.
	var bindings ResourceBindings
	bindings, err = util.ParseBindings(bRaw.(string), b64ed)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to parse bindings: %v", err)), nil
	}
	if len(bindings) == 0 {
		return logical.ErrorResponse("unable to parse any bindings from given bindings HCL"), nil
	}

	warnings, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs, project, bindings, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	} else if warnings != nil && len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolesets, err := req.Storage.List(ctx, "roleset")
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

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse(fmt.Sprintf("roleset '%s' not found", name)), nil
	}

	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.DefaultScopes
	}

	warnings, err := b.saveRoleSetWithNewAccount(ctx, req.Storage, rs, rs.AccountId.Project, rs.Bindings, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	} else if warnings != nil && len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

func (b *backend) pathRoleSetRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

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
		scopes = rs.TokenGen.DefaultScopes
	}
	if err := b.saveRoleSetWithNewTokenKey(ctx, req.Storage, rs, scopes); err != nil {
		return logical.ErrorResponse(err.Error()), nil
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
