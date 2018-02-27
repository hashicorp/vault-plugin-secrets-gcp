# Vault Plugin: Google Cloud Platform Auth Backend

This is a backend plugin to be used with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin generates either one-time (non-renewable) OAuth2 access tokens or 
service account keys with a given set of [IAM roles](https://cloud.google.com/iam/docs/understanding-roles)
bound to GCP resources for various GCP entities to authenticate with Vault. 

**Please note**: We take Vault's security and our users' trust very seriously. 
If you believe you have found a security issue in Vault or with this plugin, 
_please responsibly disclose_ by 
contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
- [Vault Website](https://www.vaultproject.io)
- [GCP Secrets BE Docs](https://www.vaultproject.io/docs/secrets/gcp/index.html)
- [Vault Github](https://www.github.com/hashicorp/vault)
- [General Announcement List](https://groups.google.com/forum/#!forum/hashicorp-announce)
- [Discussion List](https://groups.google.com/forum/#!forum/vault-tool)


## Usage

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works. Otherwise, first read this guide on 
how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

If you are using Vault v0.9.6 or above, this plugin is packaged with Vault
and by default can be enabled by running:
 ```sh
 
 $ vault secrets enable gcp
 
 Success! Enabled the gcp secrets engine at: gcp/
 
 ```
 
 If you are testing this plugin in an earlier version of Vault or 
 want to develop, see the next section. 

## Developing

If you wish to work on this plugin, you'll first need [Go](https://www.golang.org) 
installed on your machine (whichever version is required by Vault).

Make sure Go is properly installed, including setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).

### Get Plugin 
Clone this repository: 

```

mkdir $GOPATH/src/github.com/hashicorp/vault-plugin-secrets-gcp`
cd $GOPATH/src/github.com/hashicorp/
git clone https://github.com/hashicorp/vault-plugin-secrets-gcp.git

```
(or use `go get github.com/hashicorp/vault-plugin-secrets-gcp` ).

You can then download any required build tools by bootstrapping your environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

### Install Plugin in Vault

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```hcl

plugin_directory = "path/to/plugin/directory"

```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog):

```sh
$ vault write sys/plugins/catalog/gcpsecrets \
        sha_256="$(shasum -a 256 path/to/plugin/directory/vault-plugin-secrets-gcp | cut -d " " -f1)" \
        command="vault-plugin-secrets-gcp"
```

Any name can be substituted for the plugin name "mygcpplugin". This
name will be referenced in the next step, where we enable the auth
plugin backend using the GCP auth plugin:

```sh
$ vault secrets enable --plugin-name='gcpsecrets' --path="gcp" plugin

```

### Tests

This plugin has [acceptance tests](https://en.wikipedia.org/wiki/Acceptance_testing) 
covering most of the features of this auth backend.

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the acceptance tests.

Acceptance tests typically require other environment variables to be set for
things such as access keys. The test itself should error early and tell
you what to set, so it is not documented here.

**Warning:** The acceptance tests create/destroy/modify *real resources*,
which may incur real costs in some cases. In the presence of a bug,
it is technically possible that broken backends could leave dangling
data behind. Therefore, please run the acceptance tests at your own risk.
At the very least, we recommend running them in their own private
account for whatever backend you're testing.

To run the acceptance tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```

## Documentation 

(This section will eventually be moved to [Vault docs](https://www.vaultproject.io/docs/secrets/gcp/index.html) and will not be kept-up-to-date)

We assume the backend is mounted at 'gcp':

```sh
vault secrets enable gcp 

```

Or if you're using the plugin directly:

```sh
vault secrets enable --plugin_name=gcppluginname --path=gcp plugin

```

If you are running from source code, running scripts/local_dev.sh will start and mount this plugin for you:

```sh
cd $GOPATH/github.com/hashicorp/vault-plugin-secrets-gcp
./scripts/local_dev
```
There are three main paths, two of which must be used to set up the backend for secrets generation.

### Config (`/config`)

Example:

```sh
vault write gcp/config \
    credentials=@path/to/credentials.json
    ttl=3600
    max_ttl=86400
```

Params:

* `credentials` (string): Contents of JSON GCP credentials file (or path, using Vault syntax @path/to/file)
    If this is not specified, will attempt to use [application default credentials](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application).
* `ttl` (int/duration): TTL in seconds (or duration string '<#>s') for default leases on long-term secrets (i.e. service account keys)
* `max_ttl` (int/duration): Max TTL in seconds (or duration string '<#>s') for default leases on long-term secrets (i.e. service account keys); determines
    when a secret no longer can be renewed
    
### Role Sets (`/roleset/$name`)

Examples:

```sh
$ vault write gcp/roleset/token-role-set \
    project="my-gcp-project" \
    secret_type="access_token" \
    bindings="bindingsb64string..." \
    base64_encoded=true \
    token_scopes="https://www.googleapis.com/auth/cloud-platform",...
    
    
$ vault write gcp/roleset/key-role-set \
    project="my-gcp-project" \
    secret_type="service_account_key" \
    bindings=@path/to/bindings.hcl \
    base64_encoded=false \
```

Params:

* `project` (`string`: `<required>`): GCP project role set service accounts/credentials will be generated under. 
* `secret_type` (`string`: `"access_token"`): Type of secret this role set can be used to generate (either `access_token` or `service_account_key`)
* `bindings` (`string`: `<required>`): Max TTL in seconds (or duration string '<#>s') for default leases on long-term secrets (i.e. service account keys); determines
    when a secret no longer can be renewed
* `base64_encoded` (`bool`: `false`): Whether provided bindings string (if provided as raw string) has been base64 encoded
* `token_scopes` (`[]string`: `<required>` for `access_token` role sets): Only applies to `access_token` role sets. A default  list of OAuth scopes for generated tokens (can also be specified at secrets generation step)
   
Once a role-set has been created, there are two additional paths
for updating rolesets:
  
```sh

 vault write gcp/roleset/my-role-set/rotate
 
 vault write gcp/roleset/my-token-role-set/rotate-key

```

#### Bindings

The `bindings` argument provided on role creation/update is expected to be [HCL](https://github.com/hashicorp/hcl)
(or corresponding JSON) in the following format:

```hcl

resource "path/to/my/resource" {
    roles = [
      "roles/viewer",
      "roles/my-other-role",
      "...",
    ]
}

```

Each top level block is a `resource` specified by a name. This resource name
can be the following formats:

*   A project-level self-link: A URI with scheme and host that could be returned by `.self_link` on some resource.
    We only accept project-level resources (i.e. relative resource name starts with `projects/$PROJECT/...`). 
    Use if you need to specify the service and version of the resource.
    
    Example (Compute zone):
     `https://www.googleapis.com/compute/alpha/projects/my-project/zones/us-central1-c`

*   [Full resource name](https://cloud.google.com/apis/design/resource_names#full_resource_name): 
    A scheme-less URI consisting of a DNS-compatible API service name and a resource path. 
    The resource path is also known as relative resource name. Use if you want to
    use the preferred version of a service (or the only version for which this resource is IAM-enabled)
    but the service is ambiguous.  
    
    Example (Pubsub snapshot):
     `//pubsub.googleapis.com/projects/my-project/snapshots/snapshot123`
     
*   [Relative resource name](https://cloud.google.com/apis/design/resource_names#relative_resource_name):
    A [path-noscheme](https://tools.ietf.org/html/rfc3986#appendix-A) URI path. Use if version/service are
    apparent from resource type (or you want to use only the preferred version of the service):
    Example (Spanner Database):
      `projects/project0/instances/instance1/databases/db2`
     
     
#### Rotation

* `/rotate` rotates the service account (and key, if an `access_token` role set) used to generate secrets.
* `/rotate-key` applies only to `access_token` role sets and rotates only the service account key used to generate access tokens and

You can also read or list created roles back. 

At this point, the backend will be ready to generate secrets:

### Secrets 

This backend is able to generate secrets under given role sets. Depending on a role set, either a OAuth access token
or a service account key will be generated. Each secret is returned with a lease_id to reference for 
renewal/revocation.

#### Access Tokens

```
# Either path works
$ vault read gcp/token/token-roleset \
$ vault write gcp/token/token-roleset \
    
$ vault revoke gcp/key/key-roleset/lease_id
        
```
**Note** Access tokens cannot be renewed and attempts to renew will return an error.

Params:

* `scopes` (`[]string`): List of OAuth scopes to assign to token. Uses role set defaults if not specified.

Output:
```
Key                 Value
---                 -----
lease_id           gcp/token/test/<uuid>
lease_duration     59m59s
lease_renewable    false
token              ya29.c.restoftoken...
```
This token can be used by adding it as a header to any request (**note** you must add "Authorization: Bearer" prefix)
```
curl -H "Authorization: Bearer $TOKEN" ... 
```

#### Service Account Key Tokens

```sh
# Default key alg/type
$ vault read gcp/key/key-roleset

# Write allows arguments for different types of keys.
$ vault write gcp/key/key-roleset \
    key_type="TYPE_GOOGLE_CREDENTIALS_FILE"
    key_algorithm="KEY_ALG_RSA_2048"
```
Params:
* `key_type` (`string`: `TYPE_GOOGLE_CREDENTIALS_FILE`): Private key type. See enum 
    [`ServiceAccountPrivateKeyType`](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountPrivateKeyType)
* `key_algorithm` (`string`: `KEY_ALG_RSA_2048`): Algorithm used to generate key, defaults to 2k RSA. See enum
    [`ServiceAccountKeyAlgorithm`](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountKeyAlgorithm)

Output:
```
Key                 Value
---                 -----
lease_id            gcp/key/key-roleset/<uuid>
lease_duration      1h
lease_renewable     true
key_algorithm       KEY_ALG_RSA_2048
key_type            TYPE_GOOGLE_CREDENTIALS_FILE
private_key_data    <b64'd(private key)>
```

Renew/Revoke:
```
# Renew
$ vault renew gcp/key/key-roleset/lease_id

# Revoke
$ vault revoke gcp/token/token-roleset/lease_id
    
```

### Troubleshooting/Things To Note

#### Role Set + IAM Quota Limits (Error: "You've reached your limit of ...")

When we create role sets, we generate a new service account per role set. This means:

* **Role sets that create service account keys are limited to 10**: GCP IAM has a limit of 10 service account keys per
    service account. Unfortunetely , due to the way IAM service accounts are created and permissions propagated,
    we are keeping service account creation tied to role-set creation/update. If you run into this limit, 
    you will either need to create new role sets with the same set of permissions or revoke any unused keys quicker.

* **You may need to increase your service account quota if you have too many role sets**: GCP IAM has a limit of 100 
    service accounts per project, so you may get an error while creating or updating a role set telling you you have
    reached this limit. You can request more quota as needed (see [docs](https://cloud.google.com/compute/quotas#request_quotas))
    
* **If a roleset's GCP service account/key is deleted, Vault will return errors until the role-set is updated**:
    If someone starts deleting GCP resources that 'belong' to Vault, Vault will make its best effort to recover
    but will deny access to a role set until a new service account has been generatedVault tries t

### Secrets

* **Role sets by default generate access_tokens**: To generate service account keys, set the role set secret_type to "service_account_key"
* **Access tokens are non-renewable**: Because access tokens are naturally short-lived (1hr TTL), we decided to make them non-renewable and you will need to do another read/write to the /token endpoint to generate a new token.


