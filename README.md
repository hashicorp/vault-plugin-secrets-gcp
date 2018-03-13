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

## Auto-generated IAM Config 

An IAM-enabled resource (under an arbitrary GCP service) supports the following three IAM methods:

* `getIamPolicy`
* `setIamPolicy`
* `testIamPermissions`

In the case of this secrets engine, we need to call `getIamPolicy` and `setIamPolicy` on
an arbitrary resource under an arbitrary service, which would be difficult using
the [generated Go google APIs](https://github.com/google/google-api-go-client). Instead,
we autogenerated a library, using the [Google API Discovery Service](https://developers.google.com/discovery/)
to find IAM-enabled resources and configure HTTP calls on arbitrary services/resources for IAM.

For each binding config resource block (with a resource name), we attempt to find the resource type based on the 
relative resource name and match it to a service config as seen in this 
[autogenerated config file](https://github.com/hashicorp/vault-plugin-secrets-gcp/blob/master/plugin/iamutil/iam_resources_generated.go)

To re-generate this file, run: 

```
go generate github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil
```


In general, we try to make it so you can specify the resource as given in the HTTP API URL 
(between base API URL and get/setIamPolicy suffix). For some possibly non-standard APIs, we have also
 added exceptions to try to reach something more standard; a notable current example is the Google Cloud Storage API, 
 whose methods look like `https://www.googleapis.com/storage/v1/b/bucket/o/object` where we accept either 
 `b/bucket/o/object` or `buckets/bucket/objects/object` as valid relative resource names.

If you are having trouble during role set creation with errors suggesting the resource format is invalid or API calls
are failing for a resource you know exists, please [report any issues](https://github.com/hashicorp/vault-plugin-secrets-gcp/issues) 
you run into. It could be that the API is a non-standard form or we need to re-generate our config file.

## Other Docs (To Be Removed/Replaced)

See up-to-date [HTTP API Docs](https://github.com/emilymye/vault/blob/docs/website/source/api/secret/gcp/index.html.md)
and general [GCP engine docs](https://github.com/emilymye/vault/blob/docs/website/source/docs/secrets/gcp/index.html.md)