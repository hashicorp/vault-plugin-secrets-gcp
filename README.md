# Vault Plugin: Google Cloud Platform Secrets Backend [![CircleCI](https://circleci.com/gh/hashicorp/vault-plugin-secrets-gcp.svg?style=svg)](https://circleci.com/gh/hashicorp/vault-plugin-secrets-gcp)

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
- [GCP Secrets Docs](https://www.vaultproject.io/docs/secrets/gcp/index.html)
- [Vault Github](https://www.github.com/hashicorp/vault)
- [General Announcement List](https://groups.google.com/forum/#!forum/hashicorp-announce)
- [Discussion List](https://groups.google.com/forum/#!forum/vault-tool)


## Usage

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works. Otherwise, first read this guide on
how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

If you are just interested in using this plugin with Vault, it is packaged with Vault and
by default can be enabled by running:

```sh
$ vault secrets enable gcp
Success! Enabled the gcp secrets engine at: gcp/
```

If you are testing this plugin in an earlier version of Vault or want to
test or use a custom build of the plugin, see the next section.

## Developing

If you wish to work on this plugin, you'll first need [Go](https://www.golang.org)
installed on your machine (whichever version is required by Vault).

Make sure Go is properly installed, including setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).

### Get Plugin

Clone this repository:

```text
$ mkdir $GOPATH/src/github.com/hashicorp/vault-plugin-secrets-gcp`
$ cd $GOPATH/src/github.com/hashicorp/
$ git clone https://github.com/hashicorp/vault-plugin-secrets-gcp.git
```

or use `go get github.com/hashicorp/vault-plugin-secrets-gcp`

You can then download any required build tools by bootstrapping your
environment:

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
$ vault server -config=path/to/config.json #...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog):

```sh
$ vault write sys/plugins/catalog/gcpsecrets \
    sha_256="$(shasum -a 256 path/to/plugin/directory/vault-plugin-secrets-gcp | cut -d " " -f1)" \
    command="vault-plugin-secrets-gcp"
```

Any name can be substituted for the plugin name "gcpsecrets". This
name will be referenced in the next step, where we enable the secrets
plugin backend using the GCP secrets plugin:

```sh
$ vault secrets enable --plugin-name='gcpsecrets' --path="gcp" plugin
```

### Tests

To run the unit tests:

1. Run the unit tests:

   ```text
   $ make test
   ```

This plugin also has comprehensive [acceptance tests](https://en.wikipedia.org/wiki/Acceptance_testing)
covering most of the features of this auth backend.

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the acceptance tests.

**Warning:** The acceptance tests create/destroy/modify *real resources*,
which may incur real costs in some cases. In the presence of a bug,
it is technically possible that broken backends could leave dangling
data behind. Therefore, please run the acceptance tests at your own risk.
At the very least, we recommend running them in their own private
account for whatever backend you're testing.

To run the acceptance tests, you will need a GCP IAM service account with the
permissions listed below. The following steps assume you have
[gcloud][install-gcloud] installed.

1. Save the name of your test project as an environment variable for reference:

    ```text
    $ export GOOGLE_CLOUD_PROJECT=my-project # replace with your project ID
    ```

    Do not use a production project. Use a dedicated project for testing.

1. Enable the IAM service on the project:

    ```text
    $ gcloud services enable --project "${GOOGLE_CLOUD_PROJECT}" \
        cloudresourcemanager.googleapis.com \
        iam.googleapis.com
    ```

1. Create a testing service account:

    ```text
    $ gcloud iam service-accounts create vault-tester \
        --display-name vault-tester \
        --project "${GOOGLE_CLOUD_PROJECT}"
    ```

1. Grant required test permissions:

    ```text
    $ gcloud projects add-iam-policy-binding "${GOOGLE_CLOUD_PROJECT}" \
        --member "serviceAccount:vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com" \
        --role "roles/owner"
    ```

    Note: these are overly broad permissions because the account needs a
    superset of all permissions it might grant. For this reason, it is
    **strongly recommended** that you have a dedicated project for running
    tests.

1. Download the service account key file to local disk:

    ```text
    $ gcloud iam service-accounts keys create vault-tester.json \
        --iam-account "vault-tester@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
    ```

1. Export the credentials to an environment variable. You can set the env variable to either 
   the path or the JSON itself, i.e.
   
    ```text
    $ export GOOGLE_CREDENTIALS="path/to/vault-tester.json"
    ```
    
    ```text
    $ export GOOGLE_CREDENTIALS="$(cat path/to/vault-tester.json)"
    ```

1. Run the acceptance tests:

    ```text
    $ make test-acc
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

## Other Docs

See up-to-date [engine docs](https://www.vaultproject.io/docs/secrets/gcp/index.html)
and general [API docs](https://www.vaultproject.io/api/secret/gcp/index.html).

