# Acceptance Tests

The following BATs tests can be used to test basic functionality of the GCP Secrets Engine.

## Prerequisites

* Clone this repository to your workstation
* [Bats Core installed](https://bats-core.readthedocs.io/en/stable/installation.html#homebrew)
* Docker
* Vault CLI installed
* GCP Project that has a service account w/ [required permissions](https://www.vaultproject.io/docs/secrets/gcp#required-permissions)

### GCP Testing

First, set the following env variables from your GCP project 

* SERVICE_ACCOUNT_ID
* PATH_TO_CREDS env variable pointing to service account credentials JSON file
* GOOGLE_APPLICATION_CREDENTIALS
* GOOGLE_PROJECT
* GOOGLE_REGION

Next, set the following environment variable to specify the version of Vault to test
```bash
$ export VAULT_IMAGE='hashicorp/vault:1.9.0-rc1'
```

Update the file `tests/acceptance/mybindings.hcl` with your GP project name for accurate
bindings:
```
resource "//cloudresourcemanager.googleapis.com/projects/<YOUR_GCP_PROJECT>" {
    roles = ["roles/viewer"]
}
```

Finally, run the tests:
```bash
$ cd ./test/acceptance
$ bats gcp-secrets.bat
```

### Output
```
✓ Can successfully write GCP Secrets Config
✓ Can successfully write token roleset
✓ Can successfully generate oAuth tokens
✓ Can successfully write key roleset
✓ Can successfully generate dynamic keys
✓ Can successfully write access token static account
✓ Can successfully write service account key static account
```

