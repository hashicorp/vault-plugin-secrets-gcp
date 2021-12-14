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
* GOOGLE_APPLICATION_CREDENTIALS (path to service account credentials JSON file)
* GOOGLE_CLOUD_PROJECT_ID
* GOOGLE_CLOUD_PROJECT_NAME (used to write bindings file)
* GOOGLE_REGION

Run the tests:
```bash
$ cd ./tests/acceptance
$ bats gcp-secrets.bats
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

