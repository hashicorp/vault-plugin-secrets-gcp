## Unreleased

CHANGES:

* ADD YOUR CHANGE HERE [[GH-XXX](https://github.com/hashicorp/vault-plugin-secrets-gcp)]

IMPROVEMENTS:
* Enable multiplexing [[GH-172](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/172)]

## v0.15.0

IMPROVEMENTS:

* Added support for impersonated accounts [[GH-129](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/129)}

BUG FIXES:

* Fix issue where IAM bindings were not preserved during policy update [[GH-114](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/114)]
* Fix issue where duplicate service account keys would be created for rotate root
  on standby or  [[GH-153](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/153)]
* Changes user-agent header value to use correct Vault version information and include
  the plugin type and name in the comment section. [[GH-164](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/164)]

## v0.14.0

IMPROVEMENTS:

* Updates dependencies: `google.golang.org/api@v0.83.0`, `github.com/hashicorp/go-gcp-common@v0.8.0` [[GH-142](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/142)]

## v0.13.1

BUG FIXES:

* Fixes duplicate static account key creation from performance secondary clusters [[GH-144](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/144)]

## v0.12.1

BUG FIXES:

* Fixes duplicate static account key creation from performance secondary clusters [[GH-144](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/144)]

## v0.11.1

BUG FIXES:

* Fixes role bindings for BigQuery dataset resources [[GH-130](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/130)]

## v0.10.3

BUG FIXES:

* Fixes role bindings for BigQuery dataset resources [[GH-130](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/130)]

## v0.9.1

BUG FIXES:

* Fixes role bindings for BigQuery dataset resources [[GH-130](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/130)]

## 0.8.1

IMPROVEMENTS:

* Truncate ServiceAccount display names longer than 100 characters [[GH-87](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/87)]
