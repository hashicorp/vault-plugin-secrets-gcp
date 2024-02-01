## v0.18.0

IMPROVEMENTS:
* Updated dependencies [[GH-198](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/198)]:
   * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
   * `github.com/hashicorp/vault/api` v1.9.2 -> v1.11.0
   * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
   * `golang.org/x/oauth2` v0.11.0 -> v0.16.0
   * `google.golang.org/api` v0.138.0 -> v0.161.0
* Bump golang.org/x/crypto from 0.12.0 to 0.17.0: [GH-197](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/197)
* Bump github.com/go-jose/go-jose/v3 from 3.0.0 to 3.0.1: [GH-196](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/196)
* Bump google.golang.org/grpc from 1.57.0 to 1.57.1: [GH-195](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/195)
* Bump golang.org/x/net from 0.14.0 to 0.17.0: [GH-194](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/194)

## v0.17.0

CHANGES:
* Shuffle around operation IDs to present the best generated client library interface [[GH-190](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/190)]

IMPROVEMENTS:
* Add missing `Query: true` metadata to API definitions [[GH-189](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/189)]
* Updated dependencies [[GH-191](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/191)]:
   * `github.com/hashicorp/hcl` v1.0.0 -> v1.0.1-vault-5
   * `github.com/hashicorp/vault/api` v1.9.1 -> v1.9.2
   * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.9.2
   * `golang.org/x/oauth2` v0.8.0 -> v0.11.0
   * `google.golang.org/api` v0.124.0 -> v0.138.0

## v0.16.0

IMPROVEMENTS:
* Enable multiplexing [[GH-172](https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/172)]
* Updated dependencies:
   * `github.com/hashicorp/go-hclog` v1.4.0 -> v1.5.0
   * `github.com/hashicorp/vault/api` v1.8.3 -> v1.9.1
   * `github.com/hashicorp/vault/sdk` v0.7.0 -> v0.9.0
   * `golang.org/x/oauth2` v0.4.0 -> v0.8.0
   * `google.golang.org/api` v0.109.0 -> v0.124.0

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
