#!/usr/bin/env bats

#load _helpers
#
#SKIP_TEARDOWN=true
VAULT_ADDR='http://127.0.0.1:8200'
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.9.0-rc1}"

if [[ -z SERVICE_ACCOUNT_ID ]]
then
    echo "SERVICE_ACCOUNT_ID env is not set. Exiting.."
    exit 1
fi

if [[ -z PATH_TO_CREDS ]]
then
    echo "PATH_TO_CREDS env is not set. Exiting.."
    exit 1
fi

if [[ -z GOOGLE_PROJECT ]]
then
    echo "GOOGLE_PROJECT env is not set. Exiting.."
    exit 1
fi

if [[ -z GOOGLE_APPLICATION_CREDENTIALS ]]
then
    echo "GOOGLE_APPLICATION_CREDENTIALS env is not set. Exiting.."
    exit 1
fi

export SETUP_TEARDOWN_OUTFILE=/tmp/output.log

setup(){
    { # Braces used to redirect all setup logs.
    # 1. Configure Vault.
    VAULT_TOKEN='root'
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

    docker pull ${VAULT_IMAGE?}

    docker run \
      --name=vault \
      --hostname=vault \
      -p 8200:8200 \
      -e VAULT_DEV_ROOT_TOKEN_ID="root" \
      -e VAULT_ADDR="http://localhost:8200" \
      -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
      --privileged \
      --detach ${VAULT_IMAGE?}

    # Replace with a check
    sleep 2

    vault login ${VAULT_TOKEN?}

    vault secrets enable gcp
    } >> $SETUP_TEARDOWN_OUTFILE
}

teardown(){
    if [[ -n $SKIP_TEARDOWN ]]; then
        echo "Skipping teardown"
        return
    fi

    { # Braces used to redirect all teardown logs.

    vault secrets disable gcp
    # If the test failed, print some debug output
    if [[ "$BATS_ERROR_STATUS" -ne 0 ]]; then
        docker logs vault
    fi

    # Teardown Vault configuration.
    docker rm vault --force
    } >> $SETUP_TEARDOWN_OUTFILE
}

@test "Can successfully write GCP Secrets Config" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write token roleset" {

    echo ${GOOGLE_PROJECT?}
    echo ${PATH_TO_CREDS?}

    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/roleset/my-token-roleset \
      project=${GOOGLE_PROJECT?} \
      secret_type="access_token"  \
      token_scopes="https://www.googleapis.com/auth/cloud-platform" \
      bindings=@tests/acceptance/configs/mybindings.hcl
    [ "${status?}" -eq 0 ]
}

@test "Can successfully generate oAuth tokens" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/roleset/my-token-roleset \
      project=${GOOGLE_PROJECT?} \
      secret_type="access_token"  \
      token_scopes="https://www.googleapis.com/auth/cloud-platform" \
      bindings=@tests/acceptance/configs/mybindings.hcl

    run vault read gcp/roleset/my-token-roleset/token
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write key roleset" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/roleset/my-key-roleset \
          project=${GOOGLE_PROJECT?} \
          secret_type="service_account_key"  \
          token_scopes="https://www.googleapis.com/auth/cloud-platform" \
          bindings=@tests/acceptance/configs/mybindings.hcl
    [ "${status?}" -eq 0 ]
}

@test "Can successfully generate dynamic keys" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/roleset/my-key-roleset \
          project=${GOOGLE_PROJECT?} \
          secret_type="service_account_key"  \
          token_scopes="https://www.googleapis.com/auth/cloud-platform" \
          bindings=@tests/acceptance/configs/mybindings.hcl

    run vault read gcp/roleset/my-key-roleset/key
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write access token static account" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/static-account/my-token-account \
          service_account_email=${SERVICE_ACCOUNT_ID?} \
          secret_type="access_token"  \
          token_scopes="https://www.googleapis.com/auth/cloud-platform" \
          bindings=@tests/acceptance/configs/mybindings.hcl
    [ "${status?}" -eq 0 ]
}

@test "Can successfully write service account key static account" {
    run vault write gcp/config \
          credentials=@${PATH_TO_CREDS?}

    run vault write gcp/static-account/my-key-account \
          service_account_email=${SERVICE_ACCOUNT_ID?} \
          secret_type="service_account_key"  \
          token_scopes="https://www.googleapis.com/auth/cloud-platform" \
          bindings=@tests/acceptance/configs/mybindings.hcl
    [ "${status?}" -eq 0 ]
}
