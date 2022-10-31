PLUGIN_DIR=$1
PLUGIN_NAME=$2
PLUGIN_MOUNT=$3
GOOGLE_CREDENTIALS=$4

# Try to clean-up previous runs
vault plugin deregister "$PLUGIN_NAME"
vault secrets disable "$PLUGIN_MOUNT"
killall "$PLUGIN_NAME"

# Give a bit of time for the binary file to be released o we can copy over it
sleep 3

# Copies the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"/"$PLUGIN_NAME"

# Sets up the binary with local changes
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      secret "$PLUGIN_NAME"
vault secrets enable --plugin-name="$PLUGIN_NAME" --path="$PLUGIN_MOUNT" plugin
vault write "$PLUGIN_MOUNT"/config credentials=@"$GOOGLE_CREDENTIALS"

vault write local-gcp/roleset/my-token-roleset \
    project="hc-69468348cc2c49739a411d53676" \
    secret_type="access_token"  \
    token_scopes="https://www.googleapis.com/auth/cloud-platform" \
    bindings=-<<EOF
      resource "//cloudresourcemanager.googleapis.com/projects/hc-69468348cc2c49739a411d53676" {
        roles = ["roles/viewer"]
      }
EOF

vault read local-gcp/roleset/my-token-roleset/token