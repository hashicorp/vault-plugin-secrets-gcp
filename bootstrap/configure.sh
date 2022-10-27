PLUGIN_DIR=$1
PLUGIN_NAME=$2
GOOGLE_CREDENTIALS=$3
GOOGLE_CLOUD_PROJECT=$4

vault plugin deregister "$PLUGIN_NAME"
vault secrets disable gcp
killall "$PLUGIN_NAME"

rm "$PLUGIN_DIR"/"$PLUGIN_NAME"
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"/"$PLUGIN_NAME"

echo "$PLUGIN_DIR"/"$PLUGIN_NAME"
vault plugin register \
      -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
      secret "$PLUGIN_NAME"

vault secrets enable --plugin-name="$PLUGIN_NAME" --path="gcp" plugin