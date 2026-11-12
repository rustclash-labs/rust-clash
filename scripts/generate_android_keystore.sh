#!/usr/bin/env bash
set -euo pipefail

# Generates a persistent PKCS12 Android Release signing keystore locally (outside Git)
# and prints the 4 GitHub Actions repository secrets required by `.github/workflows/release.yml`
# so all future RustClash Android releases share the exact same v2/v3 signing certificate
# and support seamless in-place APK upgrades (`adb install -r` / Android Package Installer).

OUT_FILE="${1:-$HOME/.rust-clash-android-release.p12}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-rustclash}"

if [[ -f "$OUT_FILE" ]]; then
    echo "ERROR: Keystore already exists at $OUT_FILE (refusing to overwrite existing signing key!)." >&2
    exit 1
fi

if [[ -z "${ANDROID_KEYSTORE_PASSWORD:-}" ]]; then
    STORE_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
else
    STORE_PASS="$ANDROID_KEYSTORE_PASSWORD"
fi
KEY_PASS="${ANDROID_KEY_PASSWORD:-$STORE_PASS}"

umask 077
keytool -genkeypair \
    -storetype PKCS12 \
    -keystore "$OUT_FILE" \
    -alias "$KEY_ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 9125 \
    -storepass "$STORE_PASS" \
    -keypass "$KEY_PASS" \
    -dname "CN=RustClash Release, OU=Mobile, O=RustClash Labs" >/dev/null 2>&1

chmod 600 "$OUT_FILE"
B64_SINGLE_LINE="$(base64 < "$OUT_FILE" | tr -d '\r\n')"
CERT_SHA256="$(keytool -list -v -keystore "$OUT_FILE" -storepass "$STORE_PASS" -alias "$KEY_ALIAS" | grep -i 'SHA256:' | head -n 1 | sed 's/^[[:space:]]*//')"

cat <<EOF
================================================================================
Persistent Android Release Keystore generated: $OUT_FILE
Public Certificate Fingerprint -> $CERT_SHA256
IMPORTANT: Back up '$OUT_FILE' securely! Never commit it to Git.

Add the following 4 Repository Secrets on GitHub:
  Settings -> Secrets and variables -> Actions -> New repository secret

1. ANDROID_KEYSTORE_BASE64
$B64_SINGLE_LINE

2. ANDROID_KEYSTORE_PASSWORD
$STORE_PASS

3. ANDROID_KEY_ALIAS
$KEY_ALIAS

4. ANDROID_KEY_PASSWORD
$KEY_PASS
================================================================================
EOF
