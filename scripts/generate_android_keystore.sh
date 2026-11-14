#!/usr/bin/env bash
set -euo pipefail

# Generates a persistent PKCS12 Android Release signing keystore locally (outside Git)
# and writes the 4 GitHub Actions repository secrets required by `.github/workflows/release.yml`
# to a restricted `0600` file by default (never dumping raw secrets to terminal stdout unless
# `--print-secrets` is explicitly passed).

PRINT_SECRETS=0
SECRETS_OUT=""
POSITIONAL_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-secrets)
            PRINT_SECRETS=1
            shift
            ;;
        --secrets-out)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --secrets-out requires a file path argument." >&2
                exit 1
            fi
            SECRETS_OUT="$2"
            shift 2
            ;;
        -h|--help)
            cat <<'USAGE'
Usage: ./scripts/generate_android_keystore.sh [--print-secrets] [--secrets-out <path>] [keystore_path]

Options:
  --secrets-out <path>  Write GitHub Actions secret values to <path> (chmod 0600).
                        Defaults to <keystore_path>.secrets.txt.
  --print-secrets       Explicitly print raw secret values to stdout (WARNING: exposes
                        passwords and base64 keystore in terminal scrollback/logs).
USAGE
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option '$1'. Pass --help for usage." >&2
            exit 1
            ;;
        *)
            if [[ -n "$POSITIONAL_OUT" ]]; then
                echo "ERROR: Unexpected extra positional argument '$1'." >&2
                exit 1
            fi
            POSITIONAL_OUT="$1"
            shift
            ;;
    esac
done

OUT_FILE="${POSITIONAL_OUT:-$HOME/.rust-clash-android-release.p12}"
SECRETS_FILE="${SECRETS_OUT:-${OUT_FILE}.secrets.txt}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-rustclash}"

if [[ -e "$OUT_FILE" ]]; then
    echo "ERROR: Keystore already exists at $OUT_FILE (refusing to overwrite existing signing key!)." >&2
    exit 1
fi
if [[ "$PRINT_SECRETS" -eq 0 && -e "$SECRETS_FILE" ]]; then
    echo "ERROR: Secrets output file already exists at $SECRETS_FILE (refusing to overwrite!)." >&2
    exit 1
fi

if [[ -z "${ANDROID_KEYSTORE_PASSWORD:-}" ]]; then
    STORE_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
else
    STORE_PASS="$ANDROID_KEYSTORE_PASSWORD"
fi
KEY_PASS="${ANDROID_KEY_PASSWORD:-$STORE_PASS}"
export STORE_PASS KEY_PASS

umask 077
keytool -genkeypair \
    -storetype PKCS12 \
    -keystore "$OUT_FILE" \
    -alias "$KEY_ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 9125 \
    -storepass:env STORE_PASS \
    -keypass:env KEY_PASS \
    -dname "CN=RustClash Release, OU=Mobile, O=RustClash Labs" >/dev/null 2>&1

chmod 600 "$OUT_FILE"
B64_SINGLE_LINE="$(base64 < "$OUT_FILE" | tr -d '\r\n')"
CERT_SHA256="$(keytool -list -v -keystore "$OUT_FILE" -storepass:env STORE_PASS -alias "$KEY_ALIAS" | grep -i 'SHA256:' | head -n 1 | sed 's/^[[:space:]]*//')"

format_secrets_payload() {
    cat <<EOF
# GitHub Actions Repository Secrets for RustClash Android Release Signing
# Settings -> Secrets and variables -> Actions -> New repository secret
# WARNING: Delete this file securely (shred -u / rm -f) immediately after configuring GitHub Secrets!

ANDROID_KEYSTORE_BASE64=${B64_SINGLE_LINE}
ANDROID_KEYSTORE_PASSWORD=${STORE_PASS}
ANDROID_KEY_ALIAS=${KEY_ALIAS}
ANDROID_KEY_PASSWORD=${KEY_PASS}
EOF
}

if [[ "$PRINT_SECRETS" -eq 1 ]]; then
    echo "WARNING: --print-secrets requested; printing sensitive keystore credentials to stdout!" >&2
    cat <<EOF
================================================================================
Persistent Android Release Keystore generated: $OUT_FILE
Public Certificate Fingerprint -> $CERT_SHA256
Key Alias                      -> $KEY_ALIAS
IMPORTANT: Back up '$OUT_FILE' securely! Never commit it to Git, and clear your terminal scrollback.
================================================================================
EOF
    format_secrets_payload
else
    format_secrets_payload > "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
    cat <<EOF
================================================================================
Persistent Android Release Keystore generated: $OUT_FILE (mode 0600)
GitHub Actions secrets written to            : $SECRETS_FILE (mode 0600)
Public Certificate Fingerprint               : $CERT_SHA256
Key Alias                                    : $KEY_ALIAS

SECURITY NOTICE:
- Plaintext passwords and base64 keystore bytes were NOT printed to stdout.
- Upload the 4 values from '$SECRETS_FILE' into GitHub Actions Repository Secrets
  (Settings -> Secrets and variables -> Actions), back up '$OUT_FILE' offline,
  and then delete '$SECRETS_FILE' immediately ('rm -f "$SECRETS_FILE"').
- Never commit '$OUT_FILE' or '$SECRETS_FILE' to Git.
================================================================================
EOF
fi
