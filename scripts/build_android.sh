#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$REPO_ROOT/android"
JNI_LIBS_DIR="$ANDROID_DIR/app/src/main/jniLibs"

if [[ -d "$HOME/.cache/rust-clash-tools/rustup" ]]; then
    export RUSTUP_HOME="$HOME/.cache/rust-clash-tools/rustup"
fi

# Locate Android SDK & NDK
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/tmp/android-sdk}}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    if [[ -d "$ANDROID_HOME/ndk" ]]; then
        ANDROID_NDK_HOME="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
        export ANDROID_NDK_HOME
    fi
fi

if [[ ! -d "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME not found under $ANDROID_HOME/ndk" >&2
    exit 1
fi

HOST_TAG="linux-x86_64"
if [[ "$(uname -s)" == "Darwin" ]]; then
    HOST_TAG="darwin-x86_64"
fi

LLVM_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
if [[ ! -d "$LLVM_BIN" ]]; then
    echo "ERROR: NDK LLVM toolchain bin missing at $LLVM_BIN" >&2
    exit 1
fi

export PATH="$LLVM_BIN:$PATH"
export CC_aarch64_linux_android="$LLVM_BIN/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$LLVM_BIN/aarch64-linux-android26-clang"

export CC_x86_64_linux_android="$LLVM_BIN/x86_64-linux-android26-clang"
export AR_x86_64_linux_android="$LLVM_BIN/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$LLVM_BIN/x86_64-linux-android26-clang"

PROFILE="${CARGO_ANDROID_PROFILE:-release}"
CARGO_PROFILE_FLAG="--release"
TARGET_SUBDIR="release"
if [[ "$PROFILE" == "dev" ]]; then
    CARGO_PROFILE_FLAG=""
    TARGET_SUBDIR="debug"
fi
TARGET_ROOT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

echo "[android-build] Ensuring embedded Web Console UI assets are up to date..."
if [[ ! -f "$REPO_ROOT/ui/dist/index.html" ]] || [[ "${BUILD_UI:-0}" == "1" ]]; then
    (cd "$REPO_ROOT/ui" && ( [[ -d node_modules ]] || npm ci ) && npm run build)
fi

echo "[android-build] Cross-compiling Rust proxy-ffi ($PROFILE) for aarch64-linux-android & x86_64-linux-android..."
cd "$REPO_ROOT"
cargo build --locked -p proxy-ffi \
    --target aarch64-linux-android \
    --target x86_64-linux-android \
    $CARGO_PROFILE_FLAG

mkdir -p "$JNI_LIBS_DIR/arm64-v8a" "$JNI_LIBS_DIR/x86_64" "$ANDROID_DIR/app/src/main/assets/licenses"
cp "$TARGET_ROOT/aarch64-linux-android/$TARGET_SUBDIR/libproxy_ffi.so" "$JNI_LIBS_DIR/arm64-v8a/libproxy_ffi.so"
cp "$TARGET_ROOT/x86_64-linux-android/$TARGET_SUBDIR/libproxy_ffi.so" "$JNI_LIBS_DIR/x86_64/libproxy_ffi.so"
cp "$REPO_ROOT/LICENSE-MIT" "$REPO_ROOT/LICENSE-APACHE" "$REPO_ROOT/THIRD_PARTY_NOTICES.md" \
    "$ANDROID_DIR/app/src/main/assets/licenses/"

# Strip debug symbols on release builds to keep APK/AAB compact
if [[ "$PROFILE" == "release" ]] && [[ -x "$LLVM_BIN/llvm-strip" ]]; then
    "$LLVM_BIN/llvm-strip" --strip-unneeded "$JNI_LIBS_DIR/arm64-v8a/libproxy_ffi.so"
    "$LLVM_BIN/llvm-strip" --strip-unneeded "$JNI_LIBS_DIR/x86_64/libproxy_ffi.so"
fi

ls -lh "$JNI_LIBS_DIR/arm64-v8a/libproxy_ffi.so" "$JNI_LIBS_DIR/x86_64/libproxy_ffi.so"

GRADLE_EXTRA_ARGS=()
ACTIVE_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
if [[ -n "$ACTIVE_PROXY" ]]; then
    read -r PROXY_HOST PROXY_PORT < <(python3 -c '
import sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
print(u.hostname or "127.0.0.1", u.port or 80)
' "$ACTIVE_PROXY")
    JVM_OPTS="-Xmx3072m -XX:+UseParallelGC -Dfile.encoding=UTF-8 -Dhttp.proxyHost=$PROXY_HOST -Dhttp.proxyPort=$PROXY_PORT -Dhttps.proxyHost=$PROXY_HOST -Dhttps.proxyPort=$PROXY_PORT -Dhttp.nonProxyHosts=localhost"

    if [[ -f "/etc/ssl/certs/ca-certificates.crt" ]]; then
        MERGED_TRUSTSTORE="/tmp/rust-clash-java-cacerts.p12"
        rm -f "$MERGED_TRUSTSTORE"
        python3 -c '
import pathlib, re, subprocess
pem = pathlib.Path("/etc/ssl/certs/ca-certificates.crt").read_text(errors="ignore")
certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
for idx, cert in enumerate(certs):
    cert_path = pathlib.Path(f"/tmp/rust-clash-ca-{idx}.pem")
    cert_path.write_text(cert + "\n")
    subprocess.run([
        "keytool", "-importcert", "-noprompt",
        "-storetype", "PKCS12",
        "-alias", f"ca-{idx}",
        "-file", str(cert_path),
        "-keystore", "/tmp/rust-clash-java-cacerts.p12",
        "-storepass", "changeit",
    ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cert_path.unlink(missing_ok=True)
'
        if [[ -f "$MERGED_TRUSTSTORE" ]]; then
            TRUST_OPTS="-Djavax.net.ssl.trustStore=$MERGED_TRUSTSTORE -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit"
            JVM_OPTS="$JVM_OPTS $TRUST_OPTS"
        fi
    fi

    export GRADLE_OPTS="${GRADLE_OPTS:-} $JVM_OPTS"
    GRADLE_EXTRA_ARGS+=("-Dorg.gradle.jvmargs=$JVM_OPTS" "-Pkotlin.daemon.jvmargs=$JVM_OPTS")
fi

echo "[android-build] Bootstrapping Gradle Wrapper & running Android tasks..."
cd "$ANDROID_DIR"

WRAPPER_PROPS="$ANDROID_DIR/gradle/wrapper/gradle-wrapper.properties"
WRAPPER_PROPS_BAK=""
cleanup_wrapper_props() {
    if [[ -n "$WRAPPER_PROPS_BAK" ]] && [[ -f "$WRAPPER_PROPS_BAK" ]]; then
        mv -f "$WRAPPER_PROPS_BAK" "$WRAPPER_PROPS"
    fi
}
trap cleanup_wrapper_props EXIT

GRADLE_DIST_VERSION="8.11.1"
GRADLE_DIST_SHA256="f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6"
GRADLE_DISTS_DIR="${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists/gradle-${GRADLE_DIST_VERSION}-bin"

verify_gradle_zip() {
    local zip_file="$1"
    [[ -s "$zip_file" ]] && echo "${GRADLE_DIST_SHA256}  ${zip_file}" | sha256sum -c - >/dev/null 2>&1
}

if ! find "$GRADLE_DISTS_DIR" -name "*.ok" 2>/dev/null | grep -q .; then
    LOCAL_GRADLE_ZIP="/tmp/gradle-${GRADLE_DIST_VERSION}-bin.zip"
    if ! verify_gradle_zip "$LOCAL_GRADLE_ZIP"; then
        rm -f "$LOCAL_GRADLE_ZIP"
        echo "[android-build] Pre-fetching SHA-256-pinned gradle-${GRADLE_DIST_VERSION}-bin.zip..."
        if command -v gh >/dev/null 2>&1 && [[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
            for gh_try in 1 2 3; do
                if gh release download "v${GRADLE_DIST_VERSION}" \
                    -R gradle/gradle-distributions \
                    -p "gradle-${GRADLE_DIST_VERSION}-bin.zip" \
                    -O "$LOCAL_GRADLE_ZIP" --clobber 2>/dev/null && verify_gradle_zip "$LOCAL_GRADLE_ZIP"; then
                    echo "[android-build] Verified gradle-${GRADLE_DIST_VERSION}-bin.zip via authenticated GitHub API."
                    break
                fi
                rm -f "$LOCAL_GRADLE_ZIP"
                sleep $((gh_try * 2))
            done
        fi
    fi

    if ! verify_gradle_zip "$LOCAL_GRADLE_ZIP"; then
        for mirror_url in \
            "https://services.gradle.org/distributions/gradle-${GRADLE_DIST_VERSION}-bin.zip" \
            "https://github.com/gradle/gradle-distributions/releases/download/v${GRADLE_DIST_VERSION}/gradle-${GRADLE_DIST_VERSION}-bin.zip" \
            "https://downloads.gradle-dn.com/distributions/gradle-${GRADLE_DIST_VERSION}-bin.zip" \
            "https://mirrors.cloud.tencent.com/gradle/gradle-${GRADLE_DIST_VERSION}-bin.zip"
        do
            echo "[android-build] Trying Gradle distribution mirror: $mirror_url"
            rm -f "$LOCAL_GRADLE_ZIP"
            if curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 25 \
                -o "$LOCAL_GRADLE_ZIP" "$mirror_url" && verify_gradle_zip "$LOCAL_GRADLE_ZIP"; then
                echo "[android-build] Verified SHA-256 for gradle-${GRADLE_DIST_VERSION}-bin.zip from $mirror_url"
                break
            fi
            rm -f "$LOCAL_GRADLE_ZIP"
        done
    fi

    if verify_gradle_zip "$LOCAL_GRADLE_ZIP"; then
        WRAPPER_PROPS_BAK="/tmp/gradle-wrapper.properties.bak.$$"
        cp "$WRAPPER_PROPS" "$WRAPPER_PROPS_BAK"
        sed -i.tmp "s|^distributionUrl=.*|distributionUrl=file\\\\:///tmp/gradle-${GRADLE_DIST_VERSION}-bin.zip|" "$WRAPPER_PROPS"
        rm -f "$WRAPPER_PROPS.tmp"
    fi
fi

if [[ -n "$WRAPPER_PROPS_BAK" ]]; then
    ./gradlew --no-daemon "${GRADLE_EXTRA_ARGS[@]}" --version >/dev/null
    cleanup_wrapper_props
    WRAPPER_PROPS_BAK=""
fi

VARIANT="${ANDROID_BUILD_VARIANT:-debug}"
SKIP_CHECKS="${ANDROID_SKIP_CHECKS:-0}"
SKIP_BUNDLE="${ANDROID_SKIP_BUNDLE:-0}"

GRADLE_TASKS=()
if [[ "$SKIP_CHECKS" != "1" ]]; then
    GRADLE_TASKS+=(testDebugUnitTest lintDebug)
fi

case "$VARIANT" in
    debug)
        GRADLE_TASKS+=(assembleDebug)
        if [[ "$SKIP_BUNDLE" != "1" ]]; then
            GRADLE_TASKS+=(bundleDebug)
        fi
        ;;
    release)
        GRADLE_TASKS+=(assembleRelease)
        if [[ "$SKIP_BUNDLE" != "1" ]]; then
            GRADLE_TASKS+=(bundleRelease)
        fi
        ;;
    both)
        GRADLE_TASKS+=(assembleDebug)
        if [[ "$SKIP_BUNDLE" != "1" ]]; then
            GRADLE_TASKS+=(bundleDebug)
        fi
        GRADLE_TASKS+=(assembleRelease)
        if [[ "$SKIP_BUNDLE" != "1" ]]; then
            GRADLE_TASKS+=(bundleRelease)
        fi
        ;;
    *)
        echo "ERROR: Unsupported ANDROID_BUILD_VARIANT='$VARIANT' (expected debug, release, or both)" >&2
        exit 1
        ;;
esac

echo "[android-build] Running Gradle tasks (variant=$VARIANT, skip_checks=$SKIP_CHECKS, skip_bundle=$SKIP_BUNDLE): ${GRADLE_TASKS[*]}"
for build_attempt in 1 2; do
    if ./gradlew --no-daemon "${GRADLE_EXTRA_ARGS[@]}" "${GRADLE_TASKS[@]}"; then
        break
    fi
    if [[ "$build_attempt" -eq 2 ]]; then
        exit 1
    fi
    echo "[android-build] Gradle build encountered transient error; retrying once in 5s..." >&2
    sleep 5
done

if [[ "$VARIANT" == "release" || "$VARIANT" == "both" ]]; then
    REL_APK_DIR="$ANDROID_DIR/app/build/outputs/apk/release"
    RELEASE_UNIVERSAL_APK="$REL_APK_DIR/app-universal-release.apk"
    RELEASE_ARM64_APK="$REL_APK_DIR/app-arm64-v8a-release.apk"
    RELEASE_X86_64_APK="$REL_APK_DIR/app-x86_64-release.apk"
    RELEASE_COMPAT_APK="$REL_APK_DIR/app-release.apk"
    RELEASE_AAB="$ANDROID_DIR/app/build/outputs/bundle/release/app-release.aab"

    for req_apk in "$RELEASE_UNIVERSAL_APK" "$RELEASE_ARM64_APK" "$RELEASE_X86_64_APK"; do
        if [[ ! -f "$req_apk" ]]; then
            echo "ERROR: Signed release APK missing at $req_apk (ensure ANDROID_KEYSTORE_PATH, ANDROID_KEYSTORE_PASSWORD, and ANDROID_KEY_ALIAS are set)" >&2
            exit 1
        fi
    done
    cp -f "$RELEASE_UNIVERSAL_APK" "$RELEASE_COMPAT_APK"

    if [[ "$SKIP_BUNDLE" != "1" ]] && [[ ! -f "$RELEASE_AAB" ]]; then
        echo "ERROR: Signed release AAB missing at $RELEASE_AAB" >&2
        exit 1
    fi
    APKSIGNER_BIN="$(find "$ANDROID_HOME/build-tools" -name apksigner -type f 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "$APKSIGNER_BIN" && -x "$APKSIGNER_BIN" ]]; then
        echo "[android-build] Verifying APK Signature Scheme v2/v3 via apksigner across split & universal APKs..."
        for signed_apk in "$RELEASE_UNIVERSAL_APK" "$RELEASE_ARM64_APK" "$RELEASE_X86_64_APK"; do
            "$APKSIGNER_BIN" verify --min-sdk-version 26 --v --print-certs "$signed_apk"
        done
    fi
    ls -lh "$RELEASE_ARM64_APK" "$RELEASE_X86_64_APK" "$RELEASE_UNIVERSAL_APK"
    if [[ -f "$RELEASE_AAB" ]]; then
        ls -lh "$RELEASE_AAB"
    fi
fi

if [[ "$VARIANT" == "debug" || "$VARIANT" == "both" ]]; then
    DBG_APK_DIR="$ANDROID_DIR/app/build/outputs/apk/debug"
    if [[ -f "$DBG_APK_DIR/app-universal-debug.apk" ]]; then
        cp -f "$DBG_APK_DIR/app-universal-debug.apk" "$DBG_APK_DIR/app-debug.apk"
    fi
    ls -lh "$DBG_APK_DIR"/app-*debug.apk
    if [[ -f "$ANDROID_DIR/app/build/outputs/bundle/debug/app-debug.aab" ]]; then
        ls -lh "$ANDROID_DIR/app/build/outputs/bundle/debug/app-debug.aab"
    fi
fi
