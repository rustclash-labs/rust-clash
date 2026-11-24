package io.github.rustclashlabs.rustclash.vpn

import io.github.rustclashlabs.rustclash.security.AndroidKeystoreVault

internal class NativeLibraryLoader(
    private val loadLibrary: () -> Boolean,
    private val registerVaultKeyWrapper: () -> Unit,
) {
    private val loadLock = Any()

    @Volatile
    private var loadedState: Boolean? = null

    val isLoadedFast: Boolean
        get() = loadedState == true

    fun ensureLoaded(): Boolean {
        loadedState?.let { return it }
        return synchronized(loadLock) {
            loadedState?.let { return@synchronized it }
            val loaded = try {
                loadLibrary()
            } catch (_: UnsatisfiedLinkError) {
                false
            }
            if (loaded) {
                runCatching { registerVaultKeyWrapper() }
            }
            loadedState = loaded
            loaded
        }
    }
}

/**
 * JNI bridge to `libproxy_ffi.so` (`crates/proxy-ffi/src/android_jni.rs`).
 *
 * Loads the native Rust core lazily so pure-JVM JUnit tests can exercise Kotlin policy/lifecycle
 * models on any host without requiring Android ART native libraries.
 */
object NativeBridge {
    private val loader = NativeLibraryLoader(
        loadLibrary = {
            System.loadLibrary("proxy_ffi")
            true
        },
        registerVaultKeyWrapper = {
            if (AndroidKeystoreVault.isKeystoreAvailable()) {
                nativeRegisterVaultKeyWrapper(AndroidKeystoreVault)
            }
        },
    )

    /**
     * Non-blocking volatile check for whether `libproxy_ffi.so` (and vault wrapper registration)
     * has completed. Safe to call on the Android main thread.
     */
    val isLoadedFast: Boolean
        get() = loader.isLoadedFast

    /**
     * Non-blocking readiness alias for [isLoadedFast]. Never triggers `System.loadLibrary` or
     * Keystore IPC; callers that need to initialize the native library must call [ensureLoaded]
     * from a background/IO dispatcher.
     */
    val isNativeLoaded: Boolean
        get() = loader.isLoadedFast

    /**
     * Lazily loads `libproxy_ffi.so` and registers the Android Keystore vault wrapper once.
     *
     * Performs native library I/O (`dlopen`) and Keystore IPC on first call; invoke exclusively off
     * the Android main thread (e.g. `Dispatchers.IO`).
     */
    fun ensureLoaded(): Boolean = loader.ensureLoaded()

    external fun nativeRegisterVaultKeyWrapper(vaultHelper: Any): Boolean

    external fun nativeStartVpn(
        vpnService: Any,
        tunFd: Int,
        yamlConfig: String,
        demoMode: Boolean,
    ): String

    external fun nativeStartVpnWithStateDir(
        vpnService: Any,
        tunFd: Int,
        stateDir: String,
        yamlConfig: String,
        demoMode: Boolean,
        enableIpv6: Boolean,
    ): String

    external fun nativeStopVpn(): Boolean

    external fun nativeNotifyNetworkChanged(
        networkHandle: Long,
        isWifi: Boolean,
    ): Boolean

    external fun nativeNotifyNetworkChangedWithCaps(
        networkHandle: Long,
        isWifi: Boolean,
        hasIpv6: Boolean,
    ): Boolean

    external fun nativeGetStatusJson(): String

    external fun nativeGetNodeManagerSnapshot(stateDir: String): String

    external fun nativeImportUnifiedPayload(
        stateDir: String,
        payload: String,
        deduplicate: Boolean,
        autoSelect: Boolean,
    ): String

    external fun nativeSelectProxyPersisted(
        stateDir: String,
        groupName: String,
        proxyName: String,
    ): String

    external fun nativeUpsertNodeJson(
        stateDir: String,
        originalName: String,
        nodeJson: String,
        autoSelect: Boolean,
    ): String

    external fun nativeDeleteNodePersisted(
        stateDir: String,
        nodeName: String,
    ): String

    external fun nativeDeduplicateNodesPersisted(stateDir: String): String

    external fun nativeSwitchMode(mode: String): Boolean

    external fun nativeSelectProxy(groupName: String, proxyName: String): Boolean

    external fun nativeReloadConfig(yamlConfig: String): String

    external fun nativeImportUris(urisPayload: String): String

    external fun nativeFlushDns(): Boolean

    external fun nativeExplainRule(target: String, network: String): String

    external fun nativeGetDiagnosticsJson(limit: Int): String

    external fun nativeClearDiagnostics(): Boolean

    external fun nativeGetRoutingSnapshotJson(stateDir: String): String

    external fun nativeSetRoutingPresetJson(
        stateDir: String,
        preset: String,
    ): String

    external fun nativeSaveCustomRulesJson(
        stateDir: String,
        rulesPayload: String,
    ): String

    external fun nativeGetGeoDataStatusJson(stateDir: String): String

    external fun nativeUpdateGeoDataJson(stateDir: String): String

    external fun nativeExplainRuleWithStateDirJson(
        stateDir: String,
        target: String,
    ): String

    external fun nativeTestLatencyJson(
        stateDir: String,
        targetName: String,
        probeUrl: String,
        timeoutMs: Long,
    ): String

    external fun nativeGetProfilesSnapshotJson(stateDir: String): String

    external fun nativeActivateProfileJson(
        stateDir: String,
        profileId: String,
    ): String

    external fun nativeDeleteProfileJson(
        stateDir: String,
        profileId: String,
    ): String

    external fun nativeRefreshProfileJson(
        stateDir: String,
        profileId: String,
    ): String

    external fun nativeGetActiveYamlJson(stateDir: String): String

    external fun nativeSaveActiveYamlJson(
        stateDir: String,
        yamlPayload: String,
    ): String

    external fun nativeSetDemoSandboxJson(enable: Boolean): String

    external fun nativeSetLowPowerMode(enable: Boolean): Boolean

    external fun nativeUpdateProfileSettingsJson(
        stateDir: String,
        profileId: String,
        name: String,
        intervalSecs: Long,
    ): String

    external fun nativeSetDebugLogging(enable: Boolean): Boolean

    external fun nativeCollectDebugSnapshotJson(
        stateDir: String,
        sinceEpochMs: Long,
        untilEpochMs: Long,
    ): String

    external fun nativeDiagnoseSiteJson(
        stateDir: String,
        target: String,
    ): String

    external fun nativeProbeExitIpJson(
        stateDir: String,
        forceRefresh: Boolean,
    ): String
}
