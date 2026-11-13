package io.github.rustclashlabs.rustclash.vpn

enum class VpnLifecycleState {
    DISCONNECTED,
    PREPARING,
    STARTING,
    RUNNING,
    RECONNECTING,
    STOPPING,
    REVOKED,
    ERROR,
}

data class VpnSessionConfig(
    val sessionName: String = "RustClash",
    val mtu: Int = 1400,
    val ipv4Address: String = "198.18.0.1",
    val ipv4PrefixLength: Int = 15,
    val dnsIpv4: String = "198.19.255.254",
    val enableIpv6: Boolean = true,
    val ipv6Address: String = "fdfe:dcba:9876::1",
    val ipv6PrefixLength: Int = 126,
    val perAppMode: PerAppMode = PerAppMode.ALL_APPS,
    val selectedPackages: Set<String> = emptySet(),
    val demoMode: Boolean = false,
) {
    fun validated(): VpnSessionConfig {
        val safeMtu = mtu.coerceIn(1280, 9000)
        val safeV4Prefix = ipv4PrefixLength.coerceIn(8, 30)
        val safeV6Prefix = ipv6PrefixLength.coerceIn(64, 126)
        return copy(
            mtu = safeMtu,
            ipv4PrefixLength = safeV4Prefix,
            ipv6PrefixLength = safeV6Prefix,
        )
    }
}

data class NetworkTransitionDecision(
    val updateUnderlyingNetworks: Boolean,
    val triggerSessionRecovery: Boolean,
    val notifyNative: Boolean,
    val effectiveHandle: Long,
    val isWifi: Boolean,
) {
    companion object {
        val IGNORE = NetworkTransitionDecision(
            updateUnderlyingNetworks = false,
            triggerSessionRecovery = false,
            notifyNative = false,
            effectiveHandle = 0L,
            isWifi = false,
        )
    }
}

/**
 * Deduplicates noisy Android `ConnectivityManager.NetworkCallback.onCapabilitiesChanged` RSSI/bandwidth
 * callbacks while deterministically detecting real physical transitions (Wi-Fi <-> Cellular, Wi-Fi AP
 * roaming, Ethernet changes, and network loss -> reconnect).
 */
class UnderlyingNetworkTracker {
    companion object {
        const val MASK_WIFI = 1 shl 0
        const val MASK_CELLULAR = 1 shl 1
        const val MASK_ETHERNET = 1 shl 2
    }

    private var initialized = false
    private var activeHandle: Long = 0L
    private var activeTransportMask: Int = 0

    @Synchronized
    fun reset() {
        initialized = false
        activeHandle = 0L
        activeTransportMask = 0
    }

    @Synchronized
    fun onUnderlyingCandidate(
        networkHandle: Long,
        isVpnTransport: Boolean,
        isWifi: Boolean,
        isCellular: Boolean,
        isEthernet: Boolean = false,
    ): NetworkTransitionDecision {
        if (isVpnTransport || networkHandle == 0L) {
            return NetworkTransitionDecision.IGNORE
        }
        var mask = 0
        if (isWifi) mask = mask or MASK_WIFI
        if (isCellular) mask = mask or MASK_CELLULAR
        if (isEthernet) mask = mask or MASK_ETHERNET

        if (!initialized) {
            initialized = true
            activeHandle = networkHandle
            activeTransportMask = mask
            // Initial network registration on VPN startup: bind underlying network & baseline in Rust
            // without gratuitously tearing down brand-new sockets.
            return NetworkTransitionDecision(
                updateUnderlyingNetworks = true,
                triggerSessionRecovery = false,
                notifyNative = true,
                effectiveHandle = networkHandle,
                isWifi = isWifi,
            )
        }

        if (networkHandle == activeHandle && mask == activeTransportMask) {
            // Spurious RSSI / link-bandwidth update on the exact same physical network: ignore!
            return NetworkTransitionDecision.IGNORE
        }

        activeHandle = networkHandle
        activeTransportMask = mask
        return NetworkTransitionDecision(
            updateUnderlyingNetworks = true,
            triggerSessionRecovery = true,
            notifyNative = true,
            effectiveHandle = networkHandle,
            isWifi = isWifi,
        )
    }

    @Synchronized
    fun onUnderlyingLost(networkHandle: Long): NetworkTransitionDecision {
        if (!initialized || activeHandle != networkHandle) {
            // Stale network lost AFTER Android already handed off to the replacement default network!
            return NetworkTransitionDecision.IGNORE
        }
        activeHandle = 0L
        activeTransportMask = 0
        return NetworkTransitionDecision(
            updateUnderlyingNetworks = true,
            triggerSessionRecovery = true,
            notifyNative = true,
            effectiveHandle = 0L,
            isWifi = false,
        )
    }
}

/**
 * Deterministic state machine tracking `RustClashVpnService` transitions for UI & JUnit tests.
 */
class VpnStateTracker(initial: VpnLifecycleState = VpnLifecycleState.DISCONNECTED) {
    @Volatile
    var state: VpnLifecycleState = initial
        private set

    @Volatile
    var lastError: String? = null
        private set

    @Synchronized
    fun onPrepareRequested() {
        state = VpnLifecycleState.PREPARING
        lastError = null
    }

    @Synchronized
    fun onStartRequested() {
        state = VpnLifecycleState.STARTING
        lastError = null
    }

    @Synchronized
    fun onRunning() {
        state = VpnLifecycleState.RUNNING
        lastError = null
    }

    @Synchronized
    fun onUnderlyingLost() {
        if (state == VpnLifecycleState.RUNNING) {
            state = VpnLifecycleState.RECONNECTING
        }
    }

    @Synchronized
    fun onNetworkHandoff() {
        if (state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECONNECTING) {
            state = VpnLifecycleState.RUNNING
        }
    }

    @Synchronized
    fun onStopRequested() {
        if (state != VpnLifecycleState.DISCONNECTED && state != VpnLifecycleState.REVOKED) {
            state = VpnLifecycleState.STOPPING
        }
    }

    @Synchronized
    fun onStopped() {
        if (state != VpnLifecycleState.REVOKED) {
            state = VpnLifecycleState.DISCONNECTED
        }
    }

    @Synchronized
    fun onSystemRevoked() {
        state = VpnLifecycleState.REVOKED
        lastError = "VPN 连接权限已被系统或其他 VPN 应用接管撤销"
    }

    @Synchronized
    fun onError(message: String) {
        state = VpnLifecycleState.ERROR
        lastError = message
    }

    @Synchronized
    fun clearError() {
        lastError = null
        if (state == VpnLifecycleState.ERROR || state == VpnLifecycleState.REVOKED) {
            state = VpnLifecycleState.DISCONNECTED
        }
    }
}
