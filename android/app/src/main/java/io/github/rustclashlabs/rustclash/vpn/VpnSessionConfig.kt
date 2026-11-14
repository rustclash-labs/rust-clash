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
    val hasIpv6: Boolean = true,
    val syncInitialBaselineToNative: Boolean = false,
) {
    companion object {
        val IGNORE = NetworkTransitionDecision(
            updateUnderlyingNetworks = false,
            triggerSessionRecovery = false,
            notifyNative = false,
            effectiveHandle = 0L,
            isWifi = false,
            hasIpv6 = false,
            syncInitialBaselineToNative = false,
        )
    }
}

/**
 * Deduplicates noisy Android `ConnectivityManager.NetworkCallback.onCapabilitiesChanged` RSSI/bandwidth
 * callbacks while deterministically ranking physical `NOT_VPN` networks (Ethernet > Wi-Fi > Cellular,
 * validated > unvalidated) and tracking per-link global IPv6 availability across API 26–35+.
 */
class UnderlyingNetworkTracker(
    @Volatile private var singleBestMatchingMode: Boolean = false,
) {
    companion object {
        const val MASK_WIFI = 1 shl 0
        const val MASK_CELLULAR = 1 shl 1
        const val MASK_ETHERNET = 1 shl 2
    }

    private data class CandidateEntry(
        val handle: Long,
        val isWifi: Boolean,
        val isCellular: Boolean,
        val isEthernet: Boolean,
        val isValidated: Boolean,
        val hasIpv6: Boolean,
    ) {
        val transportMask: Int
            get() {
                var mask = 0
                if (isWifi) mask = mask or MASK_WIFI
                if (isCellular) mask = mask or MASK_CELLULAR
                if (isEthernet) mask = mask or MASK_ETHERNET
                return mask
            }

        val transportPriority: Int
            get() = when {
                isEthernet -> 3
                isWifi -> 2
                isCellular -> 1
                else -> 0
            }
    }

    private val candidates = LinkedHashMap<Long, CandidateEntry>()
    private val pendingIpv6ByHandle = HashMap<Long, Boolean>()
    private var hasBaseline = false
    private var activeHandle: Long = 0L
    private var activeTransportMask: Int = 0
    private var activeIsWifi: Boolean = false
    private var activeHasIpv6: Boolean = true

    @Synchronized
    fun setSingleBestMatchingMode(enabled: Boolean) {
        singleBestMatchingMode = enabled
    }

    @Synchronized
    fun reset() {
        candidates.clear()
        pendingIpv6ByHandle.clear()
        hasBaseline = false
        activeHandle = 0L
        activeTransportMask = 0
        activeIsWifi = false
        activeHasIpv6 = true
    }

    @Synchronized
    fun knownHasIpv6(networkHandle: Long): Boolean? =
        candidates[networkHandle]?.hasIpv6 ?: pendingIpv6ByHandle[networkHandle]

    @Synchronized
    fun onUnderlyingCandidate(
        networkHandle: Long,
        isVpnTransport: Boolean,
        isWifi: Boolean,
        isCellular: Boolean,
        isEthernet: Boolean = false,
    ): NetworkTransitionDecision {
        if (isVpnTransport || networkHandle == 0L) {
            return currentNoOpDecision()
        }
        val inheritedIpv6 = candidates[networkHandle]?.hasIpv6 ?: pendingIpv6ByHandle[networkHandle] ?: true
        // Legacy 5-parameter callers observe a single OS-selected default/best network stream where
        // a new handle supersedes the prior handle before late `onLost(oldHandle)` arrives.
        candidates.keys.retainAll(setOf(networkHandle))
        return onUnderlyingCandidate(
            networkHandle = networkHandle,
            isVpnTransport = false,
            isWifi = isWifi,
            isCellular = isCellular,
            isEthernet = isEthernet,
            isValidated = true,
            hasIpv6 = inheritedIpv6,
        )
    }

    @Synchronized
    fun onUnderlyingCandidate(
        networkHandle: Long,
        isVpnTransport: Boolean,
        isWifi: Boolean,
        isCellular: Boolean,
        isEthernet: Boolean = false,
        isValidated: Boolean,
        hasIpv6: Boolean,
    ): NetworkTransitionDecision {
        if (isVpnTransport || networkHandle == 0L) {
            return currentNoOpDecision()
        }
        if (singleBestMatchingMode) {
            candidates.keys.retainAll(setOf(networkHandle))
        }
        pendingIpv6ByHandle[networkHandle] = hasIpv6
        candidates[networkHandle] = CandidateEntry(
            handle = networkHandle,
            isWifi = isWifi,
            isCellular = isCellular,
            isEthernet = isEthernet,
            isValidated = isValidated,
            hasIpv6 = hasIpv6,
        )
        return evaluateBestCandidate()
    }

    @Synchronized
    fun onLinkPropertiesIpv6Changed(
        networkHandle: Long,
        hasIpv6: Boolean,
    ): NetworkTransitionDecision {
        if (networkHandle == 0L) {
            return currentNoOpDecision()
        }
        pendingIpv6ByHandle[networkHandle] = hasIpv6
        val existing = candidates[networkHandle] ?: return currentNoOpDecision()
        if (existing.hasIpv6 == hasIpv6) {
            return currentNoOpDecision()
        }
        candidates[networkHandle] = existing.copy(hasIpv6 = hasIpv6)
        return evaluateBestCandidate()
    }

    @Synchronized
    fun onNetworkLost(networkHandle: Long): NetworkTransitionDecision =
        onUnderlyingLost(networkHandle)

    @Synchronized
    fun onUnderlyingLost(networkHandle: Long): NetworkTransitionDecision {
        candidates.remove(networkHandle)
        pendingIpv6ByHandle.remove(networkHandle)
        if (!hasBaseline) {
            return currentNoOpDecision()
        }

        val best = selectBestCandidate()
        if (best != null) {
            if (best.handle == activeHandle) {
                // Lost a lower-priority or already-superseded network while active handle stays best.
                return currentNoOpDecision()
            }
            activeHandle = best.handle
            activeTransportMask = best.transportMask
            activeIsWifi = best.isWifi
            activeHasIpv6 = best.hasIpv6
            return NetworkTransitionDecision(
                updateUnderlyingNetworks = true,
                triggerSessionRecovery = true,
                notifyNative = true,
                effectiveHandle = best.handle,
                isWifi = best.isWifi,
                hasIpv6 = best.hasIpv6,
                syncInitialBaselineToNative = false,
            )
        }

        if (activeHandle != networkHandle) {
            return currentNoOpDecision()
        }
        activeHandle = 0L
        activeTransportMask = 0
        activeIsWifi = false
        activeHasIpv6 = false
        return NetworkTransitionDecision(
            updateUnderlyingNetworks = true,
            triggerSessionRecovery = true,
            notifyNative = true,
            effectiveHandle = 0L,
            isWifi = false,
            hasIpv6 = false,
            syncInitialBaselineToNative = false,
        )
    }

    private fun evaluateBestCandidate(): NetworkTransitionDecision {
        val best = selectBestCandidate() ?: return currentNoOpDecision()
        val bestWifi = best.isWifi
        val bestMask = best.transportMask

        if (!hasBaseline) {
            hasBaseline = true
            activeHandle = best.handle
            activeTransportMask = bestMask
            activeIsWifi = bestWifi
            activeHasIpv6 = best.hasIpv6
            // Initial network registration on VPN startup: bind underlying network & baseline in Rust
            // without gratuitously tearing down brand-new sockets.
            return NetworkTransitionDecision(
                updateUnderlyingNetworks = true,
                triggerSessionRecovery = false,
                notifyNative = true,
                effectiveHandle = best.handle,
                isWifi = bestWifi,
                hasIpv6 = best.hasIpv6,
                syncInitialBaselineToNative = true,
            )
        }

        if (best.handle != activeHandle || bestWifi != activeIsWifi || bestMask != activeTransportMask) {
            val handleChanged = best.handle != activeHandle
            activeHandle = best.handle
            activeTransportMask = bestMask
            activeIsWifi = bestWifi
            activeHasIpv6 = best.hasIpv6
            return NetworkTransitionDecision(
                updateUnderlyingNetworks = handleChanged,
                triggerSessionRecovery = true,
                notifyNative = true,
                effectiveHandle = best.handle,
                isWifi = bestWifi,
                hasIpv6 = best.hasIpv6,
                syncInitialBaselineToNative = false,
            )
        }

        if (best.hasIpv6 != activeHasIpv6) {
            val lostIpv6 = activeHasIpv6 && !best.hasIpv6
            activeHasIpv6 = best.hasIpv6
            return NetworkTransitionDecision(
                updateUnderlyingNetworks = false,
                triggerSessionRecovery = lostIpv6,
                notifyNative = true,
                effectiveHandle = best.handle,
                isWifi = bestWifi,
                hasIpv6 = best.hasIpv6,
                syncInitialBaselineToNative = false,
            )
        }

        return currentNoOpDecision()
    }

    private fun selectBestCandidate(): CandidateEntry? {
        var best: CandidateEntry? = null
        for (entry in candidates.values) {
            val current = best
            if (current == null || isHigherPriority(entry, current)) {
                best = entry
            }
        }
        return best
    }

    private fun isHigherPriority(challenger: CandidateEntry, incumbent: CandidateEntry): Boolean {
        if (challenger.isValidated != incumbent.isValidated) {
            return challenger.isValidated
        }
        if (challenger.transportPriority != incumbent.transportPriority) {
            return challenger.transportPriority > incumbent.transportPriority
        }
        if (incumbent.handle == activeHandle) {
            return false
        }
        if (challenger.handle == activeHandle) {
            return true
        }
        return false
    }

    private fun currentNoOpDecision(): NetworkTransitionDecision = NetworkTransitionDecision(
        updateUnderlyingNetworks = false,
        triggerSessionRecovery = false,
        notifyNative = false,
        effectiveHandle = activeHandle,
        isWifi = activeIsWifi,
        hasIpv6 = if (activeHandle == 0L) false else activeHasIpv6,
        syncInitialBaselineToNative = false,
    )
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
