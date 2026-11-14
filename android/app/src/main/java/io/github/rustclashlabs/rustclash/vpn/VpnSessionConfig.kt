package io.github.rustclashlabs.rustclash.vpn

import java.net.Inet6Address
import java.net.InetAddress

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

data class CidrRoute(
    val address: String,
    val prefixLength: Int,
) {
    val cidr: String
        get() = "$address/$prefixLength"
}

data class VpnRoutePlan(
    val useExcludeRoutes: Boolean,
    val includedIpv4: List<CidrRoute>,
    val excludedIpv4: List<CidrRoute>,
    val includedIpv6: List<CidrRoute>,
    val excludedIpv6: List<CidrRoute>,
) {
    fun matchesTun(ip: String): Boolean = VpnRoutePlanner.matchesTun(ip, this)
}

/**
 * Pure-Kotlin VPN route planner that excludes private LAN, loopback, link-local, multicast,
 * Class E reserved, and limited-broadcast traffic from `tun0` while preserving Fake-IP
 * (`198.18.0.0/15`), TUN DNS (`198.19.255.254/32`), CGNAT (`100.64.0.0/10`), global unicast IPv6
 * (`2000::/3`), and TUN IPv6 (`fdfe:dcba:9876::/126`).
 *
 * Uses positive unicast CIDR `Builder.addRoute(...)` entries across all Android API levels
 * (API 26–37+). Unlike `Builder.excludeRoute(IpPrefix)` on API 33+, positive unicast routes never
 * pass loopback (`127.0.0.0/8`, `::1/128` — rejected by AOSP `VpnService.check()` with
 * `IllegalArgumentException("Bad address")`), unspecified (`0.0.0.0/8`, `::/128`), link-local
 * (`169.254.0.0/16`, `fe80::/10`), or multicast/broadcast (`224.0.0.0/3`, `ff00::/8`) prefixes to
 * `VpnService.Builder` or OEM `netd` `RTN_THROW` rules.
 */
object VpnRoutePlanner {
    const val API_TIRAMISU = 33

    /** Non-unicast IPv4 blocks that can never be added to `VpnService.Builder` under any config. */
    val NON_ROUTABLE_IPV4_PREFIXES: List<CidrRoute> = listOf(
        CidrRoute("0.0.0.0", 8),
        CidrRoute("127.0.0.0", 8),
        CidrRoute("224.0.0.0", 3),
    )

    /** Private LAN + link-local IPv4 blocks bypassed from `tun0` unless overlapped by custom TUN/DNS. */
    val PRIVATE_LAN_IPV4_PREFIXES: List<CidrRoute> = listOf(
        CidrRoute("10.0.0.0", 8),
        CidrRoute("169.254.0.0", 16),
        CidrRoute("172.16.0.0", 12),
        CidrRoute("192.168.0.0", 16),
    )

    val EXCLUDED_IPV4_PREFIXES: List<CidrRoute> = listOf(
        CidrRoute("0.0.0.0", 8),
        CidrRoute("10.0.0.0", 8),
        CidrRoute("127.0.0.0", 8),
        CidrRoute("169.254.0.0", 16),
        CidrRoute("172.16.0.0", 12),
        CidrRoute("192.168.0.0", 16),
        CidrRoute("224.0.0.0", 3),
    )

    val INCLUDED_IPV6_PREFIXES: List<CidrRoute> = listOf(
        CidrRoute("2000::", 3),
    )

    @Suppress("UNUSED_PARAMETER")
    fun buildPlan(
        sessionCfg: VpnSessionConfig,
        sdkInt: Int,
    ): VpnRoutePlan {
        val cfg = sessionCfg.validated()
        val protectedIpv4 = buildList {
            canonicalizeIpv4Cidr(cfg.ipv4Address, cfg.ipv4PrefixLength)?.let { add(it) }
            canonicalizeIpv4Cidr(cfg.dnsIpv4, 32)?.let { add(it) }
        }
        val effectivePrivateExclusions = if (protectedIpv4.isEmpty()) {
            PRIVATE_LAN_IPV4_PREFIXES
        } else {
            subtractIpv4Cidrs(PRIVATE_LAN_IPV4_PREFIXES, protectedIpv4)
        }
        val effectiveExcludedIpv4 = NON_ROUTABLE_IPV4_PREFIXES + effectivePrivateExclusions
        val includedIpv4 = computeIpv4IncludedRoutesExcluding(effectiveExcludedIpv4)
            .filter { isValidVpnBuilderRoute(it) }

        val tunIpv6 = if (cfg.enableIpv6) {
            canonicalizeIpv6Cidr(cfg.ipv6Address, cfg.ipv6PrefixLength)
        } else {
            null
        }
        val includedIpv6 = if (cfg.enableIpv6) {
            buildList {
                addAll(INCLUDED_IPV6_PREFIXES)
                if (tunIpv6 != null && none { inc ->
                        inc.prefixLength <= tunIpv6.prefixLength && ipv6CidrsOverlap(inc, tunIpv6)
                    }
                ) {
                    add(tunIpv6)
                }
            }.filter { isValidVpnBuilderRoute(it) }
        } else {
            emptyList()
        }

        return VpnRoutePlan(
            useExcludeRoutes = false,
            includedIpv4 = includedIpv4,
            excludedIpv4 = emptyList(),
            includedIpv6 = includedIpv6,
            excludedIpv6 = emptyList(),
        )
    }

    /**
     * Validates a candidate `CidrRoute` against AOSP `android.net.VpnService.check()` and
     * `IpPrefix` invariants so `Builder.addRoute` can never throw `IllegalArgumentException("Bad address")`.
     */
    fun isValidVpnBuilderRoute(route: CidrRoute): Boolean {
        val addr = runCatching { InetAddress.getByName(route.address.trim()) }.getOrNull() ?: return false
        if (addr.isLoopbackAddress) {
            return false
        }
        return if (addr is Inet6Address) {
            if (route.prefixLength !in 0..128) return false
            if (route.prefixLength > 0 &&
                (addr.isAnyLocalAddress || addr.isLinkLocalAddress || addr.isMulticastAddress)
            ) {
                return false
            }
            val canonical = canonicalizeIpv6Cidr(route.address, route.prefixLength) ?: return false
            val canonicalBytes = parseIpv6Bytes(canonical.address) ?: return false
            addr.address.contentEquals(canonicalBytes)
        } else {
            if (route.prefixLength !in 0..32) return false
            if (route.prefixLength > 0 &&
                (addr.isAnyLocalAddress || addr.isLinkLocalAddress || addr.isMulticastAddress)
            ) {
                return false
            }
            val canonical = canonicalizeIpv4Cidr(route.address, route.prefixLength) ?: return false
            canonical.address == route.address.trim() && canonical.prefixLength == route.prefixLength
        }
    }

    fun computeIpv4IncludedRoutesExcluding(excluded: List<CidrRoute>): List<CidrRoute> =
        subtractIpv4Cidrs(listOf(CidrRoute("0.0.0.0", 0)), excluded)

    fun subtractIpv4Cidrs(
        base: List<CidrRoute>,
        excluded: List<CidrRoute>,
    ): List<CidrRoute> {
        val excludedRanges = mergeIpv4Ranges(
            excluded.mapNotNull { cidrToIpv4Range(it) },
        )
        val out = ArrayList<CidrRoute>(32)
        for (route in base) {
            val addr = parseIpv4ToUInt(route.address) ?: continue
            val prefixLen = route.prefixLength.coerceIn(0, 32)
            val netStart = ipv4NetworkStart(addr, prefixLen)
            subtractIpv4Trie(
                nodeAddr = netStart,
                prefixLen = prefixLen,
                excludedRanges = excludedRanges,
                out = out,
            )
        }
        return out
    }

    fun matchesTun(ip: String, plan: VpnRoutePlan): Boolean {
        val trimmed = ip.trim()
        val v4 = parseIpv4ToUInt(trimmed)
        if (v4 != null) {
            val bestIncluded = plan.includedIpv4
                .filter { ipv4MatchesCidr(v4, it) }
                .maxOfOrNull { it.prefixLength }
                ?: return false
            val bestExcluded = plan.excludedIpv4
                .filter { ipv4MatchesCidr(v4, it) }
                .maxOfOrNull { it.prefixLength }
                ?: return true
            return bestIncluded > bestExcluded
        }

        val v6Bytes = parseIpv6Bytes(trimmed) ?: return false
        val bestIncluded = plan.includedIpv6
            .filter { ipv6MatchesCidr(v6Bytes, it) }
            .maxOfOrNull { it.prefixLength }
            ?: return false
        val bestExcluded = plan.excludedIpv6
            .filter { ipv6MatchesCidr(v6Bytes, it) }
            .maxOfOrNull { it.prefixLength }
            ?: return true
        return bestIncluded > bestExcluded
    }

    private fun subtractIpv4Trie(
        nodeAddr: UInt,
        prefixLen: Int,
        excludedRanges: List<UIntRange>,
        out: MutableList<CidrRoute>,
    ) {
        val nodeStart = nodeAddr
        val nodeEnd = if (prefixLen == 0) {
            0xFFFF_FFFFu
        } else {
            nodeAddr or ((1u shl (32 - prefixLen)) - 1u)
        }
        if (excludedRanges.any { it.first <= nodeStart && nodeEnd <= it.last }) {
            return
        }
        if (excludedRanges.none { it.first <= nodeEnd && nodeStart <= it.last }) {
            out.add(CidrRoute(uintToIpv4(nodeStart), prefixLen))
            return
        }
        if (prefixLen < 32) {
            val nextPrefix = prefixLen + 1
            val rightBit = 1u shl (31 - prefixLen)
            subtractIpv4Trie(nodeStart, nextPrefix, excludedRanges, out)
            subtractIpv4Trie(nodeStart or rightBit, nextPrefix, excludedRanges, out)
        }
    }

    private fun mergeIpv4Ranges(ranges: List<UIntRange>): List<UIntRange> {
        if (ranges.size <= 1) return ranges
        val sorted = ranges.sortedBy { it.first }
        val merged = ArrayList<UIntRange>(sorted.size)
        var curStart = sorted[0].first
        var curEnd = sorted[0].last
        for (i in 1 until sorted.size) {
            val next = sorted[i]
            if (next.first <= curEnd || (curEnd < 0xFFFF_FFFFu && next.first == curEnd + 1u)) {
                if (next.last > curEnd) {
                    curEnd = next.last
                }
            } else {
                merged.add(curStart..curEnd)
                curStart = next.first
                curEnd = next.last
            }
        }
        merged.add(curStart..curEnd)
        return merged
    }

    internal fun canonicalizeIpv4Cidr(address: String, prefixLength: Int): CidrRoute? {
        val addr = parseIpv4ToUInt(address) ?: return null
        val clamped = prefixLength.coerceIn(0, 32)
        return CidrRoute(uintToIpv4(ipv4NetworkStart(addr, clamped)), clamped)
    }

    internal fun cidrToIpv4Range(route: CidrRoute): UIntRange? {
        val addr = parseIpv4ToUInt(route.address) ?: return null
        val clamped = route.prefixLength.coerceIn(0, 32)
        if (clamped == 0) {
            return 0u..0xFFFF_FFFFu
        }
        val hostMask = (1u shl (32 - clamped)) - 1u
        val start = addr and hostMask.inv()
        val end = start or hostMask
        return start..end
    }

    internal fun ipv4NetworkStart(addr: UInt, prefixLength: Int): UInt {
        val clamped = prefixLength.coerceIn(0, 32)
        if (clamped == 0) return 0u
        val hostMask = (1u shl (32 - clamped)) - 1u
        return addr and hostMask.inv()
    }

    internal fun ipv4MatchesCidr(addr: UInt, route: CidrRoute): Boolean {
        val range = cidrToIpv4Range(route) ?: return false
        return addr in range
    }

    internal fun parseIpv4ToUInt(ip: String): UInt? {
        val trimmed = ip.trim()
        if (trimmed.isEmpty() || ':' in trimmed) return null
        val parts = trimmed.split('.')
        if (parts.size != 4) return null
        var acc = 0u
        for (part in parts) {
            if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) {
                return null
            }
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            acc = (acc shl 8) or octet.toUInt()
        }
        return acc
    }

    internal fun uintToIpv4(value: UInt): String {
        val b0 = (value shr 24) and 0xFFu
        val b1 = (value shr 16) and 0xFFu
        val b2 = (value shr 8) and 0xFFu
        val b3 = value and 0xFFu
        return "$b0.$b1.$b2.$b3"
    }

    internal fun canonicalizeIpv6Cidr(address: String, prefixLength: Int): CidrRoute? {
        val raw = parseIpv6Bytes(address)?.copyOf() ?: return null
        val clamped = prefixLength.coerceIn(0, 128)
        val fullBytes = clamped / 8
        val remBits = clamped % 8
        if (fullBytes < raw.size) {
            if (remBits > 0) {
                val mask = (0xFF shl (8 - remBits)) and 0xFF
                raw[fullBytes] = (raw[fullBytes].toInt() and mask).toByte()
                for (i in (fullBytes + 1) until raw.size) {
                    raw[i] = 0
                }
            } else {
                for (i in fullBytes until raw.size) {
                    raw[i] = 0
                }
            }
        }
        val masked = runCatching { InetAddress.getByAddress(null, raw) }.getOrNull() ?: return null
        return CidrRoute(masked.hostAddress ?: address.trim(), clamped)
    }

    internal fun parseIpv6Bytes(ip: String): ByteArray? {
        val clean = ip.trim().removeSurrounding("[", "]")
        if (!clean.contains(':')) return null
        val parsed = runCatching { InetAddress.getByName(clean) }.getOrNull() as? Inet6Address ?: return null
        val bytes = parsed.address
        return if (bytes.size == 16) bytes else null
    }

    internal fun ipv6MatchesCidr(addrBytes: ByteArray, route: CidrRoute): Boolean {
        val routeBytes = parseIpv6Bytes(route.address) ?: return false
        return ipv6PrefixEquals(addrBytes, routeBytes, route.prefixLength.coerceIn(0, 128))
    }

    internal fun ipv6CidrsOverlap(a: CidrRoute, b: CidrRoute): Boolean {
        val aBytes = parseIpv6Bytes(a.address) ?: return false
        val bBytes = parseIpv6Bytes(b.address) ?: return false
        val commonBits = minOf(a.prefixLength.coerceIn(0, 128), b.prefixLength.coerceIn(0, 128))
        return ipv6PrefixEquals(aBytes, bBytes, commonBits)
    }

    private fun ipv6PrefixEquals(a: ByteArray, b: ByteArray, prefixBits: Int): Boolean {
        if (a.size != 16 || b.size != 16) return false
        val fullBytes = prefixBits / 8
        for (i in 0 until fullBytes) {
            if (a[i] != b[i]) return false
        }
        val remBits = prefixBits % 8
        if (remBits > 0) {
            val mask = (0xFF shl (8 - remBits)) and 0xFF
            if ((a[fullBytes].toInt() and mask) != (b[fullBytes].toInt() and mask)) {
                return false
            }
        }
        return true
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
