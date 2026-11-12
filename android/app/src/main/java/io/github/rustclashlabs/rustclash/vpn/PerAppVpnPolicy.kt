package io.github.rustclashlabs.rustclash.vpn

enum class PerAppMode {
    ALL_APPS,
    ALLOWLIST,
    BLOCKLIST;

    companion object {
        fun fromWire(raw: String?): PerAppMode =
            when (raw?.trim()?.uppercase()) {
                "ALLOWLIST" -> ALLOWLIST
                "BLOCKLIST" -> BLOCKLIST
                else -> ALL_APPS
            }
    }
}

data class EffectivePerAppPlan(
    val mode: PerAppMode,
    val allowedPackages: List<String>,
    val disallowedPackages: List<String>,
    val lockdownConflictWarning: String?,
)

/**
 * Pure, deterministic Per-App VPN & Android Always-On Lockdown policy planner.
 *
 * Key Android `VpnService.Builder` & `netd` invariants enforced:
 * 1. `addAllowedApplication` and `addDisallowedApplication` are mutually exclusive on a single
 *    `VpnService.Builder` instance (calling both throws `IllegalArgumentException`).
 * 2. Outbound proxy & DNS sockets from `selfPackageName` (`io.github.rustclashlabs.rustclash`) are
 *    protected individually via `VpnService.protect(fd)` over JNI. Crucially, we NEVER add
 *    `selfPackageName` to `addDisallowedApplication` when `isLockdownEnabled == true`, because
 *    Android's `netd` drops ALL packets from disallowed UIDs under Always-On Lockdown ("Block
 *    connections without VPN"), whereas `VpnService.protect(fd)` marks sockets with the explicit
 *    VPN bypass fwmark permitted even during Lockdown!
 * 3. In `ALLOWLIST` mode, `selfPackageName` is automatically stripped from `allowedPackages` as
 *    defense-in-depth so app UI/WebView requests never recursively loop into `tun0`.
 * 4. When `isLockdownEnabled == true` and `mode != ALL_APPS`, any app excluded from the VPN will
 *    be blocked from accessing the internet by Android OS; we surface a clear warning banner.
 */
object PerAppVpnPolicy {
    fun buildPlan(
        mode: PerAppMode,
        selectedPackages: Set<String>,
        selfPackageName: String,
        isLockdownEnabled: Boolean,
    ): EffectivePerAppPlan {
        val cleaned = selectedPackages
            .map { it.trim() }
            .filter { it.isNotEmpty() && it != selfPackageName }
            .sorted()

        val warning = when {
            isLockdownEnabled && mode == PerAppMode.ALLOWLIST ->
                "Android Always-On 'Block connections without VPN' (Lockdown) is enabled: apps NOT in your Allowlist will have all internet access blocked by Android."
            isLockdownEnabled && mode == PerAppMode.BLOCKLIST && cleaned.isNotEmpty() ->
                "Android Always-On 'Block connections without VPN' (Lockdown) is enabled: apps in your Bypass Blocklist will have all internet access blocked by Android instead of bypassing."
            mode == PerAppMode.ALLOWLIST && cleaned.isEmpty() ->
                "Per-App Allowlist is empty: select at least one app or switch to All Apps mode so traffic is routed through RustClash."
            else -> null
        }

        return when (mode) {
            PerAppMode.ALL_APPS -> EffectivePerAppPlan(
                mode = PerAppMode.ALL_APPS,
                allowedPackages = emptyList(),
                disallowedPackages = emptyList(),
                lockdownConflictWarning = warning,
            )
            PerAppMode.ALLOWLIST -> EffectivePerAppPlan(
                mode = PerAppMode.ALLOWLIST,
                allowedPackages = cleaned,
                disallowedPackages = emptyList(),
                lockdownConflictWarning = warning,
            )
            PerAppMode.BLOCKLIST -> EffectivePerAppPlan(
                mode = PerAppMode.BLOCKLIST,
                allowedPackages = emptyList(),
                disallowedPackages = cleaned,
                lockdownConflictWarning = warning,
            )
        }
    }
}
