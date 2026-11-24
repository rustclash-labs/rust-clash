package io.github.rustclashlabs.rustclash.vpn

import android.content.pm.PackageManager

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
    val blockingError: String? = null,
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
 * 4. When `mode == ALLOWLIST` and zero effective packages remain (either empty selection, only
 *    `selfPackageName`, or all listed packages uninstalled on the device), startup MUST fail closed
 *    instead of silently establishing an all-apps VPN tunnel.
 * 5. When `isLockdownEnabled == true` and `mode != ALL_APPS`, any app excluded from the VPN will
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

        val blockingError = if (mode == PerAppMode.ALLOWLIST && cleaned.isEmpty()) {
            "分应用代理白名单为空：请至少勾选 1 个非本应用的目标应用，或切换为「全部应用」模式。"
        } else {
            null
        }

        val warning = when {
            isLockdownEnabled && mode == PerAppMode.ALLOWLIST ->
                "系统已开启始终在线 VPN「阻断无 VPN 连接」(Lockdown)：未勾选的应用将被系统断网，无法直连访问。"
            isLockdownEnabled && mode == PerAppMode.BLOCKLIST && cleaned.isNotEmpty() ->
                "系统已开启始终在线 VPN「阻断无 VPN 连接」(Lockdown)：绕过名单中的应用将被系统直接断网，而非本地直连。"
            blockingError != null ->
                blockingError
            else -> null
        }

        return when (mode) {
            PerAppMode.ALL_APPS -> EffectivePerAppPlan(
                mode = PerAppMode.ALL_APPS,
                allowedPackages = emptyList(),
                disallowedPackages = emptyList(),
                lockdownConflictWarning = warning,
                blockingError = null,
            )
            PerAppMode.ALLOWLIST -> EffectivePerAppPlan(
                mode = PerAppMode.ALLOWLIST,
                allowedPackages = cleaned,
                disallowedPackages = emptyList(),
                lockdownConflictWarning = warning,
                blockingError = blockingError,
            )
            PerAppMode.BLOCKLIST -> EffectivePerAppPlan(
                mode = PerAppMode.BLOCKLIST,
                allowedPackages = emptyList(),
                disallowedPackages = cleaned,
                lockdownConflictWarning = warning,
                blockingError = null,
            )
        }
    }

    /**
     * Validates that an `ALLOWLIST` VPN builder registered at least one installed target package.
     * Throws `IllegalStateException` (never `IllegalArgumentException`, so split-route fallback
     * will not retry and accidentally establish an open all-apps tunnel).
     */
    fun validateAppliedAllowlistCount(mode: PerAppMode, appliedAllowedCount: Int) {
        if (mode == PerAppMode.ALLOWLIST && appliedAllowedCount <= 0) {
            throw IllegalStateException(
                "分应用代理白名单中没有任何已安装的目标应用，已拒绝建立全部应用 VPN 隧道；请重新勾选应用或切换为「全部应用」模式。",
            )
        }
    }

    /**
     * Applies `plan` package rules onto a VPN builder (or unit-test double) with fail-closed
     * enforcement for `ALLOWLIST` mode.
     *
     * Returns the number of successfully applied allowed or disallowed package entries.
     */
    fun applyPackagesFailClosed(
        plan: EffectivePerAppPlan,
        addAllowed: (String) -> Unit,
        addDisallowed: (String) -> Unit,
    ): Int {
        if (plan.blockingError != null) {
            throw IllegalStateException(plan.blockingError)
        }
        return when (plan.mode) {
            PerAppMode.ALL_APPS -> 0
            PerAppMode.ALLOWLIST -> {
                var appliedAllowedCount = 0
                for (pkg in plan.allowedPackages) {
                    try {
                        addAllowed(pkg)
                        appliedAllowedCount++
                    } catch (_: PackageManager.NameNotFoundException) {
                        // Track uninstalled stale package entries; fail closed if 0 remain
                    }
                }
                validateAppliedAllowlistCount(plan.mode, appliedAllowedCount)
                appliedAllowedCount
            }
            PerAppMode.BLOCKLIST -> {
                var appliedDisallowedCount = 0
                for (pkg in plan.disallowedPackages) {
                    try {
                        addDisallowed(pkg)
                        appliedDisallowedCount++
                    } catch (_: PackageManager.NameNotFoundException) {
                        // Ignore uninstalled stale package entries in blocklist
                    }
                }
                appliedDisallowedCount
            }
        }
    }
}
