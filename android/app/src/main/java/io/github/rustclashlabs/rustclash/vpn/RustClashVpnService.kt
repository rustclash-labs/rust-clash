package io.github.rustclashlabs.rustclash.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.rustclashlabs.rustclash.MainActivity
import io.github.rustclashlabs.rustclash.R
import io.github.rustclashlabs.rustclash.security.AndroidKeystoreVault
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

internal fun isGlobalUnicastIpv6Address(addr: InetAddress?): Boolean {
    val v6 = addr as? Inet6Address ?: return false
    if (v6.isAnyLocalAddress ||
        v6.isLoopbackAddress ||
        v6.isLinkLocalAddress ||
        v6.isMulticastAddress ||
        v6.isSiteLocalAddress
    ) {
        return false
    }
    val raw = v6.address
    return raw.size == 16 && (raw[0].toInt() and 0xE0) == 0x20
}

internal fun hasGlobalUnicastIpv6Link(linkProperties: LinkProperties?): Boolean {
    if (linkProperties == null) return false
    val hasGlobalAddr = linkProperties.linkAddresses.any { la ->
        isGlobalUnicastIpv6Address(la.address)
    }
    if (!hasGlobalAddr) return false
    val hasIpv6DefaultRoute = linkProperties.routes.any { route ->
        route.destination.address is Inet6Address && route.destination.prefixLength == 0
    }
    return hasIpv6DefaultRoute
}

class RustClashVpnService : VpnService() {
    private val sessionMutex = Mutex()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var telemetryJob: Job? = null
    private var debugSliceJob: Job? = null
    private var connectivityCallback: ConnectivityManager.NetworkCallback? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private val underlyingNetworkTracker = UnderlyingNetworkTracker()
    private val livePhysicalNetworks = ConcurrentHashMap<Long, Network>()

    @Volatile
    private var isScreenInteractive: Boolean = true

    @Volatile
    private var engineRunningNative: Boolean = false

    @Volatile
    private var serviceDestroyedOrRevoked: Boolean = false

    private val openPendingIntent: PendingIntent by lazy {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val stopPendingIntent: PendingIntent by lazy {
        val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
            action = ACTION_STOP_VPN
        }
        PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    companion object {
        const val ACTION_START_VPN = "io.github.rustclashlabs.rustclash.action.START_VPN"
        const val ACTION_STOP_VPN = "io.github.rustclashlabs.rustclash.action.STOP_VPN"
        const val EXTRA_DEMO_MODE = "extra_demo_mode"

        const val PREFS_VPN_SETTINGS = "rust_clash_vpn_settings"
        const val KEY_PER_APP_MODE = "per_app_mode"
        const val KEY_SELECTED_PACKAGES = "selected_packages"
        const val KEY_DEMO_MODE = "demo_mode"
        const val KEY_ENABLE_IPV6 = "enable_ipv6"
        const val KEY_THEME_MODE = "theme_mode"
        const val KEY_FAVORITE_NODES = "favorite_nodes"
        const val KEY_PROFILE_ALIASES = "profile_aliases_json"
        const val KEY_DEFAULT_SUB_AUTO_UPDATE_SECS = "default_sub_auto_update_secs"
        const val VAULT_KEY_ACTIVE_YAML = "active_profile_yaml"
        const val VAULT_KEY_SUBSCRIPTION_URL = "active_subscription_url"

        private const val NOTIFICATION_CHANNEL_ID = "rust_clash_vpn_channel"
        private const val NOTIFICATION_ID = 19818

        val stateTracker = VpnStateTracker()

        @Volatile
        var lockdownWarning: String? = null
            private set

        @Volatile
        var latestStatusJson: String = "{\"running\":false}"
            private set

        @Volatile
        var activeOutboundLabel: String = ""
            private set

        fun formatBytesPerSec(bytes: Long): String =
            when {
                bytes >= 1_048_576L -> String.format("%.1f MB/s", bytes / 1_048_576.0)
                bytes >= 1_024L -> String.format("%.1f KB/s", bytes / 1_024.0)
                else -> "$bytes B/s"
            }

        fun updateLockdownWarning(warning: String?) {
            lockdownWarning = warning
        }
    }

    /**
     * Invoked directly from Rust (`CallbackSocketProtector` in `crates/proxy-ffi/src/android_jni.rs`)
     * on **every** outbound TCP, UDP, and bootstrap DNS socket BEFORE `connect()`.
     */
    @Suppress("unused")
    fun protectSocket(fd: Int): Boolean = runCatching { protect(fd) }.getOrDefault(false)

    override fun onCreate() {
        super.onCreate()
        DebugLogManager.installCrashBreadcrumbHook(applicationContext)
        ensureNotificationChannel()
        val pm = getSystemService(PowerManager::class.java)
        isScreenInteractive = pm?.isInteractive ?: true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                serviceDestroyedOrRevoked = true
                stateTracker.onStopRequested()
                RustClashTileService.requestTileSync(this)
                serviceScope.launch {
                    sessionMutex.withLock {
                        stopVpnSessionInternal(revokedBySystem = false)
                    }
                }
                return START_NOT_STICKY
            }
            ACTION_START_VPN, SERVICE_INTERFACE, null -> {
                serviceDestroyedOrRevoked = false
                val prefs = getSharedPreferences(PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
                val demoMode = intent?.getBooleanExtra(
                    EXTRA_DEMO_MODE,
                    prefs.getBoolean(KEY_DEMO_MODE, false),
                ) ?: prefs.getBoolean(KEY_DEMO_MODE, false)

                // Promote foreground immediately on the main thread within Android's 5s FGS budget,
                // then execute TUN establishment & Rust engine initialization on Dispatchers.IO.
                stateTracker.onStartRequested()
                promoteForeground("RustClash 正在连接…", "正在初始化 TUN 隧道与出站套接字保护")
                RustClashTileService.requestTileSync(this)

                serviceScope.launch {
                    sessionMutex.withLock {
                        startVpnSessionInternal(demoMode)
                    }
                }
                return START_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    private data class InitialPhysicalNetworkSnapshot(
        val network: Network,
        val caps: NetworkCapabilities,
        val linkProperties: LinkProperties?,
    )

    private fun captureInitialPhysicalNetworkSnapshot(
        cm: ConnectivityManager?,
    ): InitialPhysicalNetworkSnapshot? {
        if (cm == null) return null
        val active = runCatching { cm.activeNetwork }.getOrNull() ?: return null
        val caps = runCatching { cm.getNetworkCapabilities(active) }.getOrNull() ?: return null
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return null
        }
        val lp = runCatching { cm.getLinkProperties(active) }.getOrNull()
        return InitialPhysicalNetworkSnapshot(
            network = active,
            caps = caps,
            linkProperties = lp,
        )
    }

    private fun startVpnSessionInternal(demoMode: Boolean) {
        // Clean up any prior ticker/network/screen observer on duplicate start before re-establishing
        telemetryJob?.cancel()
        telemetryJob = null
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        underlyingNetworkTracker.setSingleBestMatchingMode(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        livePhysicalNetworks.clear()

        if (!serviceScope.isActive || serviceDestroyedOrRevoked) {
            return
        }

        if (!NativeBridge.ensureLoaded()) {
            stateTracker.onError("当前设备架构未能加载 Rust 核心库 (libproxy_ffi.so)")
            RustClashTileService.requestTileSync(this)
            stopForegroundCompat()
            stopSelf()
            return
        }

        DebugLogManager.syncNativeDebugFlag(this)

        val prefs = getSharedPreferences(PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val perAppMode = PerAppMode.fromWire(prefs.getString(KEY_PER_APP_MODE, null))
        val selectedPkgs = prefs.getStringSet(KEY_SELECTED_PACKAGES, emptySet())?.toSet() ?: emptySet()
        val enableIpv6 = prefs.getBoolean(KEY_ENABLE_IPV6, true)
        val storedYaml = AndroidKeystoreVault.getDecryptedString(this, VAULT_KEY_ACTIVE_YAML) ?: ""

        val sessionCfg = VpnSessionConfig(
            enableIpv6 = enableIpv6,
            perAppMode = perAppMode,
            selectedPackages = selectedPkgs,
            demoMode = demoMode,
        ).validated()

        val lockdownActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            isLockdownEnabled
        } else {
            false
        }

        val perAppPlan = PerAppVpnPolicy.buildPlan(
            mode = sessionCfg.perAppMode,
            selectedPackages = sessionCfg.selectedPackages,
            selfPackageName = packageName,
            isLockdownEnabled = lockdownActive,
        )
        lockdownWarning = perAppPlan.lockdownConflictWarning

        // RAII guard on the Java side up to the exact point `detachFd()` transfers ownership into
        // `NativeBridge.nativeStartVpnWithStateDir` (which wraps `tun_fd` in Rust `OwnedFd` on line 1).
        var pendingPfd: ParcelFileDescriptor? = null
        try {
            if (!serviceScope.isActive || serviceDestroyedOrRevoked) {
                return
            }

            // Capture physical NOT_VPN network BEFORE `builder.establish()` switches `cm.activeNetwork` to `tun0`.
            val cm = getSystemService(ConnectivityManager::class.java)
            val initialPhysicalSnapshot = captureInitialPhysicalNetworkSnapshot(cm)

            val underlyingNetwork = initialPhysicalSnapshot?.network
            val established = try {
                createConfiguredVpnBuilder(
                    sessionCfg = sessionCfg,
                    underlyingNetwork = underlyingNetwork,
                    perAppPlan = perAppPlan,
                    useSplitRoutes = true,
                ).establish()
            } catch (_: IllegalArgumentException) {
                createConfiguredVpnBuilder(
                    sessionCfg = sessionCfg,
                    underlyingNetwork = underlyingNetwork,
                    perAppPlan = perAppPlan,
                    useSplitRoutes = false,
                ).establish()
            } ?: throw IllegalStateException("无法建立系统 VPN 隧道：连接授权缺失或被其他 VPN 应用抢占")
            pendingPfd = established

            // Atomically transfer exclusive FD ownership to Rust (`OwnedFd::from_raw_fd(tun_fd)`).
            val detachedFd = established.detachFd()
            pendingPfd = null

            val startJsonStr = NativeBridge.nativeStartVpnWithStateDir(
                vpnService = this,
                tunFd = detachedFd,
                stateDir = filesDir.absolutePath,
                yamlConfig = storedYaml,
                demoMode = sessionCfg.demoMode,
                enableIpv6 = sessionCfg.enableIpv6,
            )

            // Guard against `onRevoke()` / `onDestroy()` / `ACTION_STOP_VPN` arriving while
            // `nativeStartVpnWithStateDir` was executing: tear down immediately without registering
            // observers or marking the dead/revoked service as RUNNING!
            if (!serviceScope.isActive || serviceDestroyedOrRevoked) {
                runCatching { NativeBridge.nativeStopVpn() }
                engineRunningNative = false
                activeOutboundLabel = ""
                latestStatusJson = "{\"running\":false}"
                if (stateTracker.state != VpnLifecycleState.REVOKED) {
                    stateTracker.onStopped()
                }
                RustClashTileService.requestTileSync(this)
                stopForegroundCompat()
                stopSelf()
                return
            }

            val resp = JSONObject(startJsonStr)
            if (!resp.optBoolean("ok", false)) {
                val err = NodeImportSupport.redactSecretsForUi(
                    resp.optString("error", "Unknown Rust JNI start failure"),
                )
                throw IllegalStateException(err)
            }
            engineRunningNative = true

            if (storedYaml.isNotEmpty()) {
                // Clear legacy Keystore blob once migrated into persistent ProfileManager
                AndroidKeystoreVault.putEncryptedString(this, VAULT_KEY_ACTIVE_YAML, "")
            }

            stateTracker.onRunning()

            val pm = getSystemService(PowerManager::class.java)
            isScreenInteractive = pm?.isInteractive ?: true
            runCatching { NativeBridge.nativeSetLowPowerMode(!isScreenInteractive) }
            DebugLogManager.onVpnSessionStarted(
                context = this,
                isInteractive = isScreenInteractive,
                demoMode = sessionCfg.demoMode,
                enableIpv6 = sessionCfg.enableIpv6,
            )

            if (initialPhysicalSnapshot != null) {
                applyCapabilitiesTransition(
                    network = initialPhysicalSnapshot.network,
                    caps = initialPhysicalSnapshot.caps,
                    lp = initialPhysicalSnapshot.linkProperties,
                    eventType = "NET_AVAILABLE",
                )
            }

            registerScreenStateObserver()
            registerNetworkHandoffObserver()
            if (isScreenInteractive) {
                startNotificationTicker()
                startDebugSliceTicker()
            }
            RustClashTileService.requestTileSync(this)
        } catch (t: Throwable) {
            telemetryJob?.cancel()
            telemetryJob = null
            debugSliceJob?.cancel()
            debugSliceJob = null
            unregisterNetworkHandoffObserver()
            unregisterScreenStateObserver()
            livePhysicalNetworks.clear()
            engineRunningNative = false
            val errMsg = NodeImportSupport.redactSecretsForUi(t.message ?: t.javaClass.simpleName)
            DebugLogManager.onVpnSessionError(errMsg)
            if (NativeBridge.isNativeLoaded) {
                // Idempotent: ensures any partially-initialized or post-JNI-exception native state & FD are closed.
                runCatching { NativeBridge.nativeStopVpn() }
            }
            activeOutboundLabel = ""
            latestStatusJson = "{\"running\":false}"
            stateTracker.onError(errMsg)
            RustClashTileService.requestTileSync(this)
            stopForegroundCompat()
            stopSelf()
        } finally {
            runCatching { pendingPfd?.close() }
        }
    }

    private fun registerScreenStateObserver() {
        unregisterScreenStateObserver()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        isScreenInteractive = false
                        DebugLogManager.onScreenInteractiveChanged(false)
                        if (NativeBridge.isNativeLoaded) {
                            runCatching { NativeBridge.nativeSetLowPowerMode(true) }
                        }
                        telemetryJob?.cancel()
                        telemetryJob = null
                        debugSliceJob?.cancel()
                        debugSliceJob = null
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        isScreenInteractive = true
                        DebugLogManager.onScreenInteractiveChanged(true)
                        if (NativeBridge.isNativeLoaded) {
                            runCatching { NativeBridge.nativeSetLowPowerMode(false) }
                        }
                        if (!serviceDestroyedOrRevoked && isSessionRunningOrReconnecting()) {
                            startNotificationTicker()
                            startDebugSliceTicker()
                        }
                        if (stateTracker.state != VpnLifecycleState.RECONNECTING &&
                            DebugLogManager.isEnabled(this@RustClashVpnService)
                        ) {
                            val intervalMs = DebugLogManager.getSliceIntervalSecs(this@RustClashVpnService) * 1000L
                            if (DebugLogManager.currentWindowAgeMs() >= intervalMs) {
                                serviceScope.launch {
                                    if (stateTracker.state != VpnLifecycleState.RECONNECTING) {
                                        runCatching {
                                            DebugLogManager.captureSlice(
                                                context = this@RustClashVpnService,
                                                stateDir = filesDir.absolutePath,
                                                trigger = "screen-on",
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        runCatching {
            ContextCompat.registerReceiver(
                this,
                receiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            screenStateReceiver = receiver
        }
    }

    private fun unregisterScreenStateObserver() {
        val rec = screenStateReceiver ?: return
        screenStateReceiver = null
        runCatching { unregisterReceiver(rec) }
    }

    private fun registerNetworkHandoffObserver() {
        unregisterNetworkHandoffObserver()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: return
                val lp = runCatching { cm.getLinkProperties(network) }.getOrNull()
                applyCapabilitiesTransition(network, caps, lp, eventType = "NET_AVAILABLE")
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val lp = runCatching { cm.getLinkProperties(network) }.getOrNull()
                applyCapabilitiesTransition(network, caps, lp, eventType = "NET_CAPS")
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return
                }
                if (caps != null) {
                    livePhysicalNetworks[network.networkHandle] = network
                }
                val hasIpv6 = hasGlobalUnicastIpv6Link(linkProperties)
                val decision = underlyingNetworkTracker.onLinkPropertiesIpv6Changed(
                    networkHandle = network.networkHandle,
                    hasIpv6 = hasIpv6,
                )
                if (decision.notifyNative) {
                    val transport = when {
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WIFI"
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "CELLULAR"
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ETHERNET"
                        else -> if (decision.isWifi) "WIFI" else "CELLULAR"
                    }
                    DebugLogManager.onNetworkLinkIpv6Changed(
                        context = this@RustClashVpnService,
                        networkHandle = network.networkHandle,
                        transportLabel = transport,
                        hasIpv6 = hasIpv6,
                        handoffTriggered = decision.triggerSessionRecovery,
                    )
                }
                applyNetworkDecision(networkForHandle = network, decision = decision)
            }

            override fun onLost(network: Network) {
                livePhysicalNetworks.remove(network.networkHandle)
                val decision = underlyingNetworkTracker.onUnderlyingLost(network.networkHandle)
                DebugLogManager.onNetworkLostObserved(
                    networkHandle = network.networkHandle,
                    lostActiveUnderlying = decision.triggerSessionRecovery,
                    fallbackHandle = decision.effectiveHandle,
                )
                applyNetworkDecision(networkForHandle = null, decision = decision)
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val mainHandler = Handler(Looper.getMainLooper())
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                cm.registerBestMatchingNetworkCallback(request, cb, mainHandler)
            } else {
                cm.registerNetworkCallback(request, cb, mainHandler)
            }
            connectivityCallback = cb
        } catch (_: SecurityException) {
            // Best-effort if OS restricts callback registration
        } catch (_: RuntimeException) {
            // Guard against ConnectivityService callback limit / Binder edge cases
        }
    }

    private fun applyCapabilitiesTransition(
        network: Network,
        caps: NetworkCapabilities,
        lp: LinkProperties?,
        eventType: String,
    ) {
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return
        }
        livePhysicalNetworks[network.networkHandle] = network
        val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val isEthernet = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        val isValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val hasIpv6 = if (lp != null) {
            hasGlobalUnicastIpv6Link(lp)
        } else {
            underlyingNetworkTracker.knownHasIpv6(network.networkHandle) ?: false
        }
        val decision = underlyingNetworkTracker.onUnderlyingCandidate(
            networkHandle = network.networkHandle,
            isVpnTransport = false,
            isWifi = isWifi,
            isCellular = isCellular,
            isEthernet = isEthernet,
            isValidated = isValidated,
            hasIpv6 = hasIpv6,
        )
        DebugLogManager.onNetworkCandidateObserved(
            eventType = eventType,
            networkHandle = network.networkHandle,
            isWifi = isWifi,
            isCellular = isCellular,
            isEthernet = isEthernet,
            isValidated = isValidated,
            isNotMetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            downBandwidthKbps = caps.linkDownstreamBandwidthKbps,
            upBandwidthKbps = caps.linkUpstreamBandwidthKbps,
            triggeredHandoff = decision.triggerSessionRecovery,
            hasIpv6 = hasIpv6,
        )
        applyNetworkDecision(networkForHandle = network, decision = decision)
    }

    private fun applyNetworkDecision(
        networkForHandle: Network?,
        decision: NetworkTransitionDecision,
    ) {
        if (decision.updateUnderlyingNetworks) {
            if (decision.effectiveHandle == 0L) {
                runCatching { setUnderlyingNetworks(emptyArray()) }
            } else {
                val resolvedNet = livePhysicalNetworks[decision.effectiveHandle]
                    ?: networkForHandle?.takeIf { it.networkHandle == decision.effectiveHandle }
                if (resolvedNet != null) {
                    runCatching { setUnderlyingNetworks(arrayOf(resolvedNet)) }
                }
            }
        }
        if ((decision.notifyNative || decision.syncInitialBaselineToNative) && NativeBridge.isNativeLoaded) {
            runCatching {
                NativeBridge.nativeNotifyNetworkChangedWithCaps(
                    decision.effectiveHandle,
                    decision.isWifi,
                    decision.hasIpv6,
                )
            }
        }
        if (decision.triggerSessionRecovery) {
            triggerPostWakeupOrHandoffRecovery("network-handoff", decision.effectiveHandle)
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun triggerPostWakeupOrHandoffRecovery(reason: String, effectiveHandle: Long) {
        if (effectiveHandle == 0L) {
            stateTracker.onUnderlyingLost()
        } else {
            stateTracker.onNetworkHandoff()
        }
    }

    private fun unregisterNetworkHandoffObserver() {
        val cb = connectivityCallback ?: return
        connectivityCallback = null
        livePhysicalNetworks.clear()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        try {
            cm.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
    }

    private fun isSessionRunningOrReconnecting(): Boolean {
        val st = stateTracker.state
        return st == VpnLifecycleState.RUNNING || st == VpnLifecycleState.RECONNECTING
    }

    private fun startDebugSliceTicker() {
        debugSliceJob?.cancel()
        debugSliceJob = serviceScope.launch {
            while (isActive && isScreenInteractive && isSessionRunningOrReconnecting()) {
                delay(30_000L)
                if (!isScreenInteractive) {
                    break
                }
                if (stateTracker.state == VpnLifecycleState.RECONNECTING) {
                    // Reconnect-safe: stay alive across temporary underlying network loss
                    // and flush overdue slices once RUNNING & interactive or upon disconnect.
                    continue
                }
                if (!DebugLogManager.isEnabled(this@RustClashVpnService)) {
                    continue
                }
                val intervalMs = DebugLogManager.getSliceIntervalSecs(this@RustClashVpnService) * 1000L
                if (DebugLogManager.currentWindowAgeMs() >= intervalMs) {
                    runCatching {
                        DebugLogManager.captureSlice(
                            context = this@RustClashVpnService,
                            stateDir = filesDir.absolutePath,
                            trigger = "periodic",
                        )
                    }
                }
            }
        }
    }

    private fun startNotificationTicker() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            var lastTitle = ""
            var lastBody = ""
            while (isActive && isScreenInteractive && isSessionRunningOrReconnecting()) {
                if (stateTracker.state == VpnLifecycleState.RECONNECTING) {
                    val nextTitle = "RustClash 网络重连中…"
                    val nextBody = "正在等待底层物理网络恢复"
                    if (nextTitle != lastTitle || nextBody != lastBody) {
                        lastTitle = nextTitle
                        lastBody = nextBody
                        val nm = getSystemService(NotificationManager::class.java)
                        nm?.notify(
                            NOTIFICATION_ID,
                            buildNotification(title = nextTitle, body = nextBody),
                        )
                    }
                    delay(5_000L)
                    continue
                }
                val raw = NativeBridge.nativeGetStatusJson()
                latestStatusJson = raw
                runCatching {
                    val obj = JSONObject(raw)
                    val up = formatBytesPerSec(obj.optLong("upRate", 0L))
                    val down = formatBytesPerSec(obj.optLong("downRate", 0L))
                    val modeRaw = obj.optString("mode", "rule").lowercase()
                    val modeLabel = when (modeRaw) {
                        "global" -> "全局代理"
                        "direct" -> "全局直连"
                        else -> "智能分流"
                    }
                    val outbound = obj.optString("effectiveOutbound", "DIRECT")
                    activeOutboundLabel = outbound
                    val conns = obj.optInt("activeConnections", 0)
                    val nextTitle = "RustClash 已连接 · $modeLabel"
                    val nextBody = "↓ $down  ↑ $up  ·  $outbound ($conns 活跃连接)"
                    if (nextTitle != lastTitle || nextBody != lastBody) {
                        lastTitle = nextTitle
                        lastBody = nextBody
                        val nm = getSystemService(NotificationManager::class.java)
                        nm?.notify(
                            NOTIFICATION_ID,
                            buildNotification(title = nextTitle, body = nextBody),
                        )
                    }
                }
                delay(5_000L)
            }
        }
    }

    override fun onRevoke() {
        serviceDestroyedOrRevoked = true
        stateTracker.onSystemRevoked()
        RustClashTileService.requestTileSync(this)
        serviceScope.launch {
            sessionMutex.withLock {
                stopVpnSessionInternal(revokedBySystem = true)
            }
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        serviceDestroyedOrRevoked = true
        telemetryJob?.cancel()
        telemetryJob = null
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        livePhysicalNetworks.clear()
        val wasRunning = engineRunningNative
        engineRunningNative = false
        activeOutboundLabel = ""
        latestStatusJson = "{\"running\":false}"
        if (stateTracker.state != VpnLifecycleState.REVOKED) {
            stateTracker.onStopped()
        }
        RustClashTileService.requestTileSync(this)
        if (wasRunning || NativeBridge.isNativeLoaded) {
            val appCtx = applicationContext
            val statePath = filesDir.absolutePath
            Thread {
                if (wasRunning && DebugLogManager.isEnabled(appCtx)) {
                    DebugLogManager.onVpnSessionStopping(revokedBySystem = false)
                    runCatching {
                        DebugLogManager.captureSlice(
                            context = appCtx,
                            stateDir = statePath,
                            trigger = "service-destroy",
                        )
                    }
                }
                if (NativeBridge.isNativeLoaded) {
                    runCatching { NativeBridge.nativeStopVpn() }
                }
            }.start()
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun stopVpnSessionInternal(revokedBySystem: Boolean) {
        serviceDestroyedOrRevoked = true
        if (revokedBySystem) {
            stateTracker.onSystemRevoked()
        } else {
            stateTracker.onStopRequested()
        }
        telemetryJob?.cancel()
        telemetryJob = null
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        livePhysicalNetworks.clear()
        // Capture disconnect diagnostic slice BEFORE stopping native runtime so session stats are preserved!
        if (engineRunningNative && DebugLogManager.isEnabled(this)) {
            DebugLogManager.onVpnSessionStopping(revokedBySystem)
            runCatching {
                DebugLogManager.captureSlice(
                    context = this,
                    stateDir = filesDir.absolutePath,
                    trigger = if (revokedBySystem) "revoked" else "disconnect",
                )
            }
        }
        engineRunningNative = false
        if (NativeBridge.isNativeLoaded) {
            runCatching { NativeBridge.nativeStopVpn() }
        }
        activeOutboundLabel = ""
        latestStatusJson = "{\"running\":false}"
        stateTracker.onStopped()
        RustClashTileService.requestTileSync(this)
        stopForegroundCompat()
        stopSelf()
    }

    private fun promoteForeground(title: String, body: String) {
        val notification = buildNotification(title, body)
        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, fgType)
    }

    private fun stopForegroundCompat() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun createConfiguredVpnBuilder(
        sessionCfg: VpnSessionConfig,
        underlyingNetwork: Network?,
        perAppPlan: EffectivePerAppPlan,
        useSplitRoutes: Boolean,
    ): Builder {
        val builder = Builder()
            .setSession(sessionCfg.sessionName)
            .setMtu(sessionCfg.mtu)
            .addAddress(sessionCfg.ipv4Address, sessionCfg.ipv4PrefixLength)
            .addDnsServer(sessionCfg.dnsIpv4)

        if (sessionCfg.enableIpv6) {
            builder.addAddress(sessionCfg.ipv6Address, sessionCfg.ipv6PrefixLength)
        }
        if (useSplitRoutes) {
            applyVpnRoutes(builder, sessionCfg)
        } else {
            builder.addRoute("0.0.0.0", 0)
            if (sessionCfg.enableIpv6) {
                builder.addRoute("::", 0)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        if (underlyingNetwork != null) {
            runCatching { builder.setUnderlyingNetworks(arrayOf(underlyingNetwork)) }
        }

        for (pkg in perAppPlan.allowedPackages) {
            try {
                builder.addAllowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Ignore uninstalled stale package entries
            }
        }
        for (pkg in perAppPlan.disallowedPackages) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Ignore uninstalled stale package entries
            }
        }
        return builder
    }

    private fun applyVpnRoutes(builder: Builder, sessionCfg: VpnSessionConfig) {
        val routePlan = VpnRoutePlanner.buildPlan(
            sessionCfg = sessionCfg,
            sdkInt = Build.VERSION.SDK_INT,
        )
        for (route in routePlan.includedIpv4) {
            builder.addRoute(route.address, route.prefixLength)
        }
        for (route in routePlan.includedIpv6) {
            builder.addRoute(route.address, route.prefixLength)
        }
    }

    private fun buildNotification(title: String, body: String): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(io.github.rustclashlabs.rustclash.R.drawable.ic_stat_rustclash_vpn)
            .setColor(0xFF059669.toInt())
            .setContentTitle(title)
            .setContentText(body)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openPendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.vpn_action_disconnect),
                stopPendingIntent,
            )
            .build()
    }
}
