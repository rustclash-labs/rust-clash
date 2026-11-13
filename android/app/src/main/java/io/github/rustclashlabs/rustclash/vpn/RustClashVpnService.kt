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
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
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

class RustClashVpnService : VpnService() {
    private val sessionMutex = Mutex()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var telemetryJob: Job? = null
    private var connectivityCallback: ConnectivityManager.NetworkCallback? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private val underlyingNetworkTracker = UnderlyingNetworkTracker()

    @Volatile
    private var isScreenInteractive: Boolean = true

    @Volatile
    private var engineRunningNative: Boolean = false

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
        const val VAULT_KEY_ACTIVE_YAML = "active_profile_yaml"
        const val VAULT_KEY_SUBSCRIPTION_URL = "active_subscription_url"

        private const val NOTIFICATION_CHANNEL_ID = "rust_clash_vpn_channel"
        private const val NOTIFICATION_ID = 19818

        val stateTracker = VpnStateTracker()

        @Volatile
        var activeApiUrl: String? = null
            private set

        @Volatile
        var activeApiSecret: String? = null
            private set

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
    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        val pm = getSystemService(PowerManager::class.java)
        isScreenInteractive = pm?.isInteractive ?: true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
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

    private fun startVpnSessionInternal(demoMode: Boolean) {
        // Clean up any prior ticker/network/screen observer on duplicate start before re-establishing
        telemetryJob?.cancel()
        telemetryJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()

        if (!NativeBridge.ensureLoaded()) {
            stateTracker.onError("当前设备架构未能加载 Rust 核心库 (libproxy_ffi.so)")
            RustClashTileService.requestTileSync(this)
            stopForegroundCompat()
            stopSelf()
            return
        }

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
            val builder = Builder()
                .setSession(sessionCfg.sessionName)
                .setMtu(sessionCfg.mtu)
                .addAddress(sessionCfg.ipv4Address, sessionCfg.ipv4PrefixLength)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(sessionCfg.dnsIpv4)

            if (sessionCfg.enableIpv6) {
                builder.addAddress(sessionCfg.ipv6Address, sessionCfg.ipv6PrefixLength)
                builder.addRoute("::", 0)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
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

            val established = builder.establish()
                ?: throw IllegalStateException("无法建立系统 VPN 隧道：连接授权缺失或被其他 VPN 应用抢占")
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
            )
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

            activeApiUrl = resp.optString("apiUrl").takeIf { it.isNotEmpty() }
            activeApiSecret = resp.optString("apiSecret").takeIf { it.isNotEmpty() }
            stateTracker.onRunning()

            val pm = getSystemService(PowerManager::class.java)
            isScreenInteractive = pm?.isInteractive ?: true
            runCatching { NativeBridge.nativeSetLowPowerMode(!isScreenInteractive) }

            registerScreenStateObserver()
            registerNetworkHandoffObserver()
            startNotificationTicker()
            RustClashTileService.requestTileSync(this)
        } catch (t: Throwable) {
            telemetryJob?.cancel()
            telemetryJob = null
            unregisterNetworkHandoffObserver()
            unregisterScreenStateObserver()
            engineRunningNative = false
            if (NativeBridge.isNativeLoaded) {
                // Idempotent: ensures any partially-initialized or post-JNI-exception native state & FD are closed.
                runCatching { NativeBridge.nativeStopVpn() }
            }
            activeApiUrl = null
            activeApiSecret = null
            activeOutboundLabel = ""
            latestStatusJson = "{\"running\":false}"
            stateTracker.onError(
                NodeImportSupport.redactSecretsForUi(t.message ?: t.javaClass.simpleName),
            )
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
                        if (NativeBridge.isNativeLoaded) {
                            runCatching { NativeBridge.nativeSetLowPowerMode(true) }
                        }
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        isScreenInteractive = true
                        if (NativeBridge.isNativeLoaded) {
                            runCatching { NativeBridge.nativeSetLowPowerMode(false) }
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
                cm.getNetworkCapabilities(network)?.let { caps ->
                    applyCapabilitiesTransition(network, caps)
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                applyCapabilitiesTransition(network, caps)
            }

            override fun onLost(network: Network) {
                val decision = underlyingNetworkTracker.onUnderlyingLost(network.networkHandle)
                if (decision.updateUnderlyingNetworks) {
                    runCatching { setUnderlyingNetworks(null) }
                }
                if (decision.triggerSessionRecovery) {
                    stateTracker.onUnderlyingLost()
                }
                if (decision.notifyNative && NativeBridge.isNativeLoaded) {
                    NativeBridge.nativeNotifyNetworkChanged(decision.effectiveHandle, decision.isWifi)
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            connectivityCallback = cb
        } catch (_: SecurityException) {
            // Best-effort if OS restricts callback registration
        }
    }

    private fun applyCapabilitiesTransition(network: Network, caps: NetworkCapabilities) {
        val decision = underlyingNetworkTracker.onUnderlyingCandidate(
            networkHandle = network.networkHandle,
            isVpnTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
            isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            isEthernet = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
        )
        if (decision.updateUnderlyingNetworks) {
            runCatching { setUnderlyingNetworks(arrayOf(network)) }
        }
        if (decision.triggerSessionRecovery) {
            stateTracker.onNetworkHandoff()
        }
        if (decision.notifyNative && NativeBridge.isNativeLoaded) {
            NativeBridge.nativeNotifyNetworkChanged(decision.effectiveHandle, decision.isWifi)
        }
    }

    private fun unregisterNetworkHandoffObserver() {
        val cb = connectivityCallback ?: return
        connectivityCallback = null
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        try {
            cm.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
    }

    private fun startNotificationTicker() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            var lastTitle = ""
            var lastBody = ""
            while (isActive && stateTracker.state == VpnLifecycleState.RUNNING) {
                if (!isScreenInteractive) {
                    // Screen is off: skip JNI status polling & SystemUI Binder IPC wakeups
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
                delay(2_000L)
            }
        }
    }

    override fun onRevoke() {
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
        telemetryJob?.cancel()
        telemetryJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        if (engineRunningNative) {
            engineRunningNative = false
            activeApiUrl = null
            activeApiSecret = null
            activeOutboundLabel = ""
            latestStatusJson = "{\"running\":false}"
            stateTracker.onStopped()
            RustClashTileService.requestTileSync(this)
            Thread {
                if (NativeBridge.isNativeLoaded) {
                    runCatching { NativeBridge.nativeStopVpn() }
                }
            }.start()
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun stopVpnSessionInternal(revokedBySystem: Boolean) {
        if (revokedBySystem) {
            stateTracker.onSystemRevoked()
        } else {
            stateTracker.onStopRequested()
        }
        telemetryJob?.cancel()
        telemetryJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        engineRunningNative = false
        if (NativeBridge.isNativeLoaded) {
            runCatching { NativeBridge.nativeStopVpn() }
        }
        activeApiUrl = null
        activeApiSecret = null
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

    private fun buildNotification(title: String, body: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPending = PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
            action = ACTION_STOP_VPN
        }
        val stopPending = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(io.github.rustclashlabs.rustclash.R.drawable.ic_stat_rustclash_vpn)
            .setColor(0xFF059669.toInt())
            .setContentTitle(title)
            .setContentText(body)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openPending)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.vpn_action_disconnect),
                stopPending,
            )
            .build()
    }
}
