package io.github.rustclashlabs.rustclash.vpn

import android.app.ForegroundServiceStartNotAllowedException
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import androidx.annotation.RequiresApi
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
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

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
    private val notificationLock = Any()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var telemetryJob: Job? = null
    private var debugSliceJob: Job? = null
    private var connectivityCallback: ConnectivityManager.NetworkCallback? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private val underlyingNetworkTracker = UnderlyingNetworkTracker()
    private val livePhysicalNetworks = ConcurrentHashMap<Long, Network>()
    private val instanceSessionToken = AtomicLong(0L)
    private val sliceCapturedForToken = AtomicLong(0L)
    private val lifecycleCoordinator = VpnServiceLifecycleCoordinator()

    @Volatile
    private var isScreenInteractive: Boolean = true

    @Volatile
    private var engineRunningNative: Boolean = false

    @Volatile
    private var activeSessionEpoch: Long = 0L

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

    internal data class StartRegistrationResult(
        val startEpoch: Long,
        val promoted: Boolean,
    )

    @RequiresApi(Build.VERSION_CODES.S)
    private object Api31FgsHelper {
        fun isForegroundServiceStartNotAllowed(t: Throwable): Boolean =
            t is ForegroundServiceStartNotAllowedException
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

        private val nativeLifecycleLock = Any()
        private val statusSnapshotLock = Any()
        private val nextSessionToken = AtomicLong(0L)
        internal val activeNativeSessionToken = AtomicLong(0L)

        val stateTracker = VpnStateTracker()

        @Volatile
        var lockdownWarning: String? = null
            private set

        @Volatile
        var latestStatusJson: String = "{\"running\":false}"
            private set

        @Volatile
        var latestStatusUpdatedAtMs: Long = 0L
            private set

        @Volatile
        var activeOutboundLabel: String = ""
            private set

        fun publishFreshStatusSnapshot(
            rawJson: String,
            expectedToken: Long,
            nowMs: Long = System.currentTimeMillis(),
        ): Boolean = synchronized(statusSnapshotLock) {
            if (expectedToken == 0L ||
                activeNativeSessionToken.get() != expectedToken ||
                stateTracker.state != VpnLifecycleState.RUNNING
            ) {
                return false
            }
            latestStatusJson = rawJson
            latestStatusUpdatedAtMs = nowMs
            true
        }

        internal fun clearFreshStatusSnapshot() {
            synchronized(statusSnapshotLock) {
                latestStatusJson = "{\"running\":false}"
                latestStatusUpdatedAtMs = 0L
            }
        }

        internal fun shouldReuseFreshStatus(
            nowMs: Long,
            lastUpdatedMs: Long,
            maxAgeMs: Long = 2_500L,
        ): Boolean = lastUpdatedMs > 0L && nowMs >= lastUpdatedMs && (nowMs - lastUpdatedMs) <= maxAgeMs

        internal fun canPostSessionNotification(
            coroutineActive: Boolean,
            serviceDestroyed: Boolean,
            instanceToken: Long,
            activeGlobalToken: Long,
            expectedToken: Long,
            lifecycleState: VpnLifecycleState,
        ): Boolean =
            coroutineActive &&
                !serviceDestroyed &&
                expectedToken != 0L &&
                instanceToken == expectedToken &&
                activeGlobalToken == expectedToken &&
                (lifecycleState == VpnLifecycleState.RUNNING || lifecycleState == VpnLifecycleState.RECONNECTING)

        /**
         * Atomically registers a new start command, transitions [stateTracker] to `STARTING`,
         * and promotes the Service to foreground under [notificationLock].
         *
         * Strict lock hierarchy: `notificationLock -> lifecycleCoordinator -> stateTracker`.
         */
        internal fun registerStartAndPromoteForeground(
            notificationLock: Any,
            coordinator: VpnServiceLifecycleCoordinator,
            stateTracker: VpnStateTracker,
            startCommandId: Int,
            promoteForeground: () -> Boolean,
            fgsRestrictedErrorMessage: String,
        ): StartRegistrationResult = synchronized(notificationLock) {
            val startEpoch = coordinator.onStartRequested(startCommandId)
            if (startEpoch == 0L) {
                return@synchronized StartRegistrationResult(startEpoch = 0L, promoted = false)
            }
            stateTracker.onStartRequested()
            val promoted = promoteForeground()
            if (!promoted) {
                coordinator.onStartAbortedBeforeLaunch(startEpoch)
                stateTracker.onError(fgsRestrictedErrorMessage)
            }
            StartRegistrationResult(startEpoch = startEpoch, promoted = promoted)
        }

        /**
         * Atomically verifies under [notificationLock] that a stop/revoke teardown has not been
         * superseded by a newer active `onStartCommand`, updates [stateTracker] + clears
         * notification, and invokes `stopSelfResult(effectiveStopStartId)` ONLY when a positive
         * delivered `startId > 0` exists.
         *
         * Never falls back to unconditional zero-arg `stopSelf()` when `stopStartId` is null or
         * `<= 0` (e.g., pure `BIND_VPN_SERVICE` binding with no `onStartCommand`): on Android,
         * `stopSelf()` on a purely bound Service is a no-op anyway, and calling it outside
         * [notificationLock] would only risk killing a newly racing `onStartCommand(startId = 1)`.
         */
        internal fun finalizeStopSession(
            notificationLock: Any,
            coordinator: VpnServiceLifecycleCoordinator,
            stateTracker: VpnStateTracker,
            expectedEpoch: Long,
            supersededAtEntry: Boolean,
            stopStartId: Int?,
            isCurrentOrIdleGlobalSession: () -> Boolean,
            onClearSessionState: () -> Unit,
            stopForegroundAndClearNotification: () -> Unit,
            requestTileSync: () -> Unit,
            stopSelfWithResult: (Int) -> Boolean,
        ): Boolean {
            var shouldRequestTileSync = false
            var finalized = false
            synchronized(notificationLock) {
                if (supersededAtEntry || coordinator.isStopSupersededByNewerStart(expectedEpoch)) {
                    return false
                }
                if (isCurrentOrIdleGlobalSession()) {
                    stateTracker.onStopped()
                    onClearSessionState()
                    shouldRequestTileSync = true
                }
                stopForegroundAndClearNotification()
                finalized = true
            }
            if (shouldRequestTileSync) {
                requestTileSync()
            }
            if (finalized) {
                val effectiveStopStartId = stopStartId?.takeIf { it > 0 }
                if (effectiveStopStartId != null) {
                    stopSelfWithResult(effectiveStopStartId)
                }
            }
            return finalized
        }

        /**
         * Atomically verifies under [notificationLock] that an aborted start has not been
         * superseded by a newer start before clearing foreground state and calling
         * `stopSelfResult(startCommandId)` (only when `startCommandId > 0`).
         */
        internal fun finalizeAbortedStartInternal(
            notificationLock: Any,
            coordinator: VpnServiceLifecycleCoordinator,
            stateTracker: VpnStateTracker,
            startEpoch: Long,
            startCommandId: Int,
            isCurrentOrIdleGlobalSession: () -> Boolean,
            onClearSessionState: () -> Unit,
            stopForegroundAndClearNotification: () -> Unit,
            requestTileSync: () -> Unit,
            stopSelfWithResult: (Int) -> Boolean,
        ): Boolean {
            var shouldRequestTileSync = false
            var shouldStopService = false
            synchronized(notificationLock) {
                if (!coordinator.shouldFinalizeFailedOrAbortedStart(startEpoch, startCommandId)) {
                    return false
                }
                if (isCurrentOrIdleGlobalSession()) {
                    stateTracker.onStopped()
                    onClearSessionState()
                    shouldRequestTileSync = true
                }
                stopForegroundAndClearNotification()
                shouldStopService = true
            }
            if (shouldRequestTileSync) {
                requestTileSync()
            }
            if (shouldStopService && startCommandId > 0) {
                stopSelfWithResult(startCommandId)
            }
            return shouldStopService
        }

        internal fun isServiceStartRestrictionException(t: Throwable): Boolean {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                Api31FgsHelper.isForegroundServiceStartNotAllowed(t)
            ) {
                return true
            }
            return t is IllegalStateException || t is SecurityException
        }

        internal fun runSafeServiceCall(block: () -> Unit): Boolean =
            try {
                block()
                true
            } catch (t: Throwable) {
                if (isServiceStartRestrictionException(t)) {
                    false
                } else {
                    throw t
                }
            }

        fun safeStartVpnForegroundService(context: Context, intent: Intent): Boolean =
            runSafeServiceCall {
                ContextCompat.startForegroundService(context, intent)
            }

        internal fun safeRequestStopVpnInternal(
            startStopIntent: () -> Unit,
            stopServiceFallback: () -> Boolean,
        ): Boolean {
            val delivered = runSafeServiceCall(startStopIntent)
            if (delivered) {
                return true
            }
            // Android 12–15 background startService fallback: Context.stopService() is never
            // subject to ForegroundServiceStartNotAllowedException / background start limits.
            val stoppedRunningService = runCatching { stopServiceFallback() }.getOrDefault(false)
            if (!stoppedRunningService && activeNativeSessionToken.get() == 0L) {
                stateTracker.onStopped()
            }
            return stoppedRunningService
        }

        fun safeRequestStopVpn(context: Context, intent: Intent): Boolean =
            safeRequestStopVpnInternal(
                startStopIntent = { context.startService(intent) },
                stopServiceFallback = { context.stopService(intent) },
            )

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

    private fun isStartSupersededOrCancelled(startEpoch: Long, startCommandId: Int): Boolean =
        lifecycleCoordinator.isStartSupersededOrCancelled(
            startEpoch = startEpoch,
            startCommandId = startCommandId,
            scopeActive = serviceScope.isActive,
        )

    private fun isCurrentOrIdleGlobalSession(token: Long): Boolean {
        val active = activeNativeSessionToken.get()
        return active == 0L || (token != 0L && active == token)
    }

    private suspend fun cancelAndJoinTelemetryJob() {
        val job = telemetryJob
        telemetryJob = null
        if (job != null) {
            withTimeoutOrNull(500L) {
                job.cancelAndJoin()
            } ?: job.cancel()
        }
    }

    private fun stopForegroundAndClearNotification() {
        synchronized(notificationLock) {
            runCatching { stopForegroundCompat() }
            runCatching {
                getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
            }
        }
    }

    private fun finalizeAbortedStart(
        startEpoch: Long,
        startCommandId: Int,
        stoppedToken: Long = 0L,
    ) {
        finalizeAbortedStartInternal(
            notificationLock = notificationLock,
            coordinator = lifecycleCoordinator,
            stateTracker = stateTracker,
            startEpoch = startEpoch,
            startCommandId = startCommandId,
            isCurrentOrIdleGlobalSession = { isCurrentOrIdleGlobalSession(stoppedToken) },
            onClearSessionState = {
                activeOutboundLabel = ""
                clearFreshStatusSnapshot()
            },
            stopForegroundAndClearNotification = { stopForegroundAndClearNotification() },
            requestTileSync = { RustClashTileService.requestTileSync(this) },
            stopSelfWithResult = { cmdId -> stopSelfResult(cmdId) },
        )
    }

    private fun captureStoppingSliceOnce(
        context: Context,
        stateDir: String,
        token: Long,
        revokedBySystem: Boolean,
        trigger: String,
    ) {
        if (token == 0L) return
        if (activeNativeSessionToken.get() != token) return
        if (!sliceCapturedForToken.compareAndSet(0L, token)) return
        if (DebugLogManager.isEnabled(context)) {
            DebugLogManager.onVpnSessionStopping(revokedBySystem)
            runCatching {
                DebugLogManager.captureSlice(
                    context = context,
                    stateDir = stateDir,
                    trigger = trigger,
                )
            }
        }
    }

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
                val stopEpoch = synchronized(notificationLock) {
                    val epoch = lifecycleCoordinator.onStopRequested(startId)
                    stateTracker.onStopRequested()
                    epoch
                }
                RustClashTileService.requestTileSync(this)
                val stopCmdId = startId
                serviceScope.launch {
                    sessionMutex.withLock {
                        stopVpnSessionInternal(
                            revokedBySystem = false,
                            expectedEpoch = stopEpoch,
                            stopStartId = stopCmdId,
                        )
                    }
                }
                return START_NOT_STICKY
            }
            ACTION_START_VPN, SERVICE_INTERFACE -> {
                val prefs = getSharedPreferences(PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
                val demoMode = intent.getBooleanExtra(
                    EXTRA_DEMO_MODE,
                    prefs.getBoolean(KEY_DEMO_MODE, false),
                )

                // Atomically register start epoch, transition state to STARTING, and promote
                // foreground on the main thread under `notificationLock` within Android's 5s FGS
                // budget so concurrent IO stop/revoke/abort finalizers cannot clobber STARTING or
                // strip this session's foreground notification.
                val startReg = registerStartAndPromoteForeground(
                    notificationLock = notificationLock,
                    coordinator = lifecycleCoordinator,
                    stateTracker = stateTracker,
                    startCommandId = startId,
                    promoteForeground = {
                        promoteForeground("RustClash 正在连接…", "正在初始化 TUN 隧道与出站套接字保护")
                    },
                    fgsRestrictedErrorMessage = "系统限制了后台启动 VPN 前台服务，请返回应用前台后重试连接",
                )
                if (startReg.startEpoch == 0L) {
                    if (startId > 0) {
                        stopSelfResult(startId)
                    }
                    return START_NOT_STICKY
                }
                if (!startReg.promoted) {
                    RustClashTileService.requestTileSync(this)
                    if (startId > 0) {
                        stopSelfResult(startId)
                    }
                    return START_NOT_STICKY
                }
                RustClashTileService.requestTileSync(this)

                val startEpoch = startReg.startEpoch
                val startCmdId = startId
                serviceScope.launch {
                    sessionMutex.withLock {
                        startVpnSessionInternal(
                            demoMode = demoMode,
                            startCommandId = startCmdId,
                            startEpoch = startEpoch,
                        )
                    }
                }
                return START_NOT_STICKY
            }
            null -> {
                lifecycleCoordinator.recordDeliveredCommandId(startId)
                if (instanceSessionToken.get() == 0L && !isSessionRunningOrReconnecting()) {
                    if (startId > 0) {
                        stopSelfResult(startId)
                    }
                }
                return START_NOT_STICKY
            }
            else -> {
                lifecycleCoordinator.recordDeliveredCommandId(startId)
                return START_NOT_STICKY
            }
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

    private suspend fun startVpnSessionInternal(
        demoMode: Boolean,
        startCommandId: Int,
        startEpoch: Long,
    ) {
        // Ensure any previous session owned by this Service instance is cleanly stopped before re-starting.
        val priorToken = instanceSessionToken.getAndSet(0L)
        activeSessionEpoch = 0L
        engineRunningNative = false
        cancelAndJoinTelemetryJob()
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        underlyingNetworkTracker.setSingleBestMatchingMode(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        livePhysicalNetworks.clear()

        if (priorToken != 0L) {
            synchronized(nativeLifecycleLock) {
                if (activeNativeSessionToken.compareAndSet(priorToken, 0L) && NativeBridge.isNativeLoaded) {
                    runCatching { NativeBridge.nativeStopVpn() }
                }
            }
            clearFreshStatusSnapshot()
        }
        sliceCapturedForToken.set(0L)

        if (isStartSupersededOrCancelled(startEpoch, startCommandId)) {
            finalizeAbortedStart(startEpoch, startCommandId, stoppedToken = priorToken)
            return
        }

        if (!NativeBridge.ensureLoaded()) {
            var shouldFinalize = false
            synchronized(notificationLock) {
                if (lifecycleCoordinator.shouldFinalizeFailedOrAbortedStart(startEpoch, startCommandId)) {
                    stateTracker.onError("当前设备架构未能加载 Rust 核心库 (libproxy_ffi.so)")
                    stopForegroundAndClearNotification()
                    shouldFinalize = true
                }
            }
            if (shouldFinalize) {
                RustClashTileService.requestTileSync(this)
                if (startCommandId > 0) {
                    stopSelfResult(startCommandId)
                }
            }
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
        val myToken = nextSessionToken.incrementAndGet()
        try {
            if (isStartSupersededOrCancelled(startEpoch, startCommandId)) {
                finalizeAbortedStart(startEpoch, startCommandId)
                return
            }

            if (perAppPlan.blockingError != null) {
                throw IllegalStateException(perAppPlan.blockingError)
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

            var abortedBeforeNativeStart = false
            val startJsonStr = synchronized(nativeLifecycleLock) {
                if (isStartSupersededOrCancelled(startEpoch, startCommandId)) {
                    runCatching { ParcelFileDescriptor.adoptFd(detachedFd).close() }
                    abortedBeforeNativeStart = true
                    ""
                } else {
                    val rawJson = try {
                        NativeBridge.nativeStartVpnWithStateDir(
                            vpnService = this,
                            tunFd = detachedFd,
                            stateDir = filesDir.absolutePath,
                            yamlConfig = storedYaml,
                            demoMode = sessionCfg.demoMode,
                            enableIpv6 = sessionCfg.enableIpv6,
                        )
                    } catch (jniErr: Throwable) {
                        activeNativeSessionToken.set(0L)
                        if (NativeBridge.isNativeLoaded) {
                            runCatching { NativeBridge.nativeStopVpn() }
                        }
                        throw jniErr
                    }
                    val startedOk = runCatching {
                        JSONObject(rawJson).optBoolean("ok", false)
                    }.getOrDefault(false)
                    if (startedOk) {
                        activeNativeSessionToken.set(myToken)
                        instanceSessionToken.set(myToken)
                        activeSessionEpoch = startEpoch
                        engineRunningNative = true
                    }
                    rawJson
                }
            }

            if (abortedBeforeNativeStart) {
                finalizeAbortedStart(startEpoch, startCommandId)
                return
            }

            val resp = JSONObject(startJsonStr)
            if (!resp.optBoolean("ok", false)) {
                val err = NodeImportSupport.redactSecretsForUi(
                    resp.optString("error", "Unknown Rust JNI start failure"),
                )
                throw IllegalStateException(err)
            }

            // Guard against `onRevoke()` / `onDestroy()` / newer `ACTION_STOP_VPN` arriving while
            // `nativeStartVpnWithStateDir` was executing: atomically check lifecycle under
            // `notificationLock` before transitioning to RUNNING, or tear down `myToken` cleanly.
            val becameRunning = synchronized(notificationLock) {
                if (isStartSupersededOrCancelled(startEpoch, startCommandId)) {
                    false
                } else {
                    stateTracker.onRunning()
                    true
                }
            }
            if (!becameRunning) {
                val tok = instanceSessionToken.getAndSet(0L)
                activeSessionEpoch = 0L
                engineRunningNative = false
                synchronized(nativeLifecycleLock) {
                    if (tok != 0L && activeNativeSessionToken.compareAndSet(tok, 0L) && NativeBridge.isNativeLoaded) {
                        runCatching { NativeBridge.nativeStopVpn() }
                    }
                }
                finalizeAbortedStart(startEpoch, startCommandId, stoppedToken = tok)
                return
            }

            if (storedYaml.isNotEmpty()) {
                // Remove legacy Keystore blob once migrated into persistent ProfileManager without invoking Keystore encrypt
                runCatching { AndroidKeystoreVault.removeEncryptedKey(this, VAULT_KEY_ACTIVE_YAML) }
            }

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
            val tok = instanceSessionToken.getAndSet(0L)
            activeSessionEpoch = 0L
            engineRunningNative = false
            val errMsg = NodeImportSupport.redactSecretsForUi(t.message ?: t.javaClass.simpleName)
            DebugLogManager.onVpnSessionError(errMsg)
            synchronized(nativeLifecycleLock) {
                if (tok != 0L && activeNativeSessionToken.compareAndSet(tok, 0L) && NativeBridge.isNativeLoaded) {
                    runCatching { NativeBridge.nativeStopVpn() }
                }
            }
            var shouldFinalize = false
            synchronized(notificationLock) {
                if (lifecycleCoordinator.shouldFinalizeFailedOrAbortedStart(startEpoch, startCommandId) &&
                    isCurrentOrIdleGlobalSession(tok)
                ) {
                    activeOutboundLabel = ""
                    if (!lifecycleCoordinator.isRevokedForCurrentSession &&
                        stateTracker.state != VpnLifecycleState.REVOKED
                    ) {
                        stateTracker.onError(errMsg)
                    }
                    clearFreshStatusSnapshot()
                    stopForegroundAndClearNotification()
                    shouldFinalize = true
                }
            }
            if (shouldFinalize) {
                RustClashTileService.requestTileSync(this)
                if (startCommandId > 0) {
                    stopSelfResult(startCommandId)
                }
            }
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
                        if (!lifecycleCoordinator.isDestroyed &&
                            !lifecycleCoordinator.isRevokedForCurrentSession &&
                            isSessionRunningOrReconnecting()
                        ) {
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
                    PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                        val pm = getSystemService(PowerManager::class.java)
                        val isDoze = pm?.isDeviceIdleMode ?: false
                        val interactive = pm?.isInteractive ?: isScreenInteractive
                        DebugLogManager.onDeviceIdleModeChanged(isDoze = isDoze, interactive = interactive)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
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
            var tickCount = 0
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
                tickCount++
                val intervalMs = DebugLogManager.getSliceIntervalSecs(this@RustClashVpnService) * 1000L
                if (DebugLogManager.currentWindowAgeMs() >= intervalMs) {
                    runCatching {
                        DebugLogManager.captureSlice(
                            context = this@RustClashVpnService,
                            stateDir = filesDir.absolutePath,
                            trigger = "periodic",
                        )
                    }
                } else if (tickCount % 4 == 0) {
                    runCatching {
                        DebugLogManager.inspectLiveHealthAndCaptureIfAnomalous(
                            context = this@RustClashVpnService,
                            stateDir = filesDir.absolutePath,
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
                val myToken = instanceSessionToken.get()
                if (myToken == 0L || activeNativeSessionToken.get() != myToken) {
                    break
                }
                if (stateTracker.state == VpnLifecycleState.RECONNECTING) {
                    val nextTitle = "RustClash 网络重连中…"
                    val nextBody = "正在等待底层物理网络恢复"
                    if (nextTitle != lastTitle || nextBody != lastBody) {
                        val posted = synchronized(notificationLock) {
                            if (canPostSessionNotification(
                                    coroutineActive = isActive,
                                    serviceDestroyed = lifecycleCoordinator.isDestroyed,
                                    instanceToken = instanceSessionToken.get(),
                                    activeGlobalToken = activeNativeSessionToken.get(),
                                    expectedToken = myToken,
                                    lifecycleState = stateTracker.state,
                                )
                            ) {
                                val nm = getSystemService(NotificationManager::class.java)
                                nm?.notify(
                                    NOTIFICATION_ID,
                                    buildNotification(title = nextTitle, body = nextBody),
                                )
                                true
                            } else {
                                false
                            }
                        }
                        if (posted) {
                            lastTitle = nextTitle
                            lastBody = nextBody
                        } else {
                            break
                        }
                    }
                    delay(5_000L)
                    continue
                }
                val nowMs = System.currentTimeMillis()
                val raw = if (shouldReuseFreshStatus(nowMs, latestStatusUpdatedAtMs)) {
                    latestStatusJson
                } else {
                    NativeBridge.nativeGetStatusJson().also { fresh ->
                        publishFreshStatusSnapshot(fresh, expectedToken = myToken, nowMs = nowMs)
                    }
                }
                if (!isActive ||
                    lifecycleCoordinator.isDestroyed ||
                    instanceSessionToken.get() != myToken ||
                    activeNativeSessionToken.get() != myToken ||
                    stateTracker.state != VpnLifecycleState.RUNNING
                ) {
                    break
                }
                var sessionEnded = false
                runCatching {
                    val obj = JSONObject(raw)
                    if (!obj.optBoolean("running", false)) {
                        return@runCatching
                    }
                    val up = formatBytesPerSec(obj.optLong("upRate", 0L))
                    val down = formatBytesPerSec(obj.optLong("downRate", 0L))
                    val modeRaw = obj.optString("mode", "rule").lowercase()
                    val modeLabel = when (modeRaw) {
                        "global" -> "全局代理"
                        "direct" -> "全局直连"
                        else -> "智能分流"
                    }
                    val outbound = obj.optString("effectiveOutbound", "DIRECT")
                    val conns = obj.optInt("activeConnections", 0)
                    val nextTitle = "RustClash 已连接 · $modeLabel"
                    val nextBody = "↓ $down  ↑ $up  ·  $outbound ($conns 活跃连接)"
                    synchronized(notificationLock) {
                        if (canPostSessionNotification(
                                coroutineActive = isActive,
                                serviceDestroyed = lifecycleCoordinator.isDestroyed,
                                instanceToken = instanceSessionToken.get(),
                                activeGlobalToken = activeNativeSessionToken.get(),
                                expectedToken = myToken,
                                lifecycleState = stateTracker.state,
                            )
                        ) {
                            activeOutboundLabel = outbound
                            if (nextTitle != lastTitle || nextBody != lastBody) {
                                lastTitle = nextTitle
                                lastBody = nextBody
                                val nm = getSystemService(NotificationManager::class.java)
                                nm?.notify(
                                    NOTIFICATION_ID,
                                    buildNotification(title = nextTitle, body = nextBody),
                                )
                            }
                        } else {
                            sessionEnded = true
                        }
                    }
                }
                if (sessionEnded) {
                    break
                }
                delay(5_000L)
            }
        }
    }

    override fun onRevoke() {
        // Intentionally do NOT call `super.onRevoke()`: AOSP `VpnService.onRevoke()` is not
        // `@CallSuper` and its entire implementation is an unconditional zero-arg `stopSelf()`
        // executed on a Binder thread. Calling it would prematurely trigger `onDestroy()` (cancelling
        // `serviceScope` mid-teardown) and bypass `stopSelfResult(capturedCommandId)`, killing a
        // newly started session on an Android-reused Service instance. Async `stopVpnSessionInternal`
        // -> `finalizeStopSession` -> `stopSelfResult(capturedCommandId)` exclusively owns teardown
        // and conditional service stop.
        val revokeResult = synchronized(notificationLock) {
            val res = lifecycleCoordinator.onRevokeRequested()
            if (res != null) {
                stateTracker.onSystemRevoked()
            }
            res
        }
        if (revokeResult == null) {
            return
        }
        RustClashTileService.requestTileSync(this)
        serviceScope.launch {
            sessionMutex.withLock {
                stopVpnSessionInternal(
                    revokedBySystem = true,
                    expectedEpoch = revokeResult.epoch,
                    stopStartId = revokeResult.capturedCommandId.takeIf { it > 0 },
                )
            }
        }
    }

    override fun onDestroy() {
        val isRevoked = lifecycleCoordinator.isRevokedForCurrentSession
        lifecycleCoordinator.onDestroy()
        telemetryJob?.cancel()
        telemetryJob = null
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        livePhysicalNetworks.clear()
        val tokenToStop = instanceSessionToken.getAndSet(0L)
        activeSessionEpoch = 0L
        engineRunningNative = false
        if (isCurrentOrIdleGlobalSession(tokenToStop)) {
            activeOutboundLabel = ""
            stateTracker.onStopped()
            clearFreshStatusSnapshot()
            RustClashTileService.requestTileSync(this)
        }
        stopForegroundAndClearNotification()
        if (tokenToStop != 0L) {
            val appCtx = applicationContext
            val statePath = filesDir.absolutePath
            Thread {
                captureStoppingSliceOnce(
                    context = appCtx,
                    stateDir = statePath,
                    token = tokenToStop,
                    revokedBySystem = isRevoked,
                    trigger = if (isRevoked) "revoked" else "service-destroy",
                )
                synchronized(nativeLifecycleLock) {
                    if (activeNativeSessionToken.compareAndSet(tokenToStop, 0L) && NativeBridge.isNativeLoaded) {
                        runCatching { NativeBridge.nativeStopVpn() }
                    }
                }
            }.start()
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private suspend fun stopVpnSessionInternal(
        revokedBySystem: Boolean,
        expectedEpoch: Long,
        stopStartId: Int? = null,
    ) {
        if (activeSessionEpoch > expectedEpoch) {
            return
        }
        val supersededAtEntry = synchronized(notificationLock) {
            val superseded = lifecycleCoordinator.isStopSupersededByNewerStart(expectedEpoch)
            if (!superseded) {
                if (revokedBySystem) {
                    if (lifecycleCoordinator.isRevokedForCurrentSession) {
                        stateTracker.onSystemRevoked()
                    }
                } else {
                    stateTracker.onStopRequested()
                }
            }
            superseded
        }

        val tokenToStop = instanceSessionToken.getAndSet(0L)
        activeSessionEpoch = 0L
        engineRunningNative = false
        cancelAndJoinTelemetryJob()
        debugSliceJob?.cancel()
        debugSliceJob = null
        unregisterNetworkHandoffObserver()
        unregisterScreenStateObserver()
        underlyingNetworkTracker.reset()
        livePhysicalNetworks.clear()

        if (tokenToStop != 0L) {
            // Capture disconnect diagnostic slice BEFORE stopping native runtime so session stats are preserved!
            captureStoppingSliceOnce(
                context = this,
                stateDir = filesDir.absolutePath,
                token = tokenToStop,
                revokedBySystem = revokedBySystem,
                trigger = if (revokedBySystem) "revoked" else "disconnect",
            )
            synchronized(nativeLifecycleLock) {
                if (activeNativeSessionToken.compareAndSet(tokenToStop, 0L) && NativeBridge.isNativeLoaded) {
                    runCatching { NativeBridge.nativeStopVpn() }
                }
            }
        }

        finalizeStopSession(
            notificationLock = notificationLock,
            coordinator = lifecycleCoordinator,
            stateTracker = stateTracker,
            expectedEpoch = expectedEpoch,
            supersededAtEntry = supersededAtEntry,
            stopStartId = stopStartId,
            isCurrentOrIdleGlobalSession = { isCurrentOrIdleGlobalSession(tokenToStop) },
            onClearSessionState = {
                activeOutboundLabel = ""
                clearFreshStatusSnapshot()
            },
            stopForegroundAndClearNotification = { stopForegroundAndClearNotification() },
            requestTileSync = { RustClashTileService.requestTileSync(this) },
            stopSelfWithResult = { cmdId -> stopSelfResult(cmdId) },
        )
    }

    private fun promoteForeground(title: String, body: String): Boolean {
        val notification = buildNotification(title, body)
        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        return runSafeServiceCall {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, fgType)
        }
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
        DebugLogManager.ensureAnomalyNotificationChannel(this)
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

        PerAppVpnPolicy.applyPackagesFailClosed(
            plan = perAppPlan,
            addAllowed = { pkg -> builder.addAllowedApplication(pkg) },
            addDisallowed = { pkg -> builder.addDisallowedApplication(pkg) },
        )
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
