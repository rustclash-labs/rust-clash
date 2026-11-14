package io.github.rustclashlabs.rustclash.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.github.rustclashlabs.rustclash.MainActivity
import io.github.rustclashlabs.rustclash.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Android Quick Settings Tile allowing 1-tap VPN connect/disconnect from the system notification shade.
 */
class RustClashTileService : TileService() {
    private val tileScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var clickJob: Job? = null

    companion object {
        fun requestTileSync(context: Context) {
            runCatching {
                requestListeningState(
                    context.applicationContext,
                    ComponentName(context.applicationContext, RustClashTileService::class.java),
                )
            }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        syncTileUi()
    }

    override fun onDestroy() {
        tileScope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        val currentState = RustClashVpnService.stateTracker.state
        if (currentState == VpnLifecycleState.RUNNING ||
            currentState == VpnLifecycleState.STARTING ||
            currentState == VpnLifecycleState.RECONNECTING
        ) {
            val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
                action = RustClashVpnService.ACTION_STOP_VPN
            }
            startService(stopIntent)
            syncTileUi()
            return
        }
        if (currentState == VpnLifecycleState.PREPARING || currentState == VpnLifecycleState.STOPPING) {
            syncTileUi()
            return
        }
        if (clickJob?.isActive == true) {
            return
        }

        val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val demoMode = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
        val appContext = applicationContext
        val stateDirPath = filesDir.absolutePath

        clickJob = tileScope.launch {
            val shouldOpenAppForEmptyNodes = if (demoMode) {
                false
            } else {
                withContext(Dispatchers.IO) {
                    if (!NativeBridge.ensureLoaded()) {
                        false
                    } else {
                        val snap = io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers.parseNodeManagerSnapshot(
                            NativeBridge.nativeGetNodeManagerSnapshot(stateDirPath),
                        )
                        snap.ok &&
                            snap.nodes.isEmpty() &&
                            snap.routingPreset != io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi.DIRECT
                    }
                }
            }

            if (shouldOpenAppForEmptyNodes) {
                val openIntent = Intent(this@RustClashTileService, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
                launchMainActivityAndCollapse(openIntent)
                return@launch
            }

            val prepareIntent = VpnService.prepare(this@RustClashTileService)
            if (prepareIntent == null) {
                val startIntent = Intent(appContext, RustClashVpnService::class.java).apply {
                    action = RustClashVpnService.ACTION_START_VPN
                    putExtra(RustClashVpnService.EXTRA_DEMO_MODE, demoMode)
                }
                ContextCompat.startForegroundService(appContext, startIntent)
                syncTileUi()
            } else {
                // VPN permission has not yet been granted by the user; open MainActivity to show consent dialog.
                val openIntent = Intent(this@RustClashTileService, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
                launchMainActivityAndCollapse(openIntent)
            }
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun launchMainActivityAndCollapse(openIntent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this,
                100,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(openIntent)
        }
    }

    private fun syncTileUi() {
        val tile = qsTile ?: return
        val state = RustClashVpnService.stateTracker.state
        tile.label = getString(R.string.app_name)
        when (state) {
            VpnLifecycleState.RUNNING -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = RustClashVpnService.activeOutboundLabel.ifBlank { "已连接" }
                }
            }
            VpnLifecycleState.STARTING,
            VpnLifecycleState.PREPARING,
            VpnLifecycleState.RECONNECTING,
            VpnLifecycleState.STOPPING,
            -> {
                tile.state = Tile.STATE_UNAVAILABLE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "切换中…"
                }
            }
            VpnLifecycleState.DISCONNECTED,
            VpnLifecycleState.ERROR,
            VpnLifecycleState.REVOKED,
            -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "未连接"
                }
            }
        }
        tile.updateTile()
    }
}
