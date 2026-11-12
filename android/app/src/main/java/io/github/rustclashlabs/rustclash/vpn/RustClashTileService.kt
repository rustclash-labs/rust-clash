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

/**
 * Android Quick Settings Tile allowing 1-tap VPN connect/disconnect from the system notification shade.
 */
class RustClashTileService : TileService() {

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

    override fun onClick() {
        super.onClick()
        val currentState = RustClashVpnService.stateTracker.state
        if (currentState == VpnLifecycleState.RUNNING || currentState == VpnLifecycleState.STARTING) {
            val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
                action = RustClashVpnService.ACTION_STOP_VPN
            }
            startService(stopIntent)
            syncTileUi()
            return
        }

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
            val demoMode = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
            val startIntent = Intent(this, RustClashVpnService::class.java).apply {
                action = RustClashVpnService.ACTION_START_VPN
                putExtra(RustClashVpnService.EXTRA_DEMO_MODE, demoMode)
            }
            ContextCompat.startForegroundService(this, startIntent)
            syncTileUi()
        } else {
            // VPN permission has not yet been granted by the user; open MainActivity to show consent dialog.
            val openIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            launchMainActivityAndCollapse(openIntent)
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
