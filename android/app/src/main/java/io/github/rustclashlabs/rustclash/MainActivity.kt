package io.github.rustclashlabs.rustclash

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Route
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import io.github.rustclashlabs.rustclash.ui.RustClashViewModel
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.MainDestination
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.screens.ActiveYamlEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.CustomRulesEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.HomeScreen
import io.github.rustclashlabs.rustclash.ui.screens.ImportPayloadBottomSheet
import io.github.rustclashlabs.rustclash.ui.screens.NodeEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.NodesScreen
import io.github.rustclashlabs.rustclash.ui.screens.ProfilesScreen
import io.github.rustclashlabs.rustclash.ui.screens.RulesScreen
import io.github.rustclashlabs.rustclash.ui.screens.SettingsScreen
import io.github.rustclashlabs.rustclash.ui.screens.homeAmbientGlow
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashTheme
import io.github.rustclashlabs.rustclash.vpn.DebugLogManager
import io.github.rustclashlabs.rustclash.vpn.NativeBridge
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.RustClashVpnService
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

class MainActivity : AppCompatActivity() {
    private val viewModel: RustClashViewModel by viewModels()
    private var pendingCameraQrFile: File? = null
    private var pendingExportYamlContent: String? = null
    private var pendingExportDebugFile: File? = null
    private var vpnConsentInFlight: Boolean = false

    companion object {
        private const val KEY_VPN_CONSENT_IN_FLIGHT = "vpn_consent_in_flight"
    }

    private fun exitDemoModeIfActive() {
        val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        if (viewModel.uiState.value.demoMode || prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)) {
            viewModel.setDemoMode(false)
        }
    }

    private fun reconcileDemoModeAfterAsyncMutation() {
        val current = viewModel.uiState.value
        val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val demoPref = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
        if (!current.demoMode && !demoPref) return
        if (current.vpnState != VpnLifecycleState.RUNNING) {
            if (NativeBridge.ensureLoaded()) {
                viewModel.setDemoMode(false)
            }
            return
        }
        lifecycleScope.launch {
            for (waitMs in longArrayOf(80L, 200L, 500L)) {
                delay(waitMs)
                val st = viewModel.uiState.value
                if (!st.demoMode || st.vpnState != VpnLifecycleState.RUNNING) break
                if (!NativeBridge.isNativeLoaded) break
                val demoStillActive = withContext(Dispatchers.IO) {
                    runCatching {
                        JSONObject(NativeBridge.nativeGetStatusJson()).optBoolean("demoActive", true)
                    }.getOrDefault(true)
                }
                if (!demoStillActive) {
                    viewModel.setDemoMode(false)
                    break
                }
            }
        }
    }

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        vpnConsentInFlight = false
        if (result.resultCode == RESULT_OK) {
            launchVpnForegroundService()
        } else {
            RustClashVpnService.stateTracker.onError("VPN 连接授权已被取消")
            viewModel.syncServiceStateImmediate()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* Foreground VPN works regardless; permission surfaces status bar notification */ }

    private val cameraQrFullLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicture(),
    ) { captured: Boolean ->
        val tempFile = pendingCameraQrFile
        pendingCameraQrFile = null
        if (!captured || tempFile == null || !tempFile.isFile) {
            runCatching { tempFile?.delete() }
            return@registerForActivityResult
        }
        lifecycleScope.launch {
            val bitmap = withContext(Dispatchers.IO) {
                try {
                    decodeSampledBitmapFromFile(tempFile, maxDim = 1600)
                } finally {
                    runCatching { tempFile.delete() }
                }
            }
            if (bitmap != null) {
                decodeQrBitmapAndImport(bitmap)
            } else {
                viewModel.emitUiMessage("未识别到有效的二维码，请对准清晰的节点或订阅二维码重试")
            }
        }
    }

    private val galleryQrImageLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri: Uri? ->
        if (uri != null) {
            lifecycleScope.launch {
                val decodedBitmap = withContext(Dispatchers.IO) {
                    decodeSampledBitmapFromUri(uri, maxDim = 1600)
                }
                if (decodedBitmap != null) {
                    decodeQrBitmapAndImport(decodedBitmap)
                } else {
                    viewModel.emitUiMessage("无法读取所选图片，请选择清晰的二维码截图")
                }
            }
        }
    }

    private val safImportYamlLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri != null) {
            lifecycleScope.launch {
                val text = withContext(Dispatchers.IO) {
                    runCatching {
                        contentResolver.openInputStream(uri)?.bufferedReader(Charsets.UTF_8)?.use { reader ->
                            reader.readText()
                        }
                    }.getOrNull()
                }
                if (!text.isNullOrBlank()) {
                    val autoSelect = viewModel.shouldAutoSelectOnImport()
                    viewModel.importUnifiedPayload(
                        rawPayload = text,
                        deduplicate = true,
                        autoSelect = autoSelect,
                        onSuccess = {
                            if (autoSelect) exitDemoModeIfActive() else reconcileDemoModeAfterAsyncMutation()
                        },
                    )
                } else {
                    viewModel.emitUiMessage("所选 YAML 配置文件为空或无法读取")
                }
            }
        }
    }

    private val safExportYamlLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-yaml"),
    ) { uri: Uri? ->
        val content = pendingExportYamlContent
        pendingExportYamlContent = null
        if (uri != null && !content.isNullOrBlank()) {
            lifecycleScope.launch {
                val ok = withContext(Dispatchers.IO) {
                    runCatching {
                        contentResolver.openOutputStream(uri)?.bufferedWriter(Charsets.UTF_8)?.use { writer ->
                            writer.write(content)
                        }
                        true
                    }.getOrDefault(false)
                }
                if (ok) {
                    viewModel.emitUiMessage("已导出脱敏 YAML（密码已隐去为 ***REDACTED***，适合排障分享，不可跨设备恢复密钥）")
                } else {
                    viewModel.emitUiMessage("导出 YAML 配置文件失败")
                }
            }
        }
    }

    private val safExportDebugLogLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri: Uri? ->
        val srcFile = pendingExportDebugFile
        pendingExportDebugFile = null
        if (uri != null && srcFile != null && srcFile.isFile) {
            lifecycleScope.launch {
                val ok = withContext(Dispatchers.IO) {
                    runCatching {
                        srcFile.inputStream().use { input ->
                            contentResolver.openOutputStream(uri)?.use { output ->
                                input.copyTo(output)
                            } ?: error("null output stream")
                        }
                        true
                    }.getOrDefault(false)
                }
                if (ok) {
                    viewModel.emitUiMessage("已保存脱敏诊断报告")
                } else {
                    viewModel.emitUiMessage("保存诊断报告失败")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        vpnConsentInFlight = savedInstanceState?.getBoolean(KEY_VPN_CONSENT_IN_FLIGHT, false) ?: false
        requestNotificationPermissionIfNeeded()
        handleIncomingShareOrDeepLinkIntent(intent)

        setContent {
            val state by viewModel.uiState.collectAsStateWithLifecycle()
            val snackbarHostState = remember { SnackbarHostState() }

            LaunchedEffect(viewModel) {
                viewModel.messages.collectLatest { msg ->
                    snackbarHostState.showSnackbar(msg)
                }
            }

            // Reconcile UI + SharedPreferences `demoMode` whenever a live engine mutation exits Demo Sandbox.
            LaunchedEffect(
                state.vpnState,
                state.demoMode,
                state.nodes,
                state.activeProfileId,
                state.routingPreset,
            ) {
                if (state.vpnState == VpnLifecycleState.RUNNING &&
                    state.demoMode &&
                    NativeBridge.isNativeLoaded
                ) {
                    val liveDemoActive = withContext(Dispatchers.IO) {
                        runCatching {
                            val obj = JSONObject(NativeBridge.nativeGetStatusJson())
                            if (obj.optBoolean("running", false)) {
                                obj.optBoolean("demoActive", true)
                            } else {
                                true
                            }
                        }.getOrDefault(true)
                    }
                    if (!liveDemoActive) {
                        viewModel.setDemoMode(false)
                    }
                }
            }

            RustClashTheme(themePreference = state.themePreference) {
                RustClashAppScaffold(
                    state = state,
                    snackbarHostState = snackbarHostState,
                    viewModel = viewModel,
                    onToggleVpn = ::onConnectToggleClicked,
                    onReadClipboard = ::readSystemClipboardText,
                    onLaunchCameraQr = ::launchFullResolutionCameraQr,
                    onLaunchGalleryQr = {
                        runCatching { galleryQrImageLauncher.launch("image/*") }
                    },
                    onImportYamlFile = {
                        runCatching {
                            safImportYamlLauncher.launch(arrayOf("application/x-yaml", "text/yaml", "text/plain", "*/*"))
                        }
                    },
                    onExportYamlFile = {
                        viewModel.exportActiveYamlForSaf { yaml ->
                            pendingExportYamlContent = yaml
                            runCatching { safExportYamlLauncher.launch("rustclash-config.yaml") }
                        }
                    },
                    onShareDebugReport = {
                        viewModel.prepareDebugReportForExport { reportFile ->
                            shareDebugReportFile(reportFile)
                        }
                    },
                    onSaveDebugReportToFile = {
                        viewModel.prepareDebugReportForExport { reportFile ->
                            pendingExportDebugFile = reportFile
                            runCatching { safExportDebugLogLauncher.launch(reportFile.name) }
                        }
                    },
                    onOpenBatteryOptimizationSettings = ::openBatteryOptimizationSettings,
                    onCopyExitIp = ::copyExitIpToClipboard,
                    onExitDemoModeSync = ::exitDemoModeIfActive,
                    onReconcileAsyncMutationDemoExit = ::reconcileDemoModeAfterAsyncMutation,
                )
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (isChangingConfigurations && vpnConsentInFlight) {
            outState.putBoolean(KEY_VPN_CONSENT_IN_FLIGHT, true)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingShareOrDeepLinkIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (!vpnConsentInFlight && RustClashVpnService.stateTracker.state == VpnLifecycleState.PREPARING) {
            RustClashVpnService.stateTracker.onStopped()
            viewModel.syncServiceStateImmediate()
        }
        viewModel.refreshAll()
        viewModel.startForegroundTicker()
    }

    override fun onPause() {
        viewModel.stopForegroundTicker()
        super.onPause()
    }

    private fun launchFullResolutionCameraQr() {
        runCatching {
            val dir = File(cacheDir, "qr_captures").apply { mkdirs() }
            val tempFile = File.createTempFile("qr_scan_", ".jpg", dir)
            pendingCameraQrFile = tempFile
            val uri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                tempFile,
            )
            cameraQrFullLauncher.launch(uri)
        }.onFailure {
            pendingCameraQrFile = null
            viewModel.emitUiMessage("无法启动系统相机扫码")
        }
    }

    private fun calculateInSampleSize(width: Int, height: Int, maxDim: Int): Int {
        var inSampleSize = 1
        if (height > maxDim || width > maxDim) {
            val halfH = height / 2
            val halfW = width / 2
            while ((halfH / inSampleSize) >= maxDim || (halfW / inSampleSize) >= maxDim) {
                inSampleSize *= 2
            }
        }
        return inSampleSize
    }

    private fun decodeSampledBitmapFromFile(file: File, maxDim: Int): Bitmap? = runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = calculateInSampleSize(bounds.outWidth, bounds.outHeight, maxDim)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        BitmapFactory.decodeFile(file.absolutePath, decodeOpts)
    }.getOrNull()

    private fun decodeSampledBitmapFromUri(uri: Uri, maxDim: Int): Bitmap? = runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        contentResolver.openInputStream(uri)?.use { stream ->
            BitmapFactory.decodeStream(stream, null, bounds)
        }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = calculateInSampleSize(bounds.outWidth, bounds.outHeight, maxDim)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        contentResolver.openInputStream(uri)?.use { stream ->
            BitmapFactory.decodeStream(stream, null, decodeOpts)
        }
    }.getOrNull()

    private fun handleIncomingShareOrDeepLinkIntent(incoming: Intent?) {
        if (incoming == null) return
        if (incoming.getBooleanExtra(DebugLogManager.EXTRA_AUTO_SHARE_DEBUG_REPORT, false)) {
            incoming.removeExtra(DebugLogManager.EXTRA_AUTO_SHARE_DEBUG_REPORT)
            DebugLogManager.cancelAnomalyNotification(this)
            viewModel.prepareDebugReportForExport { reportFile ->
                shareDebugReportFile(reportFile)
            }
            return
        }
        val extracted = NodeImportSupport.extractImportPayloadFromIntent(
            action = incoming.action,
            mimeType = incoming.type,
            extraText = incoming.getStringExtra(Intent.EXTRA_TEXT),
            dataUriString = incoming.dataString,
        ) ?: return

        // Consume intent extras so configuration changes never re-import twice
        incoming.action = Intent.ACTION_MAIN
        incoming.data = null
        incoming.removeExtra(Intent.EXTRA_TEXT)

        // Stage external deep link / share payload for explicit user confirmation (never silent-import)
        viewModel.stageExternalImportPayload(extracted)
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun onConnectToggleClicked() {
        val currentState = RustClashVpnService.stateTracker.state
        if (currentState == VpnLifecycleState.RUNNING ||
            currentState == VpnLifecycleState.STARTING ||
            currentState == VpnLifecycleState.RECONNECTING
        ) {
            val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
                action = RustClashVpnService.ACTION_STOP_VPN
            }
            RustClashVpnService.safeRequestStopVpn(this, stopIntent)
            viewModel.syncServiceStateImmediate()
            return
        }
        if (currentState == VpnLifecycleState.STOPPING ||
            (currentState == VpnLifecycleState.PREPARING && vpnConsentInFlight)
        ) {
            return
        }

        RustClashVpnService.stateTracker.onPrepareRequested()
        viewModel.syncServiceStateImmediate()
        val prepareIntent = runCatching { VpnService.prepare(this) }.getOrElse { err ->
            vpnConsentInFlight = false
            RustClashVpnService.stateTracker.onError("无法请求系统 VPN 授权：${err.message ?: "系统限制"}")
            viewModel.syncServiceStateImmediate()
            return
        }
        if (prepareIntent != null) {
            vpnConsentInFlight = true
            runCatching {
                vpnPrepareLauncher.launch(prepareIntent)
            }.onFailure { err ->
                vpnConsentInFlight = false
                RustClashVpnService.stateTracker.onError("无法拉起系统 VPN 授权弹窗：${err.message ?: "系统限制"}")
                viewModel.syncServiceStateImmediate()
            }
        } else {
            vpnConsentInFlight = false
            launchVpnForegroundService()
        }
    }

    private fun launchVpnForegroundService() {
        val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val demoMode = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
        RustClashVpnService.stateTracker.onStartRequested()
        viewModel.syncServiceStateImmediate()
        val startIntent = Intent(this, RustClashVpnService::class.java).apply {
            action = RustClashVpnService.ACTION_START_VPN
            putExtra(RustClashVpnService.EXTRA_DEMO_MODE, demoMode)
        }
        if (!RustClashVpnService.safeStartVpnForegroundService(this, startIntent)) {
            val errMsg = "系统限制了 VPN 前台服务启动，请保持应用在前台后重试连接"
            RustClashVpnService.stateTracker.onError(errMsg)
            viewModel.syncServiceStateImmediate()
            viewModel.emitUiMessage(errMsg)
        }
    }

    private fun readSystemClipboardText(): String? {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return null
        val clip = cm.primaryClip ?: return null
        if (clip.itemCount <= 0) return null
        return clip.getItemAt(0)?.coerceToText(this)?.toString()?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun copyExitIpToClipboard(ip: String) {
        val cleaned = ip.trim()
        if (cleaned.isEmpty()) return
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Exit IP", cleaned))
            viewModel.emitUiMessage("已复制落地 IP：$cleaned")
        } else {
            viewModel.emitUiMessage("无法访问系统剪贴板")
        }
    }

    private fun decodeQrBitmapAndImport(rawBitmap: Bitmap) {
        lifecycleScope.launch {
            val decodedText = withContext(Dispatchers.Default) {
                val argbBitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    rawBitmap.config == Bitmap.Config.HARDWARE
                ) {
                    rawBitmap.copy(Bitmap.Config.ARGB_8888, false)
                } else if (rawBitmap.config != Bitmap.Config.ARGB_8888) {
                    rawBitmap.copy(Bitmap.Config.ARGB_8888, false)
                } else {
                    rawBitmap
                } ?: return@withContext null

                val w = argbBitmap.width
                val h = argbBitmap.height
                val pixels = IntArray(w * h)
                argbBitmap.getPixels(pixels, 0, w, 0, 0, w, h)
                NodeImportSupport.decodeQrCodeFromArgbPixels(pixels, w, h)
            }

            if (!decodedText.isNullOrBlank()) {
                val autoSelect = viewModel.shouldAutoSelectOnImport()
                viewModel.importUnifiedPayload(
                    rawPayload = decodedText,
                    deduplicate = true,
                    autoSelect = autoSelect,
                    onSuccess = {
                        if (autoSelect) exitDemoModeIfActive() else reconcileDemoModeAfterAsyncMutation()
                    },
                )
            } else {
                viewModel.emitUiMessage("未识别到有效的二维码，请对准清晰的节点或订阅二维码重试")
            }
        }
    }

    private fun shareDebugReportFile(reportFile: File) {
        runCatching {
            val uri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                reportFile,
            )
            val sendIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "RustClash Android 诊断报告 (${reportFile.name})")
                clipData = android.content.ClipData.newRawUri(reportFile.name, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            val chooser = Intent.createChooser(sendIntent, "分享或发送诊断报告").apply {
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(chooser)
        }.onFailure {
            viewModel.emitUiMessage("无法打开系统分享面板，请使用「保存到手机」导出")
        }
    }

    private fun openBatteryOptimizationSettings() {
        val launchedIgnoreList = runCatching {
            val intent = Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            startActivity(intent)
        }.isSuccess
        if (!launchedIgnoreList) {
            runCatching {
                val fallback = Intent(
                    android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", packageName, null),
                )
                startActivity(fallback)
            }.onFailure {
                viewModel.emitUiMessage("无法打开系统电池优化设置页面，请前往系统设置手动开启后台不受限制")
            }
        }
    }
}

@Composable
internal fun RustClashAppScaffold(
    state: AppUiState,
    snackbarHostState: SnackbarHostState,
    viewModel: RustClashViewModel,
    onToggleVpn: () -> Unit,
    onReadClipboard: () -> String?,
    onLaunchCameraQr: () -> Unit,
    onLaunchGalleryQr: () -> Unit,
    onImportYamlFile: () -> Unit = {},
    onExportYamlFile: () -> Unit = {},
    onShareDebugReport: () -> Unit = {},
    onSaveDebugReportToFile: () -> Unit = {},
    onOpenBatteryOptimizationSettings: () -> Unit = {},
    onCopyExitIp: (String) -> Unit = {},
    onExitDemoModeSync: () -> Unit = {},
    onReconcileAsyncMutationDemoExit: () -> Unit = {},
) {
    val extColors = LocalRustClashColors.current
    var currentDestination by rememberSaveable { mutableStateOf(MainDestination.HOME) }
    var rulesInitialTab by rememberSaveable { mutableIntStateOf(0) }

    LaunchedEffect(currentDestination) {
        viewModel.setActiveDestination(currentDestination)
    }

    var showImportSheet by remember { mutableStateOf(false) }
    var showNodeEditor by remember { mutableStateOf(false) }
    var editingNode by remember { mutableStateOf<ProxyNodeItem?>(null) }
    var showCustomRulesDialog by remember { mutableStateOf(false) }
    var showYamlEditorDialog by remember { mutableStateOf(false) }
    var awaitingExternalImportDemoExit by remember { mutableStateOf(false) }

    LaunchedEffect(state.pendingExternalImportPayload, state.isImporting, state.modalError) {
        if (awaitingExternalImportDemoExit && !state.isImporting) {
            if (state.pendingExternalImportPayload == null && state.modalError == null) {
                awaitingExternalImportDemoExit = false
                onExitDemoModeSync()
            } else if (state.modalError != null) {
                awaitingExternalImportDemoExit = false
            }
        }
    }

    val haptic = LocalHapticFeedback.current
    val rootHomeGlowAlpha by animateFloatAsState(
        targetValue = if (currentDestination == MainDestination.HOME && state.vpnState == VpnLifecycleState.RUNNING) 1f else 0f,
        animationSpec = tween(durationMillis = 320),
        label = "rootHomeAmbientGlow",
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .homeAmbientGlow(extColors = extColors, alpha = rootHomeGlowAlpha),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = Color.Transparent,
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            bottomBar = {
                androidx.compose.foundation.layout.Column {
                    HorizontalDivider(
                        thickness = 0.8.dp,
                        color = extColors.hairline.copy(alpha = if (extColors.isDark) 0.7f else 0.75f),
                    )
                    NavigationBar(
                        containerColor = extColors.navBarSurface,
                        tonalElevation = 0.dp,
                    ) {
                        MainDestination.entries.forEach { dest ->
                            val selected = currentDestination == dest
                            NavigationBarItem(
                                selected = selected,
                                onClick = {
                                    if (currentDestination != dest) {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        currentDestination = dest
                                    }
                                },
                                icon = {
                                    val icon = when (dest) {
                                        MainDestination.HOME -> if (selected) Icons.Rounded.Home else Icons.Outlined.Home
                                        MainDestination.NODES -> if (selected) Icons.Rounded.Dns else Icons.Outlined.Dns
                                        MainDestination.RULES -> if (selected) Icons.Rounded.Route else Icons.Outlined.Route
                                        MainDestination.PROFILES -> if (selected) Icons.Rounded.Description else Icons.Outlined.Description
                                        MainDestination.SETTINGS -> if (selected) Icons.Rounded.Settings else Icons.Outlined.Settings
                                    }
                                    Icon(imageVector = icon, contentDescription = dest.label)
                                },
                                label = {
                                    Text(
                                        text = dest.label,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                                        maxLines = 1,
                                        softWrap = false,
                                    )
                                },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = extColors.onNavSelected,
                                    selectedTextColor = extColors.onNavSelected,
                                    indicatorColor = extColors.navIndicator,
                                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                ),
                            )
                        }
                    }
                }
            },
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                Crossfade(
                    targetState = currentDestination,
                    animationSpec = tween(durationMillis = 140),
                    label = "mainDestination",
                ) { destination ->
                    when (destination) {
                        MainDestination.HOME -> HomeScreen(
                            state = state,
                            onToggleVpn = {
                                if (state.vpnState in setOf(
                                        VpnLifecycleState.DISCONNECTED,
                                        VpnLifecycleState.ERROR,
                                        VpnLifecycleState.REVOKED,
                                    ) &&
                                    state.nodes.isEmpty() &&
                                    !state.demoMode &&
                                    state.routingPreset != io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi.DIRECT
                                ) {
                                    viewModel.clearModalError()
                                    showImportSheet = true
                                } else {
                                    onToggleVpn()
                                }
                            },
                            onOpenQuickImport = {
                                viewModel.clearModalError()
                                showImportSheet = true
                            },
                            onSelectRoutingPreset = viewModel::setRoutingPreset,
                            onNavigateToNodes = { currentDestination = MainDestination.NODES },
                            onNavigateToRules = { tab ->
                                rulesInitialTab = tab
                                currentDestination = MainDestination.RULES
                            },
                            onTestActiveLatency = {
                                if (state.effectiveOutbound != "DIRECT" && state.effectiveOutbound != "REJECT") {
                                    viewModel.testLatency(state.effectiveOutbound)
                                } else {
                                    viewModel.testLatency(null)
                                }
                            },
                            onDismissError = viewModel::clearLastError,
                            onShareDebugReport = onShareDebugReport,
                            onDismissDebugAnomaly = viewModel::dismissDebugAnomaly,
                            onRefreshExitIp = { viewModel.probeExitIp(forceRefresh = true) },
                            onCopyExitIp = onCopyExitIp,
                            drawAmbientGlow = false,
                        )

                        MainDestination.NODES -> NodesScreen(
                            state = state,
                            onSearchQueryChange = viewModel::setNodeSearchQuery,
                            onToggleSortByDelay = viewModel::toggleSortNodesByDelay,
                            onSelectGroupTab = viewModel::selectGroupTab,
                            onSelectProxyInGroup = viewModel::selectProxyInGroup,
                            onToggleFavorite = viewModel::toggleFavoriteNode,
                            onTestAllDelays = { viewModel.testLatency(null) },
                            onTestSingleDelay = { name -> viewModel.testLatency(name) },
                            onOpenImportSheet = {
                                viewModel.clearModalError()
                                showImportSheet = true
                            },
                            onImportClipboardDirect = {
                                val clip = onReadClipboard()
                                if (!clip.isNullOrBlank()) {
                                    val autoSelect = viewModel.shouldAutoSelectOnImport()
                                    viewModel.importUnifiedPayload(
                                        rawPayload = clip,
                                        deduplicate = true,
                                        autoSelect = autoSelect,
                                        onSuccess = {
                                            if (autoSelect) onExitDemoModeSync() else onReconcileAsyncMutationDemoExit()
                                        },
                                    )
                                } else {
                                    viewModel.clearModalError()
                                    showImportSheet = true
                                    viewModel.emitUiMessage("剪贴板为空，请粘贴节点链接或订阅地址")
                                }
                            },
                            onOpenQrCamera = onLaunchCameraQr,
                            onOpenManualCreate = {
                                viewModel.clearModalError()
                                editingNode = null
                                showNodeEditor = true
                            },
                            onOpenNodeEdit = { item ->
                                viewModel.clearModalError()
                                editingNode = item
                                showNodeEditor = true
                            },
                            onDeleteNode = { nodeName ->
                                viewModel.deleteNode(nodeName)
                                onReconcileAsyncMutationDemoExit()
                            },
                            onDeduplicateNodes = {
                                viewModel.deduplicateNodes()
                                onReconcileAsyncMutationDemoExit()
                            },
                        )

                        MainDestination.RULES -> RulesScreen(
                            state = state,
                            requestedSubTab = rulesInitialTab,
                            onSelectRoutingPreset = viewModel::setRoutingPreset,
                            onUpdateGeoData = viewModel::updateGeoDataNow,
                            onOpenCustomRuleEditor = {
                                viewModel.loadActiveYamlAndRules {
                                    viewModel.clearModalError()
                                    showCustomRulesDialog = true
                                }
                            },
                            onSetDiagnosticsFilter = viewModel::setDiagnosticsFilter,
                            onClearDiagnostics = viewModel::clearDiagnostics,
                            onExplainTarget = viewModel::explainTargetRule,
                            onDiagnoseSite = viewModel::diagnoseSite,
                            onNavigateToNodes = { currentDestination = MainDestination.NODES },
                            onRuleSearchChange = viewModel::setRuleSearchQuery,
                        )

                        MainDestination.PROFILES -> ProfilesScreen(
                            state = state,
                            onOpenImportSheet = {
                                viewModel.clearModalError()
                                showImportSheet = true
                            },
                            onActivateProfile = { profileId ->
                                viewModel.activateProfile(profileId)
                                onReconcileAsyncMutationDemoExit()
                            },
                            onRefreshProfile = viewModel::refreshProfileSubscription,
                            onDeleteProfile = viewModel::deleteProfile,
                            onRenameProfile = viewModel::renameProfile,
                            onUpdateProfileAutoUpdate = viewModel::updateProfileAutoUpdate,
                            onDismissOpSummary = viewModel::dismissProfileOpSummary,
                            onOpenCustomRulesEditor = {
                                viewModel.loadActiveYamlAndRules {
                                    viewModel.clearModalError()
                                    showCustomRulesDialog = true
                                }
                            },
                            onOpenYamlEditor = {
                                viewModel.loadActiveYamlAndRules {
                                    viewModel.clearModalError()
                                    showYamlEditorDialog = true
                                }
                            },
                            onImportYamlFile = onImportYamlFile,
                            onExportYamlFile = onExportYamlFile,
                        )

                        MainDestination.SETTINGS -> SettingsScreen(
                            state = state,
                            onSetThemePreference = viewModel::setThemePreference,
                            onRequestInstalledApps = viewModel::loadInstalledAppsIfNeeded,
                            onSavePerAppPolicy = viewModel::savePerAppPolicy,
                            onSetEnableIpv6 = viewModel::setEnableIpv6,
                            onSetDemoMode = viewModel::setDemoMode,
                            onFlushDns = viewModel::flushDnsCache,
                            onSetShowSystemApps = viewModel::setShowSystemApps,
                            onSetDefaultSubAutoUpdateSecs = viewModel::setDefaultSubAutoUpdateSecs,
                            onClearSettingsNotice = viewModel::clearSettingsSheetNotice,
                            onSetDebugLogEnabled = viewModel::setDebugLogEnabled,
                            onSetDebugSliceIntervalSecs = viewModel::setDebugSliceIntervalSecs,
                            onCaptureDebugSliceNow = viewModel::captureDebugSliceNow,
                            onShareDebugReport = onShareDebugReport,
                            onSaveDebugReportToFile = onSaveDebugReportToFile,
                            onClearDebugLogs = viewModel::clearAllDebugLogs,
                            onRefreshDebugSummary = viewModel::refreshDebugLogSummary,
                            onDismissDebugAnomaly = viewModel::dismissDebugAnomaly,
                            onOpenBatteryOptimizationSettings = onOpenBatteryOptimizationSettings,
                        )
                    }
                }
            }
        }
    }

    if (showImportSheet) {
        ImportPayloadBottomSheet(
            isImporting = state.isImporting,
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            defaultSubAutoUpdateSecs = state.defaultSubAutoUpdateSecs,
            defaultAutoSelect = viewModel.shouldAutoSelectOnImport(),
            onDismiss = {
                viewModel.cancelImportAndClearModalError()
                showImportSheet = false
            },
            onReadClipboard = onReadClipboard,
            onLaunchCameraQr = onLaunchCameraQr,
            onLaunchGalleryQr = onLaunchGalleryQr,
            onOpenManualForm = {
                viewModel.cancelImportAndClearModalError()
                editingNode = null
                showNodeEditor = true
            },
            onSubmitImportDetailed = { payload, dedup, autoSel, subSecs ->
                viewModel.importUnifiedPayload(
                    rawPayload = payload,
                    deduplicate = dedup,
                    autoSelect = autoSel,
                    subscriptionAutoUpdateSecs = subSecs,
                    onSuccess = {
                        if (autoSel) onExitDemoModeSync() else onReconcileAsyncMutationDemoExit()
                        viewModel.clearModalError()
                        showImportSheet = false
                    },
                )
            },
        )
    }

    if (showNodeEditor) {
        NodeEditorDialog(
            existingNode = editingNode,
            isSaving = state.isSavingModal,
            backendError = state.modalError,
            onClearBackendError = viewModel::clearModalError,
            defaultAutoSelect = editingNode == null && viewModel.shouldAutoSelectOnImport(),
            onDismiss = {
                if (!state.isSavingModal) {
                    viewModel.clearModalError()
                    showNodeEditor = false
                }
            },
            onSave = { originalName, nodeJson, autoSelect ->
                viewModel.upsertNode(
                    originalName = originalName,
                    nodeJson = nodeJson,
                    autoSelect = autoSelect,
                    onSuccess = {
                        if (autoSelect) onExitDemoModeSync() else onReconcileAsyncMutationDemoExit()
                        viewModel.clearModalError()
                        showNodeEditor = false
                    },
                )
            },
        )
    }

    if (showCustomRulesDialog) {
        CustomRulesEditorDialog(
            initialRulesText = state.editableRulesText,
            isSaving = state.isSavingModal,
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            onDismiss = {
                if (!state.isSavingModal) {
                    viewModel.clearModalError()
                    showCustomRulesDialog = false
                }
            },
            onSaveRules = { text ->
                viewModel.saveCustomRules(
                    rulesText = text,
                    onSuccess = {
                        onExitDemoModeSync()
                        viewModel.clearModalError()
                        showCustomRulesDialog = false
                    },
                )
            },
        )
    }

    if (showYamlEditorDialog) {
        ActiveYamlEditorDialog(
            initialYamlText = state.activeYamlRedacted,
            isSaving = state.isSavingModal,
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            onDismiss = {
                if (!state.isSavingModal) {
                    viewModel.clearModalError()
                    showYamlEditorDialog = false
                }
            },
            onSaveYaml = { yaml ->
                viewModel.saveActiveYaml(
                    yamlText = yaml,
                    onSuccess = {
                        onExitDemoModeSync()
                        viewModel.clearModalError()
                        showYamlEditorDialog = false
                    },
                )
            },
        )
    }

    val pendingExternalPayload = state.pendingExternalImportPayload
    if (pendingExternalPayload != null) {
        ExternalImportConfirmDialog(
            rawPayload = pendingExternalPayload,
            isImporting = state.isImporting,
            errorMessage = state.modalError,
            onDismiss = {
                awaitingExternalImportDemoExit = false
                viewModel.dismissPendingExternalImport()
            },
            onConfirm = { switchImmediately, enableAutoUpdate ->
                awaitingExternalImportDemoExit = true
                viewModel.confirmPendingExternalImport(
                    autoSelect = switchImmediately,
                    enableSubscriptionAutoUpdate = enableAutoUpdate,
                )
            },
        )
    }
}

@Composable
private fun ExternalImportConfirmDialog(
    rawPayload: String,
    isImporting: Boolean,
    errorMessage: String?,
    onDismiss: () -> Unit,
    onConfirm: (switchImmediately: Boolean, enableSubscriptionAutoUpdate: Boolean) -> Unit,
) {
    val ext = LocalRustClashColors.current
    val preview = remember(rawPayload) {
        NodeImportSupport.classifyExternalImportPreview(rawPayload)
    }
    var switchImmediately by rememberSaveable(rawPayload) { mutableStateOf(false) }
    var enableAutoUpdate by rememberSaveable(rawPayload) { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = {
            if (!isImporting) {
                onDismiss()
            }
        },
        title = {
            Text(
                text = if (preview.isRemoteSubscription) {
                    "确认导入外部远程订阅"
                } else {
                    "确认外部导入请求"
                },
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = ext.cardSubtle,
                    border = BorderStroke(1.dp, ext.hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = preview.sanitizedSummary,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        if (!preview.targetHost.isNullOrBlank()) {
                            Text(
                                text = "目标主机：${preview.targetHost}",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                color = ext.emerald,
                            )
                        }
                        if (!preview.profileDisplayHint.isNullOrBlank()) {
                            Text(
                                text = "配置名称：${preview.profileDisplayHint}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (preview.sanitizedPayloadPreview.isNotBlank()) {
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = preview.sanitizedPayloadPreview,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }

                if (!preview.securityWarning.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = ext.amberContainer,
                        border = BorderStroke(1.dp, ext.amber.copy(alpha = 0.5f)),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = preview.securityWarning,
                            style = MaterialTheme.typography.bodySmall,
                            color = ext.onAmberContainer,
                            modifier = Modifier.padding(10.dp),
                        )
                    }
                }

                if (!errorMessage.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = ext.dangerContainer,
                        border = BorderStroke(1.dp, ext.danger.copy(alpha = 0.5f)),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = NodeImportSupport.redactSecretsForUi(errorMessage),
                            style = MaterialTheme.typography.bodySmall,
                            color = ext.onDangerContainer,
                            modifier = Modifier.padding(10.dp),
                        )
                    }
                }

                HorizontalDivider(color = ext.hairline)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !isImporting) {
                            switchImmediately = !switchImmediately
                        }
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(
                        checked = switchImmediately,
                        onCheckedChange = if (isImporting) {
                            null
                        } else {
                            { switchImmediately = it }
                        },
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "立即切换到导入的节点/配置",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = "Switch to imported node/profile immediately",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                if (preview.isRemoteSubscription) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(enabled = !isImporting) {
                                enableAutoUpdate = !enableAutoUpdate
                            }
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = enableAutoUpdate,
                            onCheckedChange = if (isImporting) {
                                null
                            } else {
                                { enableAutoUpdate = it }
                            },
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "允许后台定时自动更新此远程订阅",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                            )
                            Text(
                                text = "仅在您完全信任该订阅源时开启",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        },
        dismissButton = {
            TextButton(
                enabled = !isImporting,
                onClick = onDismiss,
            ) {
                Text("取消 (Cancel)")
            }
        },
        confirmButton = {
            Button(
                enabled = !isImporting,
                onClick = {
                    onConfirm(switchImmediately, preview.isRemoteSubscription && enableAutoUpdate)
                },
            ) {
                Text(if (isImporting) "正在导入…" else "确认导入 (Import)")
            }
        },
    )
}

