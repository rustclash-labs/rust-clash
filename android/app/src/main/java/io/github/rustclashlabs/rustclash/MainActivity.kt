package io.github.rustclashlabs.rustclash

import android.Manifest
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
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
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
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashTheme
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.RustClashVpnService
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {
    private val viewModel: RustClashViewModel by viewModels()
    private var pendingCameraQrFile: File? = null
    private var pendingExportYamlContent: String? = null

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
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
                    viewModel.importUnifiedPayload(text, deduplicate = true, autoSelect = true)
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
                    viewModel.emitUiMessage("已导出脱敏 YAML 配置文件")
                } else {
                    viewModel.emitUiMessage("导出 YAML 配置文件失败")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
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
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingShareOrDeepLinkIntent(intent)
    }

    override fun onResume() {
        super.onResume()
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

        viewModel.importUnifiedPayload(extracted, deduplicate = true, autoSelect = true)
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
        if (currentState == VpnLifecycleState.RUNNING || currentState == VpnLifecycleState.STARTING) {
            val stopIntent = Intent(this, RustClashVpnService::class.java).apply {
                action = RustClashVpnService.ACTION_STOP_VPN
            }
            startService(stopIntent)
            viewModel.syncServiceStateImmediate()
            return
        }

        RustClashVpnService.stateTracker.onPrepareRequested()
        viewModel.syncServiceStateImmediate()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPrepareLauncher.launch(prepareIntent)
        } else {
            launchVpnForegroundService()
        }
    }

    private fun launchVpnForegroundService() {
        val prefs = getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val demoMode = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
        val startIntent = Intent(this, RustClashVpnService::class.java).apply {
            action = RustClashVpnService.ACTION_START_VPN
            putExtra(RustClashVpnService.EXTRA_DEMO_MODE, demoMode)
        }
        ContextCompat.startForegroundService(this, startIntent)
    }

    private fun readSystemClipboardText(): String? {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return null
        val clip = cm.primaryClip ?: return null
        if (clip.itemCount <= 0) return null
        return clip.getItemAt(0)?.coerceToText(this)?.toString()?.trim()?.takeIf { it.isNotEmpty() }
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
                viewModel.importUnifiedPayload(decodedText, deduplicate = true, autoSelect = true)
            } else {
                viewModel.emitUiMessage("未识别到有效的二维码，请对准清晰的节点或订阅二维码重试")
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

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        bottomBar = {
            androidx.compose.foundation.layout.Column {
                HorizontalDivider(thickness = 1.dp, color = extColors.hairline)
                NavigationBar(
                    containerColor = extColors.cardSurface,
                    tonalElevation = 0.dp,
                ) {
                    MainDestination.entries.forEach { dest ->
                        val selected = currentDestination == dest
                        NavigationBarItem(
                            selected = selected,
                            onClick = { currentDestination = dest },
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
                                    maxLines = 1,
                                    softWrap = false,
                                )
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = extColors.emerald,
                                selectedTextColor = extColors.emerald,
                                indicatorColor = extColors.emeraldContainer.copy(alpha = 0.65f),
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
            when (currentDestination) {
                MainDestination.HOME -> HomeScreen(
                    state = state,
                    onToggleVpn = {
                        if (state.vpnState == VpnLifecycleState.DISCONNECTED &&
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
                            viewModel.importUnifiedPayload(clip, deduplicate = true, autoSelect = true)
                        } else {
                            viewModel.clearModalError()
                            showImportSheet = true
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
                    onDeleteNode = viewModel::deleteNode,
                    onDeduplicateNodes = viewModel::deduplicateNodes,
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
                    onRuleSearchChange = viewModel::setRuleSearchQuery,
                )

                MainDestination.PROFILES -> ProfilesScreen(
                    state = state,
                    onOpenImportSheet = {
                        viewModel.clearModalError()
                        showImportSheet = true
                    },
                    onActivateProfile = viewModel::activateProfile,
                    onRefreshProfile = viewModel::refreshProfileSubscription,
                    onDeleteProfile = viewModel::deleteProfile,
                    onRenameProfile = viewModel::renameProfile,
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
                )
            }
        }
    }

    if (showImportSheet) {
        ImportPayloadBottomSheet(
            isImporting = state.isImporting,
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            onDismiss = {
                viewModel.clearModalError()
                showImportSheet = false
            },
            onReadClipboard = onReadClipboard,
            onLaunchCameraQr = onLaunchCameraQr,
            onLaunchGalleryQr = onLaunchGalleryQr,
            onOpenManualForm = {
                viewModel.clearModalError()
                editingNode = null
                showNodeEditor = true
            },
            onSubmitImport = { payload, dedup, autoSel ->
                viewModel.importUnifiedPayload(
                    rawPayload = payload,
                    deduplicate = dedup,
                    autoSelect = autoSel,
                    onSuccess = {
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
            backendError = state.modalError,
            onClearBackendError = viewModel::clearModalError,
            onDismiss = {
                viewModel.clearModalError()
                showNodeEditor = false
            },
            onSave = { originalName, nodeJson, autoSelect ->
                viewModel.upsertNode(
                    originalName = originalName,
                    nodeJson = nodeJson,
                    autoSelect = autoSelect,
                    onSuccess = {
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
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            onDismiss = {
                viewModel.clearModalError()
                showCustomRulesDialog = false
            },
            onSaveRules = { text ->
                viewModel.saveCustomRules(
                    rulesText = text,
                    onSuccess = {
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
            errorMessage = state.modalError,
            onClearError = viewModel::clearModalError,
            onDismiss = {
                viewModel.clearModalError()
                showYamlEditorDialog = false
            },
            onSaveYaml = { yaml ->
                viewModel.saveActiveYaml(
                    yamlText = yaml,
                    onSuccess = {
                        viewModel.clearModalError()
                        showYamlEditorDialog = false
                    },
                )
            },
        )
    }
}
