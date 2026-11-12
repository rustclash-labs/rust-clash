package io.github.rustclashlabs.rustclash.ui

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.DiagnosticsFilter
import io.github.rustclashlabs.rustclash.ui.model.InstalledAppUi
import io.github.rustclashlabs.rustclash.ui.model.MainDestination
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.vpn.NativeBridge
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.RustClashVpnService
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class RustClashViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext: Context = application.applicationContext
    private val stateDir: String = appContext.filesDir.absolutePath
    private val prefs = appContext.getSharedPreferences(
        RustClashVpnService.PREFS_VPN_SETTINGS,
        Context.MODE_PRIVATE,
    )

    private val _uiState = MutableStateFlow(loadInitialPrefsState())
    val uiState: StateFlow<AppUiState> = _uiState.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var tickerJob: Job? = null
    private var previousVpnRunning: Boolean = false

    init {
        refreshAll()
    }

    private fun loadInitialPrefsState(): AppUiState {
        val theme = ThemePreference.fromWire(prefs.getString(RustClashVpnService.KEY_THEME_MODE, null))
        val perApp = PerAppMode.fromWire(prefs.getString(RustClashVpnService.KEY_PER_APP_MODE, null))
        val pkgs = prefs.getStringSet(RustClashVpnService.KEY_SELECTED_PACKAGES, emptySet())?.toSet() ?: emptySet()
        val favs = prefs.getStringSet(RustClashVpnService.KEY_FAVORITE_NODES, emptySet())?.toSet() ?: emptySet()
        val aliasesRaw = prefs.getString(RustClashVpnService.KEY_PROFILE_ALIASES, null)
        val aliases = mutableMapOf<String, String>()
        if (!aliasesRaw.isNullOrBlank()) {
            runCatching {
                val obj = JSONObject(aliasesRaw)
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = obj.optString(k, "").trim()
                    if (k.isNotBlank() && v.isNotEmpty()) {
                        aliases[k] = v
                    }
                }
            }
        }
        val ipv6 = prefs.getBoolean(RustClashVpnService.KEY_ENABLE_IPV6, true)
        val demo = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)
        return AppUiState(
            nativeLoaded = NativeBridge.ensureLoaded(),
            vpnState = RustClashVpnService.stateTracker.state,
            lastError = RustClashVpnService.stateTracker.lastError,
            lockdownWarning = RustClashVpnService.lockdownWarning,
            themePreference = theme,
            perAppMode = perApp,
            selectedPackages = pkgs,
            favoriteNodes = favs,
            profileAliases = aliases,
            enableIpv6 = ipv6,
            demoMode = demo,
        )
    }

    private fun emitMessage(raw: String) {
        val safe = NodeImportSupport.redactSecretsForUi(raw)
        _messages.tryEmit(safe)
    }

    fun emitUiMessage(raw: String) {
        emitMessage(raw)
    }

    fun clearModalError() {
        if (_uiState.value.modalError != null) {
            _uiState.update { it.copy(modalError = null) }
        }
    }

    private fun reportActionError(raw: String, isModal: Boolean) {
        val safe = NodeImportSupport.redactSecretsForUi(raw)
        if (isModal) {
            _uiState.update { it.copy(modalError = safe) }
        } else {
            _messages.tryEmit(safe)
        }
    }

    fun setActiveDestination(dest: MainDestination) {
        if (_uiState.value.activeDestination == dest) return
        _uiState.update { it.copy(activeDestination = dest) }
        if (dest == MainDestination.RULES && previousVpnRunning) {
            viewModelScope.launch {
                pollLiveStatusAndDiagnostics(includeDiagnostics = true)
            }
        }
    }

    fun startForegroundTicker() {
        tickerJob?.cancel()
        tickerJob = viewModelScope.launch {
            var tickCount = 0
            while (isActive) {
                val dest = _uiState.value.activeDestination
                val includeDiag = dest == MainDestination.RULES ||
                    (dest == MainDestination.HOME && tickCount % 5 == 0)
                pollLiveStatusAndDiagnostics(includeDiagnostics = includeDiag)
                if (tickCount > 0 && tickCount % 5 == 0 && previousVpnRunning) {
                    syncSnapshotQuietly()
                }
                tickCount++
                delay(1_000L)
            }
        }
    }

    fun stopForegroundTicker() {
        tickerJob?.cancel()
        tickerJob = null
    }

    fun syncServiceStateImmediate() {
        _uiState.update {
            it.copy(
                vpnState = RustClashVpnService.stateTracker.state,
                lastError = RustClashVpnService.stateTracker.lastError,
                lockdownWarning = RustClashVpnService.lockdownWarning,
            )
        }
    }

    fun refreshAll() {
        if (!NativeBridge.ensureLoaded()) {
            _uiState.update { it.copy(nativeLoaded = false) }
            return
        }
        viewModelScope.launch {
            syncSnapshotQuietly()
            refreshProfilesQuietly()
            pollLiveStatusAndDiagnostics(includeDiagnostics = true)
        }
    }

    private suspend fun pollLiveStatusAndDiagnostics(includeDiagnostics: Boolean) {
        val state = RustClashVpnService.stateTracker.state
        val err = RustClashVpnService.stateTracker.lastError
        val warn = RustClashVpnService.lockdownWarning

        if (!NativeBridge.ensureLoaded()) {
            _uiState.update {
                it.copy(
                    nativeLoaded = false,
                    vpnState = state,
                    lastError = err,
                    lockdownWarning = warn,
                )
            }
            return
        }

        val (telemetry, diagnostics) = withContext(Dispatchers.IO) {
            val statusJson = if (state == VpnLifecycleState.RUNNING) {
                NativeBridge.nativeGetStatusJson()
            } else {
                RustClashVpnService.latestStatusJson
            }
            val parsedStatus = UiJsonParsers.parseLiveTelemetry(statusJson)
            val parsedDiag = if (includeDiagnostics && parsedStatus.running) {
                UiJsonParsers.parseDiagnosticsResponse(NativeBridge.nativeGetDiagnosticsJson(150))
            } else if (!parsedStatus.running) {
                emptyList()
            } else {
                _uiState.value.diagnostics
            }
            parsedStatus to parsedDiag
        }

        val transitioned = previousVpnRunning != telemetry.running
        previousVpnRunning = telemetry.running

        _uiState.update { prev ->
            val nextHistory = if (telemetry.running) {
                (prev.rateHistory + (telemetry.upRate + telemetry.downRate)).takeLast(24)
            } else {
                emptyList()
            }
            prev.copy(
                vpnState = state,
                lastError = err?.let(NodeImportSupport::redactSecretsForUi),
                lockdownWarning = warn,
                telemetry = telemetry,
                diagnostics = diagnostics,
                rateHistory = nextHistory,
                effectiveOutbound = if (telemetry.running) telemetry.effectiveOutbound else prev.effectiveOutbound,
                effectiveProtocol = if (telemetry.running) telemetry.effectiveProtocol else prev.effectiveProtocol,
            )
        }

        if (transitioned) {
            syncSnapshotQuietly()
            refreshProfilesQuietly()
        }
    }

    private suspend fun syncSnapshotQuietly() {
        if (!NativeBridge.ensureLoaded()) return
        val raw = withContext(Dispatchers.IO) {
            NativeBridge.nativeGetNodeManagerSnapshot(stateDir)
        }
        applyNodeManagerSnapshot(raw)
    }

    private fun applyNodeManagerSnapshot(rawJson: String) {
        val parsed = UiJsonParsers.parseNodeManagerSnapshot(rawJson)
        if (!parsed.ok) {
            if (!parsed.error.isNullOrBlank()) {
                emitMessage(parsed.error)
            }
            return
        }
        _uiState.update { prev ->
            val availableGroupNames = parsed.groups.map { it.name }
            val validTab = when {
                prev.selectedGroupTab in availableGroupNames -> prev.selectedGroupTab
                parsed.primaryGroup in availableGroupNames -> parsed.primaryGroup
                availableGroupNames.isNotEmpty() -> availableGroupNames.first()
                else -> parsed.primaryGroup
            }
            prev.copy(
                activeProfileId = parsed.activeProfileId,
                primaryGroup = parsed.primaryGroup,
                selectedGroupTab = validTab,
                effectiveOutbound = parsed.effectiveOutbound,
                effectiveProtocol = parsed.effectiveProtocol,
                routingPreset = parsed.routingPreset,
                hasCustomRulesBackup = parsed.hasCustomRulesBackup,
                nodes = parsed.nodes,
                groups = parsed.groups,
                delays = parsed.delays,
                rules = parsed.rules,
                geodata = parsed.geodata,
            )
        }
    }

    private suspend fun refreshProfilesQuietly() {
        if (!NativeBridge.ensureLoaded()) return
        val raw = withContext(Dispatchers.IO) {
            NativeBridge.nativeGetProfilesSnapshotJson(stateDir)
        }
        val parsed = UiJsonParsers.parseProfilesSnapshot(raw) ?: return
        _uiState.update { prev ->
            prev.copy(
                activeProfileId = parsed.first,
                profiles = parsed.second,
            )
        }
    }

    fun setNodeSearchQuery(query: String) {
        _uiState.update { it.copy(nodeSearchQuery = query) }
    }

    fun toggleSortNodesByDelay() {
        _uiState.update { it.copy(sortNodesByDelay = !it.sortNodesByDelay) }
    }

    fun selectGroupTab(groupName: String) {
        _uiState.update { it.copy(selectedGroupTab = groupName) }
    }

    fun setRuleSearchQuery(query: String) {
        _uiState.update { it.copy(ruleSearchQuery = query) }
    }

    fun setDiagnosticsFilter(filter: DiagnosticsFilter) {
        _uiState.update { it.copy(diagnosticsFilter = filter) }
    }

    fun selectProxyInGroup(groupName: String, proxyName: String) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeSelectProxyPersisted(stateDir, groupName, proxyName)
            }
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            if (obj != null && obj.optBoolean("ok", false)) {
                applyNodeManagerSnapshot(raw)
                emitMessage("已切换节点：$proxyName")
            } else {
                emitMessage(obj?.optString("error") ?: "切换节点失败")
            }
        }
    }

    fun importUnifiedPayload(
        rawPayload: String,
        deduplicate: Boolean = true,
        autoSelect: Boolean = true,
        onSuccess: (() -> Unit)? = null,
    ) {
        val isModal = onSuccess != null
        val trimmed = rawPayload.trim()
        if (trimmed.isEmpty()) {
            reportActionError("导入内容为空，请粘贴节点链接、Base64 订阅、YAML 或订阅地址", isModal)
            return
        }
        if (!NativeBridge.ensureLoaded()) {
            reportActionError("Rust 核心库未加载", isModal)
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, modalError = null) }
            try {
                val respStr = withContext(Dispatchers.IO) {
                    NativeBridge.nativeImportUnifiedPayload(stateDir, trimmed, deduplicate, autoSelect)
                }
                val resp = JSONObject(respStr)
                if (!resp.optBoolean("ok", false)) {
                    val detail = UiJsonParsers.formatCleanBackendError(
                        resp.optString("error"),
                        "格式校验未通过",
                    )
                    reportActionError("导入失败：$detail", isModal)
                    return@launch
                }
                val added = resp.optInt("count", 0)
                val total = resp.optInt("totalNodes", added)
                val skipped = resp.optInt("skippedDuplicates", 0)
                val skippedUnsupported = resp.optInt("skippedUnsupported", 0)
                val eff = resp.optString("effectiveOutbound", "DIRECT")

                if (prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)) {
                    prefs.edit().putBoolean(RustClashVpnService.KEY_DEMO_MODE, false).apply()
                    _uiState.update { it.copy(demoMode = false) }
                }

                clearModalError()
                syncSnapshotQuietly()
                refreshProfilesQuietly()
                val notes = buildList {
                    if (skipped > 0) add("跳过重复 $skipped 个")
                    if (skippedUnsupported > 0) add("已忽略不兼容节点 $skippedUnsupported 个")
                }
                val suffixNote = if (notes.isNotEmpty()) "（${notes.joinToString("，")}）" else ""
                emitMessage("成功导入 $added 个节点$suffixNote · 共 $total 个 · 当前出口：$eff")
                onSuccess?.invoke()
            } catch (e: Exception) {
                val detail = UiJsonParsers.formatCleanBackendError(
                    e.message,
                    e.javaClass.simpleName,
                )
                reportActionError("导入异常：$detail", isModal)
            } finally {
                _uiState.update { it.copy(isImporting = false) }
            }
        }
    }

    fun upsertNode(
        originalName: String?,
        nodeJson: JSONObject,
        autoSelect: Boolean,
        onSuccess: (() -> Unit)? = null,
    ) {
        val isModal = onSuccess != null
        if (!NativeBridge.ensureLoaded()) {
            reportActionError("Rust 核心库未加载", isModal)
            return
        }
        if (isModal) clearModalError()
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeUpsertNodeJson(
                    stateDir,
                    originalName ?: "",
                    nodeJson.toString(),
                    autoSelect,
                )
            }
            val resp = runCatching { JSONObject(raw) }.getOrNull()
            if (resp != null && resp.optBoolean("ok", false)) {
                clearModalError()
                syncSnapshotQuietly()
                refreshProfilesQuietly()
                val name = nodeJson.optString("name")
                emitMessage(if (originalName != null) "已保存节点：$name" else "已添加节点：$name")
                onSuccess?.invoke()
            } else {
                val detail = UiJsonParsers.formatCleanBackendError(
                    resp?.optString("error"),
                    "保存节点失败",
                )
                reportActionError(detail, isModal)
            }
        }
    }

    fun deleteNode(nodeName: String) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeDeleteNodePersisted(stateDir, nodeName)
            }
            val resp = runCatching { JSONObject(raw) }.getOrNull()
            if (resp != null && resp.optBoolean("ok", false)) {
                syncSnapshotQuietly()
                refreshProfilesQuietly()
                emitMessage("已删除节点：$nodeName")
            } else {
                emitMessage(resp?.optString("error") ?: "删除节点失败")
            }
        }
    }

    fun deduplicateNodes() {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeDeduplicateNodesPersisted(stateDir)
            }
            val resp = runCatching { JSONObject(raw) }.getOrNull()
            if (resp != null && resp.optBoolean("ok", false)) {
                val removed = resp.optJSONArray("removedNodes")?.length() ?: 0
                syncSnapshotQuietly()
                refreshProfilesQuietly()
                emitMessage(if (removed > 0) "已清理 $removed 个重复节点" else "未发现重复节点")
            } else {
                emitMessage(resp?.optString("error") ?: "去重失败")
            }
        }
    }

    fun testLatency(targetNodeName: String? = null) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            if (targetNodeName == null) {
                _uiState.update { it.copy(isTestingAllDelays = true) }
            } else {
                _uiState.update { it.copy(testingNodeName = targetNodeName) }
            }
            try {
                val raw = withContext(Dispatchers.IO) {
                    NativeBridge.nativeTestLatencyJson(
                        stateDir,
                        targetNodeName ?: "",
                        "http://www.gstatic.com/generate_204",
                        4_000L,
                    )
                }
                val resp = runCatching { JSONObject(raw) }.getOrNull()
                if (resp != null && resp.optBoolean("ok", false)) {
                    syncSnapshotQuietly()
                    if (targetNodeName != null) {
                        val ms = resp.optJSONObject("delays")?.optLong(targetNodeName, 0L) ?: 0L
                        emitMessage(
                            if (ms > 0L) "$targetNodeName 延迟：${ms} ms" else "$targetNodeName 测速超时或不可达",
                        )
                    } else {
                        emitMessage("已完成全部节点延迟测试")
                    }
                } else {
                    emitMessage(resp?.optString("error") ?: "延迟测速失败")
                }
            } finally {
                _uiState.update {
                    it.copy(
                        isTestingAllDelays = false,
                        testingNodeName = null,
                    )
                }
            }
        }
    }

    fun setRoutingPreset(preset: RoutingPresetUi) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeSetRoutingPresetJson(stateDir, preset.wire)
            }
            val resp = runCatching { JSONObject(raw) }.getOrNull()
            if (resp != null && resp.optBoolean("ok", false)) {
                applyNodeManagerSnapshot(raw)
                refreshProfilesQuietly()
                emitMessage("路由模式已切换为：${preset.title}（${preset.homeSubtitle}）")
            } else {
                emitMessage(resp?.optString("error") ?: "切换路由模式失败")
            }
        }
    }

    fun updateGeoDataNow() {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            _uiState.update { it.copy(isUpdatingGeoData = true) }
            try {
                val raw = withContext(Dispatchers.IO) {
                    NativeBridge.nativeUpdateGeoDataJson(stateDir)
                }
                val resp = runCatching { JSONObject(raw) }.getOrNull()
                if (resp != null && resp.optBoolean("ok", false)) {
                    val geo = UiJsonParsers.parseGeoDataObject(resp.optJSONObject("geodata"))
                    _uiState.update { it.copy(geodata = geo) }
                    emitMessage("GeoSite / GeoIP 分流规则库更新成功（${geo.sourceLabel}）")
                } else {
                    syncSnapshotQuietly()
                    emitMessage(
                        "规则库下载未成功（已安全保留现有分流数据）：${resp?.optString("error") ?: "网络不可达"}",
                    )
                }
            } finally {
                _uiState.update { it.copy(isUpdatingGeoData = false) }
            }
        }
    }

    fun explainTargetRule(targetInput: String) {
        val cleaned = targetInput.trim()
        if (cleaned.isEmpty()) {
            emitMessage("请输入要测试的域名或 IP（例如 bilibili.com 或 google.com）")
            return
        }
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            _uiState.update { it.copy(isExplaining = true) }
            try {
                val raw = withContext(Dispatchers.IO) {
                    NativeBridge.nativeExplainRuleWithStateDirJson(stateDir, cleaned)
                }
                UiJsonParsers.parseExplainResponse(raw)
                    .onSuccess { res ->
                        _uiState.update { it.copy(explainResult = res) }
                    }
                    .onFailure { err ->
                        emitMessage(err.message ?: "规则测试失败")
                    }
            } finally {
                _uiState.update { it.copy(isExplaining = false) }
            }
        }
    }

    fun clearDiagnostics() {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                NativeBridge.nativeClearDiagnostics()
            }
            _uiState.update { it.copy(diagnostics = emptyList()) }
            emitMessage("已清空连接诊断记录")
        }
    }

    fun activateProfile(profileId: String) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeActivateProfileJson(stateDir, profileId)
            }
            val parsed = UiJsonParsers.parseProfilesSnapshot(raw)
            if (parsed != null) {
                _uiState.update { it.copy(activeProfileId = parsed.first, profiles = parsed.second) }
                syncSnapshotQuietly()
                emitMessage("已启用配置：${_uiState.value.activeProfileName}")
            } else {
                val err = runCatching { JSONObject(raw).optString("error") }.getOrNull()
                emitMessage(err ?: "切换配置失败")
            }
        }
    }

    fun refreshProfileSubscription(profileId: String) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            _uiState.update { it.copy(refreshingProfileId = profileId) }
            try {
                val raw = withContext(Dispatchers.IO) {
                    NativeBridge.nativeRefreshProfileJson(stateDir, profileId)
                }
                val parsed = UiJsonParsers.parseProfilesSnapshot(raw)
                if (parsed != null) {
                    _uiState.update { it.copy(activeProfileId = parsed.first, profiles = parsed.second) }
                    syncSnapshotQuietly()
                    emitMessage("订阅更新完成")
                } else {
                    val err = runCatching { JSONObject(raw).optString("error") }.getOrNull()
                    emitMessage("订阅更新失败（已保留原配置）：${err ?: "请求失败"}")
                }
            } finally {
                _uiState.update { it.copy(refreshingProfileId = null) }
            }
        }
    }

    fun deleteProfile(profileId: String) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeDeleteProfileJson(stateDir, profileId)
            }
            val parsed = UiJsonParsers.parseProfilesSnapshot(raw)
            if (parsed != null) {
                _uiState.update { it.copy(activeProfileId = parsed.first, profiles = parsed.second) }
                syncSnapshotQuietly()
                emitMessage("已删除配置")
            } else {
                val err = runCatching { JSONObject(raw).optString("error") }.getOrNull()
                emitMessage(err ?: "无法删除当前正在使用的配置")
            }
        }
    }

    fun loadActiveYamlAndRules(onLoaded: (() -> Unit)? = null) {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeGetActiveYamlJson(stateDir)
            }
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            if (obj != null && obj.optBoolean("ok", false)) {
                val yaml = obj.optString("yaml", "")
                val rArr = obj.optJSONArray("rules") ?: JSONArray()
                val lines = buildList {
                    for (i in 0 until rArr.length()) {
                        val line = rArr.optString(i).trim()
                        if (line.isNotEmpty()) add(line)
                    }
                }.joinToString("\n")
                _uiState.update {
                    it.copy(
                        activeYamlRedacted = yaml,
                        editableRulesText = lines,
                    )
                }
                onLoaded?.invoke()
            } else {
                emitMessage(obj?.optString("error") ?: "读取配置失败")
            }
        }
    }

    fun exportActiveYamlForSaf(onReady: (String) -> Unit) {
        if (!NativeBridge.ensureLoaded()) {
            emitMessage("Rust 核心库未加载")
            return
        }
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeGetActiveYamlJson(stateDir)
            }
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            val yaml = obj?.takeIf { it.optBoolean("ok", false) }?.optString("yaml", "").orEmpty()
            if (yaml.isNotBlank()) {
                onReady(yaml)
            } else {
                emitMessage(obj?.optString("error") ?: "无法导出当前 YAML 配置")
            }
        }
    }

    fun saveCustomRules(rulesText: String, onSuccess: (() -> Unit)? = null) {
        val isModal = onSuccess != null
        if (!NativeBridge.ensureLoaded()) {
            reportActionError("Rust 核心库未加载", isModal)
            return
        }
        if (isModal) clearModalError()
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeSaveCustomRulesJson(stateDir, rulesText)
            }
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            if (obj != null && obj.optBoolean("ok", false)) {
                clearModalError()
                applyNodeManagerSnapshot(raw)
                refreshProfilesQuietly()
                emitMessage("已保存自定义分流规则（已标记为自定义模式，不会被默认模板覆盖）")
                onSuccess?.invoke()
            } else {
                val detail = UiJsonParsers.formatCleanBackendError(obj?.optString("error"), "格式错误")
                reportActionError("规则校验未通过：$detail", isModal)
            }
        }
    }

    fun saveActiveYaml(yamlText: String, onSuccess: (() -> Unit)? = null) {
        val isModal = onSuccess != null
        if (!NativeBridge.ensureLoaded()) {
            reportActionError("Rust 核心库未加载", isModal)
            return
        }
        if (isModal) clearModalError()
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                NativeBridge.nativeSaveActiveYamlJson(stateDir, yamlText)
            }
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            if (obj != null && obj.optBoolean("ok", false)) {
                clearModalError()
                applyNodeManagerSnapshot(raw)
                refreshProfilesQuietly()
                emitMessage("YAML 配置已验证并生效")
                onSuccess?.invoke()
            } else {
                val detail = UiJsonParsers.formatCleanBackendError(obj?.optString("error"), "语法错误")
                reportActionError("YAML 校验失败（未破坏原配置）：$detail", isModal)
            }
        }
    }

    fun setThemePreference(pref: ThemePreference) {
        prefs.edit().putString(RustClashVpnService.KEY_THEME_MODE, pref.wire).apply()
        _uiState.update { it.copy(themePreference = pref) }
    }

    fun setShowSystemApps(show: Boolean) {
        if (_uiState.value.showSystemApps == show) return
        _uiState.update { it.copy(showSystemApps = show) }
        loadInstalledAppsIfNeeded(forceReload = true)
    }

    fun loadInstalledAppsIfNeeded(forceReload: Boolean = false) {
        if (!forceReload && _uiState.value.installedApps.isNotEmpty()) return
        val includeSystem = _uiState.value.showSystemApps
        val currentlySelected = _uiState.value.selectedPackages
        viewModelScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val pm = appContext.packageManager
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .filter { info ->
                        if (info.packageName == appContext.packageName) {
                            false
                        } else if (includeSystem || info.packageName in currentlySelected) {
                            true
                        } else {
                            (info.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                                (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        }
                    }
                    .map { info ->
                        InstalledAppUi(
                            packageName = info.packageName,
                            label = pm.getApplicationLabel(info).toString(),
                            isSystemApp = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                                (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
                        )
                    }
                    .sortedBy { it.label.lowercase() }
            }
            _uiState.update { it.copy(installedApps = apps) }
        }
    }

    fun savePerAppPolicy(mode: PerAppMode, selectedPackages: Set<String>) {
        prefs.edit()
            .putString(RustClashVpnService.KEY_PER_APP_MODE, mode.name)
            .putStringSet(RustClashVpnService.KEY_SELECTED_PACKAGES, selectedPackages)
            .apply()
        _uiState.update {
            it.copy(
                perAppMode = mode,
                selectedPackages = selectedPackages,
            )
        }
        val runningNote = if (_uiState.value.vpnState == VpnLifecycleState.RUNNING) {
            "（重新连接 VPN 后对系统隧道生效）"
        } else {
            ""
        }
        emitMessage("已保存分应用代理策略$runningNote")
    }

    fun setEnableIpv6(enabled: Boolean) {
        prefs.edit().putBoolean(RustClashVpnService.KEY_ENABLE_IPV6, enabled).apply()
        _uiState.update { it.copy(enableIpv6 = enabled) }
        if (_uiState.value.vpnState == VpnLifecycleState.RUNNING) {
            emitMessage("IPv6 设置已保存，重新连接 VPN 后生效")
        }
    }

    fun setDemoMode(enabled: Boolean) {
        prefs.edit().putBoolean(RustClashVpnService.KEY_DEMO_MODE, enabled).apply()
        _uiState.update { it.copy(demoMode = enabled) }
        if (_uiState.value.vpnState == VpnLifecycleState.RUNNING && NativeBridge.ensureLoaded()) {
            viewModelScope.launch {
                withContext(Dispatchers.IO) {
                    NativeBridge.nativeSetDemoSandboxJson(enabled)
                }
                syncSnapshotQuietly()
            }
        }
    }

    fun flushDnsCache() {
        if (!NativeBridge.ensureLoaded()) return
        viewModelScope.launch {
            val flushed = withContext(Dispatchers.IO) {
                NativeBridge.nativeFlushDns()
            }
            emitMessage(if (flushed) "已清空 Fake-IP 与 DNS 解析缓存" else "VPN 未连接，启动时将使用全新 DNS 缓存")
        }
    }

    fun toggleFavoriteNode(nodeName: String) {
        val clean = nodeName.trim()
        if (clean.isEmpty()) return
        val next = _uiState.value.favoriteNodes.toMutableSet()
        val added = if (clean in next) {
            next.remove(clean)
            false
        } else {
            next.add(clean)
            true
        }
        prefs.edit().putStringSet(RustClashVpnService.KEY_FAVORITE_NODES, next).apply()
        _uiState.update { it.copy(favoriteNodes = next.toSet()) }
        emitMessage(if (added) "已收藏节点：$clean" else "已取消收藏：$clean")
    }

    fun renameProfile(profileId: String, newName: String) {
        val cleanId = profileId.trim()
        val cleanName = newName.trim()
        if (cleanId.isEmpty() || cleanName.isEmpty()) return
        val nextAliases = _uiState.value.profileAliases.toMutableMap()
        nextAliases[cleanId] = cleanName
        val jsonObj = JSONObject()
        nextAliases.forEach { (k, v) -> jsonObj.put(k, v) }
        prefs.edit().putString(RustClashVpnService.KEY_PROFILE_ALIASES, jsonObj.toString()).apply()
        _uiState.update { it.copy(profileAliases = nextAliases.toMap()) }
        emitMessage("配置名称已更新为：$cleanName")
    }
}
