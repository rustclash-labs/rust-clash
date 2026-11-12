package io.github.rustclashlabs.rustclash.ui.model

import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class MainDestination(val label: String) {
    HOME("首页"),
    NODES("节点"),
    RULES("规则"),
    PROFILES("配置"),
    SETTINGS("设置"),
}

enum class ThemePreference(val wire: String, val label: String, val shortLabel: String) {
    LIGHT("LIGHT", "浅色模式", "浅色"),
    DARK("DARK", "深色模式", "深色"),
    SYSTEM("SYSTEM", "跟随系统", "跟随系统");

    companion object {
        fun fromWire(raw: String?): ThemePreference =
            entries.firstOrNull { it.wire.equals(raw?.trim(), ignoreCase = true) } ?: SYSTEM
    }
}

enum class RoutingPresetUi(
    val wire: String,
    val title: String,
    val homeSubtitle: String,
    val homeBadge: String,
    val modeDisplay: String,
    val detailDescription: String,
) {
    SMART_CN(
        wire = "smart-cn",
        title = "智能分流",
        homeSubtitle = "国内直连 · 国外代理",
        homeBadge = "规则分流",
        modeDisplay = "Rule 模式",
        detailDescription = "中国大陆域名与 IP 直连访问，海外流量经由选中节点代理转发",
    ),
    GLOBAL(
        wire = "global",
        title = "全局代理",
        homeSubtitle = "所有流量经由代理出口",
        homeBadge = "全局代理",
        modeDisplay = "Global 模式",
        detailDescription = "除本地回环外，所有流量统一经由当前选中的代理节点转发",
    ),
    DIRECT(
        wire = "direct",
        title = "全局直连",
        homeSubtitle = "所有流量直接连接",
        homeBadge = "全局直连",
        modeDisplay = "Direct 模式",
        detailDescription = "所有流量直接通过设备本地网络访问，不经过代理节点",
    ),
    CUSTOM(
        wire = "custom",
        title = "自定义规则",
        homeSubtitle = "使用用户自定义分流规则",
        homeBadge = "自定义",
        modeDisplay = "Rule · 自定义",
        detailDescription = "执行当前配置文件或您手动编辑的分流规则列表",
    );

    companion object {
        fun fromWireAndMode(activeChoice: String?, mode: String?, rulePreset: String?): RoutingPresetUi {
            when (activeChoice?.trim()?.lowercase(Locale.ROOT)) {
                "smart-cn", "smart_cn", "smart" -> return SMART_CN
                "global" -> return GLOBAL
                "direct" -> return DIRECT
                "custom" -> return CUSTOM
            }
            return when (mode?.trim()?.lowercase(Locale.ROOT)) {
                "global" -> GLOBAL
                "direct" -> DIRECT
                else -> if (rulePreset?.trim()?.lowercase(Locale.ROOT) == "custom") CUSTOM else SMART_CN
            }
        }
    }
}

enum class DiagnosticsFilter(val label: String) {
    ALL("全部"),
    PROXY("代理出口"),
    DIRECT("本地直连"),
    FAILED("异常"),
}

data class ProxyNodeItem(
    val name: String,
    val type: String,
    val server: String,
    val port: Int,
    val cipher: String = "",
    val encryption: String = "",
    val sni: String = "",
    val tls: Boolean = true,
    val skipCertVerify: Boolean = false,
    val udp: Boolean = true,
    val network: String = "tcp",
    val wsPath: String = "",
    val wsHost: String = "",
    val maxEarlyData: Int = 0,
    val username: String = "",
    val delayMs: Long? = null,
    val rawRedactedJson: String = "{}",
) {
    val protocolDisplay: String
        get() = when (type.lowercase(Locale.ROOT)) {
            "ss", "shadowsocks" -> "Shadowsocks"
            "vless" -> "VLESS"
            "anytls" -> "AnyTLS"
            "trojan" -> "Trojan"
            "socks5", "socks" -> "SOCKS5"
            "http" -> "HTTP"
            "direct" -> "DIRECT"
            "reject" -> "REJECT"
            else -> type.uppercase(Locale.ROOT)
        }

    val protocolShortBadge: String
        get() = when (type.lowercase(Locale.ROOT)) {
            "ss", "shadowsocks" -> "SS"
            "vless" -> if (network.equals("ws", ignoreCase = true)) "VLESS·WS" else "VLESS"
            "anytls" -> "AnyTLS"
            "trojan" -> if (network.equals("ws", ignoreCase = true)) "Trojan·WS" else "Trojan"
            "socks5", "socks" -> "SOCKS5"
            "http" -> "HTTP"
            else -> type.uppercase(Locale.ROOT)
        }
}

data class ProxyGroupItem(
    val name: String,
    val type: String,
    val now: String,
    val members: List<String>,
    val effectiveOutbound: String,
    val effectiveProtocol: String,
) {
    val isSelectable: Boolean
        get() = type.equals("Select", ignoreCase = true) || type.equals("Selector", ignoreCase = true)
}

data class RuleItem(
    val type: String,
    val payload: String,
    val proxy: String,
    val hits: Long,
)

data class GeoDataUiStatus(
    val usingPersistedData: Boolean = false,
    val builtinFallbackActive: Boolean = true,
    val isExpired: Boolean = false,
    val lastUpdatedMs: Long = 0L,
    val expiresAtMs: Long = 0L,
    val sourceLabel: String = "built-in",
    val geositeCnEntries: Int = 0,
    val geositeNonCnEntries: Int = 0,
    val geoipCnRanges: Int = 0,
    val mmdbPresent: Boolean = false,
    val lastError: String? = null,
)

data class DiagnosticEntryUi(
    val id: String,
    val network: String,
    val inboundType: String,
    val host: String,
    val destinationIp: String?,
    val destinationPort: Int,
    val fakeIpRestored: String?,
    val rule: String,
    val rulePayload: String,
    val chains: List<String>,
    val effectiveOutbound: String,
    val effectiveProtocol: String,
    val exitType: String,
    val remoteEndpoint: String,
    val status: String,
    val error: String?,
    val uploadBytes: Long,
    val downloadBytes: Long,
    val startEpochMs: Long,
) {
    val displayTarget: String
        get() {
            val base = host.ifBlank { destinationIp ?: "unknown" }
            return if (destinationPort > 0 && !base.endsWith(":$destinationPort")) {
                "$base:$destinationPort"
            } else {
                base
            }
        }

    val matchedRuleSummary: String
        get() = if (rulePayload.isBlank()) rule else "$rule($rulePayload)"

    val isFailed: Boolean
        get() = status.equals("failed", ignoreCase = true) ||
            exitType.equals("ERROR", ignoreCase = true) ||
            exitType.equals("REJECT", ignoreCase = true) ||
            !error.isNullOrBlank()
}

data class ExplainResultUi(
    val input: String,
    val normalizedTarget: String,
    val restoredFromFakeIp: String?,
    val mode: String,
    val ruleType: String,
    val rulePayload: String,
    val chains: List<String>,
    val outbound: String,
    val protocol: String,
    val exitType: String,
    val remoteEndpoint: String,
    val vpnRunning: Boolean,
) {
    val ruleDisplay: String
        get() = if (rulePayload.isBlank()) ruleType else "$ruleType, $rulePayload"
}

data class ProfileUiItem(
    val id: String,
    val name: String,
    val kind: String,
    val subscriptionUrlRedacted: String?,
    val lastUpdatedMs: Long,
    val lastError: String?,
    val proxyCount: Int,
    val ruleCount: Int,
    val rulePreset: String?,
    val hasCustomBackup: Boolean,
    val uploadBytes: Long?,
    val downloadBytes: Long?,
    val totalBytes: Long?,
    val expireUnixSecs: Long?,
) {
    val isSubscription: Boolean
        get() = kind.contains("subscription", ignoreCase = true) || !subscriptionUrlRedacted.isNullOrBlank()
}

data class LiveTelemetryUi(
    val running: Boolean = false,
    val demoActive: Boolean = false,
    val mode: String = "rule",
    val effectiveOutbound: String = "DIRECT",
    val effectiveProtocol: String = "DIRECT",
    val effectiveDelayMs: Long? = null,
    val upRate: Long = 0L,
    val downRate: Long = 0L,
    val upTotal: Long = 0L,
    val downTotal: Long = 0L,
    val rssBytes: Long = 0L,
    val activeConnections: Int = 0,
    val fakeIpEntries: Int = 0,
    val protectedSockets: Long = 0L,
    val networkTransitions: Long = 0L,
    val isWifi: Boolean = true,
)

data class InstalledAppUi(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean = false,
)

data class AppUiState(
    val nativeLoaded: Boolean = true,
    val vpnState: VpnLifecycleState = VpnLifecycleState.DISCONNECTED,
    val lastError: String? = null,
    val lockdownWarning: String? = null,
    val telemetry: LiveTelemetryUi = LiveTelemetryUi(),
    val activeProfileId: String = "default",
    val profiles: List<ProfileUiItem> = emptyList(),
    val primaryGroup: String = "PROXY",
    val selectedGroupTab: String = "PROXY",
    val effectiveOutbound: String = "DIRECT",
    val effectiveProtocol: String = "DIRECT",
    val routingPreset: RoutingPresetUi = RoutingPresetUi.SMART_CN,
    val hasCustomRulesBackup: Boolean = false,
    val nodes: List<ProxyNodeItem> = emptyList(),
    val groups: List<ProxyGroupItem> = emptyList(),
    val delays: Map<String, Long> = emptyMap(),
    val rules: List<RuleItem> = emptyList(),
    val geodata: GeoDataUiStatus = GeoDataUiStatus(),
    val diagnostics: List<DiagnosticEntryUi> = emptyList(),
    val diagnosticsFilter: DiagnosticsFilter = DiagnosticsFilter.ALL,
    val explainResult: ExplainResultUi? = null,
    val nodeSearchQuery: String = "",
    val sortNodesByDelay: Boolean = false,
    val ruleSearchQuery: String = "",
    val themePreference: ThemePreference = ThemePreference.SYSTEM,
    val perAppMode: PerAppMode = PerAppMode.ALL_APPS,
    val selectedPackages: Set<String> = emptySet(),
    val installedApps: List<InstalledAppUi> = emptyList(),
    val showSystemApps: Boolean = false,
    val activeDestination: MainDestination = MainDestination.HOME,
    val enableIpv6: Boolean = true,
    val demoMode: Boolean = false,
    val isImporting: Boolean = false,
    val isTestingAllDelays: Boolean = false,
    val testingNodeName: String? = null,
    val isUpdatingGeoData: Boolean = false,
    val isExplaining: Boolean = false,
    val refreshingProfileId: String? = null,
    val activeYamlRedacted: String = "",
    val editableRulesText: String = "",
    val favoriteNodes: Set<String> = emptySet(),
    val profileAliases: Map<String, String> = emptyMap(),
    val rateHistory: List<Long> = emptyList(),
) {
    fun resolveProfileDisplayName(profile: ProfileUiItem): String {
        val customAlias = profileAliases[profile.id]?.trim()
        if (!customAlias.isNullOrEmpty()) return customAlias
        val raw = profile.name.trim()
        if (raw.equals("Starter Profile", ignoreCase = true) || raw.equals("default", ignoreCase = true)) {
            return if (profile.proxyCount > 0 || nodes.isNotEmpty()) {
                "默认配置"
            } else {
                "初始配置"
            }
        }
        if (raw.equals("Imported Subscription", ignoreCase = true) || raw.equals("Subscription", ignoreCase = true)) {
            val host = profile.subscriptionUrlRedacted
                ?.substringAfter("://", "")
                ?.substringBefore("/")
                ?.takeIf { it.isNotBlank() && !it.contains("REDACTED") }
            return if (host != null) "订阅: $host" else "订阅配置"
        }
        return raw.ifEmpty { "默认配置" }
    }

    val activeProfileName: String
        get() {
            val customAlias = profileAliases[activeProfileId]?.trim()
            if (!customAlias.isNullOrEmpty()) return customAlias
            val active = profiles.firstOrNull { it.id == activeProfileId }
            if (active != null) return resolveProfileDisplayName(active)
            return if (nodes.isNotEmpty()) "默认配置" else "初始配置"
        }

    val effectiveNodeDelayMs: Long?
        get() = telemetry.effectiveDelayMs?.takeIf { it > 0L }
            ?: delays[effectiveOutbound]?.takeIf { it > 0L }

    val effectiveProtocolDisplay: String
        get() {
            val matched = nodes.firstOrNull { it.name == effectiveOutbound }
            if (matched != null) return matched.protocolShortBadge
            return when (effectiveProtocol.lowercase(Locale.ROOT)) {
                "ss", "shadowsocks" -> "SS"
                "vless" -> "VLESS"
                "anytls" -> "AnyTLS"
                "trojan" -> "Trojan"
                "socks5", "socks" -> "SOCKS5"
                "http" -> "HTTP"
                "direct" -> "DIRECT"
                "reject" -> "REJECT"
                else -> effectiveProtocol
            }
        }

    val directDiagnosticCount: Int
        get() = diagnostics.count { it.exitType.equals("DIRECT", ignoreCase = true) }

    val proxyDiagnosticCount: Int
        get() = diagnostics.count { it.exitType.equals("PROXY", ignoreCase = true) }

    val failedDiagnosticCount: Int
        get() = diagnostics.count { it.isFailed }
}

/**
 * Pure-JVM JSON parsers and list transformation helpers for `NativeBridge` responses.
 */
object UiJsonParsers {

    fun parseLiveTelemetry(rawJson: String): LiveTelemetryUi {
        val obj = runCatching { JSONObject(rawJson) }.getOrNull() ?: return LiveTelemetryUi()
        val running = obj.optBoolean("running", false)
        if (!running) return LiveTelemetryUi(running = false)
        val rawDelay = if (obj.has("effectiveDelayMs") && !obj.isNull("effectiveDelayMs")) {
            obj.optLong("effectiveDelayMs", 0L).takeIf { it > 0L }
        } else {
            null
        }
        return LiveTelemetryUi(
            running = true,
            demoActive = obj.optBoolean("demoActive", false),
            mode = obj.optString("mode", "rule"),
            effectiveOutbound = obj.optString("effectiveOutbound", "DIRECT"),
            effectiveProtocol = obj.optString("effectiveProtocol", "DIRECT"),
            effectiveDelayMs = rawDelay,
            upRate = obj.optLong("upRate", 0L),
            downRate = obj.optLong("downRate", 0L),
            upTotal = obj.optLong("upTotal", 0L),
            downTotal = obj.optLong("downTotal", 0L),
            rssBytes = obj.optLong("rssBytes", 0L),
            activeConnections = obj.optInt("activeConnections", 0),
            fakeIpEntries = obj.optInt("fakeIpEntries", 0),
            protectedSockets = obj.optLong("protectedSockets", 0L),
            networkTransitions = obj.optLong("networkTransitions", 0L),
            isWifi = obj.optBoolean("isWifi", true),
        )
    }

    data class NodeSnapshotParsed(
        val ok: Boolean,
        val error: String? = null,
        val vpnRunning: Boolean = false,
        val demoActive: Boolean = false,
        val activeProfileId: String = "default",
        val mode: String = "rule",
        val primaryGroup: String = "PROXY",
        val effectiveOutbound: String = "DIRECT",
        val effectiveProtocol: String = "DIRECT",
        val routingPreset: RoutingPresetUi = RoutingPresetUi.SMART_CN,
        val hasCustomRulesBackup: Boolean = false,
        val delays: Map<String, Long> = emptyMap(),
        val nodes: List<ProxyNodeItem> = emptyList(),
        val groups: List<ProxyGroupItem> = emptyList(),
        val rules: List<RuleItem> = emptyList(),
        val geodata: GeoDataUiStatus = GeoDataUiStatus(),
    )

    fun parseNodeManagerSnapshot(rawJson: String): NodeSnapshotParsed {
        val obj = runCatching { JSONObject(rawJson) }.getOrNull()
            ?: return NodeSnapshotParsed(ok = false, error = "Invalid JSON response")
        if (!obj.optBoolean("ok", false)) {
            return NodeSnapshotParsed(
                ok = false,
                error = NodeImportSupport.redactSecretsForUi(obj.optString("error", "Snapshot failed")),
            )
        }

        val delaysMap = mutableMapOf<String, Long>()
        obj.optJSONObject("delays")?.let { dObj ->
            val keys = dObj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val v = dObj.optLong(k, 0L)
                if (v > 0L) {
                    delaysMap[k] = v
                }
            }
        }

        val nodesList = mutableListOf<ProxyNodeItem>()
        val nodesArr = obj.optJSONArray("nodes") ?: JSONArray()
        for (i in 0 until nodesArr.length()) {
            val n = nodesArr.optJSONObject(i) ?: continue
            val name = n.optString("name")
            if (name.isBlank()) continue
            val nodeType = n.optString("type", "ss")
            val sni = n.optString("servername").takeIf { it.isNotBlank() && it != "null" }
                ?: n.optString("sni").takeIf { it.isNotBlank() && it != "null" }
                ?: ""
            val defaultTls = nodeType.lowercase(Locale.ROOT) in setOf("vless", "anytls", "trojan")
            val wsOpts = n.optJSONObject("ws-opts")
            val wsHost = wsOpts?.optJSONObject("headers")?.let { hdrs ->
                hdrs.optString("Host").takeIf { it.isNotBlank() }
                    ?: hdrs.optString("host").takeIf { it.isNotBlank() }
            } ?: ""
            nodesList.add(
                ProxyNodeItem(
                    name = name,
                    type = nodeType,
                    server = n.optString("server", ""),
                    port = n.optInt("port", 443),
                    cipher = n.optString("cipher", ""),
                    encryption = n.optString("encryption", ""),
                    sni = sni,
                    tls = if (n.has("tls")) n.optBoolean("tls", defaultTls) else defaultTls,
                    skipCertVerify = n.optBoolean("skip-cert-verify", false),
                    udp = n.optBoolean("udp", true),
                    network = n.optString("network", "tcp").ifBlank { "tcp" },
                    wsPath = wsOpts?.optString("path", "") ?: "",
                    wsHost = wsHost,
                    maxEarlyData = wsOpts?.optInt("max-early-data", 0) ?: 0,
                    username = n.optString("username", "").takeIf { it != "null" && it != "***REDACTED***" } ?: "",
                    delayMs = delaysMap[name],
                    rawRedactedJson = n.toString(),
                ),
            )
        }

        val groupsList = mutableListOf<ProxyGroupItem>()
        val groupsArr = obj.optJSONArray("groups") ?: JSONArray()
        for (i in 0 until groupsArr.length()) {
            val g = groupsArr.optJSONObject(i) ?: continue
            val gName = g.optString("name")
            if (gName.isBlank()) continue
            val members = mutableListOf<String>()
            val allArr = g.optJSONArray("all") ?: JSONArray()
            for (j in 0 until allArr.length()) {
                val m = allArr.optString(j)
                if (m.isNotBlank()) members.add(m)
            }
            groupsList.add(
                ProxyGroupItem(
                    name = gName,
                    type = g.optString("type", "Select"),
                    now = g.optString("now", ""),
                    members = members,
                    effectiveOutbound = g.optString("effectiveOutbound", ""),
                    effectiveProtocol = g.optString("effectiveProtocol", ""),
                ),
            )
        }

        val rulesList = mutableListOf<RuleItem>()
        val rulesArr = obj.optJSONArray("rules") ?: JSONArray()
        for (i in 0 until rulesArr.length()) {
            val r = rulesArr.optJSONObject(i) ?: continue
            rulesList.add(
                RuleItem(
                    type = r.optString("type", ""),
                    payload = r.optString("payload", ""),
                    proxy = r.optString("proxy", ""),
                    hits = r.optLong("hits", 0L),
                ),
            )
        }

        val mode = obj.optString("mode", "rule")
        val routingObj = obj.optJSONObject("routing")
        val routingPreset = RoutingPresetUi.fromWireAndMode(
            activeChoice = routingObj?.optString("active_choice"),
            mode = routingObj?.optString("mode")?.ifBlank { mode } ?: mode,
            rulePreset = routingObj?.optString("rule_preset"),
        )
        val hasCustomBackup = routingObj?.optBoolean("has_custom_rules_backup", false) ?: false
        val geoStatus = parseGeoDataObject(obj.optJSONObject("geodata"))

        return NodeSnapshotParsed(
            ok = true,
            vpnRunning = obj.optBoolean("vpnRunning", false),
            demoActive = obj.optBoolean("demoActive", false),
            activeProfileId = obj.optString("activeProfileId", "default"),
            mode = mode,
            primaryGroup = obj.optString("primaryGroup", "PROXY"),
            effectiveOutbound = obj.optString("effectiveOutbound", "DIRECT"),
            effectiveProtocol = obj.optString("effectiveProtocol", "DIRECT"),
            routingPreset = routingPreset,
            hasCustomRulesBackup = hasCustomBackup,
            delays = delaysMap,
            nodes = nodesList,
            groups = groupsList,
            rules = rulesList,
            geodata = geoStatus,
        )
    }

    fun parseGeoDataObject(g: JSONObject?): GeoDataUiStatus {
        if (g == null) return GeoDataUiStatus()
        val rawErr = if (g.has("last_error") && !g.isNull("last_error")) {
            g.optString("last_error").takeIf { it.isNotBlank() }?.let(NodeImportSupport::redactSecretsForUi)
        } else {
            null
        }
        return GeoDataUiStatus(
            usingPersistedData = g.optBoolean("using_persisted_data", false),
            builtinFallbackActive = g.optBoolean("builtin_fallback_active", true),
            isExpired = g.optBoolean("is_expired", false),
            lastUpdatedMs = g.optLong("last_updated_ms", 0L),
            expiresAtMs = g.optLong("expires_at_ms", 0L),
            sourceLabel = g.optString("source_label", "built-in"),
            geositeCnEntries = g.optInt("geosite_cn_entries", 0),
            geositeNonCnEntries = g.optInt("geosite_non_cn_entries", 0),
            geoipCnRanges = g.optInt("geoip_cn_ranges", 0),
            mmdbPresent = g.optBoolean("mmdb_present", false),
            lastError = rawErr,
        )
    }

    fun parseDiagnosticsResponse(rawJson: String): List<DiagnosticEntryUi> {
        val obj = runCatching { JSONObject(rawJson) }.getOrNull() ?: return emptyList()
        val arr = obj.optJSONArray("diagnostics") ?: return emptyList()
        val out = ArrayList<DiagnosticEntryUi>(arr.length())
        for (i in 0 until arr.length()) {
            val d = arr.optJSONObject(i) ?: continue
            val meta = d.optJSONObject("metadata")
            val chains = mutableListOf<String>()
            val cArr = d.optJSONArray("chains") ?: JSONArray()
            for (j in 0 until cArr.length()) {
                val c = cArr.optString(j)
                if (c.isNotBlank()) chains.add(c)
            }
            val fakeIp = if (meta != null && meta.has("fake_ip") && !meta.isNull("fake_ip")) {
                meta.optString("fake_ip").takeIf { it.isNotBlank() }
            } else {
                null
            }
            val dstIp = if (meta != null && meta.has("destination_ip") && !meta.isNull("destination_ip")) {
                meta.optString("destination_ip").takeIf { it.isNotBlank() }
            } else {
                null
            }
            val errStr = if (d.has("error") && !d.isNull("error")) {
                d.optString("error").takeIf { it.isNotBlank() }?.let(NodeImportSupport::redactSecretsForUi)
            } else {
                null
            }
            out.add(
                DiagnosticEntryUi(
                    id = d.optString("id", "$i"),
                    network = meta?.optString("network", "tcp")?.uppercase(Locale.ROOT) ?: "TCP",
                    inboundType = meta?.optString("type", "TUN") ?: "TUN",
                    host = meta?.optString("host", "") ?: "",
                    destinationIp = dstIp,
                    destinationPort = meta?.optInt("destination_port", 0) ?: 0,
                    fakeIpRestored = fakeIp,
                    rule = d.optString("rule", ""),
                    rulePayload = d.optString("rule_payload", ""),
                    chains = chains,
                    effectiveOutbound = d.optString("effective_outbound", ""),
                    effectiveProtocol = d.optString("effective_protocol", ""),
                    exitType = d.optString("exit_type", ""),
                    remoteEndpoint = d.optString("remote_endpoint", ""),
                    status = d.optString("status", "active"),
                    error = errStr,
                    uploadBytes = d.optLong("upload", 0L),
                    downloadBytes = d.optLong("download", 0L),
                    startEpochMs = d.optLong("start_epoch_ms", 0L),
                ),
            )
        }
        return out
    }

    fun parseExplainResponse(rawJson: String): Result<ExplainResultUi> {
        val obj = runCatching { JSONObject(rawJson) }.getOrNull()
            ?: return Result.failure(IllegalArgumentException("无法解析分流测试响应"))
        if (!obj.optBoolean("ok", false)) {
            val err = NodeImportSupport.redactSecretsForUi(obj.optString("error", "规则匹配测试失败"))
            return Result.failure(IllegalStateException(err))
        }
        val chains = mutableListOf<String>()
        val cArr = obj.optJSONArray("chains") ?: JSONArray()
        for (i in 0 until cArr.length()) {
            val item = cArr.optString(i)
            if (item.isNotBlank()) chains.add(item)
        }
        val fakeIp = if (obj.has("restored_from_fake_ip") && !obj.isNull("restored_from_fake_ip")) {
            obj.optString("restored_from_fake_ip").takeIf { it.isNotBlank() }
        } else {
            null
        }
        return Result.success(
            ExplainResultUi(
                input = obj.optString("input", ""),
                normalizedTarget = obj.optString("normalized_target", ""),
                restoredFromFakeIp = fakeIp,
                mode = obj.optString("mode", "rule"),
                ruleType = obj.optString("rule_type", ""),
                rulePayload = obj.optString("rule_payload", ""),
                chains = chains,
                outbound = obj.optString("outbound", "DIRECT"),
                protocol = obj.optString("protocol", "DIRECT"),
                exitType = obj.optString("exit_type", "DIRECT"),
                remoteEndpoint = obj.optString("remote_endpoint", ""),
                vpnRunning = obj.optBoolean("vpnRunning", false),
            ),
        )
    }

    fun parseProfilesSnapshot(rawJson: String): Pair<String, List<ProfileUiItem>>? {
        val root = runCatching { JSONObject(rawJson) }.getOrNull() ?: return null
        if (!root.optBoolean("ok", false)) return null
        val snap = root.optJSONObject("profilesSnapshot") ?: return null
        val activeId = snap.optString("active_profile_id", "default")
        val arr = snap.optJSONArray("profiles") ?: JSONArray()
        val list = ArrayList<ProfileUiItem>(arr.length())
        for (i in 0 until arr.length()) {
            val p = arr.optJSONObject(i) ?: continue
            val subUrl = if (p.has("subscription_url_redacted") && !p.isNull("subscription_url_redacted")) {
                p.optString("subscription_url_redacted").takeIf { it.isNotBlank() }
            } else {
                null
            }
            val lastErr = if (p.has("last_error") && !p.isNull("last_error")) {
                p.optString("last_error").takeIf { it.isNotBlank() }?.let(NodeImportSupport::redactSecretsForUi)
            } else {
                null
            }
            val preset = if (p.has("rule_preset") && !p.isNull("rule_preset")) {
                p.optString("rule_preset").takeIf { it.isNotBlank() }
            } else {
                null
            }
            val backupArr = p.optJSONArray("custom_rules_backup")
            val userInfo = p.optJSONObject("userinfo")
            list.add(
                ProfileUiItem(
                    id = p.optString("id", ""),
                    name = p.optString("name", "未命名配置"),
                    kind = p.optString("kind", "local-yaml"),
                    subscriptionUrlRedacted = subUrl,
                    lastUpdatedMs = p.optLong("last_updated_ms", 0L),
                    lastError = lastErr,
                    proxyCount = p.optInt("proxy_count", 0),
                    ruleCount = p.optInt("rule_count", 0),
                    rulePreset = preset,
                    hasCustomBackup = (backupArr != null && backupArr.length() > 0),
                    uploadBytes = userInfo?.optLong("upload_bytes", 0L),
                    downloadBytes = userInfo?.optLong("download_bytes", 0L),
                    totalBytes = if (userInfo != null && userInfo.has("total_bytes") && !userInfo.isNull("total_bytes")) {
                        userInfo.optLong("total_bytes", 0L).takeIf { it > 0L }
                    } else {
                        null
                    },
                    expireUnixSecs = if (userInfo != null && userInfo.has("expire_unix_secs") && !userInfo.isNull("expire_unix_secs")) {
                        userInfo.optLong("expire_unix_secs", 0L).takeIf { it > 0L }
                    } else {
                        null
                    },
                ),
            )
        }
        return activeId to list
    }

    /**
     * Filters concrete proxy nodes by search query (`name`, `server`, `protocolDisplay`) and optionally
     * sorts reachable low-latency nodes (`delayMs > 0`) first while keeping untested/timeout nodes after.
     */
    fun filterAndSortNodes(
        nodes: List<ProxyNodeItem>,
        delays: Map<String, Long>,
        query: String,
        sortByDelay: Boolean,
    ): List<ProxyNodeItem> {
        val needle = query.trim().lowercase(Locale.ROOT)
        val enriched = nodes.map { node ->
            val d = delays[node.name]?.takeIf { it > 0L } ?: node.delayMs?.takeIf { it > 0L }
            if (d != node.delayMs) node.copy(delayMs = d) else node
        }
        val filtered = if (needle.isEmpty()) {
            enriched
        } else {
            enriched.filter { n ->
                n.name.lowercase(Locale.ROOT).contains(needle) ||
                    n.server.lowercase(Locale.ROOT).contains(needle) ||
                    n.protocolDisplay.lowercase(Locale.ROOT).contains(needle) ||
                    n.type.lowercase(Locale.ROOT).contains(needle)
            }
        }
        if (!sortByDelay) return filtered
        return filtered.sortedWith(
            compareBy<ProxyNodeItem>(
                { it.delayMs == null || it.delayMs <= 0L },
                { it.delayMs ?: Long.MAX_VALUE },
                { it.name.lowercase(Locale.ROOT) },
            ),
        )
    }

    fun filterDiagnostics(
        entries: List<DiagnosticEntryUi>,
        filter: DiagnosticsFilter,
    ): List<DiagnosticEntryUi> =
        when (filter) {
            DiagnosticsFilter.ALL -> entries
            DiagnosticsFilter.PROXY -> entries.filter { it.exitType.equals("PROXY", ignoreCase = true) }
            DiagnosticsFilter.DIRECT -> entries.filter { it.exitType.equals("DIRECT", ignoreCase = true) }
            DiagnosticsFilter.FAILED -> entries.filter { it.isFailed }
        }

    fun formatBytes(bytes: Long): String =
        when {
            bytes >= 1_073_741_824L -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
            bytes >= 1_048_576L -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
            bytes >= 1_024L -> String.format(Locale.US, "%.1f KB", bytes / 1_024.0)
            else -> "$bytes B"
        }

    fun formatRate(bytesPerSec: Long): String =
        when {
            bytesPerSec >= 1_048_576L -> String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
            bytesPerSec >= 1_024L -> String.format(Locale.US, "%.0f KB/s", bytesPerSec / 1_024.0)
            else -> "$bytesPerSec B/s"
        }

    fun formatEpochMillis(epochMs: Long): String {
        if (epochMs <= 0L) return "内置基准数据"
        return runCatching {
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(epochMs))
        }.getOrDefault("-")
    }
}
