package io.github.rustclashlabs.rustclash.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CellTower
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRowDefaults
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.DiagnosticEntryUi
import io.github.rustclashlabs.rustclash.ui.model.DiagnosticsFilter
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RulesScreen(
    state: AppUiState,
    requestedSubTab: Int = 0,
    onSelectRoutingPreset: (RoutingPresetUi) -> Unit,
    onUpdateGeoData: () -> Unit,
    onOpenCustomRuleEditor: () -> Unit,
    onSetDiagnosticsFilter: (DiagnosticsFilter) -> Unit,
    onClearDiagnostics: () -> Unit,
    onExplainTarget: (String) -> Unit,
    onRuleSearchChange: (String) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    var selectedTab by rememberSaveable { mutableIntStateOf(requestedSubTab.coerceIn(0, 2)) }
    LaunchedEffect(requestedSubTab) {
        selectedTab = requestedSubTab.coerceIn(0, 2)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 10.dp),
    ) {
        Text(
            text = "规则与分流",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(3.dp))
        Text(
            text = "当前方案：${state.routingPreset.title}（${state.routingPreset.homeSubtitle}）",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(modifier = Modifier.height(10.dp))

        SecondaryTabRow(
            selectedTabIndex = selectedTab,
            containerColor = Color.Transparent,
            contentColor = extColors.emerald,
            indicator = {
                TabRowDefaults.SecondaryIndicator(
                    Modifier.tabIndicatorOffset(selectedTab),
                    color = extColors.emerald,
                    height = 2.5.dp,
                )
            },
            divider = {
                HorizontalDivider(color = extColors.hairline)
            },
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                selectedContentColor = extColors.emerald,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    Text(
                        text = "分流策略",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (selectedTab == 0) FontWeight.SemiBold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                selectedContentColor = extColors.emerald,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    val suffix = if (state.diagnostics.isNotEmpty()) " (${state.diagnostics.size})" else ""
                    Text(
                        text = "实时诊断$suffix",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (selectedTab == 1) FontWeight.SemiBold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
            Tab(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                selectedContentColor = extColors.emerald,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    Text(
                        text = "命中测试",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (selectedTab == 2) FontWeight.SemiBold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        when (selectedTab) {
            0 -> RoutingPresetsAndGeoTab(
                state = state,
                onSelectRoutingPreset = onSelectRoutingPreset,
                onUpdateGeoData = onUpdateGeoData,
                onOpenCustomRuleEditor = onOpenCustomRuleEditor,
            )
            1 -> LiveDiagnosticsTab(
                state = state,
                onSetFilter = onSetDiagnosticsFilter,
                onClear = onClearDiagnostics,
            )
            else -> RuleExplainAndTableTab(
                state = state,
                onExplainTarget = onExplainTarget,
                onRuleSearchChange = onRuleSearchChange,
            )
        }
    }
}

private fun presetLeadingIcon(preset: RoutingPresetUi): ImageVector = when (preset) {
    RoutingPresetUi.SMART_CN -> Icons.Rounded.CellTower
    RoutingPresetUi.GLOBAL -> Icons.Rounded.Public
    RoutingPresetUi.DIRECT -> Icons.Rounded.Link
    RoutingPresetUi.CUSTOM -> Icons.Rounded.Tune
}

@Composable
private fun RoutingPresetsAndGeoTab(
    state: AppUiState,
    onSelectRoutingPreset: (RoutingPresetUi) -> Unit,
    onUpdateGeoData: () -> Unit,
    onOpenCustomRuleEditor: () -> Unit,
) {
    val extColors = LocalRustClashColors.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        RoutingPresetUi.entries.forEach { preset ->
            val selected = state.routingPreset == preset
            val icon = presetLeadingIcon(preset)

            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .clickable {
                        if (preset == RoutingPresetUi.CUSTOM && !state.hasCustomRulesBackup && state.routingPreset != RoutingPresetUi.CUSTOM) {
                            onOpenCustomRuleEditor()
                        } else {
                            onSelectRoutingPreset(preset)
                        }
                    },
                shape = RoundedCornerShape(16.dp),
                color = if (selected) extColors.selectedCardBg else extColors.cardSurface,
                border = BorderStroke(
                    width = if (selected) 1.5.dp else 1.dp,
                    color = if (selected) extColors.selectedCardBorder else extColors.hairline,
                ),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(RoundedCornerShape(11.dp))
                            .background(
                                if (selected) extColors.emeraldContainer else extColors.iconBadgeBg,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = if (selected) extColors.emerald else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp),
                        )
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = preset.title,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            if (preset == RoutingPresetUi.SMART_CN) {
                                Spacer(modifier = Modifier.width(8.dp))
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = extColors.emerald,
                                ) {
                                    Text(
                                        text = "推荐",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(3.dp))
                        Text(
                            text = preset.detailDescription,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    if (selected) {
                        Spacer(modifier = Modifier.width(10.dp))
                        Icon(
                            imageVector = Icons.Rounded.CheckCircle,
                            contentDescription = "已启用",
                            tint = extColors.emerald,
                            modifier = Modifier.size(22.dp),
                        )
                    }
                }
            }
        }

        // Custom Rule Editor Entry
        OutlinedButton(
            onClick = onOpenCustomRuleEditor,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, extColors.hairline),
        ) {
            Icon(
                Icons.Rounded.EditNote,
                contentDescription = null,
                tint = extColors.emerald,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = if (state.routingPreset == RoutingPresetUi.CUSTOM || state.hasCustomRulesBackup) {
                    "查看 / 编辑自定义分流规则"
                } else {
                    "编写自定义分流规则"
                },
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
            )
        }

        // GeoSite / GeoIP Status & Update Card
        val geo = state.geodata
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            color = extColors.cardSurface,
            border = BorderStroke(1.dp, extColors.hairline),
        ) {
            Column(modifier = Modifier.padding(15.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "GeoSite / GeoIP 分流数据库",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        val srcDesc = when {
                            geo.usingPersistedData && !geo.isExpired -> "持久化规则库 · 共 ${state.rules.size} 条生效规则"
                            geo.usingPersistedData && geo.isExpired -> "持久化规则库（建议更新）"
                            else -> "内置基准规则库 · 共 ${state.rules.size} 条生效规则"
                        }
                        Text(
                            text = srcDesc,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (geo.isExpired) extColors.amber else extColors.emerald,
                        )
                    }

                    Button(
                        onClick = onUpdateGeoData,
                        enabled = !state.isUpdatingGeoData,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = extColors.emerald,
                            contentColor = Color.White,
                        ),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 7.dp),
                    ) {
                        if (state.isUpdatingGeoData) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(14.dp),
                                strokeWidth = 2.dp,
                                color = Color.White,
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                        } else {
                            Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                        }
                        Text("更新规则库", style = MaterialTheme.typography.labelMedium, maxLines = 1)
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                HorizontalDivider(color = extColors.hairline)
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    GeoStatMini("国内域名 (CN)", "${geo.geositeCnEntries}", modifier = Modifier.weight(1f))
                    GeoStatMini("国际域名 (!CN)", "${geo.geositeNonCnEntries}", modifier = Modifier.weight(1f))
                    GeoStatMini("中国 IP 网段", "${geo.geoipCnRanges}", modifier = Modifier.weight(1f))
                }

                if (!geo.lastError.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "提示：${geo.lastError}",
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.amber,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
    }
}

@Composable
private fun GeoStatMini(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun LiveDiagnosticsTab(
    state: AppUiState,
    onSetFilter: (DiagnosticsFilter) -> Unit,
    onClear: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val filtered = remember(state.diagnostics, state.diagnosticsFilter) {
        UiJsonParsers.filterDiagnostics(state.diagnostics, state.diagnosticsFilter)
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                DiagnosticsFilter.entries.forEach { f ->
                    val count = when (f) {
                        DiagnosticsFilter.ALL -> state.diagnostics.size
                        DiagnosticsFilter.PROXY -> state.proxyDiagnosticCount
                        DiagnosticsFilter.DIRECT -> state.directDiagnosticCount
                        DiagnosticsFilter.FAILED -> state.failedDiagnosticCount
                    }
                    FilterChip(
                        selected = state.diagnosticsFilter == f,
                        onClick = { onSetFilter(f) },
                        label = { Text("${f.label} ($count)", style = MaterialTheme.typography.labelSmall, maxLines = 1) },
                    )
                }
            }

            if (state.diagnostics.isNotEmpty()) {
                IconButton(onClick = onClear) {
                    Icon(
                        imageVector = Icons.Rounded.DeleteSweep,
                        contentDescription = "清空诊断列表",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (state.vpnState != VpnLifecycleState.RUNNING) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Text(
                        text = "VPN 未连接",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "启动连接后，此处将实时显示每个网络请求的访问域名、Fake-IP 还原状态、命中的分流规则、实际出站节点（DIRECT 直连或 PROXY 代理）以及失败原因。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else if (filtered.isEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Text(
                    text = "暂无符合当前筛选条件的连接记录。打开浏览器或应用访问国内/国外网站即可实时观察分流出口。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(18.dp),
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(bottom = 18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(filtered, key = { it.id }) { item ->
                    DiagnosticRowCard(item)
                }
            }
        }
    }
}

@Composable
private fun DiagnosticRowCard(entry: DiagnosticEntryUi) {
    val extColors = LocalRustClashColors.current
    val isProxy = entry.exitType.equals("PROXY", ignoreCase = true)
    val isDirect = entry.exitType.equals("DIRECT", ignoreCase = true)

    val (badgeBg, badgeFg, badgeLabel) = when {
        entry.isFailed -> Triple(extColors.dangerContainer, extColors.onDangerContainer, "异常")
        isProxy -> Triple(extColors.infoContainer, extColors.onInfoContainer, "代理 PROXY")
        isDirect -> Triple(extColors.emeraldContainer, extColors.onEmeraldContainer, "直连 DIRECT")
        else -> Triple(MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer, entry.exitType)
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(13.dp),
        color = extColors.cardSurface,
        border = BorderStroke(1.dp, if (entry.isFailed) extColors.danger.copy(alpha = 0.5f) else extColors.hairline),
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(shape = CircleShape, color = badgeBg) {
                    Text(
                        text = badgeLabel,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = badgeFg,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = entry.network,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (entry.fakeIpRestored != null) {
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Fake-IP 还原",
                        style = MaterialTheme.typography.labelSmall,
                        color = extColors.emerald,
                    )
                }
                Spacer(modifier = Modifier.weight(1f))
                val statusLabel = when (entry.status.lowercase()) {
                    "active" -> "活跃"
                    "connecting" -> "握手中"
                    "closed" -> "已完成"
                    "failed" -> "失败"
                    else -> entry.status
                }
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (entry.isFailed) extColors.danger else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = entry.displayTarget,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "命中：${entry.matchedRuleSummary}  →  出站：${entry.effectiveOutbound} (${entry.effectiveProtocol})",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )

            if (entry.uploadBytes > 0L || entry.downloadBytes > 0L) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "↓ ${UiJsonParsers.formatBytes(entry.downloadBytes)}  ↑ ${UiJsonParsers.formatBytes(entry.uploadBytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (!entry.error.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "原因：${entry.error}",
                    style = MaterialTheme.typography.bodySmall,
                    color = extColors.danger,
                )
            }
        }
    }
}

@Composable
private fun RuleExplainAndTableTab(
    state: AppUiState,
    onExplainTarget: (String) -> Unit,
    onRuleSearchChange: (String) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    var targetInput by rememberSaveable { mutableStateOf("www.bilibili.com") }
    val quickSamples = listOf(
        "www.baidu.com",
        "www.bilibili.com",
        "wx.qq.com",
        "www.google.com",
        "github.com",
        "114.114.114.114",
        "8.8.8.8",
    )

    val filteredRules = remember(state.rules, state.ruleSearchQuery) {
        val q = state.ruleSearchQuery.trim().lowercase()
        if (q.isEmpty()) {
            state.rules
        } else {
            state.rules.filter {
                it.type.lowercase().contains(q) ||
                    it.payload.lowercase().contains(q) ||
                    it.proxy.lowercase().contains(q)
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "域名 / IP 分流命中测试（离线与在线均可用）",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        OutlinedTextField(
                            value = targetInput,
                            onValueChange = { targetInput = it },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp),
                            placeholder = { Text("如 bilibili.com 或 google.com") },
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = { onExplainTarget(targetInput) },
                            enabled = !state.isExplaining && targetInput.isNotBlank(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = extColors.emerald,
                                contentColor = Color.White,
                            ),
                        ) {
                            Icon(Icons.Rounded.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("测试", maxLines = 1)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        quickSamples.forEach { sample ->
                            TextButton(
                                onClick = {
                                    targetInput = sample
                                    onExplainTarget(sample)
                                },
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            ) {
                                Text(sample, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }

                    val res = state.explainResult
                    if (res != null) {
                        HorizontalDivider(color = extColors.hairline, modifier = Modifier.padding(vertical = 8.dp))
                        val isDirect = res.exitType.equals("DIRECT", ignoreCase = true)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Surface(
                                shape = CircleShape,
                                color = if (isDirect) extColors.emeraldContainer else extColors.infoContainer,
                            ) {
                                Text(
                                    text = if (isDirect) "直连 DIRECT" else "代理 ${res.exitType}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isDirect) extColors.onEmeraldContainer else extColors.onInfoContainer,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = res.normalizedTarget,
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "命中规则：${res.ruleDisplay}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            text = "实际出站：${res.outbound} (${res.protocol}) · 链路：${res.chains.reversed().joinToString(" → ")}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(4.dp))
            OutlinedTextField(
                value = state.ruleSearchQuery,
                onValueChange = onRuleSearchChange,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                placeholder = { Text("搜索当前生效规则…") },
                leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                trailingIcon = {
                    if (state.ruleSearchQuery.isNotEmpty()) {
                        IconButton(onClick = { onRuleSearchChange("") }) {
                            Icon(Icons.Rounded.Clear, contentDescription = "清除")
                        }
                    }
                },
            )
        }

        if (filteredRules.isEmpty() && state.ruleSearchQuery.isNotBlank()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = extColors.cardSurface,
                    border = BorderStroke(1.dp, extColors.hairline),
                ) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            text = "未找到匹配「${state.ruleSearchQuery}」的分流规则",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        TextButton(onClick = { onRuleSearchChange("") }) {
                            Text("清除搜索")
                        }
                    }
                }
            }
        }

        items(filteredRules.take(200)) { rule ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = if (rule.payload.isBlank()) rule.type else "${rule.type}, ${rule.payload}",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (rule.hits > 0L) {
                            Text(
                                text = "已命中 ${rule.hits} 次",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    val isDirectRule = rule.proxy.equals("DIRECT", ignoreCase = true)
                    Surface(
                        modifier = Modifier.widthIn(max = 136.dp),
                        shape = CircleShape,
                        color = if (isDirectRule) extColors.emeraldContainer else extColors.infoContainer,
                    ) {
                        Text(
                            text = rule.proxy,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = if (isDirectRule) extColors.onEmeraldContainer else extColors.onInfoContainer,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(horizontal = 9.dp, vertical = 3.dp),
                        )
                    }
                }
            }
        }
    }
}
