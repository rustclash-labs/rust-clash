package io.github.rustclashlabs.rustclash.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CellTower
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.ExitIpUi
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LatencyPill
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashBrandIcon
import io.github.rustclashlabs.rustclash.ui.theme.TrafficWaveformGraph
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    state: AppUiState,
    onToggleVpn: () -> Unit,
    onOpenQuickImport: () -> Unit,
    onSelectRoutingPreset: (RoutingPresetUi) -> Unit,
    onNavigateToNodes: () -> Unit,
    onNavigateToRules: (initialTab: Int) -> Unit,
    onTestActiveLatency: () -> Unit,
    onDismissError: () -> Unit = {},
    onShareDebugReport: () -> Unit = {},
    onDismissDebugAnomaly: () -> Unit = {},
    onRefreshExitIp: () -> Unit = {},
    onCopyExitIp: (String) -> Unit = {},
) {
    val extColors = LocalRustClashColors.current
    var showRoutingSheet by remember { mutableStateOf(false) }
    var showTopMenu by remember { mutableStateOf(false) }
    var showExitIpSheet by remember { mutableStateOf(false) }

    val isConnected = state.vpnState == VpnLifecycleState.RUNNING
    val isTransitioning = state.vpnState == VpnLifecycleState.PREPARING ||
        state.vpnState == VpnLifecycleState.STARTING ||
        state.vpnState == VpnLifecycleState.RECONNECTING ||
        state.vpnState == VpnLifecycleState.STOPPING
    val isErrorState = state.vpnState == VpnLifecycleState.ERROR ||
        state.vpnState == VpnLifecycleState.REVOKED

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 20.dp, top = 6.dp, end = 20.dp, bottom = 20.dp),
    ) {
        // Top Brand Bar: Geometric brand emblem + title + live protection pill + overflow menu
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RustClashBrandIcon(size = 28.dp)
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "RustClash",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f),
            )

            if (state.demoMode) {
                Surface(
                    shape = CircleShape,
                    color = extColors.amberContainer,
                    modifier = Modifier.padding(end = 4.dp),
                ) {
                    Text(
                        text = "沙盒模式",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = extColors.onAmberContainer,
                        modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
                    )
                }
            } else if (isConnected) {
                Surface(
                    shape = CircleShape,
                    color = extColors.emeraldContainer,
                    modifier = Modifier.padding(end = 4.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(extColors.emeraldBright),
                        )
                        Spacer(modifier = Modifier.width(5.dp))
                        Text(
                            text = "已保护",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = extColors.onEmeraldContainer,
                        )
                    }
                }
            }

            Box {
                IconButton(onClick = { showTopMenu = true }) {
                    Icon(
                        imageVector = Icons.Rounded.MoreVert,
                        contentDescription = "快捷菜单",
                        tint = MaterialTheme.colorScheme.onBackground,
                    )
                }
                DropdownMenu(
                    expanded = showTopMenu,
                    onDismissRequest = { showTopMenu = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("导入节点 / 订阅") },
                        leadingIcon = { Icon(Icons.Rounded.Add, contentDescription = null) },
                        onClick = {
                            showTopMenu = false
                            onOpenQuickImport()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("切换路由分流模式") },
                        leadingIcon = { Icon(Icons.Rounded.Tune, contentDescription = null) },
                        onClick = {
                            showTopMenu = false
                            showRoutingSheet = true
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("当前节点测速") },
                        leadingIcon = { Icon(Icons.Rounded.Speed, contentDescription = null) },
                        onClick = {
                            showTopMenu = false
                            onTestActiveLatency()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("查询当前落地 IP") },
                        leadingIcon = { Icon(Icons.Rounded.Language, contentDescription = null) },
                        onClick = {
                            showTopMenu = false
                            showExitIpSheet = true
                            if (!state.isProbingExitIp && (state.exitIp == null || !state.exitIp.verified)) {
                                onRefreshExitIp()
                            }
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("诊断网站连接问题") },
                        leadingIcon = { Icon(Icons.Rounded.Public, contentDescription = null) },
                        onClick = {
                            showTopMenu = false
                            onNavigateToRules(2)
                        },
                    )
                }
            }
        }

        // Alert Banner (only when error or Android Lockdown warning exists)
        val bannerMessage = state.lastError ?: state.lockdownWarning
        if (!bannerMessage.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(8.dp))
            val isHardError = state.lastError != null
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = if (isHardError) extColors.dangerContainer else extColors.amberContainer,
            ) {
                Row(
                    modifier = Modifier.padding(
                        start = 14.dp,
                        top = 10.dp,
                        bottom = 10.dp,
                        end = if (isHardError) 8.dp else 14.dp,
                    ),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = if (isHardError) Icons.Rounded.ErrorOutline else Icons.Rounded.WarningAmber,
                        contentDescription = null,
                        tint = if (isHardError) extColors.onDangerContainer else extColors.onAmberContainer,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = bannerMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isHardError) extColors.onDangerContainer else extColors.onAmberContainer,
                        modifier = Modifier.weight(1f),
                    )
                    if (isHardError) {
                        Spacer(modifier = Modifier.width(4.dp))
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(CircleShape)
                                .clickable(onClick = onDismissError),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Clear,
                                contentDescription = "关闭错误提示",
                                tint = extColors.onDangerContainer.copy(alpha = 0.85f),
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                }
            }
        }

        // Debug Anomaly Sentinel Card (proactive high-signal alert when Debug mode is enabled)
        val activeAnomaly = if (state.debugLog.enabled) state.debugLog.activeAnomaly else null
        if (activeAnomaly != null) {
            Spacer(modifier = Modifier.height(8.dp))
            val isCriticalAnomaly = activeAnomaly.severity == "critical"
            val cardBg = if (isCriticalAnomaly) extColors.dangerContainer else extColors.amberContainer
            val cardFg = if (isCriticalAnomaly) extColors.onDangerContainer else extColors.onAmberContainer
            val actionBtnBg = if (isCriticalAnomaly) extColors.danger else extColors.amber
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = cardBg,
            ) {
                Column(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = if (isCriticalAnomaly) Icons.Rounded.ErrorOutline else Icons.Rounded.BugReport,
                            contentDescription = null,
                            tint = cardFg,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = activeAnomaly.headlineZh,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = cardFg,
                            modifier = Modifier.weight(1f),
                        )
                        if (activeAnomaly.detectedAtMs > 0L) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = UiJsonParsers.formatEpochTime(activeAnomaly.detectedAtMs),
                                style = MaterialTheme.typography.labelSmall,
                                color = cardFg.copy(alpha = 0.8f),
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = activeAnomaly.detailZh,
                        style = MaterialTheme.typography.bodySmall,
                        color = cardFg,
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Button(
                            onClick = onShareDebugReport,
                            enabled = !state.isExportingDebugLog,
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = actionBtnBg,
                                contentColor = Color.White,
                            ),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Share,
                                contentDescription = null,
                                modifier = Modifier.size(15.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (state.isExportingDebugLog) "正在导出…" else "一键导出日志",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                        TextButton(
                            onClick = onDismissDebugAnomaly,
                            enabled = !state.isExportingDebugLog,
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                        ) {
                            Text(
                                text = "忽略本次",
                                style = MaterialTheme.typography.labelMedium,
                                color = cardFg.copy(alpha = 0.9f),
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Hero Connect Section
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            HeroConnectButton(
                isConnected = isConnected,
                isTransitioning = isTransitioning,
                isErrorState = isErrorState,
                onClick = onToggleVpn,
            )

            Spacer(modifier = Modifier.height(4.dp))

            val statusTitle = when (state.vpnState) {
                VpnLifecycleState.RUNNING -> if (state.routingPreset == RoutingPresetUi.DIRECT) {
                    "已连接（全局直连）"
                } else {
                    "已连接"
                }
                VpnLifecycleState.PREPARING, VpnLifecycleState.STARTING -> "正在连接…"
                VpnLifecycleState.RECONNECTING -> "网络恢复中…"
                VpnLifecycleState.STOPPING -> "正在断开…"
                VpnLifecycleState.REVOKED -> "权限已撤销"
                VpnLifecycleState.ERROR -> "连接异常"
                VpnLifecycleState.DISCONNECTED -> "未连接"
            }
            Text(
                text = statusTitle,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Spacer(modifier = Modifier.height(3.dp))

            val noSavedNodes = state.nodes.isEmpty() && !state.demoMode
            val isDirectConnected = isConnected && state.routingPreset == RoutingPresetUi.DIRECT
            val heroSubtitle = when {
                isDirectConnected -> "当前为 Direct 模式 · 流量不经过代理节点"
                noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT ->
                    "点击导入首个代理节点 · ${state.routingPreset.modeDisplay}"
                else -> "${state.effectiveOutbound} · ${state.routingPreset.modeDisplay}"
            }
            Text(
                text = heroSubtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isDirectConnected || (noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT)) {
                    extColors.amber
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            if (isConnected) {
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val networkText = if (state.telemetry.isWifi) "Wi-Fi" else "移动网络"
                    HomeMetaChip(
                        text = networkText,
                        containerColor = extColors.emeraldContainer.copy(alpha = 0.72f),
                        contentColor = extColors.onEmeraldContainer,
                    )
                    HomeMetaChip(
                        text = "${state.telemetry.activeConnections} 活跃连接",
                        containerColor = extColors.cardSubtle,
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (state.enableIpv6) {
                        HomeMetaChip(
                            text = "IPv6",
                            containerColor = extColors.violetContainer.copy(alpha = 0.78f),
                            contentColor = extColors.onVioletContainer,
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Live Speed & Waveform Card
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            color = extColors.cardSurface,
            border = BorderStroke(1.dp, extColors.hairline),
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    SpeedColumnItem(
                        arrow = "↓",
                        label = "下载",
                        rateText = UiJsonParsers.formatRate(if (isConnected) state.telemetry.downRate else 0L),
                        accentColor = extColors.emerald,
                        modifier = Modifier.weight(1f),
                    )
                    Box(
                        modifier = Modifier
                            .width(1.dp)
                            .height(32.dp)
                            .background(extColors.hairline),
                    )
                    SpeedColumnItem(
                        arrow = "↑",
                        label = "上传",
                        rateText = UiJsonParsers.formatRate(if (isConnected) state.telemetry.upRate else 0L),
                        accentColor = extColors.sky,
                        modifier = Modifier.weight(1f),
                    )
                }

                if (isConnected && (state.telemetry.downTotal > 0L || state.telemetry.upTotal > 0L)) {
                    Text(
                        text = "本次累计 ↓ ${UiJsonParsers.formatBytes(state.telemetry.downTotal)}  ·  ↑ ${UiJsonParsers.formatBytes(state.telemetry.upTotal)}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFeatureSettings = "tnum"),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 1.dp),
                    )
                }

                TrafficWaveformGraph(
                    samples = state.rateHistory,
                    isConnected = isConnected,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(42.dp)
                        .clip(RoundedCornerShape(bottomStart = 18.dp, bottomEnd = 18.dp)),
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Primary Summary Card: Routing Mode, Active Node & Unified Diagnostics
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            color = extColors.cardSurface,
            border = BorderStroke(1.dp, extColors.hairline),
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                // Row 1: 路由模式
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showRoutingSheet = true }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HomeRowIconBadge(
                        icon = Icons.Rounded.Route,
                        tint = extColors.emerald,
                        containerColor = extColors.emeraldContainer,
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "路由模式",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "${state.routingPreset.homeBadge} · ${state.routingPreset.homeSubtitle}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = "选择路由模式",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }

                HorizontalDivider(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    thickness = 0.8.dp,
                    color = extColors.hairline,
                )

                // Row 2: 当前节点
                val delayMs = state.effectiveNodeDelayMs
                val isProbing = state.isTestingAllDelays || state.testingNodeName == state.effectiveOutbound
                val canTestActiveNode = !(state.nodes.isEmpty() && !state.demoMode) &&
                    state.effectiveOutbound != "DIRECT" &&
                    state.effectiveOutbound != "REJECT"
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (state.nodes.isEmpty() && !state.demoMode) {
                                onOpenQuickImport()
                            } else {
                                onNavigateToNodes()
                            }
                        }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HomeRowIconBadge(
                        icon = Icons.Rounded.Dns,
                        tint = extColors.sky,
                        containerColor = extColors.skyContainer,
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = "当前节点",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            if (canTestActiveNode) {
                                Spacer(modifier = Modifier.width(8.dp))
                                LatencyPill(
                                    delayMs = delayMs,
                                    isProbing = isProbing,
                                    isSelected = true,
                                    onClick = onTestActiveLatency,
                                )
                            } else if (isProbing) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(15.dp),
                                    strokeWidth = 2.dp,
                                    color = extColors.emerald,
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(2.dp))

                        if (state.nodes.isEmpty() && !state.demoMode) {
                            Text(
                                text = "点击导入 vless:// · vmess:// · ss:// · trojan:// · hy2:// · tuic:// 节点",
                                style = MaterialTheme.typography.bodySmall,
                                color = extColors.emerald,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        } else {
                            Text(
                                text = "${state.effectiveOutbound} · ${state.effectiveProtocolDisplay}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        if (isConnected || state.nodes.isNotEmpty() || state.demoMode || state.exitIp != null || state.isProbingExitIp) {
                            Spacer(modifier = Modifier.height(4.dp))
                            ExitIpCompactPill(
                                exitIp = state.exitIp,
                                isProbing = state.isProbingExitIp,
                                onClick = {
                                    showExitIpSheet = true
                                    val current = state.exitIp
                                    if (!state.isProbingExitIp && (current == null || !current.verified)) {
                                        onRefreshExitIp()
                                    }
                                },
                            )
                        }
                    }

                    Spacer(modifier = Modifier.width(6.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = "查看节点列表",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }

                HorizontalDivider(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    thickness = 0.8.dp,
                    color = extColors.hairline,
                )

                // Row 3: Unified 分流诊断（点击查看诊断明细，右上角「网站排障」直达一键排障）
                val hasLiveDiagnostics = isConnected || state.diagnostics.isNotEmpty()
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateToRules(if (hasLiveDiagnostics) 1 else 2) }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    HomeRowIconBadge(
                        icon = Icons.Rounded.Public,
                        tint = extColors.violet,
                        containerColor = extColors.violetContainer,
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = "分流诊断",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Surface(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable { onNavigateToRules(2) },
                                shape = RoundedCornerShape(8.dp),
                                color = extColors.violetContainer,
                            ) {
                                Text(
                                    text = "网站排障",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = extColors.onVioletContainer,
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                        val diagSubtitle = if (hasLiveDiagnostics) {
                            val base = "直连 ${state.directDiagnosticCount} · 代理 ${state.proxyDiagnosticCount}"
                            if (state.failedDiagnosticCount > 0) {
                                "$base · 异常 ${state.failedDiagnosticCount}"
                            } else {
                                base
                            }
                        } else {
                            "查看实时分流明细 · 一键排查网站连通性"
                        }
                        Text(
                            text = diagSubtitle,
                            style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = if (hasLiveDiagnostics) "查看诊断明细" else "打开网站排障",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }
            }
        }
    }

    if (showRoutingSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showRoutingSheet = false },
            sheetState = sheetState,
            containerColor = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp, vertical = 8.dp),
            ) {
                Text(
                    text = "选择路由分流方案",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "切换实时生效，原有自定义分流规则会自动保留。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))

                RoutingPresetUi.entries.forEach { preset ->
                    val selected = state.routingPreset == preset
                    val presetIcon = when (preset) {
                        RoutingPresetUi.SMART_CN -> Icons.Rounded.CellTower
                        RoutingPresetUi.GLOBAL -> Icons.Rounded.Public
                        RoutingPresetUi.DIRECT -> Icons.Rounded.Link
                        RoutingPresetUi.CUSTOM -> Icons.Rounded.Tune
                    }
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 5.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .clickable {
                                showRoutingSheet = false
                                onSelectRoutingPreset(preset)
                            },
                        shape = RoundedCornerShape(16.dp),
                        color = if (selected) extColors.selectedCardBg else extColors.cardSubtle,
                        border = BorderStroke(
                            width = if (selected) 1.5.dp else 1.dp,
                            color = if (selected) extColors.selectedCardBorder else extColors.hairline,
                        ),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                imageVector = presetIcon,
                                contentDescription = null,
                                tint = if (selected) extColors.emerald else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(22.dp),
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = preset.title,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                    if (preset == RoutingPresetUi.SMART_CN) {
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Surface(
                                            shape = RoundedCornerShape(6.dp),
                                            color = extColors.emeraldContainer,
                                        ) {
                                            Text(
                                                text = "推荐",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.SemiBold,
                                                color = extColors.onEmeraldContainer,
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
                                )
                            }
                            if (selected) {
                                Spacer(modifier = Modifier.width(10.dp))
                                Icon(
                                    imageVector = Icons.Rounded.CheckCircle,
                                    contentDescription = "已选中",
                                    tint = extColors.emerald,
                                    modifier = Modifier.size(22.dp),
                                )
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }

    if (showExitIpSheet) {
        ExitIpDetailBottomSheet(
            state = state,
            onDismiss = { showExitIpSheet = false },
            onRefresh = onRefreshExitIp,
            onCopyIp = onCopyExitIp,
        )
    }
}

@Composable
private fun ExitIpCompactPill(
    exitIp: ExitIpUi?,
    isProbing: Boolean,
    onClick: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val verifiedIp = exitIp?.takeIf { it.verified && it.ip.isNotBlank() && it.ip != "--" }
    val isFailed = exitIp != null && verifiedIp == null && !isProbing
    val containerColor = when {
        isProbing -> extColors.cardSubtle
        verifiedIp != null && verifiedIp.demoMode -> extColors.amberContainer.copy(alpha = 0.72f)
        verifiedIp != null -> extColors.emeraldContainer.copy(alpha = 0.62f)
        isFailed -> extColors.amberContainer.copy(alpha = 0.72f)
        else -> extColors.cardSubtle
    }
    val contentColor = when {
        isProbing -> MaterialTheme.colorScheme.onSurfaceVariant
        verifiedIp != null && verifiedIp.demoMode -> extColors.onAmberContainer
        verifiedIp != null -> extColors.onEmeraldContainer
        isFailed -> extColors.onAmberContainer
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val labelText = when {
        isProbing -> "正在查询落地 IP…"
        verifiedIp != null -> verifiedIp.compactPillText
        isFailed -> "落地 IP 检测失败 · 点击重试"
        else -> "落地 IP · 点击查询"
    }

    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(7.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(7.dp),
        color = containerColor,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
        ) {
            if (isProbing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(11.dp),
                    strokeWidth = 1.6.dp,
                    color = extColors.emerald,
                )
            } else {
                Icon(
                    imageVector = Icons.Rounded.Language,
                    contentDescription = null,
                    tint = contentColor,
                    modifier = Modifier.size(12.dp),
                )
            }
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = labelText,
                style = MaterialTheme.typography.labelSmall.copy(fontFeatureSettings = "tnum"),
                fontWeight = if (verifiedIp != null) FontWeight.SemiBold else FontWeight.Medium,
                color = contentColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExitIpDetailBottomSheet(
    state: AppUiState,
    onDismiss: () -> Unit,
    onRefresh: () -> Unit,
    onCopyIp: (String) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val exitIp = state.exitIp
    val verifiedIp = exitIp?.takeIf { it.verified && it.ip.isNotBlank() && it.ip != "--" }
    val isProbing = state.isProbingExitIp

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Text(
                text = "当前落地 IP",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "通过当前出口实时探测的公网 IP 与归属地",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(14.dp))

            // Hero IP & Country Surface
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = extColors.cardSubtle,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = when {
                                verifiedIp != null -> verifiedIp.countryWithFlag
                                isProbing -> "正在检测出口 IP…"
                                else -> "未获取到落地 IP"
                            },
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        if (verifiedIp != null && verifiedIp.ipTypeDisplayZh != "未知") {
                            Spacer(modifier = Modifier.width(8.dp))
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = if (verifiedIp.demoMode) extColors.amberContainer else extColors.emeraldContainer,
                            ) {
                                Text(
                                    text = verifiedIp.ipTypeDisplayZh,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (verifiedIp.demoMode) extColors.onAmberContainer else extColors.onEmeraldContainer,
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (isProbing && verifiedIp == null) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = extColors.emerald,
                            )
                            Text(
                                text = "正在通过当前出口查询…",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    } else {
                        Text(
                            text = verifiedIp?.ip ?: "--",
                            style = MaterialTheme.typography.headlineSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontFeatureSettings = "tnum",
                            ),
                            color = if (verifiedIp != null) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    val errText = exitIp?.takeIf { !it.verified }?.error
                    if (!errText.isNullOrBlank()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp),
                            color = extColors.amberContainer,
                        ) {
                            Text(
                                text = errText,
                                style = MaterialTheme.typography.bodySmall,
                                color = extColors.onAmberContainer,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Detail rows card
            val outboundName = exitIp?.outbound?.takeIf { it.isNotBlank() } ?: state.effectiveOutbound
            val protocolLabel = exitIp?.protocol?.takeIf { it.isNotBlank() } ?: state.effectiveProtocolDisplay
            val countryDetail = if (verifiedIp != null) {
                val cc = verifiedIp.countryCode.trim().uppercase(Locale.ROOT)
                if (cc.isNotEmpty() && !verifiedIp.demoMode) {
                    "${verifiedIp.countryWithFlag} ($cc)"
                } else {
                    verifiedIp.countryWithFlag
                }
            } else {
                "--"
            }
            val latencyText = exitIp?.latencyMs?.let { ms ->
                if (exitIp.cached) "$ms ms（缓存）" else "$ms ms"
            } ?: "--"
            val checkedAtText = exitIp?.checkedAtMs?.takeIf { it > 0L }
                ?.let(UiJsonParsers::formatEpochTime) ?: "--"

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    ExitIpInfoRow(label = "出口节点", value = "$outboundName · $protocolLabel")
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 14.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    ExitIpInfoRow(label = "国家 / 地区", value = countryDetail)
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 14.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    ExitIpInfoRow(
                        label = "运营商 (ISP)",
                        value = exitIp?.isp?.takeIf { it.isNotBlank() } ?: "--",
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 14.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    ExitIpInfoRow(
                        label = "ASN",
                        value = exitIp?.asn?.takeIf { it.isNotBlank() } ?: "--",
                        monospace = true,
                    )
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 14.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    ExitIpInfoRow(label = "探测耗时", value = latencyText, monospace = true)
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 14.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    ExitIpInfoRow(label = "查询时间", value = checkedAtText, monospace = true)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(
                    onClick = {
                        if (verifiedIp != null) {
                            onCopyIp(verifiedIp.ip)
                        }
                    },
                    enabled = verifiedIp != null,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("复制 IP")
                }
                Button(
                    onClick = onRefresh,
                    enabled = !isProbing,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    if (isProbing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (isProbing) "检测中…" else "重新检测")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun ExitIpInfoRow(
    label: String,
    value: String,
    monospace: Boolean = false,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            softWrap = false,
        )
        Spacer(modifier = Modifier.width(12.dp))
        Box(
            modifier = Modifier.weight(1f),
            contentAlignment = Alignment.CenterEnd,
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                    fontWeight = FontWeight.Medium,
                    fontFeatureSettings = "tnum",
                ),
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun HomeMetaChip(
    text: String,
    containerColor: Color,
    contentColor: Color,
) {
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = containerColor,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall.copy(fontFeatureSettings = "tnum"),
            fontWeight = FontWeight.Medium,
            color = contentColor,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 3.dp),
        )
    }
}

@Composable
private fun HomeRowIconBadge(
    icon: ImageVector,
    tint: Color,
    containerColor: Color,
) {
    Box(
        modifier = Modifier
            .size(34.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(containerColor),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun HeroConnectButton(
    isConnected: Boolean,
    isTransitioning: Boolean,
    isErrorState: Boolean,
    onClick: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val haptic = LocalHapticFeedback.current
    // Only animate during active connect/disconnect transitions; steady-state connected aura stays
    // static (0 Hz) to avoid continuous 60-120 Hz idle redraws.
    val haloScale = if (isTransitioning) {
        val pulseTransition = rememberInfiniteTransition(label = "vpnTransitionHalo")
        val animatedScale by pulseTransition.animateFloat(
            initialValue = 1.0f,
            targetValue = 1.08f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "haloScale",
        )
        animatedScale
    } else {
        1.0f
    }

    val ringColor by animateColorAsState(
        targetValue = when {
            isConnected -> extColors.emeraldBright
            isErrorState -> extColors.danger
            isTransitioning -> extColors.amber
            else -> MaterialTheme.colorScheme.outline
        },
        label = "ringColor",
    )

    val glowCenterColor = when {
        isConnected -> extColors.emeraldBright.copy(alpha = if (extColors.isDark) 0.40f else 0.30f)
        isErrorState -> extColors.danger.copy(alpha = 0.24f)
        isTransitioning -> extColors.amber.copy(alpha = 0.24f)
        else -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.06f)
    }

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(118.dp),
    ) {
        // Multi-layer static-at-idle Neon radial aura + precision dashed orbit ring
        Canvas(
            modifier = Modifier
                .size(118.dp)
                .then(
                    if (haloScale != 1.0f) {
                        Modifier.graphicsLayer {
                            scaleX = haloScale
                            scaleY = haloScale
                        }
                    } else {
                        Modifier
                    },
                ),
        ) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        glowCenterColor,
                        glowCenterColor.copy(alpha = glowCenterColor.alpha * 0.42f),
                        Color.Transparent,
                    ),
                ),
                radius = size.minDimension / 2f,
            )
            drawCircle(
                color = ringColor.copy(alpha = if (isConnected) 0.42f else 0.18f),
                radius = size.minDimension / 2f - 8.dp.toPx(),
                style = Stroke(
                    width = 1.25.dp.toPx(),
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(9f, 9f), 0f),
                ),
            )
        }

        Surface(
            onClick = {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onClick()
            },
            shape = CircleShape,
            color = if (isConnected) extColors.emerald else extColors.cardSurface,
            border = BorderStroke(
                width = if (isConnected) 2.dp else 2.5.dp,
                color = if (isConnected) Color.White.copy(alpha = 0.32f) else ringColor,
            ),
            shadowElevation = if (isConnected) 10.dp else 2.dp,
            modifier = Modifier.size(82.dp),
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .fillMaxSize()
                    .then(
                        if (isConnected) {
                            Modifier.background(
                                Brush.linearGradient(
                                    colors = listOf(extColors.emeraldBright, extColors.emerald),
                                ),
                            )
                        } else {
                            Modifier
                        },
                    ),
            ) {
                if (isTransitioning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(30.dp),
                        strokeWidth = 2.8.dp,
                        color = ringColor,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.PowerSettingsNew,
                        contentDescription = if (isConnected) "断开 VPN" else "连接 VPN",
                        tint = when {
                            isConnected -> Color.White
                            isErrorState -> ringColor
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                        modifier = Modifier.size(34.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun SpeedColumnItem(
    arrow: String,
    label: String,
    rateText: String,
    accentColor: Color,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = arrow,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = accentColor,
                maxLines = 1,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = rateText,
            style = MaterialTheme.typography.titleLarge.copy(
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                fontFeatureSettings = "tnum",
            ),
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
