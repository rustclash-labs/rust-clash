package io.github.rustclashlabs.rustclash.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Shield
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
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.ExitIpUi
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.ExitCountryLandmarkCanvas
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashBrandIcon
import io.github.rustclashlabs.rustclash.ui.theme.RustClashExtendedColors
import io.github.rustclashlabs.rustclash.ui.theme.TrafficWaveformGraph
import io.github.rustclashlabs.rustclash.ui.theme.landmarkCaptionFor
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import java.util.Locale

/**
 * Draws the subtle top-edge emerald atmospheric glow used behind the Home dashboard when connected.
 * Applied at the root scaffold layer for seamless full-bleed status-bar continuity, or directly on
 * [HomeScreen] when hosted standalone.
 */
fun Modifier.homeAmbientGlow(
    extColors: RustClashExtendedColors,
    alpha: Float,
    centerYOffset: Dp = 32.dp,
): Modifier = drawBehind {
    if (alpha > 0.01f) {
        val radius = maxOf(size.width * 0.98f, 360.dp.toPx())
        val center = Offset(size.width * 0.5f, centerYOffset.toPx())
        drawCircle(
            brush = Brush.radialGradient(
                colorStops = arrayOf(
                    0.0f to extColors.ambientGlowTop.copy(
                        alpha = extColors.ambientGlowTop.alpha * alpha,
                    ),
                    0.46f to extColors.ambientGlowMid.copy(
                        alpha = extColors.ambientGlowMid.alpha * alpha,
                    ),
                    1.0f to Color.Transparent,
                ),
                center = center,
                radius = radius,
            ),
            radius = radius,
            center = center,
        )
    }
}

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
    drawAmbientGlow: Boolean = true,
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

    val ambientGlowAlpha by animateFloatAsState(
        targetValue = if (drawAmbientGlow && isConnected) 1f else 0f,
        animationSpec = tween(durationMillis = 320),
        label = "homeAmbientGlow",
    )

    val noSavedNodes = state.nodes.isEmpty() && !state.demoMode
    val canTestActiveNode = !noSavedNodes &&
        state.effectiveOutbound != "DIRECT" &&
        state.effectiveOutbound != "REJECT"
    val isProbingLatency = state.isTestingAllDelays || state.testingNodeName == state.effectiveOutbound
    val hasAlertOverlay = !(state.lastError ?: state.lockdownWarning).isNullOrBlank() ||
        (state.debugLog.enabled && state.debugLog.activeAnomaly != null)

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .then(
                if (drawAmbientGlow) {
                    Modifier.homeAmbientGlow(
                        extColors = extColors,
                        alpha = ambientGlowAlpha,
                        centerYOffset = 12.dp,
                    )
                } else {
                    Modifier
                },
            ),
    ) {
        val landmarkCardHeight = if (hasAlertOverlay) {
            204.dp
        } else {
            (maxHeight - 474.dp).coerceIn(204.dp, 288.dp)
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 18.dp, top = 8.dp, end = 18.dp, bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Top Brand Bar: Geometric emblem + title + quiet network text + overflow menu
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RustClashBrandIcon(size = 26.dp)
                Spacer(modifier = Modifier.width(9.dp))
                Text(
                    text = "RustClash",
                    style = MaterialTheme.typography.titleLarge.copy(
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = (-0.3).sp,
                    ),
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
                } else {
                    val networkSummary = when {
                        isConnected -> buildString {
                            append(if (state.telemetry.isWifi) "Wi-Fi" else "移动网络")
                            if (state.enableIpv6) append(" · IPv6")
                        }
                        isErrorState -> "异常"
                        else -> "待机"
                    }
                    Text(
                        text = networkSummary,
                        style = MaterialTheme.typography.labelMedium,
                        color = if (isErrorState) {
                            extColors.danger
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        maxLines = 1,
                        modifier = Modifier.padding(end = 2.dp),
                    )
                }

                Box {
                    IconButton(
                        onClick = { showTopMenu = true },
                        modifier = Modifier.size(36.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.MoreVert,
                            contentDescription = "快捷菜单",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp),
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
                            text = { Text("实时分流诊断") },
                            leadingIcon = { Icon(Icons.Rounded.Route, contentDescription = null) },
                            onClick = {
                                showTopMenu = false
                                onNavigateToRules(1)
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
                val isHardError = state.lastError != null
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
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
                val isCriticalAnomaly = activeAnomaly.severity == "critical"
                val cardBg = if (isCriticalAnomaly) extColors.dangerContainer else extColors.amberContainer
                val cardFg = if (isCriticalAnomaly) extColors.onDangerContainer else extColors.onAmberContainer
                val actionBtnBg = if (isCriticalAnomaly) extColors.danger else extColors.amber
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
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

            // Hero Master Control Card: Unified status, active node, tactile power trigger & telemetry footer
            HeroControlCard(
                state = state,
                isConnected = isConnected,
                isTransitioning = isTransitioning,
                isErrorState = isErrorState,
                noSavedNodes = noSavedNodes,
                onToggleVpn = onToggleVpn,
                onNodeAreaClick = {
                    if (noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT) {
                        onOpenQuickImport()
                    } else {
                        onNavigateToNodes()
                    }
                },
            )

            // Inline 3-Way Routing Mode Switcher (Zero-modal 1-tap switching; tap active first slot for full sheet)
            InlineRoutingModeSwitcher(
                currentPreset = state.routingPreset,
                onSelectPreset = onSelectRoutingPreset,
                onOpenAllPresetsSheet = { showRoutingSheet = true },
            )

            // Middle Asymmetric Bento Row: Compact Stacked Throughput (1.35f) + Node Latency (1f)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(IntrinsicSize.Max),
                horizontalArrangement = Arrangement.spacedBy(11.dp),
            ) {
                CompactThroughputCard(
                    downRate = if (isConnected) state.telemetry.downRate else 0L,
                    upRate = if (isConnected) state.telemetry.upRate else 0L,
                    downTotal = if (isConnected) state.telemetry.downTotal else 0L,
                    upTotal = if (isConnected) state.telemetry.upTotal else 0L,
                    rateHistory = state.rateHistory,
                    isConnected = isConnected,
                    modifier = Modifier
                        .weight(1.35f)
                        .fillMaxHeight()
                        .heightIn(min = 166.dp),
                )
                LatencyBentoTile(
                    delayMs = state.effectiveNodeDelayMs,
                    isProbing = isProbingLatency,
                    canTest = canTestActiveNode,
                    onClick = onTestActiveLatency,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .heightIn(min = 166.dp),
                )
            }

            // Bottom Full-Width Panoramic Exit IP & City Landmark Showcase Card
            ExitIpLandmarkCard(
                exitIp = state.exitIp,
                isProbing = state.isProbingExitIp,
                isConnected = isConnected,
                targetHeight = landmarkCardHeight,
                onClick = {
                    showExitIpSheet = true
                    val current = state.exitIp
                    if (!state.isProbingExitIp && (current == null || !current.verified)) {
                        onRefreshExitIp()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
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
private fun HeroControlCard(
    state: AppUiState,
    isConnected: Boolean,
    isTransitioning: Boolean,
    isErrorState: Boolean,
    noSavedNodes: Boolean,
    onToggleVpn: () -> Unit,
    onNodeAreaClick: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val haptic = LocalHapticFeedback.current

    // Only pulse during active connect/disconnect transitions; steady state stays 0 Hz.
    val transitionScale = if (isTransitioning) {
        val pulseTransition = rememberInfiniteTransition(label = "vpnTransitionPulse")
        val animatedScale by pulseTransition.animateFloat(
            initialValue = 1.0f,
            targetValue = 1.05f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1000, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "powerButtonScale",
        )
        animatedScale
    } else {
        1.0f
    }

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

    val isDirectConnected = isConnected && state.routingPreset == RoutingPresetUi.DIRECT
    val primaryHeadline = when {
        noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT -> "点击导入首个代理节点"
        isDirectConnected -> "本地直连出口 (DIRECT)"
        else -> state.effectiveOutbound
    }
    val metaSubtitle = when {
        noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT -> "支持 VLESS · VMess · SS · Trojan · Hy2 ›"
        isDirectConnected -> "Direct 模式 · 流量不经代理节点 ›"
        else -> "${state.effectiveProtocolDisplay} · ${state.routingPreset.homeSubtitle} ›"
    }

    val heroFg = if (isConnected) Color.White else MaterialTheme.colorScheme.onSurface
    val heroSub = if (isConnected) {
        Color.White.copy(alpha = 0.82f)
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    val statusDotColor = when {
        isConnected -> Color(0xFF86EFAC)
        isErrorState -> extColors.danger
        isTransitioning -> extColors.amber
        else -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.48f)
    }
    val stripBg = if (isConnected) {
        Color.Black.copy(alpha = if (extColors.isDark) 0.22f else 0.14f)
    } else {
        extColors.tonalTrack.copy(alpha = 0.78f)
    }
    val powerBtnBg = when {
        isConnected -> Color.White.copy(alpha = 0.96f)
        isErrorState -> extColors.dangerContainer
        else -> extColors.tonalTrack
    }
    val powerIconTint = when {
        isConnected -> Color(0xFF006B4B)
        isErrorState -> extColors.danger
        isTransitioning -> extColors.amber
        else -> MaterialTheme.colorScheme.onSurface
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = if (isConnected) extColors.heroGradientStart else extColors.cardSurface,
        shadowElevation = when {
            isConnected && !extColors.isDark -> 8.dp
            isConnected -> 3.dp
            !extColors.isDark -> 2.dp
            else -> 0.dp
        },
        border = if (!isConnected && isErrorState) {
            BorderStroke(1.dp, extColors.danger.copy(alpha = 0.36f))
        } else {
            null
        },
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .then(
                    if (isConnected) {
                        Modifier.background(
                            Brush.linearGradient(
                                colors = listOf(
                                    extColors.heroGradientStart,
                                    extColors.heroGradientEnd,
                                ),
                            ),
                        )
                    } else {
                        Modifier
                    },
                )
                .padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(12.dp))
                        .clickable(onClick = onNodeAreaClick)
                        .padding(vertical = 2.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.5.dp)
                                .clip(CircleShape)
                                .background(statusDotColor),
                        )
                        Text(
                            text = statusTitle,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = if (!isConnected && isErrorState) extColors.danger else heroSub,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))

                    Text(
                        text = primaryHeadline,
                        style = MaterialTheme.typography.titleLarge.copy(
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = (-0.2).sp,
                        ),
                        color = heroFg,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = metaSubtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (!isConnected && noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT) {
                            extColors.emerald
                        } else {
                            heroSub
                        },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                Surface(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onToggleVpn()
                    },
                    shape = RoundedCornerShape(19.dp),
                    color = powerBtnBg,
                    shadowElevation = if (isConnected) 4.dp else 0.dp,
                    modifier = Modifier
                        .size(54.dp)
                        .then(
                            if (transitionScale != 1.0f) {
                                Modifier.graphicsLayer {
                                    scaleX = transitionScale
                                    scaleY = transitionScale
                                }
                            } else {
                                Modifier
                            },
                        ),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        if (isTransitioning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.5.dp,
                                color = powerIconTint,
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Rounded.PowerSettingsNew,
                                contentDescription = if (isConnected) "断开 VPN" else "连接 VPN",
                                tint = powerIconTint,
                                modifier = Modifier.size(26.dp),
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Integrated frosted telemetry footer strip
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(13.dp),
                color = stripBg,
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 11.dp, vertical = 7.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Shield,
                            contentDescription = null,
                            tint = heroSub,
                            modifier = Modifier.size(13.5.dp),
                        )
                        Text(
                            text = when {
                                isDirectConnected -> "TUN 已启用 · 直连放行"
                                isConnected -> "TUN 通道已加密"
                                isErrorState -> "隧道未就绪"
                                else -> "TUN 通道待命"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = heroSub,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isConnected) "${state.telemetry.activeConnections} 活跃连接" else "0 活跃连接",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFeatureSettings = "tnum",
                            fontWeight = FontWeight.SemiBold,
                        ),
                        color = heroSub,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun InlineRoutingModeSwitcher(
    currentPreset: RoutingPresetUi,
    onSelectPreset: (RoutingPresetUi) -> Unit,
    onOpenAllPresetsSheet: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val haptic = LocalHapticFeedback.current
    val firstSlotPreset = if (currentPreset == RoutingPresetUi.CUSTOM) {
        RoutingPresetUi.CUSTOM
    } else {
        RoutingPresetUi.SMART_CN
    }
    val slots = listOf(
        firstSlotPreset to if (firstSlotPreset == RoutingPresetUi.CUSTOM) "自定义" else "规则分流",
        RoutingPresetUi.GLOBAL to "全局代理",
        RoutingPresetUi.DIRECT to "全局直连",
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = extColors.tonalTrack,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            slots.forEachIndexed { idx, (preset, label) ->
                val selected = currentPreset == preset
                val itemBg by animateColorAsState(
                    targetValue = if (selected) extColors.tonalThumb else Color.Transparent,
                    animationSpec = tween(180),
                    label = "routingSegBg",
                )
                val itemFg by animateColorAsState(
                    targetValue = if (selected) {
                        MaterialTheme.colorScheme.onSurface
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    animationSpec = tween(180),
                    label = "routingSegFg",
                )

                Surface(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            if (selected && idx == 0) {
                                onOpenAllPresetsSheet()
                            } else if (!selected) {
                                onSelectPreset(preset)
                            }
                        },
                    shape = RoundedCornerShape(12.dp),
                    color = itemBg,
                    shadowElevation = if (selected && !extColors.isDark) 2.dp else 0.dp,
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 8.dp),
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                            color = itemFg,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactThroughputCard(
    downRate: Long,
    upRate: Long,
    downTotal: Long,
    upTotal: Long,
    rateHistory: List<Long>,
    isConnected: Boolean,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    val onSurface = MaterialTheme.colorScheme.onSurface
    val onSurfaceVariant = MaterialTheme.colorScheme.onSurfaceVariant
    val downArrowColor = if (extColors.isDark) extColors.emeraldBright else extColors.emerald

    val (dlValue, dlUnit) = splitRateValueAndUnit(UiJsonParsers.formatRate(downRate))
    val (ulValue, ulUnit) = splitRateValueAndUnit(UiJsonParsers.formatRate(upRate))
    val totalSummary = if (isConnected) {
        "累计 ${UiJsonParsers.formatBytes(downTotal + upTotal)}"
    } else {
        "待机"
    }

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        color = extColors.cardSurface,
        shadowElevation = if (extColors.isDark) 0.dp else 1.5.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(start = 15.dp, end = 15.dp, top = 13.dp, bottom = 10.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "实时速率",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = onSurfaceVariant,
                    maxLines = 1,
                )
                Text(
                    text = totalSummary,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontSize = 10.5.sp,
                        fontFeatureSettings = "tnum",
                    ),
                    color = onSurfaceVariant.copy(alpha = 0.86f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                // Download speed row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Bottom,
                ) {
                    Text(
                        text = buildAnnotatedString {
                            withStyle(
                                SpanStyle(
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = downArrowColor,
                                ),
                            ) {
                                append("↓ ")
                            }
                            withStyle(
                                SpanStyle(
                                    fontSize = 21.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = onSurface,
                                    letterSpacing = (-0.5).sp,
                                ),
                            ) {
                                append(dlValue)
                            }
                            if (dlUnit.isNotEmpty()) {
                                withStyle(
                                    SpanStyle(
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = onSurfaceVariant,
                                    ),
                                ) {
                                    append(" ")
                                    append(dlUnit)
                                }
                            }
                        },
                        style = MaterialTheme.typography.titleLarge.copy(fontFeatureSettings = "tnum"),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = UiJsonParsers.formatBytes(downTotal),
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 10.sp,
                            fontFeatureSettings = "tnum",
                        ),
                        color = onSurfaceVariant.copy(alpha = 0.85f),
                        maxLines = 1,
                        softWrap = false,
                    )
                }

                // Upload speed row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Bottom,
                ) {
                    Text(
                        text = buildAnnotatedString {
                            withStyle(
                                SpanStyle(
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = onSurfaceVariant,
                                ),
                            ) {
                                append("↑ ")
                            }
                            withStyle(
                                SpanStyle(
                                    fontSize = 15.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = onSurface.copy(alpha = 0.90f),
                                    letterSpacing = (-0.3).sp,
                                ),
                            ) {
                                append(ulValue)
                            }
                            if (ulUnit.isNotEmpty()) {
                                withStyle(
                                    SpanStyle(
                                        fontSize = 10.5.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = onSurfaceVariant,
                                    ),
                                ) {
                                    append(" ")
                                    append(ulUnit)
                                }
                            }
                        },
                        style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = UiJsonParsers.formatBytes(upTotal),
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 10.sp,
                            fontFeatureSettings = "tnum",
                        ),
                        color = onSurfaceVariant.copy(alpha = 0.85f),
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }

            TrafficWaveformGraph(
                samples = rateHistory,
                isConnected = isConnected,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(40.dp),
            )
        }
    }
}

@Composable
private fun LatencyBentoTile(
    delayMs: Long?,
    isProbing: Boolean,
    canTest: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    val onSurface = MaterialTheme.colorScheme.onSurface
    val onSurfaceVariant = MaterialTheme.colorScheme.onSurfaceVariant
    val hasValidDelay = delayMs != null && delayMs > 0L

    val qualityColor = when {
        isProbing || !hasValidDelay -> onSurfaceVariant
        delayMs!! <= 120L -> if (extColors.isDark) extColors.emeraldBright else extColors.emerald
        delayMs <= 260L -> extColors.amber
        else -> extColors.danger
    }
    val qualityLabel = when {
        isProbing -> "测速中…"
        !hasValidDelay -> if (canTest) "点击测速" else "直连模式"
        delayMs!! <= 120L -> "质量极佳"
        delayMs <= 260L -> "质量良好"
        else -> "延迟偏高"
    }
    val activeEqualizerBars = when {
        isProbing || !hasValidDelay -> 0
        delayMs!! <= 120L -> 12
        delayMs <= 220L -> 9
        delayMs <= 360L -> 6
        else -> 3
    }
    val equalizerHeights = remember { listOf(7, 11, 15, 11, 19, 14, 22, 16, 13, 18, 10, 15) }

    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .then(if (canTest && !isProbing) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(22.dp),
        color = extColors.cardSurface,
        shadowElevation = if (extColors.isDark) 0.dp else 1.5.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 14.dp, vertical = 13.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "节点延迟",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = onSurfaceVariant,
                    maxLines = 1,
                )
                if (isProbing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(13.dp),
                        strokeWidth = 1.8.dp,
                        color = if (extColors.isDark) extColors.emeraldBright else extColors.emerald,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.Refresh,
                        contentDescription = "重新测速",
                        tint = onSurfaceVariant.copy(alpha = if (canTest) 0.85f else 0.35f),
                        modifier = Modifier.size(15.dp),
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                // Single Text node with AnnotatedString preserves "$delayMs ms" semantics cleanly
                Text(
                    text = buildAnnotatedString {
                        if (hasValidDelay) {
                            withStyle(
                                SpanStyle(
                                    fontSize = 27.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = onSurface,
                                    letterSpacing = (-0.6).sp,
                                ),
                            ) {
                                append(delayMs.toString())
                            }
                            withStyle(
                                SpanStyle(
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = onSurfaceVariant,
                                ),
                            ) {
                                append(" ms")
                            }
                        } else if (isProbing) {
                            withStyle(
                                SpanStyle(
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = onSurfaceVariant,
                                ),
                            ) {
                                append("检测中…")
                            }
                        } else {
                            withStyle(
                                SpanStyle(
                                    fontSize = 24.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = onSurfaceVariant,
                                ),
                            ) {
                                append("--")
                            }
                            withStyle(
                                SpanStyle(
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = onSurfaceVariant,
                                ),
                            ) {
                                append(" ms")
                            }
                        }
                    },
                    style = MaterialTheme.typography.headlineSmall.copy(fontFeatureSettings = "tnum"),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = qualityLabel,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = qualityColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            // Refined 12-bar emerald signal equalizer
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(24.dp),
                horizontalArrangement = Arrangement.spacedBy(3.dp),
                verticalAlignment = Alignment.Bottom,
            ) {
                equalizerHeights.forEachIndexed { idx, barDp ->
                    val isActiveBar = idx < activeEqualizerBars
                    val barAlpha = 0.36f + (idx.toFloat() / equalizerHeights.size) * 0.64f
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(barDp.dp)
                            .clip(RoundedCornerShape(2.dp))
                            .background(
                                if (isActiveBar) {
                                    qualityColor.copy(alpha = barAlpha)
                                } else {
                                    extColors.tonalTrack
                                },
                            ),
                    )
                }
            }
        }
    }
}

/**
 * Full-width panoramic Exit IP & City Landmark showcase card anchoring the bottom of the Home
 * dashboard. Pairs live region/ISP/IP details with a pure-Compose vector skyline silhouette that
 * morphs smoothly whenever the exit country changes.
 */
@Composable
private fun ExitIpLandmarkCard(
    exitIp: ExitIpUi?,
    isProbing: Boolean,
    isConnected: Boolean,
    targetHeight: Dp,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    val onSurface = MaterialTheme.colorScheme.onSurface
    val onSurfaceVariant = MaterialTheme.colorScheme.onSurfaceVariant
    val verifiedIp = exitIp?.takeIf { it.verified && it.ip.isNotBlank() && it.ip != "--" }
    val isFailed = exitIp != null && verifiedIp == null && !isProbing

    val countryCode = verifiedIp?.countryCode?.trim()?.uppercase(Locale.ROOT).orEmpty()
    val countryCodeBadge = when {
        verifiedIp != null -> countryCode.ifEmpty { "IP" }
        isProbing -> "…"
        else -> "--"
    }
    val regionHeadline = when {
        verifiedIp != null -> verifiedIp.countryWithFlag
        isProbing -> "正在检测出口…"
        isFailed -> "出口检测失败"
        else -> "点击查询出口"
    }
    val ispSubtitle = when {
        verifiedIp != null -> {
            val isp = verifiedIp.isp.takeIf { it.isNotBlank() }
            val typeZh = verifiedIp.ipTypeDisplayZh.takeIf { it != "未知" }
            when {
                isp != null && typeZh != null -> "$isp · $typeZh"
                isp != null -> isp
                typeZh != null -> typeZh
                else -> "当前公网出口"
            }
        }
        isProbing -> "正在通过当前节点探测"
        isFailed -> "点击查看详情或重试"
        else -> "查看当前公网归属地与 IP 类型"
    }
    val ipLine = when {
        verifiedIp != null -> verifiedIp.ip
        isProbing -> "…"
        else -> "--"
    }
    val landmarkSubtitle = when {
        verifiedIp != null -> landmarkCaptionFor(countryCode)
        isProbing -> "识别地区地标…"
        else -> "加密出口 · 全球节点"
    }
    val skylineHeight = (targetHeight - 102.dp).coerceIn(96.dp, 168.dp)

    Surface(
        modifier = modifier
            .heightIn(min = targetHeight)
            .clip(RoundedCornerShape(22.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(22.dp),
        color = extColors.cardSurface,
        shadowElevation = if (extColors.isDark) 0.dp else 1.5.dp,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 14.dp, top = 14.dp, bottom = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // Header row: 落地出口 + country code badge + quiet detail indicator
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        Text(
                            text = "落地出口",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = onSurfaceVariant,
                            maxLines = 1,
                        )
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = extColors.tonalTrack,
                        ) {
                            Text(
                                text = countryCodeBadge,
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                ),
                                color = onSurfaceVariant,
                                maxLines = 1,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(1.dp),
                    ) {
                        if (isProbing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(13.dp),
                                strokeWidth = 1.8.dp,
                                color = if (extColors.isDark) extColors.emeraldBright else extColors.emerald,
                            )
                        } else {
                            Text(
                                text = "详情",
                                style = MaterialTheme.typography.labelSmall,
                                color = onSurfaceVariant.copy(alpha = 0.82f),
                                maxLines = 1,
                            )
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                                contentDescription = "查看落地 IP 详情",
                                tint = onSurfaceVariant.copy(alpha = 0.62f),
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                }

                // Region + ISP (left) and IP + Landmark caption (right)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.Bottom,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = regionHeadline,
                            style = MaterialTheme.typography.titleLarge.copy(
                                fontSize = 19.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = (-0.2).sp,
                            ),
                            color = if (isFailed) extColors.amber else onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = ispSubtitle,
                            style = MaterialTheme.typography.labelSmall,
                            color = onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            text = ipLine,
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                fontFeatureSettings = "tnum",
                            ),
                            color = onSurface.copy(alpha = if (verifiedIp != null) 0.90f else 0.55f),
                            maxLines = 1,
                            softWrap = false,
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = landmarkSubtitle,
                            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                            color = onSurfaceVariant.copy(alpha = 0.78f),
                            maxLines = 1,
                            softWrap = false,
                        )
                    }
                }
            }

            // Full-bleed panoramic minimalist city skyline with mirrored waterfront reflection
            ExitCountryLandmarkCanvas(
                countryCode = countryCode,
                isConnected = isConnected,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(skylineHeight),
            )
        }
    }
}

private fun splitRateValueAndUnit(formatted: String): Pair<String, String> {
    val trimmed = formatted.trim()
    val spaceIdx = trimmed.indexOf(' ')
    if (spaceIdx <= 0) return trimmed to ""
    return trimmed.substring(0, spaceIdx) to trimmed.substring(spaceIdx + 1).trim()
}
