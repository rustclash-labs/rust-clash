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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.rounded.CellTower
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.TrafficWaveformGraph
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState

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
) {
    val extColors = LocalRustClashColors.current
    var showRoutingSheet by remember { mutableStateOf(false) }
    var showTopMenu by remember { mutableStateOf(false) }

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
            .padding(horizontal = 20.dp, vertical = 10.dp),
    ) {
        // Top Brand Bar (matching design reference: clean "RustClash" left + overflow menu right)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
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
                        color = extColors.onAmberContainer,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    )
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
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
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
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

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

            Spacer(modifier = Modifier.height(10.dp))

            val statusTitle = when (state.vpnState) {
                VpnLifecycleState.RUNNING -> "已连接"
                VpnLifecycleState.PREPARING, VpnLifecycleState.STARTING -> "正在连接…"
                VpnLifecycleState.RECONNECTING -> "网络恢复中…"
                VpnLifecycleState.STOPPING -> "正在断开…"
                VpnLifecycleState.REVOKED -> "权限已撤销"
                VpnLifecycleState.ERROR -> "连接异常"
                VpnLifecycleState.DISCONNECTED -> "未连接"
            }
            Text(
                text = statusTitle,
                fontSize = 23.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Spacer(modifier = Modifier.height(4.dp))

            val noSavedNodes = state.nodes.isEmpty() && !state.demoMode
            val heroSubtitle = if (noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT) {
                "点击导入首个代理节点 · ${state.routingPreset.modeDisplay}"
            } else {
                "${state.effectiveOutbound} · ${state.routingPreset.modeDisplay}"
            }
            Text(
                text = heroSubtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = if (noSavedNodes && state.routingPreset != RoutingPresetUi.DIRECT) {
                    extColors.amber
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Live Speed & Waveform Card (matching design reference)
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
                        .padding(start = 22.dp, end = 22.dp, top = 16.dp, bottom = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    SpeedColumnItem(
                        arrow = "↓",
                        label = "下载",
                        rateText = UiJsonParsers.formatRate(if (isConnected) state.telemetry.downRate else 0L),
                    )
                    SpeedColumnItem(
                        arrow = "↑",
                        label = "上传",
                        rateText = UiJsonParsers.formatRate(if (isConnected) state.telemetry.upRate else 0L),
                    )
                }

                TrafficWaveformGraph(
                    samples = state.rateHistory,
                    isConnected = isConnected,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                        .clip(RoundedCornerShape(bottomStart = 18.dp, bottomEnd = 18.dp)),
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Primary Summary Card: Routing Mode & Active Node
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
                        .padding(horizontal = 18.dp, vertical = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "路由模式",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.height(3.dp))
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
                    modifier = Modifier.padding(horizontal = 18.dp),
                    thickness = 0.8.dp,
                    color = extColors.hairline,
                )

                // Row 2: 当前节点
                val delayMs = state.effectiveNodeDelayMs
                val isProbing = state.isTestingAllDelays || state.testingNodeName == state.effectiveOutbound
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
                        .padding(horizontal = 18.dp, vertical = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "当前节点",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.height(3.dp))

                        if (state.nodes.isEmpty() && !state.demoMode) {
                            Text(
                                text = "点击导入 ss:// · vless:// · trojan:// · anytls:// 节点",
                                style = MaterialTheme.typography.bodySmall,
                                color = extColors.emerald,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        } else {
                            val latencyColor = when {
                                delayMs == null || delayMs <= 0L -> MaterialTheme.colorScheme.onSurfaceVariant
                                delayMs <= 180L -> extColors.emerald
                                delayMs <= 420L -> extColors.amber
                                else -> extColors.danger
                            }
                            val annotated = buildAnnotatedString {
                                append("${state.effectiveOutbound} · ${state.effectiveProtocolDisplay}")
                                if (delayMs != null && delayMs > 0L) {
                                    append(" · ")
                                    withStyle(SpanStyle(color = latencyColor, fontWeight = FontWeight.SemiBold)) {
                                        append("$delayMs ms")
                                    }
                                } else if (!isProbing && state.effectiveOutbound != "DIRECT") {
                                    append(" · 点击测速")
                                }
                            }
                            Text(
                                text = annotated,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    if (isProbing) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .padding(end = 6.dp)
                                .size(15.dp),
                            strokeWidth = 2.dp,
                            color = extColors.emerald,
                        )
                    }

                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = "查看节点列表",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }

                // Optional Row 3 when VPN is running or diagnostics exist: 实时分流概览
                if (isConnected || state.diagnostics.isNotEmpty()) {
                    HorizontalDivider(
                        modifier = Modifier.padding(horizontal = 18.dp),
                        thickness = 0.8.dp,
                        color = extColors.hairline,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onNavigateToRules(1) }
                            .padding(horizontal = 18.dp, vertical = 13.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "实时分流：直连 ${state.directDiagnosticCount} · 代理 ${state.proxyDiagnosticCount}" +
                                if (state.failedDiagnosticCount > 0) " · 异常 ${state.failedDiagnosticCount}" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "诊断明细",
                            style = MaterialTheme.typography.labelMedium,
                            color = extColors.emerald,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Spacer(modifier = Modifier.width(2.dp))
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                            contentDescription = null,
                            tint = extColors.emerald,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))
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
}

@Composable
private fun HeroConnectButton(
    isConnected: Boolean,
    isTransitioning: Boolean,
    isErrorState: Boolean,
    onClick: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val haloScale = if (isConnected) {
        val pulseTransition = rememberInfiniteTransition(label = "vpnHalo")
        val animatedScale by pulseTransition.animateFloat(
            initialValue = 1.0f,
            targetValue = 1.08f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 2000, easing = FastOutSlowInEasing),
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
        isConnected -> extColors.emeraldBright.copy(alpha = if (extColors.isDark) 0.36f else 0.28f)
        isErrorState -> extColors.danger.copy(alpha = 0.22f)
        isTransitioning -> extColors.amber.copy(alpha = 0.22f)
        else -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f)
    }

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(132.dp),
    ) {
        // Soft radial emerald aura halo matching the UI design mockup
        Canvas(
            modifier = Modifier
                .size(132.dp)
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
                        glowCenterColor.copy(alpha = glowCenterColor.alpha * 0.45f),
                        Color.Transparent,
                    ),
                ),
                radius = size.minDimension / 2f,
            )
        }

        Surface(
            onClick = onClick,
            shape = CircleShape,
            color = extColors.cardSurface,
            border = BorderStroke(width = 2.6.dp, color = ringColor),
            shadowElevation = if (isConnected) 6.dp else 1.dp,
            modifier = Modifier.size(88.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (isTransitioning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(32.dp),
                        strokeWidth = 2.8.dp,
                        color = ringColor,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.PowerSettingsNew,
                        contentDescription = if (isConnected) "断开 VPN" else "连接 VPN",
                        tint = if (isConnected || isErrorState) {
                            ringColor
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                        modifier = Modifier.size(36.dp),
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
) {
    Column {
        Text(
            text = "$arrow $label",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = rateText,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
        )
    }
}
