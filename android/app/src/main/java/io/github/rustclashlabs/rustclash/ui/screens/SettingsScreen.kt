package io.github.rustclashlabs.rustclash.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.rustclashlabs.rustclash.BuildConfig
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.ModalInlineErrorBanner
import io.github.rustclashlabs.rustclash.ui.theme.RustClashBrandIcon
import io.github.rustclashlabs.rustclash.ui.theme.SegmentedSelectorRow
import io.github.rustclashlabs.rustclash.ui.theme.SettingsGroupContainer
import io.github.rustclashlabs.rustclash.ui.theme.SettingsGroupDivider
import io.github.rustclashlabs.rustclash.ui.theme.SettingsRowItem
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: AppUiState,
    onSetThemePreference: (ThemePreference) -> Unit,
    onRequestInstalledApps: () -> Unit,
    onSavePerAppPolicy: (PerAppMode, Set<String>) -> Unit,
    onSetEnableIpv6: (Boolean) -> Unit,
    onSetDemoMode: (Boolean) -> Unit,
    onFlushDns: () -> Unit,
    onSetShowSystemApps: (Boolean) -> Unit = {},
    onSetDefaultSubAutoUpdateSecs: (Long) -> Unit = {},
    onClearSettingsNotice: () -> Unit = {},
) {
    val extColors = LocalRustClashColors.current
    var showAppearanceSheet by remember { mutableStateOf(false) }
    var showPerAppSheet by remember { mutableStateOf(false) }
    var showNetworkSheet by remember { mutableStateOf(false) }
    var showPerformanceSheet by remember { mutableStateOf(false) }
    var showGeneralSheet by remember { mutableStateOf(false) }
    var showAboutSheet by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 10.dp),
    ) {
        Text(
            text = "设置",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground,
        )

        Spacer(modifier = Modifier.height(14.dp))

        // Unified Grouped List matching the brand visual reference
        SettingsGroupContainer {
            // 1. Appearance (with inline single-line segmented control so theme switching is 1-tap and never wraps)
            SettingsRowItem(
                icon = Icons.Rounded.DarkMode,
                title = "界面外观",
                subtitle = "浅色 / 深色 / 跟随系统",
                trailingBadge = state.themePreference.shortLabel,
                onClick = { showAppearanceSheet = true },
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = 14.dp),
            ) {
                SegmentedSelectorRow(
                    items = ThemePreference.entries,
                    selectedItem = state.themePreference,
                    labelOf = { it.shortLabel },
                    onSelect = onSetThemePreference,
                )
            }
            SettingsGroupDivider()

            // 2. Per-App VPN Policy
            val perAppBadge = when (state.perAppMode) {
                PerAppMode.ALL_APPS -> null
                PerAppMode.ALLOWLIST -> "仅代理 ${state.selectedPackages.size} 项"
                PerAppMode.BLOCKLIST -> "绕过 ${state.selectedPackages.size} 项"
            }
            SettingsRowItem(
                icon = Icons.Rounded.Apps,
                title = "分应用代理 (Per-App VPN)",
                subtitle = "选择需代理或直连的应用",
                trailingBadge = perAppBadge,
                onClick = {
                    onRequestInstalledApps()
                    showPerAppSheet = true
                },
            )
            SettingsGroupDivider()

            // 3. Network & Kernel
            SettingsRowItem(
                icon = Icons.Rounded.Public,
                title = "网络与内核",
                subtitle = "TUN · IPv6 · DNS · Fake-IP",
                trailingBadge = if (state.enableIpv6) "双栈" else "IPv4",
                onClick = {
                    onClearSettingsNotice()
                    showNetworkSheet = true
                },
            )
            SettingsGroupDivider()

            // 4. Connection & Performance
            SettingsRowItem(
                icon = Icons.Rounded.Bolt,
                title = "连接与性能",
                subtitle = "并发 · 超时 · 缓存 · 资源限制",
                onClick = {
                    onClearSettingsNotice()
                    showPerformanceSheet = true
                },
            )
            SettingsGroupDivider()

            // 5. General
            SettingsRowItem(
                icon = Icons.Rounded.Tune,
                title = "通用",
                subtitle = "订阅自动更新 · 后台运行 · 通知",
                trailingBadge = UiJsonParsers.formatAutoUpdateInterval(
                    state.defaultSubAutoUpdateSecs.takeIf { it > 0L },
                ),
                onClick = { showGeneralSheet = true },
            )
            SettingsGroupDivider()

            // 6. About RustClash
            SettingsRowItem(
                icon = Icons.Rounded.Info,
                title = "关于 RustClash",
                subtitle = "v${BuildConfig.VERSION_NAME} · 高性能 Rust 代理客户端",
                onClick = { showAboutSheet = true },
            )
        }

        if (!state.lockdownWarning.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = state.lockdownWarning,
                style = MaterialTheme.typography.bodySmall,
                color = extColors.amber,
                modifier = Modifier.padding(horizontal = 4.dp),
            )
        }

        Spacer(modifier = Modifier.height(20.dp))
    }

    if (showAppearanceSheet) {
        AppearanceBottomSheet(
            currentPreference = state.themePreference,
            onSelectPreference = {
                onSetThemePreference(it)
            },
            onDismiss = { showAppearanceSheet = false },
        )
    }

    if (showPerAppSheet) {
        PerAppPickerBottomSheet(
            initialMode = state.perAppMode,
            initialSelected = state.selectedPackages,
            installedApps = state.installedApps,
            showSystemApps = state.showSystemApps,
            onSetShowSystemApps = onSetShowSystemApps,
            onDismiss = { showPerAppSheet = false },
            onSave = { mode, pkgs ->
                showPerAppSheet = false
                onSavePerAppPolicy(mode, pkgs)
            },
        )
    }

    if (showNetworkSheet) {
        NetworkKernelBottomSheet(
            state = state,
            onSetEnableIpv6 = onSetEnableIpv6,
            onSetDemoMode = onSetDemoMode,
            onFlushDns = onFlushDns,
            onDismiss = {
                onClearSettingsNotice()
                showNetworkSheet = false
            },
        )
    }

    if (showPerformanceSheet) {
        PerformanceBottomSheet(
            state = state,
            onFlushDns = onFlushDns,
            onDismiss = {
                onClearSettingsNotice()
                showPerformanceSheet = false
            },
        )
    }

    if (showGeneralSheet) {
        GeneralSettingsBottomSheet(
            state = state,
            onSetDefaultSubAutoUpdateSecs = onSetDefaultSubAutoUpdateSecs,
            onDismiss = { showGeneralSheet = false },
        )
    }

    if (showAboutSheet) {
        AboutRustClashBottomSheet(
            state = state,
            onDismiss = { showAboutSheet = false },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppearanceBottomSheet(
    currentPreference: ThemePreference,
    onSelectPreference: (ThemePreference) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 12.dp),
        ) {
            Text(
                text = "界面外观",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "支持跟随系统深浅色切换，也可固定浅色或深色主题。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(14.dp))
            SegmentedSelectorRow(
                items = ThemePreference.entries,
                selectedItem = currentPreference,
                labelOf = { it.label },
                onSelect = onSelectPreference,
            )
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NetworkKernelBottomSheet(
    state: AppUiState,
    onSetEnableIpv6: (Boolean) -> Unit,
    onSetDemoMode: (Boolean) -> Unit,
    onFlushDns: () -> Unit,
    onDismiss: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 10.dp),
        ) {
            Text(
                text = "网络与内核",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            if (!state.settingsSheetNotice.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = extColors.emeraldContainer,
                    border = BorderStroke(1.dp, extColors.emerald.copy(alpha = 0.35f)),
                ) {
                    Text(
                        text = state.settingsSheetNotice,
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.onEmeraldContainer,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            }
            Spacer(modifier = Modifier.height(14.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "启用 IPv6 隧道路由",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        text = "同时接管系统 IPv4 与 IPv6 流量并执行国内外分流",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Switch(
                    checked = state.enableIpv6,
                    onCheckedChange = onSetEnableIpv6,
                )
            }

            HorizontalDivider(color = extColors.hairline, modifier = Modifier.padding(vertical = 12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Fake-IP 与 DNS 缓存",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        text = "国内直连 DNS：223.5.5.5 / 119.29.29.29 · 代理域名远端解析",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onFlushDns,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text("清空缓存", style = MaterialTheme.typography.labelMedium, maxLines = 1)
                }
            }

            HorizontalDivider(color = extColors.hairline, modifier = Modifier.padding(vertical = 12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "本地多协议测试沙盒 (Demo)",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        text = "仅用于无真实节点时自测协议栈，导入真实节点后自动关闭",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Switch(
                    checked = state.demoMode,
                    onCheckedChange = onSetDemoMode,
                )
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PerformanceBottomSheet(
    state: AppUiState,
    onFlushDns: () -> Unit,
    onDismiss: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 10.dp),
        ) {
            Text(
                text = "连接与性能",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            if (!state.settingsSheetNotice.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = extColors.emeraldContainer,
                    border = BorderStroke(1.dp, extColors.emerald.copy(alpha = 0.35f)),
                ) {
                    Text(
                        text = state.settingsSheetNotice,
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.onEmeraldContainer,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            InfoKeyValueRow("活跃连接数", "${state.telemetry.activeConnections}")
            InfoKeyValueRow("Socket 防回环保护", "已保护 ${state.telemetry.protectedSockets} 个套接字")
            InfoKeyValueRow("Fake-IP 活跃映射", "${state.telemetry.fakeIpEntries} 条")
            InfoKeyValueRow(
                "进程内存占用",
                if (state.telemetry.rssBytes > 0L) UiJsonParsers.formatBytes(state.telemetry.rssBytes) else "低占用运行中",
            )
            InfoKeyValueRow("TCP 握手/空闲超时", "5s Happy Eyeballs / Keepalive")
            InfoKeyValueRow("UDP NAT 会话池", "Full-Cone 映射 · 网络切换自动迁移")

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = extColors.hairline)
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = onFlushDns,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text("清空 DNS 与 Fake-IP 映射缓存")
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GeneralSettingsBottomSheet(
    state: AppUiState,
    onSetDefaultSubAutoUpdateSecs: (Long) -> Unit = {},
    onDismiss: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val intervalChoices = listOf(0L, 21600L, 43200L, 86400L)
    val selectedInterval = when {
        state.defaultSubAutoUpdateSecs <= 0L -> 0L
        state.defaultSubAutoUpdateSecs in intervalChoices -> state.defaultSubAutoUpdateSecs
        else -> 86400L
    }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 10.dp),
        ) {
            Text(
                text = "通用",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "订阅默认自动更新",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "息屏低功耗模式下自动暂停后台轮询；订阅刷新时手动添加的自建节点会自动保留，永不覆盖。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(10.dp))
            SegmentedSelectorRow(
                items = intervalChoices,
                selectedItem = selectedInterval,
                labelOf = { secs ->
                    when (secs) {
                        0L -> "手动"
                        21600L -> "6 小时"
                        43200L -> "12 小时"
                        else -> "24 小时"
                    }
                },
                onSelect = onSetDefaultSubAutoUpdateSecs,
            )

            HorizontalDivider(color = extColors.hairline, modifier = Modifier.padding(vertical = 12.dp))

            InfoKeyValueRow("VPN 前台常驻通知", "已启用单色状态栏图标与息屏节电暂停")
            InfoKeyValueRow("快捷设置磁贴 (QS Tile)", "支持下拉通知栏一键开关 VPN")
            InfoKeyValueRow("Wi-Fi / 蜂窝网络切换恢复", "ConnectivityManager 自动重绑物理网络")
            InfoKeyValueRow(
                "当前物理网络状态",
                if (state.vpnState == VpnLifecycleState.RUNNING) {
                    if (state.telemetry.isWifi) "Wi-Fi（已平稳切换 ${state.telemetry.networkTransitions} 次）"
                    else "移动网络（已平稳切换 ${state.telemetry.networkTransitions} 次）"
                } else {
                    "待连接"
                },
            )
            InfoKeyValueRow("配置与节点持久化", "SharedPreferences + 敏感凭据加密存储")

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AboutRustClashBottomSheet(
    state: AppUiState,
    onDismiss: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            RustClashBrandIcon(size = 64.dp)
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = "RustClash",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "v${BuildConfig.VERSION_NAME} · 高性能 Rust 跨平台代理客户端",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider(color = extColors.hairline)
            Spacer(modifier = Modifier.height(12.dp))

            InfoKeyValueRow(
                "客户端版本",
                "v${BuildConfig.VERSION_NAME} (Build ${BuildConfig.VERSION_CODE})",
            )
            InfoKeyValueRow(
                "Rust JNI 核心",
                if (state.nativeLoaded) "libproxy_ffi.so 已加载" else "待加载",
            )
            InfoKeyValueRow("用户态网络栈", "smoltcp + Tokio 异步多路复用")
            InfoKeyValueRow("支持出站协议", "Shadowsocks / VLESS (+WS) / AnyTLS / Trojan (+WS) / SOCKS5 / HTTP")

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
private fun InfoKeyValueRow(label: String, value: String) {
    val fontScale = LocalDensity.current.fontScale
    val stackVertically = fontScale >= 1.25f || value.length > 24 || label.length > 12

    if (stackVertically) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 5.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    } else {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 5.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Text(
                text = label,
                modifier = Modifier.weight(0.42f),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                modifier = Modifier.weight(0.58f),
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.End,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PerAppPickerBottomSheet(
    initialMode: PerAppMode,
    initialSelected: Set<String>,
    installedApps: List<io.github.rustclashlabs.rustclash.ui.model.InstalledAppUi>,
    showSystemApps: Boolean,
    onSetShowSystemApps: (Boolean) -> Unit,
    onDismiss: () -> Unit,
    onSave: (PerAppMode, Set<String>) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var selectedMode by remember { mutableStateOf(initialMode) }
    var selectedPkgs by remember { mutableStateOf(initialSelected) }
    var searchQuery by remember { mutableStateOf("") }
    var validationError by remember { mutableStateOf<String?>(null) }
    // Pin initially-selected apps to the top on sheet open, keeping sort order stable while toggling checkboxes
    val initialPinned = remember(installedApps) { initialSelected }

    val filteredApps = remember(installedApps, searchQuery, initialPinned) {
        val q = searchQuery.trim().lowercase()
        val list = if (q.isEmpty()) {
            installedApps
        } else {
            installedApps.filter {
                it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
        }
        list.sortedWith(
            compareByDescending<io.github.rustclashlabs.rustclash.ui.model.InstalledAppUi> {
                it.packageName in initialPinned
            }.thenBy { it.label.lowercase() },
        )
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "分应用代理策略",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                Button(
                    onClick = {
                        if (selectedMode == PerAppMode.ALLOWLIST && selectedPkgs.isEmpty()) {
                            validationError = "「仅选中应用」模式下请至少勾选 1 个需要代理的应用，或切换为「全部应用」"
                            return@Button
                        }
                        validationError = null
                        onSave(selectedMode, selectedPkgs)
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = extColors.emerald,
                        contentColor = Color.White,
                    ),
                ) {
                    Text("保存")
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            val modes = listOf(
                PerAppMode.ALL_APPS,
                PerAppMode.ALLOWLIST,
                PerAppMode.BLOCKLIST,
            )
            SegmentedSelectorRow(
                items = modes,
                selectedItem = selectedMode,
                labelOf = { mode ->
                    when (mode) {
                        PerAppMode.ALL_APPS -> "全部应用"
                        PerAppMode.ALLOWLIST -> "仅选中应用"
                        PerAppMode.BLOCKLIST -> "绕过选中"
                    }
                },
                onSelect = {
                    selectedMode = it
                    validationError = null
                },
            )

            if (!validationError.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                ModalInlineErrorBanner(
                    message = validationError!!,
                    onDismiss = { validationError = null },
                )
            }

            if (selectedMode != PerAppMode.ALL_APPS) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        placeholder = { Text("搜索应用名称或包名…") },
                        leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                        trailingIcon = {
                            if (searchQuery.isNotEmpty()) {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(Icons.Rounded.Clear, contentDescription = "清空")
                                }
                            }
                        },
                    )
                    if (selectedPkgs.isNotEmpty()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        TextButton(onClick = { selectedPkgs = emptySet() }) {
                            Text("清空(${selectedPkgs.size})")
                        }
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "显示系统应用与底层服务",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(
                        checked = showSystemApps,
                        onCheckedChange = onSetShowSystemApps,
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                if (filteredApps.isEmpty()) {
                    Text(
                        text = if (searchQuery.isNotBlank()) {
                            "未找到匹配「$searchQuery」的应用"
                        } else {
                            "暂无可显示的已安装应用"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 14.dp),
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 140.dp, max = 260.dp),
                    ) {
                        items(filteredApps, key = { it.packageName }) { app ->
                            val checked = app.packageName in selectedPkgs
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selectedPkgs = if (checked) {
                                            selectedPkgs - app.packageName
                                        } else {
                                            selectedPkgs + app.packageName
                                        }
                                        validationError = null
                                    }
                                    .padding(vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = { isChecked ->
                                        selectedPkgs = if (isChecked) {
                                            selectedPkgs + app.packageName
                                        } else {
                                            selectedPkgs - app.packageName
                                        }
                                        validationError = null
                                    },
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = app.label,
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Text(
                                        text = app.packageName,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            } else {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "当前为「全部应用」模式，手机上所有应用的流量将按您设置的路由分流方案（如国内直连 / 国外代理）自动处理。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}
