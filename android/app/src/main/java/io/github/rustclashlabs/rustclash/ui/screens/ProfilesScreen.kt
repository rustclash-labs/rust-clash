package io.github.rustclashlabs.rustclash.ui.screens

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.DriveFileRenameOutline
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.ProfileOpSummaryUi
import io.github.rustclashlabs.rustclash.ui.model.ProfileUiItem
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.ModalInlineErrorBanner

@Composable
fun ProfilesScreen(
    state: AppUiState,
    onOpenImportSheet: () -> Unit,
    onActivateProfile: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onRenameProfile: (String, String) -> Unit = { _, _ -> },
    onUpdateProfileAutoUpdate: (String, Long) -> Unit = { _, _ -> },
    onDismissOpSummary: () -> Unit = {},
    onOpenCustomRulesEditor: () -> Unit,
    onOpenYamlEditor: () -> Unit,
    onImportYamlFile: () -> Unit = {},
    onExportYamlFile: () -> Unit = {},
) {
    val extColors = LocalRustClashColors.current
    var pendingDeleteProfile by remember { mutableStateOf<ProfileUiItem?>(null) }
    var pendingRenameProfile by remember { mutableStateOf<ProfileUiItem?>(null) }
    var pendingAutoUpdateProfile by remember { mutableStateOf<ProfileUiItem?>(null) }
    var showHeaderMenu by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "配置管理",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Spacer(modifier = Modifier.height(3.dp))
                Text(
                    text = "当前启用：${state.activeProfileName}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            Button(
                onClick = onOpenImportSheet,
                shape = RoundedCornerShape(50),
                colors = ButtonDefaults.buttonColors(
                    containerColor = extColors.emerald,
                    contentColor = Color.White,
                ),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
            ) {
                Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = "导入/订阅",
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    softWrap = false,
                )
            }

            Box {
                IconButton(onClick = { showHeaderMenu = true }) {
                    Icon(
                        imageVector = Icons.Rounded.MoreVert,
                        contentDescription = "配置导入导出",
                        tint = MaterialTheme.colorScheme.onBackground,
                    )
                }
                DropdownMenu(
                    expanded = showHeaderMenu,
                    onDismissRequest = { showHeaderMenu = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("从本地文件导入 YAML") },
                        leadingIcon = { Icon(Icons.Rounded.Folder, contentDescription = null) },
                        onClick = {
                            showHeaderMenu = false
                            onImportYamlFile()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("导出当前脱敏 YAML 文件") },
                        leadingIcon = { Icon(Icons.Rounded.Code, contentDescription = null) },
                        onClick = {
                            showHeaderMenu = false
                            onExportYamlFile()
                        },
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Quick Config Tools Row (Two equal-width single-line buttons)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Surface(
                modifier = Modifier
                    .weight(1f)
                    .height(42.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(onClick = onOpenCustomRulesEditor),
                shape = RoundedCornerShape(12.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.EditNote,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(17.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "自定义规则",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }

            Surface(
                modifier = Modifier
                    .weight(1f)
                    .height(42.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(onClick = onOpenYamlEditor),
                shape = RoundedCornerShape(12.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Code,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(17.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "查看/编辑 YAML",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        val opSummary = state.lastProfileOpSummary
        if (opSummary != null) {
            ProfileOpSummaryCard(
                summary = opSummary,
                onDismiss = onDismissOpSummary,
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

        if (state.profiles.isEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "暂无已保存的配置档案",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "点击右上角「导入/订阅」添加 Clash YAML 配置、HTTPS 订阅链接或节点分享链接。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Button(
                        onClick = onOpenImportSheet,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = extColors.emerald,
                            contentColor = Color.White,
                        ),
                    ) {
                        Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("导入配置或订阅")
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(bottom = 20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(state.profiles, key = { it.id }) { profile ->
                    val isActive = profile.id == state.activeProfileId
                    val isRefreshing = state.refreshingProfileId == profile.id
                    val displayName = state.resolveProfileDisplayName(profile)
                    ProfileCard(
                        profile = profile,
                        displayName = displayName,
                        isActive = isActive,
                        isRefreshing = isRefreshing,
                        onActivate = { if (!isActive) onActivateProfile(profile.id) },
                        onRefresh = { onRefreshProfile(profile.id) },
                        onRename = { pendingRenameProfile = profile },
                        onConfigureAutoUpdate = { pendingAutoUpdateProfile = profile },
                        onDelete = { pendingDeleteProfile = profile },
                    )
                }
            }
        }
    }

    if (pendingAutoUpdateProfile != null) {
        val target = pendingAutoUpdateProfile!!
        val currentSecs = target.autoUpdateIntervalSecs?.takeIf { it > 0L } ?: 0L
        val scheduleOptions = listOf(
            0L to "关闭自动更新（手动刷新）",
            3600L to "每 1 小时",
            21600L to "每 6 小时",
            43200L to "每 12 小时",
            86400L to "每 24 小时",
        )
        AlertDialog(
            onDismissRequest = { pendingAutoUpdateProfile = null },
            title = { Text("订阅自动更新频率") },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                ) {
                    Text(
                        text = "息屏省电 (Doze) 期间会自动推迟后台轮询；每次更新订阅时，您手动添加或导入的自建节点及策略组选中项会自动保留，不会被远程覆盖。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    scheduleOptions.forEach { (secs, label) ->
                        val selected = currentSecs == secs
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable {
                                    pendingAutoUpdateProfile = null
                                    onUpdateProfileAutoUpdate(target.id, secs)
                                }
                                .padding(vertical = 4.dp, horizontal = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = selected,
                                onClick = {
                                    pendingAutoUpdateProfile = null
                                    onUpdateProfileAutoUpdate(target.id, secs)
                                },
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = label,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { pendingAutoUpdateProfile = null }) {
                    Text("关闭")
                }
            },
        )
    }

    if (pendingRenameProfile != null) {
        val target = pendingRenameProfile!!
        val initialName = state.resolveProfileDisplayName(target)
        var newName by remember(target.id) { mutableStateOf(initialName) }

        AlertDialog(
            onDismissRequest = { pendingRenameProfile = null },
            title = { Text("重命名配置") },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "自定义配置显示名称，首页与配置管理页将同步显示该名称。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    OutlinedTextField(
                        value = newName,
                        onValueChange = { newName = it },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        placeholder = { Text("输入配置名称，如 主力订阅 / 默认配置") },
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val trimmed = newName.trim()
                        pendingRenameProfile = null
                        if (trimmed.isNotEmpty()) {
                            onRenameProfile(target.id, trimmed)
                        }
                    },
                    enabled = newName.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = extColors.emerald,
                        contentColor = Color.White,
                    ),
                ) {
                    Text("保存")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingRenameProfile = null }) {
                    Text("取消")
                }
            },
        )
    }

    if (pendingDeleteProfile != null) {
        val target = pendingDeleteProfile!!
        val targetDisplayName = state.resolveProfileDisplayName(target)
        AlertDialog(
            onDismissRequest = { pendingDeleteProfile = null },
            title = { Text("删除配置") },
            text = { Text("确定要删除配置「$targetDisplayName」吗？此操作无法撤销。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingDeleteProfile = null
                        onDeleteProfile(target.id)
                    },
                ) {
                    Text("删除", color = extColors.danger)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteProfile = null }) {
                    Text("取消")
                }
            },
        )
    }
}

@Composable
private fun ProfileCard(
    profile: ProfileUiItem,
    displayName: String,
    isActive: Boolean,
    isRefreshing: Boolean,
    onActivate: () -> Unit,
    onRefresh: () -> Unit,
    onRename: () -> Unit,
    onConfigureAutoUpdate: () -> Unit = {},
    onDelete: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    var showMenu by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onActivate),
        shape = RoundedCornerShape(16.dp),
        color = if (isActive) extColors.selectedCardBg else extColors.cardSurface,
        border = BorderStroke(
            width = if (isActive) 1.5.dp else 1.dp,
            color = if (isActive) extColors.selectedCardBorder else extColors.hairline,
        ),
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(11.dp))
                        .background(
                            if (isActive) extColors.emeraldContainer else extColors.iconBadgeBg,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = if (profile.isSubscription) Icons.Rounded.Link else Icons.Rounded.Folder,
                        contentDescription = null,
                        tint = if (isActive) extColors.emerald else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = displayName,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = if (isActive) extColors.emeraldContainer else extColors.iconBadgeBg,
                        ) {
                            Text(
                                text = if (profile.isSubscription) "远程订阅" else "本地配置",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (isActive) extColors.onEmeraldContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                softWrap = false,
                                modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = "${profile.proxyCount} 个节点 · ${profile.ruleCount} 条规则",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "更新: ${UiJsonParsers.formatEpochMillis(profile.lastUpdatedMs)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    if (profile.isSubscription || profile.manualProxyCount > 0) {
                        Spacer(modifier = Modifier.height(5.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            if (profile.isSubscription) {
                                Surface(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .clickable(onClick = onConfigureAutoUpdate),
                                    shape = RoundedCornerShape(6.dp),
                                    color = extColors.iconBadgeBg,
                                ) {
                                    Text(
                                        text = UiJsonParsers.formatAutoUpdateInterval(profile.autoUpdateIntervalSecs),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        softWrap = false,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    )
                                }
                            }
                            if (profile.manualProxyCount > 0) {
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = extColors.emeraldContainer,
                                ) {
                                    Text(
                                        text = "+${profile.manualProxyCount} 自建节点已保护",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = extColors.onEmeraldContainer,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    )
                                }
                            }
                        }
                    }
                }

                if (profile.isSubscription) {
                    IconButton(
                        onClick = onRefresh,
                        enabled = !isRefreshing,
                        modifier = Modifier.size(34.dp),
                    ) {
                        if (isRefreshing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = extColors.emerald,
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Rounded.Refresh,
                                contentDescription = "更新订阅",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(19.dp),
                            )
                        }
                    }
                }

                if (isActive) {
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = Icons.Rounded.CheckCircle,
                        contentDescription = "当前启用",
                        tint = extColors.emerald,
                        modifier = Modifier.size(22.dp),
                    )
                }

                Box {
                    IconButton(
                        onClick = { showMenu = true },
                        modifier = Modifier.size(32.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.MoreVert,
                            contentDescription = "配置操作",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                    DropdownMenu(
                        expanded = showMenu,
                        onDismissRequest = { showMenu = false },
                    ) {
                        if (!isActive) {
                            DropdownMenuItem(
                                text = { Text("设为当前启用") },
                                leadingIcon = { Icon(Icons.Rounded.CheckCircle, contentDescription = null) },
                                onClick = {
                                    showMenu = false
                                    onActivate()
                                },
                            )
                        }
                        DropdownMenuItem(
                            text = { Text("重命名配置") },
                            leadingIcon = { Icon(Icons.Rounded.DriveFileRenameOutline, contentDescription = null) },
                            onClick = {
                                showMenu = false
                                onRename()
                            },
                        )
                        if (profile.isSubscription) {
                            DropdownMenuItem(
                                text = { Text("立即更新订阅") },
                                leadingIcon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                                enabled = !isRefreshing,
                                onClick = {
                                    showMenu = false
                                    onRefresh()
                                },
                            )
                            DropdownMenuItem(
                                text = {
                                    Text("自动更新频率 (${UiJsonParsers.formatAutoUpdateInterval(profile.autoUpdateIntervalSecs)})")
                                },
                                leadingIcon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                                onClick = {
                                    showMenu = false
                                    onConfigureAutoUpdate()
                                },
                            )
                        }
                        if (!isActive) {
                            DropdownMenuItem(
                                text = { Text("删除配置", color = extColors.danger) },
                                leadingIcon = {
                                    Icon(
                                        Icons.Rounded.DeleteOutline,
                                        contentDescription = null,
                                        tint = extColors.danger,
                                    )
                                },
                                onClick = {
                                    showMenu = false
                                    onDelete()
                                },
                            )
                        }
                    }
                }
            }

            if (profile.totalBytes != null && profile.totalBytes > 0L) {
                val used = (profile.uploadBytes ?: 0L) + (profile.downloadBytes ?: 0L)
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "订阅流量：已用 ${UiJsonParsers.formatBytes(used)} / 总计 ${UiJsonParsers.formatBytes(profile.totalBytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = extColors.emerald,
                )
            }

            if (!profile.lastError.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(6.dp))
                HorizontalDivider(color = extColors.hairline)
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "上次刷新提示：${profile.lastError}",
                    style = MaterialTheme.typography.bodySmall,
                    color = extColors.amber,
                )
            }
        }
    }
}

@Composable
fun CustomRulesEditorDialog(
    initialRulesText: String,
    isSaving: Boolean = false,
    errorMessage: String? = null,
    onClearError: () -> Unit = {},
    onDismiss: () -> Unit,
    onSaveRules: (String) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val scrollState = rememberScrollState()
    var rulesText by remember(initialRulesText) { mutableStateOf(initialRulesText) }
    var localError by remember(initialRulesText) { mutableStateOf<String?>(null) }
    val activeError = localError ?: errorMessage

    val maxDialogBodyHeight = (LocalConfiguration.current.screenHeightDp * 0.56f).coerceAtLeast(200f).dp

    LaunchedEffect(activeError) {
        if (!activeError.isNullOrBlank()) {
            withFrameNanos { }
            scrollState.scrollTo(scrollState.maxValue)
        }
    }

    AlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(0.92f)
            .widthIn(max = 520.dp),
        title = { Text("自定义分流规则") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = maxDialogBodyHeight)
                    .verticalScroll(scrollState),
            ) {
                Text(
                    text = "每行一条 Clash 标准规则（例如 DOMAIN-SUFFIX,bilibili.com,DIRECT / GEOSITE,cn,DIRECT / MATCH,PROXY）。保存后将自动归档为「自定义规则」且不会被默认模板覆盖。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedTextField(
                    value = rulesText,
                    onValueChange = {
                        rulesText = it
                        if (localError != null) localError = null
                        if (!errorMessage.isNullOrBlank()) onClearError()
                    },
                    enabled = !isSaving,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 128.dp, max = 196.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                )
                if (!activeError.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(10.dp))
                    ModalInlineErrorBanner(
                        message = activeError,
                        onDismiss = {
                            localError = null
                            onClearError()
                        },
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val hasValidLine = rulesText.lineSequence()
                        .map { it.trim() }
                        .any { it.isNotEmpty() && !it.startsWith("#") }
                    if (!hasValidLine) {
                        localError = "请至少保留一条有效的非注释分流规则（如 MATCH,PROXY）"
                        return@Button
                    }
                    localError = null
                    onSaveRules(rulesText)
                },
                enabled = !isSaving && rulesText.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = extColors.emerald,
                    contentColor = Color.White,
                ),
            ) {
                if (isSaving) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = Color.White,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(if (isSaving) "保存中…" else "校验并保存")
            }
        },
        dismissButton = {
            TextButton(enabled = !isSaving, onClick = onDismiss) {
                Text("取消")
            }
        },
    )
}

@Composable
fun ActiveYamlEditorDialog(
    initialYamlText: String,
    isSaving: Boolean = false,
    errorMessage: String? = null,
    onClearError: () -> Unit = {},
    onDismiss: () -> Unit,
    onSaveYaml: (String) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val scrollState = rememberScrollState()
    var yamlText by remember(initialYamlText) { mutableStateOf(initialYamlText) }
    val maxDialogBodyHeight = (LocalConfiguration.current.screenHeightDp * 0.56f).coerceAtLeast(200f).dp

    LaunchedEffect(errorMessage) {
        if (!errorMessage.isNullOrBlank()) {
            withFrameNanos { }
            scrollState.scrollTo(scrollState.maxValue)
        }
    }

    AlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(0.92f)
            .widthIn(max = 520.dp),
        title = { Text("活跃 YAML 配置（安全脱敏）") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = maxDialogBodyHeight)
                    .verticalScroll(scrollState),
            ) {
                Text(
                    text = "节点密码与密钥以 ***REDACTED*** 保护显示；本机编辑规则/端口并保存时未改动节点的原始密钥会自动恢复。注意：导出的脱敏 YAML 适合排障分享，不能作为跨设备恢复完整密钥的备份。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedTextField(
                    value = yamlText,
                    onValueChange = {
                        yamlText = it
                        if (!errorMessage.isNullOrBlank()) onClearError()
                    },
                    enabled = !isSaving,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 136.dp, max = 208.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Normal,
                    ),
                )
                if (!errorMessage.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(10.dp))
                    ModalInlineErrorBanner(
                        message = errorMessage,
                        onDismiss = onClearError,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSaveYaml(yamlText) },
                enabled = !isSaving && yamlText.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = extColors.emerald,
                    contentColor = Color.White,
                ),
            ) {
                if (isSaving) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = Color.White,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(if (isSaving) "应用中…" else "验证并应用")
            }
        },
        dismissButton = {
            TextButton(enabled = !isSaving, onClick = onDismiss) {
                Text("关闭")
            }
        },
    )
}

@Composable
private fun ProfileOpSummaryCard(
    summary: ProfileOpSummaryUi,
    onDismiss: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val hasWarn = summary.skippedUnsupportedTotal > 0 || summary.newlyInsecureCount > 0

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(15.dp),
        color = extColors.cardSurface,
        border = BorderStroke(
            width = 1.dp,
            color = if (hasWarn) extColors.amber.copy(alpha = 0.65f) else extColors.selectedCardBorder,
        ),
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = if (summary.isRefresh) {
                        "订阅更新摘要 · ${summary.profileName}"
                    } else if (summary.skippedUnsupportedTotal > 0) {
                        "导入结果（部分兼容） · ${summary.profileName}"
                    } else {
                        "导入结果报告 · ${summary.profileName}"
                    },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.size(26.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Clear,
                        contentDescription = "关闭摘要",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            if (!summary.isRefresh) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OpMetricPill(
                        label = "成功导入",
                        value = "${summary.addedNodes}",
                        accent = extColors.emerald,
                        modifier = Modifier.weight(1f),
                    )
                    OpMetricPill(
                        label = "重复跳过",
                        value = "${summary.skippedDuplicates}",
                        accent = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    OpMetricPill(
                        label = "暂不支持",
                        value = "${summary.skippedUnsupportedTotal}",
                        accent = if (summary.skippedUnsupportedTotal > 0) extColors.amber else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                }

                if (summary.skippedGroups.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    val protoBreakdown = summary.skippedGroups.joinToString(" · ") {
                        "${it.protocolLabel} × ${it.count}"
                    }
                    Text(
                        text = "不兼容节点主要使用：$protoBreakdown（当前版本暂未内置，现有可用节点已完整保留）。",
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.amber,
                    )
                }
            } else {
                val gradeText = summary.auditGrade?.let { " · 安全评级 $it" } ?: ""
                Text(
                    text = "节点变动：+${summary.diffAddedCount} 新增 / -${summary.diffRemovedCount} 移除 / ${summary.diffChangedCount} 变更（当前共 ${summary.totalNodes} 节点）$gradeText",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(3.dp))
                val manualNote = if (summary.manualProtectedCount > 0) {
                    " · 已保留 ${summary.manualProtectedCount} 个自建节点"
                } else {
                    ""
                }
                Text(
                    text = "分流规则：${summary.rulesPrevCount} → ${summary.rulesNextCount} 条$manualNote",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (summary.newlyInsecureCount > 0) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "安全提醒：本次订阅新增了 ${summary.newlyInsecureCount} 个跳过 TLS 证书校验 (skip-cert-verify) 的高风险节点。",
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.amber,
                    )
                }
            }
        }
    }
}

@Composable
private fun OpMetricPill(
    label: String,
    value: String,
    accent: Color,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(10.dp),
        color = extColors.cardSubtle,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = accent,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
    }
}
