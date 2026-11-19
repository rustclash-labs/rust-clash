package io.github.rustclashlabs.rustclash.ui.screens

import android.graphics.Bitmap
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.FilterAlt
import androidx.compose.material.icons.rounded.FilterList
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.MoreHoriz
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.QrCode
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material.icons.rounded.StarOutline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.ProxyGroupItem
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.ui.theme.LatencyPill
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.ModalInlineErrorBanner
import io.github.rustclashlabs.rustclash.ui.theme.ProtocolBadge
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import org.json.JSONArray
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodesScreen(
    state: AppUiState,
    onSearchQueryChange: (String) -> Unit,
    onToggleSortByDelay: () -> Unit,
    onSelectGroupTab: (String) -> Unit,
    onSelectProxyInGroup: (groupName: String, proxyName: String) -> Unit,
    onTestAllDelays: () -> Unit,
    onTestSingleDelay: (nodeName: String) -> Unit,
    onOpenImportSheet: () -> Unit,
    onImportClipboardDirect: () -> Unit,
    onOpenQrCamera: () -> Unit,
    onOpenManualCreate: () -> Unit,
    onOpenNodeEdit: (ProxyNodeItem) -> Unit,
    onDeleteNode: (nodeName: String) -> Unit,
    onDeduplicateNodes: () -> Unit,
    onToggleFavorite: (nodeName: String) -> Unit = {},
) {
    val extColors = LocalRustClashColors.current
    var showOverflowMenu by remember { mutableStateOf(false) }
    var showSearchBar by rememberSaveable { mutableStateOf(false) }
    var topCategoryTab by rememberSaveable { mutableIntStateOf(0) } // 0 = 全部, 1 = 收藏, 2 = 分组
    var pendingDeleteNode by remember { mutableStateOf<String?>(null) }
    var qrPreviewNode by remember { mutableStateOf<ProxyNodeItem?>(null) }

    val selectableGroups = remember(state.groups) {
        state.groups.filter { it.name != "GLOBAL" }
    }
    val activeGroup: ProxyGroupItem? = selectableGroups.firstOrNull { it.name == state.selectedGroupTab }
        ?: selectableGroups.firstOrNull()

    val filteredConcreteNodes = remember(state.nodes, state.delays, state.nodeSearchQuery, state.sortNodesByDelay) {
        UiJsonParsers.filterAndSortNodes(
            nodes = state.nodes,
            delays = state.delays,
            query = state.nodeSearchQuery,
            sortByDelay = state.sortNodesByDelay,
        )
    }

    val concreteMap = remember(filteredConcreteNodes) {
        filteredConcreteNodes.associateBy { it.name }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 10.dp),
    ) {
        // Header Row (matching design reference: 节点 + Search, Filter/Sort, Add, More)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "节点",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f),
            )

            IconButton(
                onClick = {
                    if (showSearchBar && state.nodeSearchQuery.isNotEmpty()) {
                        onSearchQueryChange("")
                    }
                    showSearchBar = !showSearchBar
                },
            ) {
                Icon(
                    imageVector = Icons.Rounded.Search,
                    contentDescription = "搜索节点",
                    tint = if (showSearchBar || state.nodeSearchQuery.isNotEmpty()) {
                        extColors.emerald
                    } else {
                        MaterialTheme.colorScheme.onBackground
                    },
                )
            }

            IconButton(onClick = onToggleSortByDelay) {
                Icon(
                    imageVector = Icons.Rounded.FilterAlt,
                    contentDescription = "按延迟排序",
                    tint = if (state.sortNodesByDelay) {
                        extColors.emerald
                    } else {
                        MaterialTheme.colorScheme.onBackground
                    },
                )
            }

            IconButton(onClick = onOpenImportSheet) {
                Icon(
                    imageVector = Icons.Rounded.Add,
                    contentDescription = "添加或导入节点",
                    tint = extColors.emerald,
                )
            }

            Box {
                IconButton(onClick = { showOverflowMenu = true }) {
                    if (state.isTestingAllDelays) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = extColors.emerald,
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Rounded.MoreVert,
                            contentDescription = "更多节点操作",
                            tint = MaterialTheme.colorScheme.onBackground,
                        )
                    }
                }
                DropdownMenu(
                    expanded = showOverflowMenu,
                    onDismissRequest = { showOverflowMenu = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("全部节点测速") },
                        leadingIcon = { Icon(Icons.Rounded.Speed, contentDescription = null) },
                        enabled = state.nodes.isNotEmpty() && !state.isTestingAllDelays,
                        onClick = {
                            showOverflowMenu = false
                            onTestAllDelays()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("粘贴剪贴板快速导入") },
                        leadingIcon = { Icon(Icons.Rounded.ContentPaste, contentDescription = null) },
                        onClick = {
                            showOverflowMenu = false
                            onImportClipboardDirect()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("手动填写新建节点") },
                        leadingIcon = { Icon(Icons.Rounded.Edit, contentDescription = null) },
                        onClick = {
                            showOverflowMenu = false
                            onOpenManualCreate()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("清理重复节点") },
                        leadingIcon = { Icon(Icons.Rounded.FilterList, contentDescription = null) },
                        onClick = {
                            showOverflowMenu = false
                            onDeduplicateNodes()
                        },
                    )
                }
            }
        }

        // Collapsible Search Bar
        AnimatedVisibility(visible = showSearchBar || state.nodeSearchQuery.isNotEmpty()) {
            OutlinedTextField(
                value = state.nodeSearchQuery,
                onValueChange = onSearchQueryChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp, bottom = 4.dp),
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                placeholder = {
                    Text(
                        text = "搜索节点名称、服务器或协议…",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Rounded.Search,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
                trailingIcon = {
                    IconButton(
                        onClick = {
                            onSearchQueryChange("")
                            showSearchBar = false
                        },
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Clear,
                            contentDescription = "关闭搜索",
                        )
                    }
                },
            )
        }

        // Underline Tab Row: 全部 (N) | 收藏 | 分组 (matching design reference)
        val favCount = state.nodes.count { it.name in state.favoriteNodes }
        SecondaryTabRow(
            selectedTabIndex = topCategoryTab,
            containerColor = Color.Transparent,
            divider = { HorizontalDivider(thickness = 1.dp, color = extColors.hairline) },
            indicator = {
                TabRowDefaults.SecondaryIndicator(
                    modifier = Modifier.tabIndicatorOffset(topCategoryTab, matchContentSize = false),
                    height = 2.5.dp,
                    color = extColors.emerald,
                )
            },
        ) {
            Tab(
                selected = topCategoryTab == 0,
                onClick = { topCategoryTab = 0 },
                selectedContentColor = MaterialTheme.colorScheme.onBackground,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    Text(
                        text = "全部 (${state.nodes.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (topCategoryTab == 0) FontWeight.Bold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
            Tab(
                selected = topCategoryTab == 1,
                onClick = { topCategoryTab = 1 },
                selectedContentColor = MaterialTheme.colorScheme.onBackground,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    Text(
                        text = if (favCount > 0) "收藏 ($favCount)" else "收藏",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (topCategoryTab == 1) FontWeight.Bold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
            Tab(
                selected = topCategoryTab == 2,
                onClick = { topCategoryTab = 2 },
                selectedContentColor = MaterialTheme.colorScheme.onBackground,
                unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                text = {
                    Text(
                        text = "分组",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (topCategoryTab == 2) FontWeight.Bold else FontWeight.Medium,
                        maxLines = 1,
                    )
                },
            )
        }

        // When on "分组" tab and multiple groups exist, show group selector chips
        if (topCategoryTab == 2 && selectableGroups.isNotEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                selectableGroups.forEach { group ->
                    val selected = group.name == activeGroup?.name
                    FilterChip(
                        selected = selected,
                        onClick = { onSelectGroupTab(group.name) },
                        modifier = Modifier.widthIn(max = 220.dp),
                        label = {
                            Text(
                                text = "${group.name} (${group.now.ifBlank { group.type }})",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (state.nodes.isEmpty() && !state.demoMode) {
            val stackActionButtons = LocalConfiguration.current.screenWidthDp < 360 ||
                LocalDensity.current.fontScale >= 1.2f
            // Empty State
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(top = 8.dp),
                shape = RoundedCornerShape(18.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "尚未导入任何代理节点",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "支持离线或连接状态下直接导入 vless://、vmess://、ss://、trojan://、hy2://、tuic://、anytls://、socks5:// 分享链接、Base64 订阅、Clash YAML 或 HTTPS 订阅链接。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    if (stackActionButtons) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = onImportClipboardDirect,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("粘贴导入", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            OutlinedButton(
                                onClick = onOpenImportSheet,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("链接 / 订阅", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Button(
                                onClick = onImportClipboardDirect,
                                modifier = Modifier.weight(1f),
                            ) {
                                Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("粘贴导入", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            OutlinedButton(
                                onClick = onOpenImportSheet,
                                modifier = Modifier.weight(1f),
                            ) {
                                Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("链接 / 订阅", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    TextButton(onClick = onOpenQrCamera) {
                        Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("扫码导入节点")
                    }
                }
            }
        } else if (state.nodes.isEmpty() && state.demoMode) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                shape = RoundedCornerShape(18.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "沙盒演示模式已启用",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "当前未保存外部真实节点，启动 VPN 时将使用内置本地多协议测试沙盒；导入真实节点后会自动切换为真实代理模式。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    OutlinedButton(onClick = onOpenImportSheet) {
                        Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("导入真实节点 / 订阅")
                    }
                }
            }
        } else {
            val targetGroupName = if (topCategoryTab == 2) {
                activeGroup?.name ?: state.primaryGroup
            } else {
                state.primaryGroup
            }
            val selectedMemberInGroup = if (topCategoryTab == 2 && activeGroup != null) {
                activeGroup.now
            } else {
                state.effectiveOutbound
            }
            val isGroupSelectable = if (topCategoryTab == 2 && activeGroup != null) {
                activeGroup.isSelectable
            } else {
                true
            }

            val displayNodes: List<ProxyNodeItem> = when (topCategoryTab) {
                1 -> filteredConcreteNodes.filter { it.name in state.favoriteNodes }
                2 -> if (activeGroup != null) {
                    val memberSet = activeGroup.members.toSet()
                    val concreteInGroup = filteredConcreteNodes.filter { it.name in memberSet }
                    val syntheticMembers = if (state.nodeSearchQuery.isBlank()) {
                        activeGroup.members
                            .filter { m -> state.nodes.none { it.name == m } }
                            .map { m ->
                                ProxyNodeItem(
                                    name = m,
                                    type = if (m == "DIRECT" || m == "REJECT") m.lowercase() else "group",
                                    server = if (m == "DIRECT") "本地物理出口" else if (m == "REJECT") "阻断连接" else "策略组引用",
                                    port = 0,
                                    delayMs = state.delays[m],
                                )
                            }
                    } else {
                        emptyList()
                    }
                    syntheticMembers + concreteInGroup
                } else {
                    filteredConcreteNodes
                }
                else -> filteredConcreteNodes
            }

            if (displayNodes.isEmpty() && state.nodeSearchQuery.isNotBlank()) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    color = extColors.cardSurface,
                    border = BorderStroke(1.dp, extColors.hairline),
                ) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            text = "未找到匹配「${state.nodeSearchQuery}」的节点",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        TextButton(onClick = { onSearchQueryChange("") }) {
                            Text("清除搜索条件")
                        }
                    }
                }
            } else if (topCategoryTab == 1 && displayNodes.isEmpty()) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    color = extColors.cardSurface,
                    border = BorderStroke(1.dp, extColors.hairline),
                ) {
                    Text(
                        text = "暂无收藏节点。点击任意节点卡片左侧的星标即可加入收藏夹。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(18.dp),
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(bottom = 20.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(displayNodes, key = { "${topCategoryTab}:${targetGroupName}:${it.name}" }) { item ->
                        val isSelected = if (topCategoryTab == 2 && activeGroup != null) {
                            item.name == activeGroup.now
                        } else {
                            item.name == selectedMemberInGroup ||
                                (targetGroupName == state.primaryGroup && item.name == state.effectiveOutbound)
                        }
                        val isConcrete = concreteMap.containsKey(item.name)
                        val isFavorited = item.name in state.favoriteNodes
                        NodeRowCard(
                            node = item,
                            isSelected = isSelected,
                            isFavorited = isFavorited,
                            isConcrete = isConcrete,
                            isTestingThis = state.testingNodeName == item.name || state.isTestingAllDelays,
                            onSelect = {
                                if (isGroupSelectable) {
                                    onSelectProxyInGroup(targetGroupName, item.name)
                                }
                            },
                            onToggleFavorite = { onToggleFavorite(item.name) },
                            onTestDelay = { onTestSingleDelay(item.name) },
                            onEdit = { onOpenNodeEdit(item) },
                            onShowQr = { qrPreviewNode = item },
                            onDelete = { pendingDeleteNode = item.name },
                        )
                    }
                }
            }
        }
    }

    if (pendingDeleteNode != null) {
        val target = pendingDeleteNode!!
        AlertDialog(
            onDismissRequest = { pendingDeleteNode = null },
            title = { Text("删除节点") },
            text = { Text("确定要从当前配置中删除节点「$target」吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingDeleteNode = null
                        onDeleteNode(target)
                    },
                ) {
                    Text("删除", color = extColors.danger)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteNode = null }) {
                    Text("取消")
                }
            },
        )
    }

    if (qrPreviewNode != null) {
        NodeQrInfoDialog(
            node = qrPreviewNode!!,
            onDismiss = { qrPreviewNode = null },
        )
    }
}

@Composable
private fun NodeRowCard(
    node: ProxyNodeItem,
    isSelected: Boolean,
    isFavorited: Boolean,
    isConcrete: Boolean,
    isTestingThis: Boolean,
    onSelect: () -> Unit,
    onToggleFavorite: () -> Unit,
    onTestDelay: () -> Unit,
    onEdit: () -> Unit,
    onShowQr: () -> Unit,
    onDelete: () -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val haptic = LocalHapticFeedback.current
    val accentBarColor = extColors.emeraldBright
    var menuExpanded by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .clickable {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onSelect()
            },
        shape = RoundedCornerShape(20.dp),
        color = if (isSelected) extColors.selectedCardBg else extColors.cardSurface,
        shadowElevation = if (!isSelected && !extColors.isDark) 1.5.dp else 0.dp,
        border = if (isSelected) {
            BorderStroke(
                width = 1.dp,
                color = extColors.selectedCardBorder.copy(alpha = if (extColors.isDark) 0.5f else 0.35f),
            )
        } else {
            null
        },
    ) {
        Column(
            modifier = Modifier
                .drawBehind {
                    if (isSelected) {
                        val barWidth = 3.dp.toPx()
                        val insetY = 16.dp.toPx()
                        val barHeight = (size.height - insetY * 2f).coerceAtLeast(0f)
                        if (barHeight > 0f) {
                            drawRoundRect(
                                color = accentBarColor,
                                topLeft = Offset(1.5.dp.toPx(), insetY),
                                size = Size(barWidth, barHeight),
                                cornerRadius = CornerRadius(barWidth, barWidth),
                            )
                        }
                    }
                }
                .padding(start = 10.dp, end = 12.dp, top = 8.dp, bottom = 9.dp),
        ) {
            // Top Row: Star IconButton (36dp touch target) + Node Name + (Checkmark if selected, else LatencyPill)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(
                    onClick = onToggleFavorite,
                    modifier = Modifier.size(36.dp),
                ) {
                    Icon(
                        imageVector = if (isFavorited) Icons.Rounded.Star else Icons.Rounded.StarOutline,
                        contentDescription = if (isFavorited) "取消收藏" else "收藏节点",
                        tint = if (isFavorited) extColors.amber else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }

                Spacer(modifier = Modifier.width(2.dp))

                Text(
                    text = node.name,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )

                Spacer(modifier = Modifier.width(8.dp))

                if (isSelected) {
                    Icon(
                        imageVector = Icons.Rounded.CheckCircle,
                        contentDescription = "当前已选节点",
                        tint = extColors.emerald,
                        modifier = Modifier.size(21.dp),
                    )
                } else if (isConcrete) {
                    LatencyPill(
                        delayMs = node.delayMs,
                        isProbing = isTestingThis,
                        isSelected = false,
                        onClick = onTestDelay,
                    )
                }
            }

            // Bottom Row: indented under Node Name (38.dp) -> ProtocolBadge + Server:Port + Right Latency/Menu
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 38.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ProtocolBadge(
                    protocol = node.protocolShortBadge,
                    isSelected = isSelected,
                )

                Spacer(modifier = Modifier.width(8.dp))

                val endpointText = NodeImportSupport.formatHostPort(node.server, node.port)
                Text(
                    text = endpointText,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )

                if (isConcrete) {
                    if (isSelected) {
                        Spacer(modifier = Modifier.width(6.dp))
                        LatencyPill(
                            delayMs = node.delayMs,
                            isProbing = isTestingThis,
                            isSelected = true,
                            onClick = onTestDelay,
                        )
                    }

                    Box {
                        IconButton(
                            onClick = { menuExpanded = true },
                            modifier = Modifier.size(36.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.MoreHoriz,
                                contentDescription = "节点更多操作",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(20.dp),
                            )
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("单独测速") },
                                leadingIcon = { Icon(Icons.Rounded.Speed, contentDescription = null) },
                                onClick = {
                                    menuExpanded = false
                                    onTestDelay()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("编辑 / 重命名") },
                                leadingIcon = { Icon(Icons.Rounded.Edit, contentDescription = null) },
                                onClick = {
                                    menuExpanded = false
                                    onEdit()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("节点信息二维码") },
                                leadingIcon = { Icon(Icons.Rounded.QrCode, contentDescription = null) },
                                onClick = {
                                    menuExpanded = false
                                    onShowQr()
                                },
                            )
                            HorizontalDivider()
                            DropdownMenuItem(
                                text = { Text("删除节点", color = extColors.danger) },
                                leadingIcon = {
                                    Icon(
                                        Icons.Rounded.DeleteOutline,
                                        contentDescription = null,
                                        tint = extColors.danger,
                                    )
                                },
                                onClick = {
                                    menuExpanded = false
                                    onDelete()
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportPayloadBottomSheet(
    isImporting: Boolean,
    errorMessage: String? = null,
    onClearError: () -> Unit = {},
    defaultSubAutoUpdateSecs: Long = 86400L,
    defaultAutoSelect: Boolean = false,
    onDismiss: () -> Unit,
    onReadClipboard: () -> String?,
    onLaunchCameraQr: () -> Unit,
    onLaunchGalleryQr: () -> Unit,
    onOpenManualForm: () -> Unit,
    onSubmitImport: (payload: String, deduplicate: Boolean, autoSelect: Boolean) -> Unit = { _, _, _ -> },
    onSubmitImportDetailed: ((payload: String, deduplicate: Boolean, autoSelect: Boolean, subscriptionAutoUpdateSecs: Long?) -> Unit)? = null,
) {
    val extColors = LocalRustClashColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scrollState = rememberScrollState()
    val focusManager = LocalFocusManager.current
    var payloadText by remember { mutableStateOf("") }
    var deduplicate by remember { mutableStateOf(true) }
    var autoSelect by remember(defaultAutoSelect) { mutableStateOf(defaultAutoSelect) }
    var enableSubAutoUpdate by remember(defaultSubAutoUpdateSecs) { mutableStateOf(defaultSubAutoUpdateSecs > 0L) }
    var clipboardHint by remember { mutableStateOf<String?>(null) }

    val isSubscriptionUrl = remember(payloadText) {
        val trimmed = payloadText.trim()
        trimmed.startsWith("https://", ignoreCase = true) || trimmed.startsWith("clash://", ignoreCase = true)
    }

    val maxSheetHeight = (LocalConfiguration.current.screenHeightDp * 0.85f).coerceAtLeast(320f).dp

    LaunchedEffect(errorMessage) {
        if (!errorMessage.isNullOrBlank()) {
            withFrameNanos { }
            scrollState.scrollTo(scrollState.maxValue)
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = maxSheetHeight)
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(scrollState)
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Text(
                text = "添加节点 / 导入订阅",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "支持单条或多行 vless://、vmess://、ss://、trojan://、hy2://、tuic://、anytls://、socks5:// 分享链接、Base64 订阅、Clash YAML 或 HTTPS 订阅链接。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(10.dp))

            // Quick Action Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    enabled = !isImporting,
                    onClick = {
                        val clip = onReadClipboard()
                        if (!clip.isNullOrBlank()) {
                            payloadText = clip
                            clipboardHint = null
                            if (!errorMessage.isNullOrBlank()) onClearError()
                        } else {
                            clipboardHint = "当前剪贴板为空，请在下方输入框直接粘贴节点链接或订阅地址"
                        }
                    },
                ) {
                    Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("读取剪贴板")
                }
                OutlinedButton(
                    enabled = !isImporting,
                    onClick = {
                        onDismiss()
                        onLaunchCameraQr()
                    },
                ) {
                    Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("相机扫码")
                }
                OutlinedButton(
                    enabled = !isImporting,
                    onClick = {
                        onDismiss()
                        onLaunchGalleryQr()
                    },
                ) {
                    Icon(Icons.Rounded.Image, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("相册二维码")
                }
                OutlinedButton(
                    enabled = !isImporting,
                    onClick = {
                        onDismiss()
                        onOpenManualForm()
                    },
                ) {
                    Icon(Icons.Rounded.Edit, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("手动新建")
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            OutlinedTextField(
                value = payloadText,
                onValueChange = {
                    payloadText = it
                    clipboardHint = null
                    if (!errorMessage.isNullOrBlank()) onClearError()
                },
                enabled = !isImporting,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 104.dp, max = 140.dp),
                shape = RoundedCornerShape(14.dp),
                placeholder = {
                    Text(
                        text = "在此粘贴节点链接 (vless:// / vmess:// / ss:// / trojan:// / hy2:// / tuic:// / anytls:// / socks5://)、Base64 文本、Clash YAML 或 https:// 订阅地址…",
                        style = MaterialTheme.typography.bodySmall,
                    )
                },
            )

            if (!clipboardHint.isNullOrBlank() && errorMessage.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = extColors.amberContainer,
                ) {
                    Text(
                        text = clipboardHint!!,
                        style = MaterialTheme.typography.bodySmall,
                        color = extColors.onAmberContainer,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "自动跳过重复节点",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                Switch(
                    checked = deduplicate,
                    enabled = !isImporting,
                    onCheckedChange = { deduplicate = it },
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "导入后立即切换为新节点",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = "关闭时保留当前正在使用的节点，不中断现有连接",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Switch(
                    checked = autoSelect,
                    enabled = !isImporting,
                    onCheckedChange = { autoSelect = it },
                )
            }

            AnimatedVisibility(visible = isSubscriptionUrl) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "开启订阅定时自动更新",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                text = "自动刷新时保留您手动添加的节点与当前选中项",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Switch(
                            checked = enableSubAutoUpdate,
                            enabled = !isImporting,
                            onCheckedChange = { enableSubAutoUpdate = it },
                        )
                    }
                }
            }

            if (!errorMessage.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(8.dp))
                ModalInlineErrorBanner(
                    message = errorMessage,
                    onDismiss = onClearError,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = {
                    focusManager.clearFocus()
                    val subSecs: Long? = if (isSubscriptionUrl) {
                        if (enableSubAutoUpdate) (defaultSubAutoUpdateSecs.takeIf { it > 0L } ?: 86400L) else 0L
                    } else {
                        null
                    }
                    if (onSubmitImportDetailed != null) {
                        onSubmitImportDetailed(payloadText, deduplicate, autoSelect, subSecs)
                    } else {
                        onSubmitImport(payloadText, deduplicate, autoSelect)
                    }
                },
                enabled = !isImporting && payloadText.isNotBlank(),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(14.dp),
            ) {
                if (isImporting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (isImporting) "正在获取并验证…" else "验证并保存")
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
fun NodeEditorDialog(
    existingNode: ProxyNodeItem?,
    isSaving: Boolean = false,
    backendError: String? = null,
    onClearBackendError: () -> Unit = {},
    defaultAutoSelect: Boolean = false,
    onDismiss: () -> Unit,
    onSave: (originalName: String?, nodeJson: JSONObject, autoSelect: Boolean) -> Unit,
) {
    val isEditing = existingNode != null
    val dialogScrollState = rememberScrollState()
    val protocols = listOf(
        "vless" to "VLESS",
        "vmess" to "VMess",
        "ss" to "SS",
        "trojan" to "Trojan",
        "hysteria2" to "Hy2",
        "tuic" to "TUIC",
        "anytls" to "AnyTLS",
        "socks5" to "SOCKS5",
        "http" to "HTTP",
    )
    val existingProto = existingNode?.type?.lowercase()?.let {
        when (it) {
            "socks" -> "socks5"
            "hy2" -> "hysteria2"
            else -> it
        }
    }
    val existingRawObj = remember(existingNode) {
        existingNode?.rawRedactedJson
            ?.takeIf { it.isNotBlank() }
            ?.let { raw -> runCatching { JSONObject(raw) }.getOrNull() }
    }
    var selectedProto by remember(existingNode) {
        mutableStateOf(
            existingProto?.takeIf { p -> protocols.any { it.first == p } } ?: "vless",
        )
    }
    var name by remember(existingNode) { mutableStateOf(existingNode?.name ?: "") }
    var server by remember(existingNode) { mutableStateOf(existingNode?.server ?: "") }
    var portText by remember(existingNode) { mutableStateOf((existingNode?.port ?: 443).toString()) }
    var username by remember(existingNode) { mutableStateOf(existingNode?.username ?: "") }
    var secret by remember(existingNode) { mutableStateOf("") }
    var tuicPassword by remember(existingNode) { mutableStateOf("") }
    var cipherOrEnc by remember(existingNode) {
        mutableStateOf(
            when (existingProto) {
                "ss" -> existingNode.cipher.ifBlank { "aes-256-gcm" }
                "vmess" -> existingNode.cipher.ifBlank { "auto" }
                "vless" -> existingNode.encryption.takeIf { it != "***REDACTED***" } ?: "none"
                else -> "aes-256-gcm"
            },
        )
    }
    var vlessFlow by remember(existingNode) { mutableStateOf(existingNode?.flow ?: "") }
    var vlessReality by remember(existingNode) { mutableStateOf(existingNode?.realityEnabled ?: false) }
    var realityPublicKey by remember(existingNode) {
        mutableStateOf(existingNode?.realityPublicKey?.takeIf { it != "***REDACTED***" } ?: "")
    }
    var realityShortId by remember(existingNode) {
        mutableStateOf(existingNode?.realityShortId?.takeIf { it != "***REDACTED***" } ?: "")
    }
    var clientFingerprint by remember(existingNode) {
        mutableStateOf(existingNode?.clientFingerprint?.ifBlank { "chrome" } ?: "chrome")
    }
    var hy2Ports by remember(existingNode) { mutableStateOf(existingNode?.ports ?: "") }
    var hy2ObfsEnabled by remember(existingNode) {
        mutableStateOf(existingNode?.obfs?.equals("salamander", ignoreCase = true) == true)
    }
    var hy2ObfsPassword by remember(existingNode) { mutableStateOf("") }
    var hy2Up by remember(existingNode) {
        mutableStateOf(existingRawObj?.optString("up", "")?.takeIf { it != "null" } ?: "")
    }
    var hy2Down by remember(existingNode) {
        mutableStateOf(existingRawObj?.optString("down", "")?.takeIf { it != "null" } ?: "")
    }
    var tuicUdpRelayMode by remember(existingNode) {
        mutableStateOf(existingNode?.udpRelayMode?.ifBlank { "native" } ?: "native")
    }
    var tuicCongestion by remember(existingNode) {
        mutableStateOf(existingNode?.congestionController?.ifBlank { "bbr" } ?: "bbr")
    }
    var tuicZeroRtt by remember(existingNode) { mutableStateOf(existingNode?.zeroRttHandshake ?: false) }
    var transportNet by remember(existingNode) {
        mutableStateOf(
            existingNode?.network?.lowercase()?.takeIf { it == "ws" || it == "tcp" } ?: "tcp",
        )
    }
    var wsPath by remember(existingNode) { mutableStateOf(existingNode?.wsPath?.ifBlank { "/ws" } ?: "/ws") }
    var wsHost by remember(existingNode) { mutableStateOf(existingNode?.wsHost ?: "") }
    var maxEarlyDataText by remember(existingNode) {
        mutableStateOf(if ((existingNode?.maxEarlyData ?: 0) > 0) existingNode!!.maxEarlyData.toString() else "0")
    }
    var sni by remember(existingNode) { mutableStateOf(existingNode?.sni ?: "") }
    var alpnText by remember(existingNode) {
        val initialAlpn = existingRawObj?.optJSONArray("alpn")?.let { arr ->
            buildList {
                for (i in 0 until arr.length()) {
                    val item = arr.optString(i, "").trim()
                    if (item.isNotEmpty()) add(item)
                }
            }.joinToString(", ")
        } ?: ""
        mutableStateOf(initialAlpn)
    }
    var tlsEnabled by remember(existingNode) {
        mutableStateOf(
            if (existingNode?.realityEnabled == true) {
                true
            } else if (existingRawObj?.has("tls") == true) {
                existingRawObj.optBoolean("tls", existingNode?.tls ?: true)
            } else {
                existingNode?.tls ?: (selectedProto in setOf("vless", "trojan", "anytls", "hysteria2", "tuic"))
            },
        )
    }
    var udpEnabled by remember(existingNode) {
        mutableStateOf(
            if (existingRawObj?.has("udp") == true) {
                existingRawObj.optBoolean("udp", existingNode?.udp ?: (selectedProto != "http"))
            } else {
                existingNode?.udp ?: (selectedProto != "http")
            },
        )
    }
    var skipCertVerify by remember(existingNode) { mutableStateOf(existingNode?.skipCertVerify ?: false) }
    var autoSelect by remember(existingNode, defaultAutoSelect) { mutableStateOf(!isEditing && defaultAutoSelect) }
    var validationError by remember(existingNode) { mutableStateOf<String?>(null) }

    val clearErrors = {
        if (validationError != null) validationError = null
        if (!backendError.isNullOrBlank()) onClearBackendError()
    }

    val maxDialogBodyHeight = (LocalConfiguration.current.screenHeightDp * 0.56f).coerceAtLeast(200f).dp

    LaunchedEffect(validationError, backendError) {
        if (!validationError.isNullOrBlank() || !backendError.isNullOrBlank()) {
            withFrameNanos { }
            dialogScrollState.scrollTo(dialogScrollState.maxValue)
        }
    }

    val supportsWs =
        (selectedProto == "vless" && !vlessReality && vlessFlow.isBlank()) ||
            selectedProto == "vmess" ||
            selectedProto == "trojan"
    val isAuthOptional = selectedProto == "socks5" || selectedProto == "http"
    val protoSwitchedOnEdit = isEditing && selectedProto != existingProto

    AlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(0.92f)
            .widthIn(max = 520.dp),
        title = {
            Text(
                text = if (isEditing) "编辑节点：${existingNode?.name}" else "手动添加节点",
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = maxDialogBodyHeight)
                    .verticalScroll(dialogScrollState),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    protocols.forEach { (protoKey, protoLabel) ->
                        FilterChip(
                            selected = selectedProto == protoKey,
                            enabled = !isSaving,
                            onClick = {
                                if (selectedProto != protoKey) {
                                    val prevProto = selectedProto
                                    selectedProto = protoKey
                                    clearErrors()
                                    if (protoKey == "http") {
                                        udpEnabled = false
                                    } else if (!isEditing || prevProto == "http") {
                                        udpEnabled = true
                                    }
                                    when (protoKey) {
                                        "ss" -> {
                                            if (cipherOrEnc.isBlank() || cipherOrEnc == "none" || cipherOrEnc == "auto") {
                                                cipherOrEnc = "aes-256-gcm"
                                            }
                                        }
                                        "vmess" -> {
                                            if (cipherOrEnc !in setOf("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero")) {
                                                cipherOrEnc = "auto"
                                            }
                                        }
                                        "vless" -> {
                                            if (cipherOrEnc in setOf("aes-256-gcm", "auto", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305") ||
                                                cipherOrEnc.startsWith("2022-")
                                            ) {
                                                cipherOrEnc = "none"
                                            }
                                            tlsEnabled = true
                                        }
                                        "trojan", "anytls", "hysteria2", "tuic" -> {
                                            tlsEnabled = true
                                        }
                                    }
                                }
                            },
                            label = { Text(protoLabel, style = MaterialTheme.typography.labelSmall) },
                        )
                    }
                }

                OutlinedTextField(
                    value = name,
                    onValueChange = {
                        name = it
                        clearErrors()
                    },
                    enabled = !isSaving,
                    label = { Text("节点名称") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = server,
                    onValueChange = {
                        server = it
                        clearErrors()
                    },
                    enabled = !isSaving,
                    label = { Text("服务器地址 (域名或 IP)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = portText,
                    onValueChange = {
                        portText = it
                        clearErrors()
                    },
                    enabled = !isSaving,
                    label = { Text("端口 (1 - 65535)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (isAuthOptional) {
                    OutlinedTextField(
                        value = username,
                        onValueChange = {
                            username = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = { Text("用户名 (可选)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                OutlinedTextField(
                    value = secret,
                    onValueChange = {
                        secret = it
                        clearErrors()
                    },
                    enabled = !isSaving,
                    label = {
                        Text(
                            when {
                                protoSwitchedOnEdit && !isAuthOptional -> "密码 / UUID（切换协议需重新填写）"
                                isEditing -> "密码 / UUID（留空保留原密钥）"
                                selectedProto == "vless" -> "VLESS UUID"
                                selectedProto == "vmess" -> "VMess UUID"
                                selectedProto == "tuic" -> "TUIC UUID"
                                selectedProto == "hysteria2" -> "Hysteria2 鉴权密码"
                                isAuthOptional -> "连接密码 (无鉴权可留空)"
                                else -> "连接密码 / PSK"
                            },
                        )
                    },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (selectedProto == "tuic") {
                    OutlinedTextField(
                        value = tuicPassword,
                        onValueChange = {
                            tuicPassword = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = {
                            Text(
                                if (isEditing && !protoSwitchedOnEdit) {
                                    "TUIC 密码（留空保留原密码）"
                                } else {
                                    "TUIC 密码（无密码可留空）"
                                },
                            )
                        },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (selectedProto == "ss" || selectedProto == "vmess" || (selectedProto == "vless" && !vlessReality)) {
                    OutlinedTextField(
                        value = cipherOrEnc,
                        onValueChange = {
                            cipherOrEnc = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = {
                            Text(
                                when (selectedProto) {
                                    "ss" -> "加密算法 (默认 aes-256-gcm / 支持 2022-blake3-*)"
                                    "vmess" -> "VMess AEAD 算法 (auto / aes-128-gcm / chacha20-poly1305 / none / zero)"
                                    else -> "VLESS Encryption (默认 none)"
                                },
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (selectedProto == "vless") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Flow：", style = MaterialTheme.typography.bodySmall)
                        FilterChip(
                            selected = vlessFlow.isBlank(),
                            enabled = !isSaving,
                            onClick = {
                                vlessFlow = ""
                                clearErrors()
                            },
                            label = { Text("无", style = MaterialTheme.typography.labelSmall) },
                        )
                        FilterChip(
                            selected = vlessFlow == "xtls-rprx-vision",
                            enabled = !isSaving,
                            onClick = {
                                vlessFlow = "xtls-rprx-vision"
                                transportNet = "tcp"
                                tlsEnabled = true
                                clearErrors()
                            },
                            label = { Text("xtls-rprx-vision", style = MaterialTheme.typography.labelSmall) },
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = vlessReality,
                            enabled = !isSaving,
                            onCheckedChange = {
                                vlessReality = it
                                if (it) {
                                    tlsEnabled = true
                                    transportNet = "tcp"
                                }
                                clearErrors()
                            },
                        )
                        Text("启用 VLESS REALITY 伪装握手", style = MaterialTheme.typography.bodySmall)
                    }
                    if (vlessReality) {
                        OutlinedTextField(
                            value = realityPublicKey,
                            onValueChange = {
                                realityPublicKey = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = {
                                Text(
                                    if (isEditing && !protoSwitchedOnEdit && existingNode?.realityPublicKey == "***REDACTED***") {
                                        "REALITY Public Key (pbk，留空保留原公钥)"
                                    } else {
                                        "REALITY Public Key (pbk)"
                                    },
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = realityShortId,
                            onValueChange = {
                                realityShortId = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = {
                                Text(
                                    if (isEditing && !protoSwitchedOnEdit && existingNode?.realityShortId == "***REDACTED***") {
                                        "REALITY Short ID (sid，留空保留原 sid)"
                                    } else {
                                        "REALITY Short ID (sid，可选十六进制)"
                                    },
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = clientFingerprint,
                            onValueChange = {
                                clientFingerprint = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("TLS 指纹 (chrome / firefox / safari / ios)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }

                if (selectedProto == "hysteria2") {
                    OutlinedTextField(
                        value = hy2Ports,
                        onValueChange = {
                            hy2Ports = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = { Text("端口跳跃 Ports (可选，如 20000-50000)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = hy2ObfsEnabled,
                            enabled = !isSaving,
                            onCheckedChange = {
                                hy2ObfsEnabled = it
                                clearErrors()
                            },
                        )
                        Text("启用 Salamander UDP 混淆", style = MaterialTheme.typography.bodySmall)
                    }
                    if (hy2ObfsEnabled) {
                        OutlinedTextField(
                            value = hy2ObfsPassword,
                            onValueChange = {
                                hy2ObfsPassword = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = {
                                Text(
                                    if (isEditing && !protoSwitchedOnEdit && existingRawObj?.optString("obfs-password", "") == "***REDACTED***") {
                                        "Salamander 混淆密码（留空保留原密码）"
                                    } else {
                                        "Salamander 混淆密码"
                                    },
                                )
                            },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedTextField(
                            value = hy2Up,
                            onValueChange = {
                                hy2Up = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("上行带宽 (如 50 Mbps)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedTextField(
                            value = hy2Down,
                            onValueChange = {
                                hy2Down = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("下行带宽 (如 200 Mbps)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }

                if (selectedProto == "tuic") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("UDP 模式：", style = MaterialTheme.typography.bodySmall)
                        listOf("native" to "Native", "quic" to "QUIC Stream").forEach { (modeKey, modeLabel) ->
                            FilterChip(
                                selected = tuicUdpRelayMode.equals(modeKey, ignoreCase = true),
                                enabled = !isSaving,
                                onClick = {
                                    tuicUdpRelayMode = modeKey
                                    clearErrors()
                                },
                                label = { Text(modeLabel, style = MaterialTheme.typography.labelSmall) },
                            )
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("拥塞控制：", style = MaterialTheme.typography.bodySmall)
                        listOf("bbr" to "BBR", "cubic" to "CUBIC", "new_reno" to "NewReno").forEach { (ccKey, ccLabel) ->
                            FilterChip(
                                selected = tuicCongestion.equals(ccKey, ignoreCase = true),
                                enabled = !isSaving,
                                onClick = {
                                    tuicCongestion = ccKey
                                    clearErrors()
                                },
                                label = { Text(ccLabel, style = MaterialTheme.typography.labelSmall) },
                            )
                        }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = tuicZeroRtt,
                            enabled = !isSaving,
                            onCheckedChange = {
                                tuicZeroRtt = it
                                clearErrors()
                            },
                        )
                        Text("启用 QUIC 0-RTT 握手", style = MaterialTheme.typography.bodySmall)
                    }
                }

                if (supportsWs) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("传输层：", style = MaterialTheme.typography.bodySmall)
                        FilterChip(
                            selected = transportNet == "tcp",
                            enabled = !isSaving,
                            onClick = {
                                transportNet = "tcp"
                                clearErrors()
                            },
                            label = { Text("TCP", style = MaterialTheme.typography.labelSmall) },
                        )
                        FilterChip(
                            selected = transportNet == "ws",
                            enabled = !isSaving,
                            onClick = {
                                transportNet = "ws"
                                clearErrors()
                            },
                            label = { Text("WebSocket (WS)", style = MaterialTheme.typography.labelSmall) },
                        )
                    }
                    if (transportNet == "ws") {
                        OutlinedTextField(
                            value = wsPath,
                            onValueChange = {
                                wsPath = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("WS Path (如 /ws)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = wsHost,
                            onValueChange = {
                                wsHost = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("WS Host Header (可选)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = maxEarlyDataText,
                            onValueChange = {
                                maxEarlyDataText = it
                                clearErrors()
                            },
                            enabled = !isSaving,
                            label = { Text("0-RTT Early Data 字节数 (0 - 65535)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }

                if (selectedProto in setOf("vless", "vmess", "trojan", "hysteria2", "tuic", "anytls", "socks5", "http")) {
                    OutlinedTextField(
                        value = sni,
                        onValueChange = {
                            sni = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = {
                            Text(
                                if (selectedProto == "vless" && vlessReality) {
                                    "REALITY 伪装域名 ServerName (必填，如 www.microsoft.com)"
                                } else {
                                    "TLS SNI / ServerName (可选)"
                                },
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if ((selectedProto == "vless" && !vlessReality) ||
                    selectedProto in setOf("vmess", "trojan", "hysteria2", "tuic", "anytls")
                ) {
                    OutlinedTextField(
                        value = alpnText,
                        onValueChange = {
                            alpnText = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = { Text("ALPN (可选，逗号分隔如 h2, http/1.1 或 h3)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if ((selectedProto == "vless" && !vlessReality) ||
                    selectedProto in setOf("vmess", "trojan", "socks5", "http")
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = tlsEnabled,
                            enabled = !isSaving,
                            onCheckedChange = {
                                tlsEnabled = it
                                clearErrors()
                            },
                        )
                        Text("启用 TLS 传输加密", style = MaterialTheme.typography.bodySmall)
                    }
                }
                if ((selectedProto == "vless" && !vlessReality) ||
                    selectedProto in setOf("vmess", "trojan", "hysteria2", "tuic", "anytls", "socks5", "http")
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = skipCertVerify,
                            enabled = !isSaving,
                            onCheckedChange = {
                                skipCertVerify = it
                                clearErrors()
                            },
                        )
                        Text("跳过证书校验 (仅测试环境)", style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (selectedProto != "http") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("启用 UDP 转发 (UDP Relay)", style = MaterialTheme.typography.bodySmall)
                        Switch(
                            checked = udpEnabled,
                            enabled = !isSaving,
                            onCheckedChange = {
                                udpEnabled = it
                                clearErrors()
                            },
                        )
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = autoSelect,
                        enabled = !isSaving,
                        onCheckedChange = { autoSelect = it },
                    )
                    Text("保存后立即设为当前节点", style = MaterialTheme.typography.bodySmall)
                }

                val activeError = validationError ?: backendError
                if (!activeError.isNullOrBlank()) {
                    ModalInlineErrorBanner(
                        message = activeError,
                        onDismiss = {
                            validationError = null
                            onClearBackendError()
                        },
                    )
                }
            }
        },
        confirmButton = {
            Button(
                enabled = !isSaving,
                onClick = {
                    val cleanName = name.trim()
                    val cleanHost = server.trim()
                    val port = portText.trim().toIntOrNull() ?: 0
                    val cleanSec = secret.trim()
                    if (cleanName.isEmpty() || cleanHost.isEmpty() || port !in 1..65535) {
                        validationError = "请填写合法的节点名称、服务器地址与端口 (1-65535)"
                        return@Button
                    }
                    if ((!isEditing || protoSwitchedOnEdit) && !isAuthOptional && cleanSec.isEmpty()) {
                        validationError = if (protoSwitchedOnEdit) {
                            "切换节点协议后必须重新填写密码或 UUID"
                        } else {
                            "新建该协议节点必须填写密码或 UUID"
                        }
                        return@Button
                    }
                    if (selectedProto == "vless" && vlessReality) {
                        if (sni.trim().isEmpty()) {
                            validationError = "启用 VLESS REALITY 时必须填写伪装目标域名 (ServerName)"
                            return@Button
                        }
                        val hadRedactedPbk =
                            isEditing && !protoSwitchedOnEdit && existingNode?.realityPublicKey == "***REDACTED***"
                        if (realityPublicKey.trim().isEmpty() && !hadRedactedPbk) {
                            validationError = "启用 VLESS REALITY 时必须填写服务端公钥 (Public Key)"
                            return@Button
                        }
                    }
                    if (selectedProto == "hysteria2" && hy2ObfsEnabled) {
                        val hadRedactedObfsPass =
                            isEditing && !protoSwitchedOnEdit && existingRawObj?.optString("obfs-password", "") == "***REDACTED***"
                        if (hy2ObfsPassword.trim().isEmpty() && !hadRedactedObfsPass) {
                            validationError = "启用 Salamander 混淆时必须填写混淆密码"
                            return@Button
                        }
                    }
                    val parsedEarlyData = if (supportsWs && transportNet == "ws") {
                        val rawEarly = maxEarlyDataText.trim().ifEmpty { "0" }.toIntOrNull()
                        if (rawEarly == null || rawEarly !in 0..65535) {
                            validationError = "0-RTT Early Data 字节数需为 0 - 65535 之间的整数"
                            return@Button
                        }
                        rawEarly
                    } else {
                        0
                    }
                    validationError = null

                    // When editing an existing node of the same protocol, clone its raw JSON object so
                    // advanced fields (`flow`, AnyTLS session-pool intervals, HTTP `headers`, extra
                    // `ws-opts.headers`, custom `early-data-header-name`) are never wiped on save!
                    val baseJson = if (isEditing && !protoSwitchedOnEdit && existingRawObj != null) {
                        JSONObject(existingRawObj.toString())
                    } else {
                        JSONObject()
                    }
                    val json = baseJson.apply {
                        put("type", selectedProto)
                        put("name", cleanName)
                        put("server", cleanHost)
                        put("port", port)
                        if (selectedProto != "http") {
                            put("udp", udpEnabled)
                        } else {
                            remove("udp")
                        }
                        val applyAlpn = {
                            val parsedAlpn = alpnText
                                .split(',')
                                .map { it.trim() }
                                .filter { it.isNotEmpty() }
                            if (parsedAlpn.isNotEmpty()) {
                                put("alpn", JSONArray(parsedAlpn))
                            } else {
                                remove("alpn")
                            }
                        }
                        val applyWsOpts = {
                            if (supportsWs && transportNet == "ws") {
                                put("network", "ws")
                                remove("transport")
                                val prevWs = optJSONObject("ws-opts")
                                val wsObj = if (prevWs != null) JSONObject(prevWs.toString()) else JSONObject()
                                val cleanPath = wsPath.trim().ifEmpty { "/" }
                                wsObj.put("path", if (cleanPath.startsWith("/")) cleanPath else "/$cleanPath")
                                val prevHeaders = wsObj.optJSONObject("headers")
                                val headersObj = if (prevHeaders != null) JSONObject(prevHeaders.toString()) else JSONObject()
                                if (wsHost.trim().isNotEmpty()) {
                                    headersObj.remove("host")
                                    headersObj.put("Host", wsHost.trim())
                                } else {
                                    headersObj.remove("Host")
                                    headersObj.remove("host")
                                }
                                if (headersObj.length() > 0) {
                                    wsObj.put("headers", headersObj)
                                } else {
                                    wsObj.remove("headers")
                                }
                                if (parsedEarlyData > 0) {
                                    wsObj.put("max-early-data", parsedEarlyData)
                                    if (wsObj.optString("early-data-header-name", "").isBlank()) {
                                        wsObj.put("early-data-header-name", "Sec-WebSocket-Protocol")
                                    }
                                } else {
                                    wsObj.remove("max-early-data")
                                    wsObj.remove("early-data-header-name")
                                }
                                put("ws-opts", wsObj)
                            } else {
                                put("network", "tcp")
                                remove("transport")
                                remove("ws-opts")
                            }
                        }
                        when (selectedProto) {
                            "ss" -> {
                                put("cipher", cipherOrEnc.trim().ifEmpty { "aes-256-gcm" })
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                            }
                            "vless" -> {
                                put("uuid", cleanSec.ifEmpty { "00000000-0000-0000-0000-000000000000" })
                                if (vlessFlow.trim().isNotEmpty()) {
                                    put("flow", vlessFlow.trim())
                                } else {
                                    remove("flow")
                                }
                                if (vlessReality) {
                                    put("encryption", "none")
                                    put("tls", true)
                                    put("skip-cert-verify", false)
                                    remove("alpn")
                                    val pbkVal = if (realityPublicKey.trim().isNotEmpty()) {
                                        realityPublicKey.trim()
                                    } else {
                                        "***REDACTED***"
                                    }
                                    val realityObj = JSONObject().apply {
                                        put("public-key", pbkVal)
                                        val sidTrim = realityShortId.trim()
                                        if (sidTrim.isNotEmpty()) {
                                            put("short-id", sidTrim)
                                        } else if (isEditing && !protoSwitchedOnEdit && existingNode?.realityShortId == "***REDACTED***") {
                                            put("short-id", "***REDACTED***")
                                        }
                                    }
                                    put("reality-opts", realityObj)
                                    if (clientFingerprint.trim().isNotEmpty()) {
                                        put("client-fingerprint", clientFingerprint.trim())
                                    } else {
                                        remove("client-fingerprint")
                                    }
                                } else {
                                    remove("reality-opts")
                                    val prevEnc = existingNode?.encryption ?: "none"
                                    val finalEnc = if (cipherOrEnc.trim().isEmpty() && prevEnc == "***REDACTED***") {
                                        "***REDACTED***"
                                    } else {
                                        cipherOrEnc.trim().ifEmpty { "none" }
                                    }
                                    put("encryption", finalEnc)
                                    put("tls", tlsEnabled)
                                    put("skip-cert-verify", skipCertVerify)
                                    applyAlpn()
                                }
                                if (sni.trim().isNotEmpty()) {
                                    put("servername", sni.trim())
                                    remove("sni")
                                } else {
                                    remove("servername")
                                    remove("sni")
                                }
                                applyWsOpts()
                            }
                            "vmess" -> {
                                put("uuid", cleanSec.ifEmpty { "00000000-0000-0000-0000-000000000000" })
                                put("alterId", 0)
                                put("cipher", cipherOrEnc.trim().ifEmpty { "auto" })
                                put("tls", tlsEnabled)
                                if (sni.trim().isNotEmpty()) {
                                    put("servername", sni.trim())
                                    remove("sni")
                                } else {
                                    remove("servername")
                                    remove("sni")
                                }
                                put("skip-cert-verify", skipCertVerify)
                                applyAlpn()
                                applyWsOpts()
                            }
                            "trojan" -> {
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                                put("tls", tlsEnabled)
                                if (sni.trim().isNotEmpty()) {
                                    put("sni", sni.trim())
                                    remove("servername")
                                } else {
                                    remove("sni")
                                    remove("servername")
                                }
                                put("skip-cert-verify", skipCertVerify)
                                applyAlpn()
                                applyWsOpts()
                            }
                            "hysteria2" -> {
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                                if (hy2Ports.trim().isNotEmpty()) {
                                    put("ports", hy2Ports.trim())
                                } else {
                                    remove("ports")
                                }
                                if (hy2ObfsEnabled) {
                                    put("obfs", "salamander")
                                    val obfsPass = hy2ObfsPassword.trim().ifEmpty { "***REDACTED***" }
                                    put("obfs-password", obfsPass)
                                } else {
                                    remove("obfs")
                                    remove("obfs-password")
                                }
                                if (hy2Up.trim().isNotEmpty()) {
                                    put("up", hy2Up.trim())
                                } else {
                                    remove("up")
                                }
                                if (hy2Down.trim().isNotEmpty()) {
                                    put("down", hy2Down.trim())
                                } else {
                                    remove("down")
                                }
                                if (sni.trim().isNotEmpty()) {
                                    put("sni", sni.trim())
                                    remove("servername")
                                } else {
                                    remove("sni")
                                    remove("servername")
                                }
                                put("skip-cert-verify", skipCertVerify)
                                applyAlpn()
                            }
                            "tuic" -> {
                                put("uuid", cleanSec.ifEmpty { "00000000-0000-0000-0000-000000000000" })
                                val cleanTuicPass = tuicPassword.trim()
                                val hadRedactedTuicPass =
                                    isEditing && !protoSwitchedOnEdit && existingRawObj?.optString("password", "") == "***REDACTED***"
                                if (cleanTuicPass.isNotEmpty()) {
                                    put("password", cleanTuicPass)
                                } else if (hadRedactedTuicPass) {
                                    put("password", "***REDACTED***")
                                } else {
                                    put("password", "")
                                }
                                put("udp-relay-mode", tuicUdpRelayMode.trim().ifEmpty { "native" })
                                put("congestion-controller", tuicCongestion.trim().ifEmpty { "bbr" })
                                put("zero-rtt-handshake", tuicZeroRtt)
                                if (sni.trim().isNotEmpty()) {
                                    put("sni", sni.trim())
                                    remove("servername")
                                } else {
                                    remove("sni")
                                    remove("servername")
                                }
                                put("skip-cert-verify", skipCertVerify)
                                applyAlpn()
                            }
                            "anytls" -> {
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                                if (sni.trim().isNotEmpty()) {
                                    put("sni", sni.trim())
                                    remove("servername")
                                } else {
                                    remove("sni")
                                    remove("servername")
                                }
                                put("skip-cert-verify", skipCertVerify)
                                applyAlpn()
                            }
                            "socks5", "http" -> {
                                if (username.trim().isNotEmpty()) {
                                    put("username", username.trim())
                                } else {
                                    remove("username")
                                }
                                val hadSavedPassword = existingRawObj?.optString("password", "")?.isNotEmpty() == true ||
                                    (existingRawObj == null && username.trim().isNotEmpty())
                                if (cleanSec.isNotEmpty()) {
                                    put("password", cleanSec)
                                } else if (isEditing && !protoSwitchedOnEdit && hadSavedPassword) {
                                    put("password", "***REDACTED***")
                                } else {
                                    remove("password")
                                }
                                put("tls", tlsEnabled)
                                if (sni.trim().isNotEmpty()) {
                                    put("sni", sni.trim())
                                    remove("servername")
                                } else {
                                    remove("sni")
                                    remove("servername")
                                }
                                put("skip-cert-verify", skipCertVerify)
                            }
                        }
                    }
                    onSave(existingNode?.name, json, autoSelect)
                },
            ) {
                if (isSaving) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(if (isSaving) "保存中…" else "保存")
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
private fun NodeQrInfoDialog(
    node: ProxyNodeItem,
    onDismiss: () -> Unit,
) {
    // Note: Saved nodes intentionally redact secrets in UI memory (`***REDACTED***`) to prevent
    // accidental credential exfiltration; QR encodes redacted endpoint metadata safely.
    val summary = remember(node) {
        JSONObject()
            .put("name", node.name)
            .put("type", node.type)
            .put("server", node.server)
            .put("port", node.port)
            .toString()
    }
    val qrBitmap = remember(summary) {
        runCatching {
            val (pixels, dim) = NodeImportSupport.encodeQrCodeToArgbPixels(summary, dimension = 420)
            Bitmap.createBitmap(dim, dim, Bitmap.Config.ARGB_8888).apply {
                setPixels(pixels, 0, dim, 0, 0, dim, dim)
            }
        }.getOrNull()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = node.name,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                if (qrBitmap != null) {
                    Image(
                        bitmap = qrBitmap.asImageBitmap(),
                        contentDescription = "节点二维码",
                        modifier = Modifier.size(200.dp),
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                }
                Text(
                    text = "${node.protocolDisplay} · ${NodeImportSupport.formatHostPort(node.server, node.port)}",
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "出于安全保护，已保存节点的密码与密钥不会明文暴露在界面二维码中。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("关闭")
            }
        },
    )
}
