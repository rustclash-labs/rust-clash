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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
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
            .padding(horizontal = 20.dp, vertical = 10.dp),
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
                        text = "支持离线或连接状态下直接导入 ss://、vless://、trojan://、anytls://、socks5:// 分享链接、Base64 订阅、Clash YAML 或 HTTPS 订阅链接。",
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
                2 -> if (activeGroup != null && activeGroup.name != state.primaryGroup) {
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
                        val isSelected = item.name == selectedMemberInGroup ||
                            (targetGroupName == state.primaryGroup && item.name == state.effectiveOutbound)
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
    var menuExpanded by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onSelect),
        shape = RoundedCornerShape(16.dp),
        color = if (isSelected) extColors.selectedCardBg else extColors.cardSurface,
        border = BorderStroke(
            width = if (isSelected) 1.5.dp else 1.dp,
            color = if (isSelected) extColors.selectedCardBorder else extColors.hairline,
        ),
    ) {
        Column(
            modifier = Modifier.padding(start = 8.dp, end = 12.dp, top = 8.dp, bottom = 9.dp),
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

                val endpointText = if (node.port > 0) "${node.server}:${node.port}" else node.server
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
    onDismiss: () -> Unit,
    onReadClipboard: () -> String?,
    onLaunchCameraQr: () -> Unit,
    onLaunchGalleryQr: () -> Unit,
    onOpenManualForm: () -> Unit,
    onSubmitImport: (payload: String, deduplicate: Boolean, autoSelect: Boolean) -> Unit,
) {
    val extColors = LocalRustClashColors.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scrollState = rememberScrollState()
    val focusManager = LocalFocusManager.current
    var payloadText by remember { mutableStateOf("") }
    var deduplicate by remember { mutableStateOf(true) }
    var autoSelect by remember { mutableStateOf(true) }
    var clipboardHint by remember { mutableStateOf<String?>(null) }

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
                text = "支持单条或多行 ss://、vless://、trojan://、anytls://、socks5:// 分享链接、Base64 订阅、Clash YAML 或 HTTPS 订阅链接。",
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
                        text = "在此粘贴节点链接 (ss:// / vless:// / trojan:// / anytls:// / socks5://)、Base64 文本、Clash YAML 或 https:// 订阅地址…",
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
                Text(
                    text = "导入后立即选中该节点",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                Switch(
                    checked = autoSelect,
                    enabled = !isImporting,
                    onCheckedChange = { autoSelect = it },
                )
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
                    onSubmitImport(payloadText, deduplicate, autoSelect)
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
    onDismiss: () -> Unit,
    onSave: (originalName: String?, nodeJson: JSONObject, autoSelect: Boolean) -> Unit,
) {
    val isEditing = existingNode != null
    val dialogScrollState = rememberScrollState()
    val protocols = listOf(
        "ss" to "SS",
        "vless" to "VLESS",
        "trojan" to "Trojan",
        "anytls" to "AnyTLS",
        "socks5" to "SOCKS5",
        "http" to "HTTP",
    )
    val existingProto = existingNode?.type?.lowercase()?.let { if (it == "socks") "socks5" else it }
    var selectedProto by remember(existingNode) {
        mutableStateOf(
            existingProto?.takeIf { p -> protocols.any { it.first == p } } ?: "ss",
        )
    }
    var name by remember(existingNode) { mutableStateOf(existingNode?.name ?: "") }
    var server by remember(existingNode) { mutableStateOf(existingNode?.server ?: "") }
    var portText by remember(existingNode) { mutableStateOf((existingNode?.port ?: 443).toString()) }
    var username by remember(existingNode) { mutableStateOf(existingNode?.username ?: "") }
    var secret by remember(existingNode) { mutableStateOf("") }
    var cipherOrEnc by remember(existingNode) {
        mutableStateOf(
            when (existingProto) {
                "ss" -> existingNode.cipher.ifBlank { "aes-256-gcm" }
                "vless" -> existingNode.encryption.takeIf { it != "***REDACTED***" } ?: "none"
                else -> "aes-256-gcm"
            },
        )
    }
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
    var tlsEnabled by remember(existingNode) {
        mutableStateOf(
            existingNode?.tls ?: (selectedProto in setOf("vless", "trojan", "anytls")),
        )
    }
    var skipCertVerify by remember(existingNode) { mutableStateOf(existingNode?.skipCertVerify ?: false) }
    var autoSelect by remember(existingNode) { mutableStateOf(!isEditing) }
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

    val supportsWs = selectedProto == "vless" || selectedProto == "trojan"
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
                                    selectedProto = protoKey
                                    clearErrors()
                                    when (protoKey) {
                                        "ss" -> {
                                            if (cipherOrEnc.isBlank() || cipherOrEnc == "none") {
                                                cipherOrEnc = "aes-256-gcm"
                                            }
                                        }
                                        "vless" -> {
                                            if (cipherOrEnc == "aes-256-gcm" ||
                                                cipherOrEnc.startsWith("2022-") ||
                                                cipherOrEnc == "chacha20-ietf-poly1305"
                                            ) {
                                                cipherOrEnc = "none"
                                            }
                                            tlsEnabled = true
                                        }
                                        "trojan", "anytls" -> {
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
                                isAuthOptional -> "连接密码 (无鉴权可留空)"
                                else -> "连接密码 / PSK"
                            },
                        )
                    },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (selectedProto == "ss" || selectedProto == "vless") {
                    OutlinedTextField(
                        value = cipherOrEnc,
                        onValueChange = {
                            cipherOrEnc = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = {
                            Text(
                                if (selectedProto == "ss") {
                                    "加密算法 (默认 aes-256-gcm / 支持 2022-blake3-*)"
                                } else {
                                    "VLESS Encryption (默认 none)"
                                },
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
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

                if (selectedProto in setOf("vless", "trojan", "anytls", "socks5", "http")) {
                    OutlinedTextField(
                        value = sni,
                        onValueChange = {
                            sni = it
                            clearErrors()
                        },
                        enabled = !isSaving,
                        label = { Text("TLS SNI (可选)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (selectedProto in setOf("vless", "socks5", "http")) {
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
                if (selectedProto in setOf("vless", "trojan", "anytls", "socks5", "http")) {
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
                            "切换节点协议后必须重新填写密码或 VLESS UUID"
                        } else {
                            "新建该协议节点必须填写密码或 VLESS UUID"
                        }
                        return@Button
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

                    val json = JSONObject().apply {
                        put("type", selectedProto)
                        put("name", cleanName)
                        put("server", cleanHost)
                        put("port", port)
                        put("udp", selectedProto != "http")
                        val applyWsOpts = {
                            if (transportNet == "ws") {
                                put("network", "ws")
                                val wsObj = JSONObject()
                                val cleanPath = wsPath.trim().ifEmpty { "/" }
                                wsObj.put("path", if (cleanPath.startsWith("/")) cleanPath else "/$cleanPath")
                                if (wsHost.trim().isNotEmpty()) {
                                    wsObj.put("headers", JSONObject().put("Host", wsHost.trim()))
                                }
                                if (parsedEarlyData > 0) {
                                    wsObj.put("max-early-data", parsedEarlyData)
                                    wsObj.put("early-data-header-name", "Sec-WebSocket-Protocol")
                                }
                                put("ws-opts", wsObj)
                            } else {
                                put("network", "tcp")
                            }
                        }
                        when (selectedProto) {
                            "ss" -> {
                                put("cipher", cipherOrEnc.trim().ifEmpty { "aes-256-gcm" })
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                            }
                            "vless" -> {
                                put("uuid", cleanSec.ifEmpty { "00000000-0000-0000-0000-000000000000" })
                                val prevEnc = existingNode?.encryption ?: "none"
                                val finalEnc = if (cipherOrEnc.trim().isEmpty() && prevEnc == "***REDACTED***") {
                                    "***REDACTED***"
                                } else {
                                    cipherOrEnc.trim().ifEmpty { "none" }
                                }
                                put("encryption", finalEnc)
                                put("tls", tlsEnabled)
                                if (sni.trim().isNotEmpty()) put("servername", sni.trim())
                                put("skip-cert-verify", skipCertVerify)
                                applyWsOpts()
                            }
                            "trojan" -> {
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                                put("tls", true)
                                if (sni.trim().isNotEmpty()) put("sni", sni.trim())
                                put("skip-cert-verify", skipCertVerify)
                                applyWsOpts()
                            }
                            "anytls" -> {
                                put("password", cleanSec.ifEmpty { "***REDACTED***" })
                                if (sni.trim().isNotEmpty()) put("sni", sni.trim())
                                put("skip-cert-verify", skipCertVerify)
                            }
                            "socks5", "http" -> {
                                if (username.trim().isNotEmpty()) {
                                    put("username", username.trim())
                                }
                                if (cleanSec.isNotEmpty()) {
                                    put("password", cleanSec)
                                } else if (isEditing && !protoSwitchedOnEdit && username.trim().isNotEmpty()) {
                                    put("password", "***REDACTED***")
                                }
                                put("tls", tlsEnabled)
                                if (sni.trim().isNotEmpty()) put("sni", sni.trim())
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
                    text = "${node.protocolDisplay} · ${node.server}:${node.port}",
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
