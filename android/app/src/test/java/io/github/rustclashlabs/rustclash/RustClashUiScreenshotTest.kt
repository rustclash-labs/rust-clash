package io.github.rustclashlabs.rustclash

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.view.inspector.WindowInspector
import androidx.activity.ComponentActivity
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Route
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.BatteryFull
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.SignalCellular4Bar
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.GeoDataUiStatus
import io.github.rustclashlabs.rustclash.ui.model.InstalledAppUi
import io.github.rustclashlabs.rustclash.ui.model.LiveTelemetryUi
import io.github.rustclashlabs.rustclash.ui.model.MainDestination
import io.github.rustclashlabs.rustclash.ui.model.ProfileUiItem
import io.github.rustclashlabs.rustclash.ui.model.ProxyGroupItem
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.RuleItem
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.screens.ActiveYamlEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.CustomRulesEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.HomeScreen
import io.github.rustclashlabs.rustclash.ui.screens.ImportPayloadBottomSheet
import io.github.rustclashlabs.rustclash.ui.screens.NodeEditorDialog
import io.github.rustclashlabs.rustclash.ui.screens.NodesScreen
import io.github.rustclashlabs.rustclash.ui.screens.PerAppPickerBottomSheet
import io.github.rustclashlabs.rustclash.ui.screens.ProfilesScreen
import io.github.rustclashlabs.rustclash.ui.screens.RulesScreen
import io.github.rustclashlabs.rustclash.ui.screens.SettingsScreen
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashBrandIcon
import io.github.rustclashlabs.rustclash.ui.theme.RustClashTheme
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File
import java.io.FileOutputStream

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w390dp-h844dp-xxhdpi")
class RustClashUiScreenshotTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    private fun buildCjkFontFamily(): FontFamily {
        val regFile = File("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")
        val boldFile = File("/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc")
        if (regFile.isFile && boldFile.isFile) {
            return runCatching {
                FontFamily(
                    Font(regFile, FontWeight.Normal),
                    Font(regFile, FontWeight.Medium),
                    Font(boldFile, FontWeight.SemiBold),
                    Font(boldFile, FontWeight.Bold),
                )
            }.getOrDefault(FontFamily.Default)
        }
        return FontFamily.Default
    }

    private fun sampleShowcaseState(themePreference: ThemePreference): AppUiState {
        val nodes = listOf(
            ProxyNodeItem(
                name = "香港-IPLC-01",
                type = "vless",
                server = "hk01.example.com",
                port = 443,
                sni = "hk01.example.com",
                tls = true,
                delayMs = 28L,
            ),
            ProxyNodeItem(
                name = "新加坡-BGP-02",
                type = "anytls",
                server = "sg02.example.com",
                port = 443,
                sni = "sg02.example.com",
                tls = true,
                delayMs = 45L,
            ),
            ProxyNodeItem(
                name = "日本-东京-03",
                type = "ss",
                server = "jp03.example.com",
                port = 8388,
                cipher = "2022-blake3-aes-256-gcm",
                delayMs = 68L,
            ),
            ProxyNodeItem(
                name = "美国-洛杉矶-04",
                type = "vless",
                server = "us04.example.com",
                port = 443,
                sni = "us04.example.com",
                tls = true,
                delayMs = 156L,
            ),
            ProxyNodeItem(
                name = "德国-法兰克福-05",
                type = "anytls",
                server = "de05.example.com",
                port = 8443,
                sni = "de05.example.com",
                tls = true,
                delayMs = 240L,
            ),
        )

        val profiles = listOf(
            ProfileUiItem(
                id = "default",
                name = "Starter Profile",
                kind = "local-yaml",
                subscriptionUrlRedacted = null,
                lastUpdatedMs = 1778382600000L,
                lastError = null,
                proxyCount = 5,
                ruleCount = 8,
                rulePreset = "smart-cn",
                hasCustomBackup = false,
                uploadBytes = null,
                downloadBytes = null,
                totalBytes = null,
                expireUnixSecs = null,
            ),
            ProfileUiItem(
                id = "sub-1",
                name = "主力订阅 - 亚太高速",
                kind = "subscription",
                subscriptionUrlRedacted = "https://sub.example.com/api/v1?***REDACTED***",
                lastUpdatedMs = 1778376900000L,
                lastError = null,
                proxyCount = 24,
                ruleCount = 320,
                rulePreset = "smart-cn",
                hasCustomBackup = true,
                uploadBytes = 12_884_901_888L,
                downloadBytes = 51_539_607_552L,
                totalBytes = 214_748_364_800L,
                expireUnixSecs = null,
            ),
        )

        return AppUiState(
            nativeLoaded = true,
            vpnState = VpnLifecycleState.RUNNING,
            telemetry = LiveTelemetryUi(
                running = true,
                demoActive = false,
                mode = "rule",
                effectiveOutbound = "香港-IPLC-01",
                effectiveProtocol = "VLESS",
                effectiveDelayMs = 28L,
                upRate = 1_258_291L,
                downRate = 12_918_456L,
                upTotal = 319_605_964L,
                downTotal = 1_975_684_956L,
                rssBytes = 29_360_128L,
                activeConnections = 18,
                fakeIpEntries = 64,
                protectedSockets = 42L,
                networkTransitions = 2L,
                isWifi = true,
            ),
            activeProfileId = "default",
            profiles = profiles,
            primaryGroup = "PROXY",
            selectedGroupTab = "PROXY",
            effectiveOutbound = "香港-IPLC-01",
            effectiveProtocol = "VLESS",
            routingPreset = RoutingPresetUi.SMART_CN,
            hasCustomRulesBackup = true,
            nodes = nodes,
            groups = listOf(
                ProxyGroupItem(
                    name = "PROXY",
                    type = "Select",
                    now = "香港-IPLC-01",
                    members = nodes.map { it.name },
                    effectiveOutbound = "香港-IPLC-01",
                    effectiveProtocol = "VLESS",
                ),
            ),
            delays = nodes.associate { it.name to (it.delayMs ?: 0L) },
            rules = List(8) { idx ->
                RuleItem(type = "GeoSite", payload = "cn-$idx", proxy = "DIRECT", hits = 12L)
            },
            geodata = GeoDataUiStatus(
                usingPersistedData = true,
                builtinFallbackActive = true,
                isExpired = false,
                lastUpdatedMs = 1778382600000L,
                sourceLabel = "MetaCubeX GeoData",
                geositeCnEntries = 48620,
                geositeNonCnEntries = 74310,
                geoipCnRanges = 9120,
                mmdbPresent = true,
            ),
            themePreference = themePreference,
            enableIpv6 = true,
            favoriteNodes = setOf("香港-IPLC-01", "新加坡-BGP-02"),
            rateHistory = listOf(
                3_200_000L,
                6_800_000L,
                5_400_000L,
                9_100_000L,
                7_800_000L,
                11_200_000L,
                8_900_000L,
                14_150_000L,
                10_800_000L,
                13_600_000L,
            ),
        )
    }

    @Composable
    private fun SimulatedPhoneFrame(
        state: AppUiState,
        destination: MainDestination,
    ) {
        val extColors = LocalRustClashColors.current
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = MaterialTheme.colorScheme.background,
            topBar = {
                // Realistic Android status bar with VPN notification icon
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 18.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "09:41",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onBackground,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Icon(
                        painter = painterResource(id = R.drawable.ic_stat_rustclash_vpn),
                        contentDescription = null,
                        tint = extColors.emerald,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    Icon(
                        imageVector = Icons.Rounded.SignalCellular4Bar,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onBackground,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = Icons.Rounded.Wifi,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onBackground,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = Icons.Rounded.BatteryFull,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onBackground,
                        modifier = Modifier.size(14.dp),
                    )
                }
            },
            bottomBar = {
                Column {
                    HorizontalDivider(thickness = 1.dp, color = extColors.hairline)
                    NavigationBar(
                        containerColor = extColors.cardSurface,
                        tonalElevation = 0.dp,
                    ) {
                        MainDestination.entries.forEach { dest ->
                            val selected = destination == dest
                            NavigationBarItem(
                                selected = selected,
                                onClick = {},
                                icon = {
                                    val icon = when (dest) {
                                        MainDestination.HOME -> if (selected) Icons.Rounded.Home else Icons.Outlined.Home
                                        MainDestination.NODES -> if (selected) Icons.Rounded.Dns else Icons.Outlined.Dns
                                        MainDestination.RULES -> if (selected) Icons.Rounded.Route else Icons.Outlined.Route
                                        MainDestination.PROFILES -> if (selected) Icons.Rounded.Description else Icons.Outlined.Description
                                        MainDestination.SETTINGS -> if (selected) Icons.Rounded.Settings else Icons.Outlined.Settings
                                    }
                                    Icon(imageVector = icon, contentDescription = dest.label)
                                },
                                label = {
                                    Text(
                                        text = dest.label,
                                        style = MaterialTheme.typography.labelSmall,
                                        maxLines = 1,
                                        softWrap = false,
                                    )
                                },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = extColors.emerald,
                                    selectedTextColor = extColors.emerald,
                                    indicatorColor = extColors.emeraldContainer.copy(alpha = 0.65f),
                                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                ),
                            )
                        }
                    }
                }
            },
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                when (destination) {
                    MainDestination.HOME -> HomeScreen(
                        state = state,
                        onToggleVpn = {},
                        onOpenQuickImport = {},
                        onSelectRoutingPreset = {},
                        onNavigateToNodes = {},
                        onNavigateToRules = {},
                        onTestActiveLatency = {},
                    )
                    MainDestination.NODES -> NodesScreen(
                        state = state,
                        onSearchQueryChange = {},
                        onToggleSortByDelay = {},
                        onSelectGroupTab = {},
                        onSelectProxyInGroup = { _, _ -> },
                        onToggleFavorite = {},
                        onTestAllDelays = {},
                        onTestSingleDelay = {},
                        onOpenImportSheet = {},
                        onImportClipboardDirect = {},
                        onOpenQrCamera = {},
                        onOpenManualCreate = {},
                        onOpenNodeEdit = {},
                        onDeleteNode = {},
                        onDeduplicateNodes = {},
                    )
                    MainDestination.RULES -> RulesScreen(
                        state = state,
                        requestedSubTab = 0,
                        onSelectRoutingPreset = {},
                        onUpdateGeoData = {},
                        onOpenCustomRuleEditor = {},
                        onSetDiagnosticsFilter = {},
                        onClearDiagnostics = {},
                        onExplainTarget = {},
                        onRuleSearchChange = {},
                    )
                    MainDestination.PROFILES -> ProfilesScreen(
                        state = state,
                        onOpenImportSheet = {},
                        onActivateProfile = {},
                        onRefreshProfile = {},
                        onDeleteProfile = {},
                        onRenameProfile = { _, _ -> },
                        onOpenCustomRulesEditor = {},
                        onOpenYamlEditor = {},
                    )
                    MainDestination.SETTINGS -> SettingsScreen(
                        state = state,
                        onSetThemePreference = {},
                        onRequestInstalledApps = {},
                        onSavePerAppPolicy = { _, _ -> },
                        onSetEnableIpv6 = {},
                        onSetDemoMode = {},
                        onFlushDns = {},
                    )
                }
            }
        }
    }

    private fun captureDecorBitmap(): Bitmap {
        composeRule.waitForIdle()
        val decorView = composeRule.activity.window.decorView
        val w = decorView.width.coerceAtLeast(1)
        val h = decorView.height.coerceAtLeast(1)
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        composeRule.activity.runOnUiThread {
            val canvas = Canvas(bitmap)
            decorView.draw(canvas)
            val windowViews = runCatching {
                WindowInspector.getGlobalWindowViews().filter {
                    it !== decorView && it.visibility == View.VISIBLE && it.width > 0 && it.height > 0
                }
            }.getOrDefault(emptyList())
            if (windowViews.isNotEmpty()) {
                val baseLoc = IntArray(2)
                decorView.getLocationOnScreen(baseLoc)
                canvas.drawColor(0x66000000)
                for (winView in windowViews) {
                    val winLoc = IntArray(2)
                    winView.getLocationOnScreen(winLoc)
                    val dx = (winLoc[0] - baseLoc[0]).toFloat()
                    val dy = (winLoc[1] - baseLoc[1]).toFloat()
                    val count = canvas.save()
                    canvas.translate(dx, dy)
                    winView.draw(canvas)
                    canvas.restoreToCount(count)
                }
            }
        }
        composeRule.waitForIdle()
        return bitmap
    }

    private fun saveBitmap(bitmap: Bitmap, outFile: File) {
        outFile.parentFile?.mkdirs()
        FileOutputStream(outFile).use { fos ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos)
        }
    }

    private fun combineBitmapsHorizontally(bitmaps: List<Bitmap>, bgColor: Int): Bitmap {
        val pad = 28
        val totalWidth = bitmaps.sumOf { it.width } + pad * (bitmaps.size + 1)
        val maxHeight = (bitmaps.maxOfOrNull { it.height } ?: 800) + pad * 2
        val combined = Bitmap.createBitmap(totalWidth, maxHeight, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(combined)
        canvas.drawColor(bgColor)
        var curX = pad.toFloat()
        for (bmp in bitmaps) {
            canvas.drawBitmap(bmp, curX, pad.toFloat(), null)
            curX += bmp.width + pad
        }
        return combined
    }

    @Test
    fun renderAllFiveScreensLightDarkAndBrandIconsShowcase() {
        val outDir = File("build/outputs/screenshots")
        outDir.mkdirs()
        val fontFamily = buildCjkFontFamily()

        val currentThemeState = androidx.compose.runtime.mutableStateOf(ThemePreference.LIGHT)
        val currentDestState = androidx.compose.runtime.mutableStateOf(MainDestination.HOME)
        val customModeState = androidx.compose.runtime.mutableIntStateOf(0)

        composeRule.setContent {
            val theme = currentThemeState.value
            val dest = currentDestState.value
            val mode = customModeState.intValue
            RustClashTheme(
                themePreference = theme,
                fontFamily = fontFamily,
            ) {
                when (mode) {
                    0 -> SimulatedPhoneFrame(
                        state = sampleShowcaseState(theme),
                        destination = dest,
                    )
                    1 -> BrandIconsAndNotificationShowcase()
                    else -> CompactAndFontScaleShowcase(
                        state = sampleShowcaseState(ThemePreference.LIGHT),
                    )
                }
            }
        }

        val lightBitmaps = mutableListOf<Bitmap>()
        val destSlug = mapOf(
            MainDestination.HOME to "1_home",
            MainDestination.NODES to "2_nodes",
            MainDestination.RULES to "3_rules",
            MainDestination.PROFILES to "4_profiles",
            MainDestination.SETTINGS to "5_settings",
        )

        // 1. Render all 5 screens in Light Mode
        currentThemeState.value = ThemePreference.LIGHT
        customModeState.intValue = 0
        for (dest in MainDestination.entries) {
            composeRule.runOnIdle {
                currentDestState.value = dest
            }
            val bmp = captureDecorBitmap()
            lightBitmaps.add(bmp)
            val file = File(outDir, "light_${destSlug[dest]}.png")
            saveBitmap(bmp, file)
            assertTrue(file.isFile && file.length() > 1024)
        }
        saveBitmap(
            combineBitmapsHorizontally(lightBitmaps, 0xFFEFF3F6.toInt()),
            File(outDir, "overview_5screens_light.png"),
        )

        // 2. Render all 5 screens in Dark Mode
        val darkBitmaps = mutableListOf<Bitmap>()
        composeRule.runOnIdle {
            currentThemeState.value = ThemePreference.DARK
        }
        for (dest in MainDestination.entries) {
            composeRule.runOnIdle {
                currentDestState.value = dest
            }
            val bmp = captureDecorBitmap()
            darkBitmaps.add(bmp)
            val file = File(outDir, "dark_${destSlug[dest]}.png")
            saveBitmap(bmp, file)
            assertTrue(file.isFile && file.length() > 1024)
        }
        saveBitmap(
            combineBitmapsHorizontally(darkBitmaps, 0xFF060B0D.toInt()),
            File(outDir, "overview_5screens_dark.png"),
        )

        // 3. Render Brand Icons & Foreground VPN Notification Showcase
        composeRule.runOnIdle {
            currentThemeState.value = ThemePreference.LIGHT
            customModeState.intValue = 1
        }
        val iconBmp = captureDecorBitmap()
        val iconFile = File(outDir, "brand_icon_and_notification_showcase.png")
        saveBitmap(iconBmp, iconFile)
        assertTrue(iconFile.isFile && iconFile.length() > 1024)

        // 4. Render Compact Screen + 1.30x Font Scale Verification
        composeRule.runOnIdle {
            currentThemeState.value = ThemePreference.LIGHT
            customModeState.intValue = 2
        }
        val compactBmp = captureDecorBitmap()
        val compactFile = File(outDir, "compact_fontscale_check.png")
        saveBitmap(compactBmp, compactFile)
        assertTrue(compactFile.isFile && compactFile.length() > 1024)
    }

    @Composable
    private fun BrandIconsAndNotificationShowcase() {
        val extColors = LocalRustClashColors.current
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "RustClash 品牌图标与通知规范",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "祖母绿 (Emerald Green) · 几何字母 R + 分流流向箭头",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // 1. Adaptive / Monochrome / Round Icon Grid
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Text(
                        text = "Android Adaptive Icon 规范体系",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceAround,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 76.dp, isRound = false, isMonochrome = false)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Adaptive Icon", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                            Text("Squircle 圆角矩形", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 76.dp, isRound = false, isMonochrome = true)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Monochrome", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                            Text("Android 13+ 主题图标", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 76.dp, isRound = true, isMonochrome = false)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Round Icon", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                            Text("Pixel 圆形启动器", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }

            // 2. Android Launcher Homescreen Preview (Light & Dark Wallpaper)
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                color = Color(0xFF0F172A),
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Text(
                        text = "Android 桌面小尺寸多规格显示效果",
                        style = MaterialTheme.typography.titleSmall,
                        color = Color.White,
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceAround,
                        verticalAlignment = Alignment.Bottom,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 60.dp)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("RustClash", style = MaterialTheme.typography.labelSmall, color = Color.White)
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 48.dp, isRound = true)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("48dp 桌面", style = MaterialTheme.typography.labelSmall, color = Color(0xFF94A3B8))
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RustClashBrandIcon(size = 36.dp)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("36dp 列表", style = MaterialTheme.typography.labelSmall, color = Color(0xFF94A3B8))
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFF1E293B)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    painter = painterResource(id = R.drawable.ic_stat_rustclash_vpn),
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(20.dp),
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text("24dp 状态栏", style = MaterialTheme.typography.labelSmall, color = Color(0xFF94A3B8))
                        }
                    }
                }
            }

            // 3. Foreground VPN Notification Preview
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                color = extColors.cardSurface,
                border = BorderStroke(1.dp, extColors.hairline),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Android VPN 前台常驻通知栏效果",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = extColors.cardSubtle,
                        border = BorderStroke(1.dp, extColors.hairline),
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(22.dp)
                                        .clip(CircleShape)
                                        .background(extColors.emerald),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Icon(
                                        painter = painterResource(id = R.drawable.ic_stat_rustclash_vpn),
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(14.dp),
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "RustClash · 刚刚",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = extColors.emerald,
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "RustClash · 香港-IPLC-01",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "↓ 12.3 MB/s  ↑ 1.2 MB/s · 累计 2.14 GB",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun CompactAndFontScaleShowcase(state: AppUiState) {
        val currentDensity = LocalDensity.current
        // Simulate 1.30x large system font scale on a compact width
        CompositionLocalProvider(
            LocalDensity provides Density(
                density = currentDensity.density,
                fontScale = 1.3f,
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background),
            ) {
                Box(modifier = Modifier.weight(1f)) {
                    SettingsScreen(
                        state = state,
                        onSetThemePreference = {},
                        onRequestInstalledApps = {},
                        onSavePerAppPolicy = { _, _ -> },
                        onSetEnableIpv6 = {},
                        onSetDemoMode = {},
                        onFlushDns = {},
                    )
                }
            }
        }
    }

    @Test
    fun importBottomSheetDisplaysInlineErrorAndEmptyClipboardHintWithoutDismissing() {
        val outDir = File("build/outputs/screenshots")
        outDir.mkdirs()
        val fontFamily = buildCjkFontFamily()
        val errorState = androidx.compose.runtime.mutableStateOf<String?>(
            "导入失败：订阅返回了网页验证页面 (Cloudflare)，请在浏览器完成验证后重试",
        )
        var dismissed = false

        composeRule.setContent {
            RustClashTheme(themePreference = ThemePreference.DARK, fontFamily = fontFamily) {
                Box(modifier = Modifier.fillMaxSize()) {
                    SimulatedPhoneFrame(
                        state = sampleShowcaseState(ThemePreference.DARK).copy(nodes = emptyList()),
                        destination = MainDestination.NODES,
                    )
                    ImportPayloadBottomSheet(
                        isImporting = false,
                        errorMessage = errorState.value,
                        onClearError = { errorState.value = null },
                        onDismiss = { dismissed = true },
                        onReadClipboard = { null },
                        onLaunchCameraQr = {},
                        onLaunchGalleryQr = {},
                        onOpenManualForm = {},
                        onSubmitImport = { _, _, _ -> },
                    )
                }
            }
        }

        composeRule.onNodeWithText("导入失败：订阅返回了网页验证页面", substring = true).assertIsDisplayed()
        composeRule.onNodeWithText("验证并保存").assertIsDisplayed()
        assertFalse(dismissed)

        val errFile = File(outDir, "modal_import_inline_error_dark.png")
        saveBitmap(captureDecorBitmap(), errFile)
        assertTrue(errFile.isFile && errFile.length() > 1024)

        // Dismiss inline error banner via close button, then tap empty clipboard button and assert inline hint
        composeRule.onNodeWithContentDescription("关闭错误提示").performClick()
        composeRule.waitForIdle()
        assertTrue(errorState.value == null)

        composeRule.onNodeWithText("读取剪贴板").performClick()
        composeRule.onNodeWithText("当前剪贴板为空", substring = true).assertIsDisplayed()
    }

    @Test
    fun nodeEditorDialogValidatesProtocolSwitchAndDisplaysInlineError() {
        val outDir = File("build/outputs/screenshots")
        outDir.mkdirs()
        val fontFamily = buildCjkFontFamily()
        val existing = ProxyNodeItem(
            name = "香港-IPLC-01",
            type = "ss",
            server = "hk01.example.com",
            port = 8388,
            cipher = "aes-256-gcm",
        )
        var saved = false

        composeRule.setContent {
            RustClashTheme(themePreference = ThemePreference.LIGHT, fontFamily = fontFamily) {
                Box(modifier = Modifier.fillMaxSize()) {
                    SimulatedPhoneFrame(
                        state = sampleShowcaseState(ThemePreference.LIGHT),
                        destination = MainDestination.NODES,
                    )
                    NodeEditorDialog(
                        existingNode = existing,
                        backendError = null,
                        onClearBackendError = {},
                        onDismiss = {},
                        onSave = { _, _, _ -> saved = true },
                    )
                }
            }
        }

        // Switch existing SS node to VLESS and attempt to save without entering a new UUID
        composeRule.onNode(hasText("VLESS") and hasAnyAncestor(isDialog())).performClick()
        composeRule.onNode(hasText("保存") and hasAnyAncestor(isDialog())).performClick()
        composeRule.onNodeWithText("切换节点协议后必须重新填写密码或 VLESS UUID").assertIsDisplayed()
        assertFalse(saved)

        val dialogFile = File(outDir, "modal_node_editor_error_light.png")
        saveBitmap(captureDecorBitmap(), dialogFile)
        assertTrue(dialogFile.isFile && dialogFile.length() > 1024)
    }

    @Test
    @Config(sdk = [34], qualifiers = "w320dp-h640dp-xhdpi")
    fun compact320dpDialogsAndPerAppZeroAllowlistKeepErrorsInViewport() {
        val outDir = File("build/outputs/screenshots")
        outDir.mkdirs()
        val fontFamily = buildCjkFontFamily()
        val dialogStep = androidx.compose.runtime.mutableIntStateOf(0)

        composeRule.setContent {
            val step = dialogStep.intValue
            RustClashTheme(themePreference = ThemePreference.DARK, fontFamily = fontFamily) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MaterialTheme.colorScheme.background),
                ) {
                    when (step) {
                        0 -> CustomRulesEditorDialog(
                            initialRulesText = "# 仅包含注释而无实际规则\n# 另一行注释",
                            errorMessage = null,
                            onClearError = {},
                            onDismiss = {},
                            onSaveRules = {},
                        )
                        1 -> ActiveYamlEditorDialog(
                            initialYamlText = "mixed-port: 7890\ntun:\n  mtu: invalid_value\n",
                            errorMessage = "配置校验未通过：YAML parse error at 'tun.mtu': invalid integer",
                            onClearError = {},
                            onDismiss = {},
                            onSaveYaml = {},
                        )
                        else -> PerAppPickerBottomSheet(
                            initialMode = PerAppMode.ALLOWLIST,
                            initialSelected = emptySet(),
                            installedApps = listOf(
                                InstalledAppUi("org.mozilla.firefox", "Firefox", isSystemApp = false),
                                InstalledAppUi("com.github.android", "GitHub", isSystemApp = false),
                            ),
                            showSystemApps = false,
                            onSetShowSystemApps = {},
                            onDismiss = {},
                            onSave = { _, _ -> },
                        )
                    }
                }
            }
        }

        // Step 0: CustomRulesEditorDialog blocks comment-only rules and displays inline banner on 320x640dp
        composeRule.onNodeWithText("校验并保存").performClick()
        composeRule.onNodeWithText("请至少保留一条有效的非注释分流规则", substring = true).assertIsDisplayed()
        val customRulesFile = File(outDir, "compact320_custom_rules_error.png")
        saveBitmap(captureDecorBitmap(), customRulesFile)
        assertTrue(customRulesFile.isFile && customRulesFile.length() > 1024)

        // Step 1: ActiveYamlEditorDialog keeps inline error + primary button visible on 320x640dp
        composeRule.runOnIdle { dialogStep.intValue = 1 }
        composeRule.onNodeWithText("配置校验未通过", substring = true).assertIsDisplayed()
        composeRule.onNodeWithText("验证并应用").assertIsDisplayed()
        val yamlFile = File(outDir, "compact320_yaml_editor_error.png")
        saveBitmap(captureDecorBitmap(), yamlFile)
        assertTrue(yamlFile.isFile && yamlFile.length() > 1024)

        // Step 2: PerAppPickerBottomSheet blocks 0-package ALLOWLIST save with inline banner on 320x640dp
        composeRule.runOnIdle { dialogStep.intValue = 2 }
        composeRule.onNodeWithText("保存").performClick()
        composeRule.onNodeWithText("「仅选中应用」模式下请至少勾选 1 个需要代理的应用", substring = true).assertIsDisplayed()
        val perAppFile = File(outDir, "compact320_per_app_allowlist_error.png")
        saveBitmap(captureDecorBitmap(), perAppFile)
        assertTrue(perAppFile.isFile && perAppFile.length() > 1024)
    }

    @Test
    @Config(sdk = [34], qualifiers = "w360dp-h640dp-xxhdpi")
    fun smallScreen360dpLargeFont130PercentEmptyStatesAndExtremeEmojiNodeNames() {
        val outDir = File("build/outputs/screenshots")
        outDir.mkdirs()
        val fontFamily = buildCjkFontFamily()
        val extremeEmojiName = "🇭🇰🚀🔥✨ 香港-IPLC-专线-超长节点名称压力测试-" + "极速低延迟BGP中转".repeat(12)
        assertTrue(extremeEmojiName.length >= 130)

        val extremeNode = ProxyNodeItem(
            name = extremeEmojiName,
            type = "vless",
            server = "ultra-long-subdomain-edge-gateway-01.hk.example.com",
            port = 443,
            network = "ws",
            tls = true,
            delayMs = 31L,
        )
        val stageState = androidx.compose.runtime.mutableIntStateOf(0)
        var homeErrorDismissed = false

        composeRule.setContent {
            val stage = stageState.intValue
            val baseDensity = LocalDensity.current
            RustClashTheme(themePreference = ThemePreference.DARK, fontFamily = fontFamily) {
                CompositionLocalProvider(
                    LocalDensity provides Density(density = baseDensity.density, fontScale = 1.3f),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(MaterialTheme.colorScheme.background),
                    ) {
                        when (stage) {
                            0 -> HomeScreen(
                                state = sampleShowcaseState(ThemePreference.DARK).copy(
                                    vpnState = VpnLifecycleState.ERROR,
                                    lastError = "VPN 连接授权已被取消，请点击上方按钮重新授权连接",
                                    effectiveOutbound = extremeEmojiName,
                                    nodes = listOf(extremeNode),
                                ),
                                onToggleVpn = {},
                                onOpenQuickImport = {},
                                onSelectRoutingPreset = {},
                                onNavigateToNodes = {},
                                onNavigateToRules = {},
                                onTestActiveLatency = {},
                                onDismissError = { homeErrorDismissed = true },
                            )
                            1 -> NodesScreen(
                                state = sampleShowcaseState(ThemePreference.DARK).copy(
                                    effectiveOutbound = extremeEmojiName,
                                    nodes = listOf(
                                        extremeNode,
                                        ProxyNodeItem(
                                            name = "🇸🇬⚡ 新加坡-AnyTLS-专线-02",
                                            type = "anytls",
                                            server = "sg02.example.com",
                                            port = 443,
                                            delayMs = 49L,
                                        ),
                                    ),
                                    delays = mapOf(extremeEmojiName to 31L, "🇸🇬⚡ 新加坡-AnyTLS-专线-02" to 49L),
                                ),
                                onSearchQueryChange = {},
                                onToggleSortByDelay = {},
                                onSelectGroupTab = {},
                                onSelectProxyInGroup = { _, _ -> },
                                onTestAllDelays = {},
                                onTestSingleDelay = {},
                                onOpenImportSheet = {},
                                onImportClipboardDirect = {},
                                onOpenQrCamera = {},
                                onOpenManualCreate = {},
                                onOpenNodeEdit = {},
                                onDeleteNode = {},
                                onDeduplicateNodes = {},
                            )
                            2 -> NodesScreen(
                                state = sampleShowcaseState(ThemePreference.DARK).copy(
                                    nodes = emptyList(),
                                    demoMode = false,
                                ),
                                onSearchQueryChange = {},
                                onToggleSortByDelay = {},
                                onSelectGroupTab = {},
                                onSelectProxyInGroup = { _, _ -> },
                                onTestAllDelays = {},
                                onTestSingleDelay = {},
                                onOpenImportSheet = {},
                                onImportClipboardDirect = {},
                                onOpenQrCamera = {},
                                onOpenManualCreate = {},
                                onOpenNodeEdit = {},
                                onDeleteNode = {},
                                onDeduplicateNodes = {},
                            )
                            else -> ProfilesScreen(
                                state = sampleShowcaseState(ThemePreference.DARK).copy(
                                    profiles = emptyList(),
                                ),
                                onOpenImportSheet = {},
                                onActivateProfile = {},
                                onRefreshProfile = {},
                                onDeleteProfile = {},
                                onOpenCustomRulesEditor = {},
                                onOpenYamlEditor = {},
                            )
                        }
                    }
                }
            }
        }

        // Stage 0: Home error banner + dismiss button + active LatencyPill at 360dp & 1.3f fontScale
        composeRule.onNodeWithText("VPN 连接授权已被取消", substring = true).assertIsDisplayed()
        composeRule.onNodeWithText("连接异常").assertIsDisplayed()
        val homeErrFile = File(outDir, "narrow360_font130_home_error.png")
        saveBitmap(captureDecorBitmap(), homeErrFile)
        assertTrue(homeErrFile.isFile && homeErrFile.length() > 1024)
        composeRule.onNodeWithContentDescription("关闭错误提示").performClick()
        assertTrue(homeErrorDismissed)
        composeRule.onNodeWithText("31 ms").performScrollTo().assertIsDisplayed()

        // Stage 1: NodesScreen with 130+-char Emoji node name at 360dp & 1.3f fontScale
        composeRule.runOnIdle { stageState.intValue = 1 }
        composeRule.onNodeWithText("VLESS·WS").assertIsDisplayed()
        composeRule.onNodeWithText("31 ms").assertIsDisplayed()
        val emojiNodesFile = File(outDir, "narrow360_font130_emoji_nodes.png")
        saveBitmap(captureDecorBitmap(), emojiNodesFile)
        assertTrue(emojiNodesFile.isFile && emojiNodesFile.length() > 1024)

        // Stage 2: NodesScreen 0-node empty state stacked buttons at 360dp & 1.3f fontScale
        composeRule.runOnIdle { stageState.intValue = 2 }
        composeRule.onNodeWithText("尚未导入任何代理节点").assertIsDisplayed()
        composeRule.onNodeWithText("粘贴导入").assertIsDisplayed()
        composeRule.onNodeWithText("链接 / 订阅").assertIsDisplayed()

        // Stage 3: ProfilesScreen 0-profile empty state at 360dp & 1.3f fontScale
        composeRule.runOnIdle { stageState.intValue = 3 }
        composeRule.onNodeWithText("暂无已保存的配置档案").assertIsDisplayed()
        composeRule.onNodeWithText("导入配置或订阅").assertIsDisplayed()
    }

    @Test
    fun settingsScreenOpensDebugDiagnosticsBottomSheetAndTriggersShareAndToggle() {
        val fontFamily = buildCjkFontFamily()
        var toggledEnabled: Boolean? = null
        var selectedInterval: Long? = null
        var shareClicked = false
        var manualSliceClicked = false

        val uiState = sampleShowcaseState(ThemePreference.DARK).copy(
            debugLog = io.github.rustclashlabs.rustclash.vpn.DebugLogSummaryUi(
                enabled = true,
                sliceIntervalSecs = 1800L,
                sliceCount = 2,
                totalBytes = 24_576L,
                latestSliceTimeMs = 1_763_000_000_000L,
                hasCrashBreadcrumb = false,
                recentSlices = listOf(
                    io.github.rustclashlabs.rustclash.vpn.DebugSliceItemUi(
                        fileName = "rustclash-slice-20261113-120000-000-periodic.log",
                        trigger = "periodic",
                        createdAtMs = 1_763_000_000_000L,
                        sizeBytes = 12_288L,
                    ),
                ),
            ),
        )

        composeRule.setContent {
            RustClashTheme(themePreference = ThemePreference.DARK, fontFamily = fontFamily) {
                Box(modifier = Modifier.fillMaxSize()) {
                    SettingsScreen(
                        state = uiState,
                        onSetThemePreference = {},
                        onRequestInstalledApps = {},
                        onSavePerAppPolicy = { _, _ -> },
                        onSetEnableIpv6 = {},
                        onSetDemoMode = {},
                        onFlushDns = {},
                        onSetDebugLogEnabled = { toggledEnabled = it },
                        onSetDebugSliceIntervalSecs = { selectedInterval = it },
                        onCaptureDebugSliceNow = { manualSliceClicked = true },
                        onShareDebugReport = { shareClicked = true },
                    )
                }
            }
        }

        composeRule.onNodeWithText("调试与诊断 (Debug)").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("采集中 · 2 份").assertIsDisplayed()
        composeRule.onNodeWithText("调试与诊断 (Debug)").performClick()

        composeRule.onNodeWithText("开启 Debug 诊断采集").assertIsDisplayed()
        composeRule.onNodeWithText("15 分钟").performScrollTo().performClick()
        assertTrue(selectedInterval == 900L)

        composeRule.onNodeWithText("立即生成切片").performScrollTo().performClick()
        assertTrue(manualSliceClicked)

        composeRule.onNodeWithText("一键分享诊断报告").performScrollTo().performClick()
        assertTrue(shareClicked)
        assertTrue(toggledEnabled == null)
    }
}

