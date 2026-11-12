package io.github.rustclashlabs.rustclash

import android.graphics.Bitmap
import android.graphics.Canvas
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
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.GeoDataUiStatus
import io.github.rustclashlabs.rustclash.ui.model.LiveTelemetryUi
import io.github.rustclashlabs.rustclash.ui.model.MainDestination
import io.github.rustclashlabs.rustclash.ui.model.ProfileUiItem
import io.github.rustclashlabs.rustclash.ui.model.ProxyGroupItem
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.RuleItem
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.screens.HomeScreen
import io.github.rustclashlabs.rustclash.ui.screens.NodesScreen
import io.github.rustclashlabs.rustclash.ui.screens.ProfilesScreen
import io.github.rustclashlabs.rustclash.ui.screens.RulesScreen
import io.github.rustclashlabs.rustclash.ui.screens.SettingsScreen
import io.github.rustclashlabs.rustclash.ui.theme.LocalRustClashColors
import io.github.rustclashlabs.rustclash.ui.theme.RustClashBrandIcon
import io.github.rustclashlabs.rustclash.ui.theme.RustClashTheme
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
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
        org.junit.Assume.assumeTrue(
            "Skipping local screenshot generation when /tmp/robolectric-deps is absent",
            File("/tmp/robolectric-deps").isDirectory,
        )
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

        // 4. Render Compact Screen + 1.15x Font Scale Verification
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
        // Simulate 1.15x large system font scale on a compact width
        CompositionLocalProvider(
            LocalDensity provides Density(
                density = currentDensity.density,
                fontScale = 1.15f,
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
}
