package io.github.rustclashlabs.rustclash

import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.pm.PackageManager
import io.github.rustclashlabs.rustclash.security.AndroidKeystoreVault
import io.github.rustclashlabs.rustclash.ui.ActiveYamlExportRunner
import io.github.rustclashlabs.rustclash.ui.RustClashViewModel
import io.github.rustclashlabs.rustclash.ui.model.AppUiState
import io.github.rustclashlabs.rustclash.ui.model.DiagnosticsFilter
import io.github.rustclashlabs.rustclash.ui.model.ExitIpUi
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.vpn.NativeBridge
import io.github.rustclashlabs.rustclash.vpn.NativeLibraryLoader
import io.github.rustclashlabs.rustclash.vpn.NetworkCallbackLifecycle
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.PerAppVpnPolicy
import io.github.rustclashlabs.rustclash.vpn.RustClashVpnService
import io.github.rustclashlabs.rustclash.vpn.UnderlyingNetworkTracker
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import io.github.rustclashlabs.rustclash.vpn.VpnRoutePlan
import io.github.rustclashlabs.rustclash.vpn.VpnRoutePlanner
import io.github.rustclashlabs.rustclash.vpn.VpnServiceLifecycleCoordinator
import io.github.rustclashlabs.rustclash.vpn.VpnSessionConfig
import io.github.rustclashlabs.rustclash.vpn.VpnStateTracker
import io.github.rustclashlabs.rustclash.vpn.isGlobalUnicastIpv6Address
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.nio.file.Files
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.spec.SecretKeySpec

class VpnConfigAndLifecycleTest {

    @Test
    fun perAppAllowlistStripsSelfPackageAndPreventsMutualExclusionConflict() {
        val plan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.ALLOWLIST,
            selectedPackages = setOf(
                "org.mozilla.firefox",
                "io.github.rustclashlabs.rustclash",
                "com.android.chrome",
            ),
            selfPackageName = "io.github.rustclashlabs.rustclash",
            isLockdownEnabled = false,
        )
        assertEquals(PerAppMode.ALLOWLIST, plan.mode)
        assertEquals(listOf("com.android.chrome", "org.mozilla.firefox"), plan.allowedPackages)
        assertTrue(plan.disallowedPackages.isEmpty())
        assertNull(plan.lockdownConflictWarning)
    }

    @Test
    fun lockdownConflictDetectedForAllowlistAndBlocklistWithoutBreakingSelfProtect() {
        val allowPlan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.ALLOWLIST,
            selectedPackages = setOf("org.mozilla.firefox"),
            selfPackageName = "io.github.rustclashlabs.rustclash",
            isLockdownEnabled = true,
        )
        assertNotNull(allowPlan.lockdownConflictWarning)
        assertTrue(allowPlan.lockdownConflictWarning!!.contains("Lockdown"))

        val blockPlan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.BLOCKLIST,
            selectedPackages = setOf("com.whatsapp", "io.github.rustclashlabs.rustclash"),
            selfPackageName = "io.github.rustclashlabs.rustclash",
            isLockdownEnabled = true,
        )
        // Self package MUST NOT be added to disallowedPackages so Android netd Lockdown never drops
        // VpnService.protect(fd) sockets!
        assertEquals(listOf("com.whatsapp"), blockPlan.disallowedPackages)
        assertTrue(blockPlan.allowedPackages.isEmpty())
        assertNotNull(blockPlan.lockdownConflictWarning)
    }

    @Test
    fun sessionConfigClampsOutOfRangeMtuAndPrefixes() {
        val raw = VpnSessionConfig(
            mtu = 500,
            ipv4PrefixLength = 2,
            ipv6PrefixLength = 128,
        ).validated()
        assertEquals(1280, raw.mtu)
        assertEquals(8, raw.ipv4PrefixLength)
        assertEquals(126, raw.ipv6PrefixLength)
    }

    @Test
    fun vpnLifecycleStateMachineHandlesConnectHandoffStopAndSystemRevoke() {
        val tracker = VpnStateTracker()
        assertEquals(VpnLifecycleState.DISCONNECTED, tracker.state)

        tracker.onPrepareRequested()
        assertEquals(VpnLifecycleState.PREPARING, tracker.state)

        tracker.onStartRequested()
        assertEquals(VpnLifecycleState.STARTING, tracker.state)

        tracker.onRunning()
        assertEquals(VpnLifecycleState.RUNNING, tracker.state)

        tracker.onNetworkHandoff()
        assertEquals(VpnLifecycleState.RUNNING, tracker.state)

        tracker.onStopRequested()
        assertEquals(VpnLifecycleState.STOPPING, tracker.state)

        tracker.onStopped()
        assertEquals(VpnLifecycleState.DISCONNECTED, tracker.state)

        // Now verify Android system `onRevoke()` preserves REVOKED state & diagnostic message
        tracker.onStartRequested()
        tracker.onRunning()
        tracker.onSystemRevoked()
        tracker.onStopped()
        assertEquals(VpnLifecycleState.REVOKED, tracker.state)
        assertNotNull(tracker.lastError)
    }

    @Test
    fun underlyingNetworkTrackerFiltersRssiNoiseAndRecoversAcrossWifiCellularHandoffs() {
        val netTracker = UnderlyingNetworkTracker()

        // 1. Self VPN transport notifications must always be ignored
        val vpnSelf = netTracker.onUnderlyingCandidate(
            networkHandle = 9001L,
            isVpnTransport = true,
            isWifi = false,
            isCellular = false,
        )
        assertFalse(vpnSelf.updateUnderlyingNetworks)
        assertFalse(vpnSelf.notifyNative)

        // 2. Initial Wi-Fi network sets baseline without gratuitous session teardown
        val initWifi = netTracker.onUnderlyingCandidate(
            networkHandle = 100L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
        )
        assertTrue(initWifi.updateUnderlyingNetworks)
        assertFalse(initWifi.triggerSessionRecovery)
        assertTrue(initWifi.notifyNative)
        assertEquals(100L, initWifi.effectiveHandle)
        assertTrue(initWifi.isWifi)

        // 3. Repeated RSSI / link-bandwidth callbacks on the same Wi-Fi network must NOT reset sessions!
        val rssiUpdate = netTracker.onUnderlyingCandidate(
            networkHandle = 100L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
        )
        assertFalse(rssiUpdate.updateUnderlyingNetworks)
        assertFalse(rssiUpdate.triggerSessionRecovery)
        assertFalse(rssiUpdate.notifyNative)

        // 4. Seamless handoff from Wi-Fi (100L) -> Cellular 5G (200L), followed by late onLost(100L)
        val cellHandoff = netTracker.onUnderlyingCandidate(
            networkHandle = 200L,
            isVpnTransport = false,
            isWifi = false,
            isCellular = true,
        )
        assertTrue(cellHandoff.updateUnderlyingNetworks)
        assertTrue(cellHandoff.triggerSessionRecovery)
        assertTrue(cellHandoff.notifyNative)
        assertEquals(200L, cellHandoff.effectiveHandle)
        assertFalse(cellHandoff.isWifi)

        // Late onLost for the already-replaced Wi-Fi handle (100L) must NOT clobber Cellular (200L)!
        val staleWifiLost = netTracker.onUnderlyingLost(100L)
        assertFalse(staleWifiLost.updateUnderlyingNetworks)
        assertFalse(staleWifiLost.notifyNative)

        // 5. Hard drop of active Cellular (200L) followed by reconnect to Wi-Fi (100L)
        val activeLost = netTracker.onUnderlyingLost(200L)
        assertTrue(activeLost.updateUnderlyingNetworks)
        assertTrue(activeLost.triggerSessionRecovery)
        assertTrue(activeLost.notifyNative)
        assertEquals(0L, activeLost.effectiveHandle)

        val wifiReconnect = netTracker.onUnderlyingCandidate(
            networkHandle = 100L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
        )
        assertTrue(wifiReconnect.updateUnderlyingNetworks)
        assertTrue(wifiReconnect.triggerSessionRecovery)
        assertTrue(wifiReconnect.notifyNative)
        assertEquals(100L, wifiReconnect.effectiveHandle)
        assertTrue(wifiReconnect.isWifi)
    }

    @Test
    fun trafficRateFormattingProducesHumanReadableUnits() {
        assertEquals("512 B/s", RustClashVpnService.formatBytesPerSec(512))
        assertEquals("2.0 KB/s", RustClashVpnService.formatBytesPerSec(2048))
        assertEquals("1.5 MB/s", RustClashVpnService.formatBytesPerSec(1_572_864))
    }

    @Test
    fun qrCodeEncodeAndDecodeRoundtripsSsVlessAndAnytlsShareLinks() {
        val links = listOf(
            "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206dGVzdC1zZWNyZXQta2V5@jp.example.com:8388#%E9%A6%99%E6%B8%AF-SS2022",
            "vless://550e8400-e29b-41d4-a716-446655440000@de.example.com:443?security=tls&sni=de.example.com&alpn=h2#Frankfurt-VLESS",
            "anytls://super-secret-pass@sg.example.com:8443?sni=sg.example.com&alpn=h2#Singapore-AnyTLS",
        )
        for (uri in links) {
            val (pixels, dim) = NodeImportSupport.encodeQrCodeToArgbPixels(uri, dimension = 320)
            val decoded = NodeImportSupport.decodeQrCodeFromArgbPixels(pixels, dim, dim)
            assertEquals("QR roundtrip mismatch for $uri", uri, decoded)
        }

        // Empty or undersized buffers must return null safely without throwing
        assertNull(NodeImportSupport.decodeQrCodeFromArgbPixels(IntArray(0), 0, 0))
        assertNull(NodeImportSupport.decodeQrCodeFromArgbPixels(IntArray(64) { 0xFFFFFFFF.toInt() }, 8, 8))
    }

    @Test
    fun intentExtractorParsesActionSendAndActionViewSchemesCleanly() {
        // 1. Android Share Menu (`ACTION_SEND` + `text/plain`)
        val sharedMulti = "  ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#HK\nvless://550e8400-e29b-41d4-a716-446655440000@5.6.7.8:443?security=tls#US  "
        assertEquals(
            sharedMulti.trim(),
            NodeImportSupport.extractImportPayloadFromIntent(
                action = "android.intent.action.SEND",
                mimeType = "text/plain",
                extraText = sharedMulti,
                dataUriString = null,
            ),
        )

        // Non-text MIME in ACTION_SEND is ignored
        assertNull(
            NodeImportSupport.extractImportPayloadFromIntent(
                action = "android.intent.action.SEND",
                mimeType = "image/png",
                extraText = "not-text",
                dataUriString = null,
            ),
        )

        // 2. Deep-Link URI schemes (`ACTION_VIEW`: ss://, vless://, anytls://, clash://)
        for (uri in listOf(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#HK",
            "VLESS://550e8400-e29b-41d4-a716-446655440000@5.6.7.8:443?security=tls#US",
            "anytls://secret@9.9.9.9:443?sni=example.com#SG",
            "clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fclash.yaml",
        )) {
            assertEquals(
                uri,
                NodeImportSupport.extractImportPayloadFromIntent(
                    action = "android.intent.action.VIEW",
                    mimeType = null,
                    extraText = null,
                    dataUriString = uri,
                ),
            )
        }

        // Unrelated http/https browser intents or MAIN launcher intents must NOT auto-hijack
        assertNull(
            NodeImportSupport.extractImportPayloadFromIntent(
                action = "android.intent.action.VIEW",
                mimeType = null,
                extraText = null,
                dataUriString = "https://example.com",
            ),
        )
        assertNull(
            NodeImportSupport.extractImportPayloadFromIntent(
                action = "android.intent.action.MAIN",
                mimeType = null,
                extraText = "ss://ignored",
                dataUriString = null,
            ),
        )
    }

    @Test
    fun uiSecretRedactorScrubsShareLinksSubscriptionTokensAndPasswords() {
        val raw = "Import failed for vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&pbk=SECRET_PBK_777#Node " +
            "and https://sub.example.com/api/v1?token=TOP_SECRET_SUB_999&flag=clash with password=MY_NODE_PASS_888"
        val scrubbed = NodeImportSupport.redactSecretsForUi(raw)
        assertFalse(scrubbed.contains("11111111-2222-3333-4444-555555555555"))
        assertFalse(scrubbed.contains("SECRET_PBK_777"))
        assertFalse(scrubbed.contains("TOP_SECRET_SUB_999"))
        assertFalse(scrubbed.contains("MY_NODE_PASS_888"))
        assertTrue(scrubbed.contains("vless://***REDACTED***"))
        assertTrue(scrubbed.contains("https://sub.example.com/api/v1?***REDACTED***"))
        assertTrue(scrubbed.contains("password=***REDACTED***"))
    }

    @Test
    fun nodeManagerSnapshotParserExtractsSmartCnPresetGeoDataGroupsAndDelays() {
        val sampleJson = """
            {
              "ok": true,
              "vpnRunning": false,
              "activeProfileId": "default",
              "mode": "rule",
              "primaryGroup": "PROXY",
              "effectiveOutbound": "HK-Node-01",
              "effectiveProtocol": "Shadowsocks",
              "delays": { "HK-Node-01": 68, "JP-Node-02": 115 },
              "nodes": [
                { "name": "HK-Node-01", "type": "ss", "server": "hk.example.com", "port": 8388, "cipher": "2022-blake3-aes-256-gcm" },
                { "name": "JP-Node-02", "type": "vless", "server": "jp.example.com", "port": 443, "tls": true, "servername": "jp.example.com" }
              ],
              "groups": [
                { "name": "PROXY", "type": "Select", "now": "HK-Node-01", "all": ["HK-Node-01", "JP-Node-02", "DIRECT"], "effectiveOutbound": "HK-Node-01", "effectiveProtocol": "Shadowsocks" }
              ],
              "rules": [
                { "type": "GeoSite", "payload": "cn", "proxy": "DIRECT", "hits": 12 },
                { "type": "Match", "payload": "", "proxy": "PROXY", "hits": 5 }
              ],
              "routing": {
                "active_choice": "smart-cn",
                "mode": "rule",
                "rule_preset": "smart-cn",
                "has_custom_rules_backup": true
              },
              "geodata": {
                "using_persisted_data": true,
                "builtin_fallback_active": true,
                "is_expired": false,
                "last_updated_ms": 1731150000000,
                "source_label": "jsdelivr-testingcf",
                "geosite_cn_entries": 42000,
                "geosite_non_cn_entries": 68000,
                "geoip_cn_ranges": 8600
              }
            }
        """.trimIndent()

        val parsed = UiJsonParsers.parseNodeManagerSnapshot(sampleJson)
        assertTrue(parsed.ok)
        assertEquals(RoutingPresetUi.SMART_CN, parsed.routingPreset)
        assertTrue(parsed.hasCustomRulesBackup)
        assertEquals("HK-Node-01", parsed.effectiveOutbound)
        assertEquals(2, parsed.nodes.size)
        assertEquals(68L, parsed.nodes[0].delayMs)
        assertEquals("Shadowsocks", parsed.nodes[0].protocolDisplay)
        assertEquals("VLESS", parsed.nodes[1].protocolDisplay)
        assertEquals(1, parsed.groups.size)
        assertTrue(parsed.groups[0].isSelectable)
        assertEquals(2, parsed.rules.size)
        assertTrue(parsed.geodata.usingPersistedData)
        assertEquals(42000, parsed.geodata.geositeCnEntries)
        assertEquals(8600, parsed.geodata.geoipCnRanges)
    }

    @Test
    fun diagnosticsParserAndFilterSeparatesDirectProxyAndRedactsErrors() {
        val rawDiag = """
            {
              "ok": true,
              "vpnRunning": true,
              "diagnostics": [
                {
                  "id": "c-1",
                  "metadata": { "network": "tcp", "type": "TUN", "host": "www.baidu.com", "destination_port": 443, "fake_ip": "198.18.0.10" },
                  "rule": "GeoSite",
                  "rule_payload": "cn",
                  "chains": ["DIRECT"],
                  "effective_outbound": "DIRECT",
                  "effective_protocol": "DIRECT",
                  "exit_type": "DIRECT",
                  "remote_endpoint": "www.baidu.com:443",
                  "status": "active",
                  "upload": 512,
                  "download": 4096,
                  "start_epoch_ms": 1731150001000
                },
                {
                  "id": "c-2",
                  "metadata": { "network": "tcp", "type": "TUN", "host": "www.google.com", "destination_port": 443, "fake_ip": "198.18.0.11" },
                  "rule": "GeoSite",
                  "rule_payload": "geolocation-!cn",
                  "chains": ["HK-Node-01", "PROXY"],
                  "effective_outbound": "HK-Node-01",
                  "effective_protocol": "VLESS",
                  "exit_type": "PROXY",
                  "remote_endpoint": "hk.example.com:443",
                  "status": "active",
                  "upload": 1024,
                  "download": 8192,
                  "start_epoch_ms": 1731150002000
                },
                {
                  "id": "c-3",
                  "metadata": { "network": "udp", "type": "TUN", "host": "bad.example.org", "destination_port": 443 },
                  "rule": "Match",
                  "rule_payload": "",
                  "chains": ["Broken-Node", "PROXY"],
                  "effective_outbound": "Broken-Node",
                  "effective_protocol": "AnyTLS",
                  "exit_type": "PROXY",
                  "status": "failed",
                  "error": "handshake failed with password=SUPER_SECRET_PASS_123"
                }
              ]
            }
        """.trimIndent()

        val list = UiJsonParsers.parseDiagnosticsResponse(rawDiag)
        assertEquals(3, list.size)
        assertEquals("www.baidu.com:443", list[0].displayTarget)
        assertEquals("198.18.0.10", list[0].fakeIpRestored)
        assertEquals(1, UiJsonParsers.filterDiagnostics(list, DiagnosticsFilter.DIRECT).size)
        assertEquals(2, UiJsonParsers.filterDiagnostics(list, DiagnosticsFilter.PROXY).size)
        val failed = UiJsonParsers.filterDiagnostics(list, DiagnosticsFilter.FAILED)
        assertEquals(1, failed.size)
        assertFalse(failed[0].error!!.contains("SUPER_SECRET_PASS_123"))
        assertTrue(failed[0].error!!.contains("password=***REDACTED***"))
    }

    @Test
    fun nodeSearchAndLatencySortPlacesLowestDelayFirstAndUntestedLast() {
        val nodes = listOf(
            ProxyNodeItem(name = "US-West", type = "vless", server = "us.example.com", port = 443),
            ProxyNodeItem(name = "SG-Fast", type = "anytls", server = "sg.example.com", port = 443),
            ProxyNodeItem(name = "HK-Ultra", type = "ss", server = "hk.example.com", port = 8388),
        )
        val delays = mapOf("SG-Fast" to 92L, "HK-Ultra" to 35L)

        val sorted = UiJsonParsers.filterAndSortNodes(
            nodes = nodes,
            delays = delays,
            query = "",
            sortByDelay = true,
        )
        assertEquals(listOf("HK-Ultra", "SG-Fast", "US-West"), sorted.map { it.name })

        val searched = UiJsonParsers.filterAndSortNodes(
            nodes = nodes,
            delays = delays,
            query = "anytls",
            sortByDelay = false,
        )
        assertEquals(listOf("SG-Fast"), searched.map { it.name })
    }

    @Test
    fun explainRuleAndThemePreferenceParsersHandleOfflineAndLivePayloads() {
        val explainJson = """
            {
              "ok": true,
              "vpnRunning": false,
              "input": "www.bilibili.com",
              "normalized_target": "www.bilibili.com:443",
              "mode": "rule",
              "rule_type": "GeoSite",
              "rule_payload": "cn",
              "chains": ["DIRECT"],
              "outbound": "DIRECT",
              "protocol": "DIRECT",
              "exit_type": "DIRECT",
              "remote_endpoint": "www.bilibili.com:443"
            }
        """.trimIndent()
        val explain = UiJsonParsers.parseExplainResponse(explainJson).getOrThrow()
        assertEquals("DIRECT", explain.exitType)
        assertEquals("GeoSite, cn", explain.ruleDisplay)
        assertFalse(explain.vpnRunning)

        assertEquals(RoutingPresetUi.CUSTOM, RoutingPresetUi.fromWireAndMode(null, "rule", "custom"))
        assertEquals(RoutingPresetUi.GLOBAL, RoutingPresetUi.fromWireAndMode("global", "global", "smart-cn"))
        assertEquals(ThemePreference.DARK, ThemePreference.fromWire("dark"))
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromWire(null))
        assertEquals("浅色", ThemePreference.LIGHT.shortLabel)
        assertEquals("深色", ThemePreference.DARK.shortLabel)
        assertEquals("跟随系统", ThemePreference.SYSTEM.shortLabel)
    }

    @Test
    fun profileDisplayNameResolvesStarterProfileAndCustomAliasesCleanly() {
        val starterItem = io.github.rustclashlabs.rustclash.ui.model.ProfileUiItem(
            id = "default",
            name = "Starter Profile",
            kind = "local-yaml",
            subscriptionUrlRedacted = null,
            lastUpdatedMs = 1731150000000L,
            lastError = null,
            proxyCount = 3,
            ruleCount = 8,
            rulePreset = "smart-cn",
            hasCustomBackup = false,
            uploadBytes = null,
            downloadBytes = null,
            totalBytes = null,
            expireUnixSecs = null,
        )
        val emptyState = io.github.rustclashlabs.rustclash.ui.model.AppUiState(
            activeProfileId = "default",
            profiles = listOf(starterItem.copy(proxyCount = 0)),
            nodes = emptyList(),
        )
        assertEquals("初始配置", emptyState.activeProfileName)

        val populatedState = io.github.rustclashlabs.rustclash.ui.model.AppUiState(
            activeProfileId = "default",
            profiles = listOf(starterItem),
        )
        assertEquals("默认配置", populatedState.activeProfileName)

        val renamedState = populatedState.copy(
            profileAliases = mapOf("default" to "主力分流方案"),
        )
        assertEquals("主力分流方案", renamedState.activeProfileName)
        assertEquals("主力分流方案", renamedState.resolveProfileDisplayName(starterItem))
    }

    @Test
    fun routingPresetDescriptionsAvoidAbsoluteMarketingClaims() {
        for (preset in RoutingPresetUi.entries) {
            assertFalse(
                "Preset ${preset.name} should not contain unverified absolute DNS claim",
                preset.detailDescription.contains("零本地 DNS 泄漏"),
            )
            assertTrue(preset.detailDescription.isNotBlank())
        }
    }

    @Test
    fun invertedWhiteOnDarkQrCodeDecodesTrojanAndVlessWsLinksCleanly() {
        val uri = "trojan://my-trojan-pass@edge.example.com:443?type=ws&path=%2Fws-fast%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com#HK-Trojan-WS"
        val (normalPixels, dim) = NodeImportSupport.encodeQrCodeToArgbPixels(uri, dimension = 320)
        val invertedPixels = IntArray(normalPixels.size) { i ->
            val px = normalPixels[i]
            (px and -0x1000000) or ((px.inv()) and 0x00FFFFFF)
        }
        val decoded = NodeImportSupport.decodeQrCodeFromArgbPixels(invertedPixels, dim, dim)
        assertEquals(uri, decoded)
    }

    @Test
    fun expandedProtocolDeepLinksAndHttpUserinfoRedactionWorkCleanly() {
        for (uri in listOf(
            "trojan://pass123@hk.example.com:443?sni=hk.example.com#HK-Trojan",
            "socks5://user:pass@10.0.0.2:1080#LAN-SOCKS5",
            "socks://10.0.0.3:1080#Plain-SOCKS",
            "http-proxy://alice:secret@proxy.example.com:8080#Corp-HTTP",
            "https-proxy://alice:secret@proxy.example.com:8443#Corp-HTTPS",
        )) {
            assertEquals(
                uri,
                NodeImportSupport.extractImportPayloadFromIntent(
                    action = "android.intent.action.VIEW",
                    mimeType = null,
                    extraText = null,
                    dataUriString = uri,
                ),
            )
        }

        val rawLeak = "Failed connecting to trojan://TOP_TROJAN_SECRET@hk.example.com:443#HK and " +
            "http://alice:CORP_PASS_777@proxy.example.com:8080/pac and socks5://bob:SOCKS_PASS_888@1.2.3.4:1080"
        val scrubbed = NodeImportSupport.redactSecretsForUi(rawLeak)
        assertFalse(scrubbed.contains("TOP_TROJAN_SECRET"))
        assertFalse(scrubbed.contains("CORP_PASS_777"))
        assertFalse(scrubbed.contains("SOCKS_PASS_888"))
        assertTrue(scrubbed.contains("trojan://***REDACTED***"))
        assertTrue(scrubbed.contains("http://***REDACTED***@proxy.example.com:8080"))
        assertTrue(scrubbed.contains("socks5://***REDACTED***"))
    }

    @Test
    fun snapshotParserExtractsTrojanSocks5HttpAndWebSocketTransportBadges() {
        val sampleJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "activeProfileId": "default",
              "mode": "rule",
              "primaryGroup": "PROXY",
              "effectiveOutbound": "HK-VLESS-WS",
              "effectiveProtocol": "vless",
              "delays": { "HK-VLESS-WS": 41 },
              "nodes": [
                {
                  "name": "HK-VLESS-WS",
                  "type": "vless",
                  "server": "cdn.example.com",
                  "port": 443,
                  "tls": true,
                  "network": "ws",
                  "servername": "app.example.com",
                  "ws-opts": {
                    "path": "/vless-ws",
                    "headers": { "Host": "app.example.com" },
                    "max-early-data": 2048
                  }
                },
                {
                  "name": "JP-Trojan-WS",
                  "type": "trojan",
                  "server": "jp.example.com",
                  "port": 443,
                  "tls": true,
                  "network": "ws",
                  "sni": "jp.example.com",
                  "ws-opts": { "path": "/trojan" }
                },
                {
                  "name": "LAN-SOCKS5",
                  "type": "socks5",
                  "server": "192.168.1.2",
                  "port": 1080,
                  "username": "lanuser"
                },
                {
                  "name": "Edge-HTTP",
                  "type": "http",
                  "server": "proxy.example.com",
                  "port": 8443,
                  "tls": true,
                  "username": "corp"
                }
              ],
              "groups": [],
              "rules": []
            }
        """.trimIndent()

        val parsed = UiJsonParsers.parseNodeManagerSnapshot(sampleJson)
        assertEquals(4, parsed.nodes.size)
        assertEquals("VLESS·WS", parsed.nodes[0].protocolShortBadge)
        assertEquals("/vless-ws", parsed.nodes[0].wsPath)
        assertEquals("app.example.com", parsed.nodes[0].wsHost)
        assertEquals(2048, parsed.nodes[0].maxEarlyData)
        assertEquals("Trojan·WS", parsed.nodes[1].protocolShortBadge)
        assertEquals("Trojan", parsed.nodes[1].protocolDisplay)
        assertEquals("SOCKS5", parsed.nodes[2].protocolShortBadge)
        assertEquals("lanuser", parsed.nodes[2].username)
        assertEquals("HTTP", parsed.nodes[3].protocolShortBadge)
        assertEquals("corp", parsed.nodes[3].username)
    }

    @Test
    fun formatCleanBackendErrorStripsConfigurationPrefixAndRedactsSubscriptionSecrets() {
        val rawErr =
            "Configuration error: Configuration error: YAML parse error at 'tun.mtu': invalid value " +
                "from https://sub.example.com:8443/api/v1/client/subscribe?token=SUPER_SECRET_SUB_TOKEN_999"
        val cleaned = UiJsonParsers.formatCleanBackendError(rawErr, "格式校验未通过")
        assertFalse("must strip Configuration error prefix: $cleaned", cleaned.contains("Configuration error"))
        assertFalse("must redact subscription token: $cleaned", cleaned.contains("SUPER_SECRET_SUB_TOKEN_999"))
        assertTrue("must preserve field path diagnostic: $cleaned", cleaned.contains("tun.mtu"))

        assertEquals("格式校验未通过", UiJsonParsers.formatCleanBackendError("   ", "格式校验未通过"))
        assertEquals(
            "格式校验未通过",
            UiJsonParsers.formatCleanBackendError("Configuration error:   ", "格式校验未通过"),
        )

        val defaultState = io.github.rustclashlabs.rustclash.ui.model.AppUiState()
        assertNull(defaultState.modalError)
        val withErr = defaultState.copy(modalError = "导入失败：$cleaned")
        assertEquals("导入失败：$cleaned", withErr.modalError)
        assertNull(withErr.copy(modalError = null).modalError)
    }

    @Test
    fun vpnStateTrackerUnderlyingLostTransitionsRunningToReconnectingAndRecoversCleanly() {
        val tracker = VpnStateTracker()
        // Losing underlying network when DISCONNECTED is a no-op
        tracker.onUnderlyingLost()
        assertEquals(VpnLifecycleState.DISCONNECTED, tracker.state)

        tracker.onStartRequested()
        tracker.onRunning()
        assertEquals(VpnLifecycleState.RUNNING, tracker.state)

        tracker.onUnderlyingLost()
        assertEquals(VpnLifecycleState.RECONNECTING, tracker.state)

        tracker.onNetworkHandoff()
        assertEquals(VpnLifecycleState.RUNNING, tracker.state)

        tracker.onError("VPN 连接授权已被取消")
        assertEquals(VpnLifecycleState.ERROR, tracker.state)
        assertEquals("VPN 连接授权已被取消", tracker.lastError)

        tracker.clearError()
        assertEquals(VpnLifecycleState.DISCONNECTED, tracker.state)
        assertNull(tracker.lastError)
    }

    @Test
    fun expandedSecretRedactionScrubsVmessHysteria2TuicWireguardStandaloneUuidsAndTokens() {
        val raw =
            "Rejected nodes: vmess://eyJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsImlkIjoiYTFiMmMzZDQtZTVmNi00Nzg5LWFiY2QtZWYwMTIzNDU2Nzg5In0= " +
                "and hy2://HY2_SUPER_PASS_999@hy2.example.com:443?sni=hy2.example.com#HY2 " +
                "and tuic://12345678-1234-4321-abcd-9876543210ff:TUIC_PASS_777@tuic.example.com:443#TUIC " +
                "and wg://WG_PRIV_KEY_555@wg.example.com:51820 " +
                "with standalone uuid f47ac10b-58cc-4372-a567-0e02b2c3d479 and access_token=PANEL_TOKEN_333"
        val scrubbed = NodeImportSupport.redactSecretsForUi(raw)
        assertFalse(scrubbed.contains("eyJhZGQiOi"))
        assertFalse(scrubbed.contains("HY2_SUPER_PASS_999"))
        assertFalse(scrubbed.contains("TUIC_PASS_777"))
        assertFalse(scrubbed.contains("WG_PRIV_KEY_555"))
        assertFalse(scrubbed.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
        assertFalse(scrubbed.contains("PANEL_TOKEN_333"))
        assertTrue(scrubbed.contains("vmess://***REDACTED***"))
        assertTrue(scrubbed.contains("hy2://***REDACTED***"))
        assertTrue(scrubbed.contains("tuic://***REDACTED***"))
        assertTrue(scrubbed.contains("wg://***REDACTED***"))
        assertTrue(scrubbed.contains("access_token=***REDACTED***"))
    }

    @Test
    fun profilesSnapshotParserExtractsManualProxyCountAndAutoUpdateInterval() {
        val rawProfilesJson = """
            {
              "ok": true,
              "profilesSnapshot": {
                "active_profile_id": "sub-hk",
                "profiles": [
                  {
                    "id": "sub-hk",
                    "name": "主力订阅",
                    "kind": "subscription",
                    "subscription_url_redacted": "https://sub.example.com/api/v1?***REDACTED***",
                    "auto_update_interval_secs": 21600,
                    "last_updated_ms": 1731150000000,
                    "proxy_count": 18,
                    "manual_proxy_count": 2,
                    "group_count": 4,
                    "rule_count": 120
                  },
                  {
                    "id": "sub-manual-only",
                    "name": "备用订阅",
                    "kind": "subscription",
                    "subscription_url_redacted": "https://sub2.example.com/clash.yaml",
                    "auto_update_interval_secs": null,
                    "last_updated_ms": 1731150000000,
                    "proxy_count": 5,
                    "manual_proxy_count": 0,
                    "rule_count": 30
                  }
                ]
              }
            }
        """.trimIndent()

        val parsed = UiJsonParsers.parseProfilesSnapshot(rawProfilesJson)
        assertNotNull(parsed)
        assertEquals("sub-hk", parsed!!.first)
        assertEquals(2, parsed.second.size)

        val first = parsed.second[0]
        assertTrue(first.isSubscription)
        assertEquals(18, first.proxyCount)
        assertEquals(2, first.manualProxyCount)
        assertEquals(21600L, first.autoUpdateIntervalSecs)
        assertEquals("每 6 小时", UiJsonParsers.formatAutoUpdateInterval(first.autoUpdateIntervalSecs))

        val second = parsed.second[1]
        assertTrue(second.isSubscription)
        assertEquals(0, second.manualProxyCount)
        assertNull(second.autoUpdateIntervalSecs)
        assertEquals("手动更新", UiJsonParsers.formatAutoUpdateInterval(second.autoUpdateIntervalSecs))
        assertEquals("手动更新", UiJsonParsers.formatAutoUpdateInterval(0L))
        assertEquals("每 1 小时", UiJsonParsers.formatAutoUpdateInterval(3600L))
        assertEquals("每 12 小时", UiJsonParsers.formatAutoUpdateInterval(43200L))
        assertEquals("每 24 小时", UiJsonParsers.formatAutoUpdateInterval(86400L))
        assertEquals("每 15 分钟", UiJsonParsers.formatAutoUpdateInterval(900L))
    }

    @Test
    fun siteDiagnosisAndImportRefreshParsersExposePlainLanguageAndProtocolBreakdowns() {
        val rawSiteJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "diagnosis": {
                "input": "chatgpt.com",
                "normalized_url": "https://chatgpt.com/",
                "target_host": "chatgpt.com",
                "target_port": 443,
                "mode": "rule",
                "matched_rule": "DOMAIN-SUFFIX(openai.com)",
                "route_flow": ["Rule 模式", "DOMAIN-SUFFIX(openai.com)", "PROXY", "JP-VLESS-01"],
                "effective_outbound": "JP-VLESS-01",
                "effective_protocol": "vless",
                "exit_type": "PROXY",
                "diagnosis_code": "tls_handshake_failed",
                "severity": "error",
                "headline_zh": "代理 TCP 建连成功，但 TLS 加密握手失败",
                "summary_zh": "节点 JP-VLESS-01 已连通，但与目标站点协商 TLS 时被中断。",
                "route_summary_zh": "预计分流路径：Rule 模式 → DOMAIN-SUFFIX(openai.com) → PROXY → JP-VLESS-01",
                "actions_zh": ["建议切换到其他节点后重新检测。"],
                "suggested_action_kind": "switch_node",
                "stage_checks": [
                  {"stage": "routing", "label_zh": "分流规则判定", "status": "ok", "latency_ms": null, "detail_zh": "命中 PROXY"},
                  {"stage": "tunnel", "label_zh": "代理节点建连", "status": "ok", "latency_ms": 62, "detail_zh": "TCP 握手成功"},
                  {"stage": "tls", "label_zh": "TLS 加密握手", "status": "failed", "latency_ms": 115, "detail_zh": "handshake eof"}
                ]
              }
            }
        """.trimIndent()

        val diag = UiJsonParsers.parseSiteDiagnosisResponse(rawSiteJson).getOrThrow()
        assertTrue(diag.vpnRunning)
        assertEquals("chatgpt.com", diag.targetHost)
        assertEquals(443, diag.targetPort)
        assertEquals("error", diag.severity)
        assertEquals("switch_node", diag.suggestedActionKind)
        assertEquals(3, diag.stageChecks.size)
        assertEquals(62L, diag.stageChecks[1].latencyMs)
        assertEquals("failed", diag.stageChecks[2].status)

        val rawImportJson = """
            {
              "ok": true,
              "count": 18,
              "addedNodes": ["HK-01", "JP-01"],
              "totalNodes": 18,
              "skippedDuplicates": 2,
              "skippedUnsupported": [
                {"name": "US-VMess-1", "protocol": "vmess", "reason": "VMess 暂未内置"},
                {"name": "US-VMess-2", "protocol": "vmess", "reason": "VMess 暂未内置"},
                {"name": "SG-HY2-1", "protocol": "hy2", "reason": "Hysteria2 QUIC 暂未内置"}
              ]
            }
        """.trimIndent()
        val importSum = UiJsonParsers.parseImportSummary(rawImportJson, "主力订阅")
        assertNotNull(importSum)
        assertFalse(importSum!!.isRefresh)
        assertEquals(2, importSum.addedNodes)
        assertEquals(2, importSum.skippedDuplicates)
        assertEquals(3, importSum.skippedUnsupportedTotal)
        assertEquals(2, importSum.skippedGroups.size)
        assertEquals("VMess", importSum.skippedGroups[0].protocolLabel)
        assertEquals(2, importSum.skippedGroups[0].count)
        assertEquals("Hysteria2", importSum.skippedGroups[1].protocolLabel)
        assertEquals(1, importSum.skippedGroups[1].count)

        val rawRefreshJson = """
            {
              "ok": true,
              "auditScore": 92,
              "auditGrade": "A",
              "refreshedProfile": {
                "id": "sub-hk",
                "name": "主力订阅",
                "proxy_count": 20,
                "rule_count": 135,
                "manual_proxy_count": 2
              },
              "diff": {
                "added_proxies": [{"name": "TW-01"}, {"name": "TW-02"}],
                "removed_proxies": ["OLD-HK"],
                "changed_proxies": [],
                "newly_insecure_nodes": [],
                "rules_prev_count": 120,
                "rules_next_count": 135
              }
            }
        """.trimIndent()
        val refreshSum = UiJsonParsers.parseRefreshSummary(rawRefreshJson, "备用名称")
        assertNotNull(refreshSum)
        assertTrue(refreshSum!!.isRefresh)
        assertEquals("主力订阅", refreshSum.profileName)
        assertEquals(20, refreshSum.totalNodes)
        assertEquals(2, refreshSum.diffAddedCount)
        assertEquals(1, refreshSum.diffRemovedCount)
        assertEquals(120, refreshSum.rulesPrevCount)
        assertEquals(135, refreshSum.rulesNextCount)
        assertEquals("A", refreshSum.auditGrade)
        assertEquals(2, refreshSum.manualProtectedCount)
    }

    @Test
    fun externalImportPreviewClassifiesClashDeepLinksSubscriptionsAndShareUrisWithRedaction() {
        val clashDeepLink =
            "clash://install-config?url=https%3A%2F%2Fsub.provider.example%3A8443%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3DTOP_SECRET_SUB_TOKEN_999&name=My%20Provider"
        val clashPreview = NodeImportSupport.classifyExternalImportPreview(clashDeepLink)
        assertEquals(NodeImportSupport.ExternalImportKind.REMOTE_SUBSCRIPTION, clashPreview.kind)
        assertTrue(clashPreview.isRemoteSubscription)
        assertEquals("sub.provider.example:8443", clashPreview.targetHost)
        assertEquals("My Provider", clashPreview.profileDisplayHint)
        assertFalse(clashPreview.sanitizedSummary.contains("TOP_SECRET_SUB_TOKEN_999"))
        assertFalse(clashPreview.sanitizedPayloadPreview.contains("TOP_SECRET_SUB_TOKEN_999"))
        assertTrue(clashPreview.sanitizedPayloadPreview.contains("***REDACTED***"))
        assertNotNull(clashPreview.securityWarning)
        assertTrue(clashPreview.securityWarning!!.contains("sub.provider.example:8443"))
        assertTrue(clashPreview.securityWarning!!.contains("分流规则"))

        val cleartextUserInfoSub = "http://admin:SuperSecretPass@insecure.sub.example/s/abcdef1234567890"
        val httpPreview = NodeImportSupport.classifyExternalImportPreview(cleartextUserInfoSub)
        assertEquals(NodeImportSupport.ExternalImportKind.REMOTE_SUBSCRIPTION, httpPreview.kind)
        assertTrue(httpPreview.isRemoteSubscription)
        assertEquals("insecure.sub.example", httpPreview.targetHost)
        assertFalse(httpPreview.sanitizedPayloadPreview.contains("SuperSecretPass"))
        assertFalse(httpPreview.sanitizedPayloadPreview.contains("abcdef1234567890"))
        assertTrue(httpPreview.securityWarning!!.contains("HTTP"))

        val shareLinks = """
            vless://11111111-2222-3333-4444-555555555555@hk.example.com:443?security=reality&pbk=REALITY_PBK_SECRET#HK-01
            ss://YWVzLTI1Ni1nY206c2VjcmV0X3Bhc3M@jp.example.com:8388#JP-02
            trojan://TROJAN_SECRET_PASS@sg.example.com:443#SG-03
        """.trimIndent()
        val uriPreview = NodeImportSupport.classifyExternalImportPreview(shareLinks)
        assertEquals(NodeImportSupport.ExternalImportKind.PROXY_SHARE_URIS, uriPreview.kind)
        assertFalse(uriPreview.isRemoteSubscription)
        assertEquals(3, uriPreview.proxyUriCount)
        assertEquals(listOf("VLESS", "Shadowsocks", "Trojan"), uriPreview.protocols)
        assertFalse(uriPreview.sanitizedPayloadPreview.contains("11111111-2222-3333-4444-555555555555"))
        assertFalse(uriPreview.sanitizedPayloadPreview.contains("REALITY_PBK_SECRET"))
        assertFalse(uriPreview.sanitizedPayloadPreview.contains("TROJAN_SECRET_PASS"))
        assertTrue(uriPreview.sanitizedPayloadPreview.contains("#HK-01"))

        val b64Payload = java.util.Base64.getEncoder()
            .encodeToString(shareLinks.toByteArray(Charsets.UTF_8))
        val b64Preview = NodeImportSupport.classifyExternalImportPreview(b64Payload)
        assertEquals(NodeImportSupport.ExternalImportKind.BASE64_SUBSCRIPTION, b64Preview.kind)
        assertEquals(3, b64Preview.proxyUriCount)
        assertFalse(b64Preview.sanitizedPayloadPreview.contains("TROJAN_SECRET_PASS"))

        val yamlPayload = """
            proxies:
              - name: HK-YAML
                type: ss
                server: hk.example.com
                port: 8388
                password: "YAML_TOP_SECRET_PASSWORD"
            rules:
              - MATCH,PROXY
        """.trimIndent()
        val yamlPreview = NodeImportSupport.classifyExternalImportPreview(yamlPayload)
        assertEquals(NodeImportSupport.ExternalImportKind.YAML_CONFIG, yamlPreview.kind)
        assertFalse(yamlPreview.sanitizedPayloadPreview.contains("YAML_TOP_SECRET_PASSWORD"))
    }

    @Test
    fun redactSecretsScrubsJsonAndYamlDoubleQuotedSingleQuotedAndUnquotedSecrets() {
        val jsonSnippet = """
            {
              "name": "HK-Node",
              "server": "hk.example.com",
              "port": 443,
              "password": "hunter2_json_double",
              "api_key": "sk-live-secret-999",
              "client-secret": "cs_my_quoted_secret",
              "socks_password": "prefixed_key_secret"
            }
        """.trimIndent()
        val scrubbedJson = NodeImportSupport.redactSecretsForUi(jsonSnippet)
        assertFalse(scrubbedJson.contains("hunter2_json_double"))
        assertFalse(scrubbedJson.contains("sk-live-secret-999"))
        assertFalse(scrubbedJson.contains("cs_my_quoted_secret"))
        assertFalse(scrubbedJson.contains("prefixed_key_secret"))
        assertTrue(scrubbedJson.contains("\"password\": \"***REDACTED***\""))
        assertTrue(scrubbedJson.contains("\"api_key\": \"***REDACTED***\""))
        assertTrue(scrubbedJson.contains("\"client-secret\": \"***REDACTED***\""))
        assertTrue(scrubbedJson.contains("\"socks_password\": \"***REDACTED***\""))
        assertTrue(scrubbedJson.contains("\"server\": \"hk.example.com\""))

        val escapedJson = """{"nested": "{\"password\": \"escaped_hunter2\", \"host\": \"jp.example.com\"}"}"""
        val scrubbedEscaped = NodeImportSupport.redactSecretsForUi(escapedJson)
        assertFalse(scrubbedEscaped.contains("escaped_hunter2"))
        assertTrue(scrubbedEscaped.contains("""\"password\": \"***REDACTED***\""""))
        assertTrue(scrubbedEscaped.contains("""\"host\": \"jp.example.com\""""))

        val yamlAndKv = """
            password: "yaml_double_quoted_pass"
            secret: 'yaml_single_quoted_secret'
            'private-key': 'wg_single_quoted_privkey'
            auth_str: 'it''s_escaped_single_quote'
            password: yaml_unquoted_pass
            token=query_unquoted_token
        """.trimIndent()
        val scrubbedYaml = NodeImportSupport.redactSecretsForUi(yamlAndKv)
        assertFalse(scrubbedYaml.contains("yaml_double_quoted_pass"))
        assertFalse(scrubbedYaml.contains("yaml_single_quoted_secret"))
        assertFalse(scrubbedYaml.contains("wg_single_quoted_privkey"))
        assertFalse(scrubbedYaml.contains("escaped_single_quote"))
        assertFalse(scrubbedYaml.contains("yaml_unquoted_pass"))
        assertFalse(scrubbedYaml.contains("query_unquoted_token"))
        assertTrue(scrubbedYaml.contains("password: \"***REDACTED***\""))
        assertTrue(scrubbedYaml.contains("secret: '***REDACTED***'"))
        assertTrue(scrubbedYaml.contains("'private-key': '***REDACTED***'"))
        assertTrue(scrubbedYaml.contains("password: ***REDACTED***"))
        assertTrue(scrubbedYaml.contains("token=***REDACTED***"))
    }

    @Test
    fun formatHostPortBracketsIpv6LiteralsAndPreservesDomainsAndIpv4() {
        assertEquals(
            "[2001:4860:4864:4:8000::]:3478",
            NodeImportSupport.formatHostPort("2001:4860:4864:4:8000::", 3478),
        )
        assertEquals(
            "[2408:8756:c50:101d::443]:443",
            NodeImportSupport.formatHostPort("2408:8756:c50:101d::443", 443),
        )
        assertEquals(
            "[2408:8756::443]:443",
            NodeImportSupport.formatHostPort("2408:8756::443", 443),
        )
        assertEquals(
            "[2001:db8::1]:8443",
            NodeImportSupport.formatHostPort("[2001:db8::1]", 8443),
        )
        assertEquals(
            "[2001:db8::1]:8443",
            NodeImportSupport.formatHostPort("[2001:db8::1]:8443", 8443),
        )
        assertEquals("api.bilibili.com:443", NodeImportSupport.formatHostPort("api.bilibili.com", 443))
        assertEquals("api.bilibili.com:443", NodeImportSupport.formatHostPort("api.bilibili.com:443", 443))
        assertEquals("1.1.1.1:53", NodeImportSupport.formatHostPort("1.1.1.1", 53))
        assertEquals("2001:db8::1", NodeImportSupport.formatHostPort("2001:db8::1", 0))
        assertEquals("unknown:443", NodeImportSupport.formatHostPort("   ", 443))
        assertEquals("unknown", NodeImportSupport.formatHostPort("", 0))

        // Verify DiagnosticEntryUi.displayTarget uses formatHostPort for IPv6 destinations
        val ipv6DiagJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "diagnostics": [
                {
                  "id": "ipv6-1",
                  "metadata": {
                    "network": "tcp",
                    "type": "TUN",
                    "host": "",
                    "destination_ip": "2408:8756:c50:101d::443",
                    "destination_port": 443
                  },
                  "rule": "GeoIP",
                  "rule_payload": "cn",
                  "chains": ["DIRECT"],
                  "effective_outbound": "DIRECT",
                  "effective_protocol": "DIRECT",
                  "exit_type": "DIRECT",
                  "status": "active"
                }
              ]
            }
        """.trimIndent()
        val parsedDiag = UiJsonParsers.parseDiagnosticsResponse(ipv6DiagJson)
        assertEquals(1, parsedDiag.size)
        assertEquals("[2408:8756:c50:101d::443]:443", parsedDiag[0].displayTarget)
    }

    @Test
    fun redactSecretsScrubsSubIpLabelsAndIpv4Ipv6SubscriptionUrls() {
        val raw = buildString {
            appendLine("Profile: Sub (203.0.113.124) active")
            appendLine("Ipv4Sub: https://203.0.113.124:8443/s/abcd")
            appendLine("Ipv6Sub: https://[2001:db8::1]:8443/s/secret123?token=xyz")
            appendLine("ShortDomainPathSub: https://panel.example.com/s/abcd")
            appendLine("LoopbackIpv6: https://[::1]:8443/s/secret123?token=xyz")
            appendLine("Probe: http://www.gstatic.com/generate_204")
        }
        val scrubbed = NodeImportSupport.redactSecretsForUi(raw)

        assertFalse(scrubbed.contains("203.0.113.124"))
        assertFalse(scrubbed.contains("2001:db8::1"))
        assertFalse(scrubbed.contains("abcd"))
        assertFalse(scrubbed.contains("secret123"))
        assertFalse(scrubbed.contains("xyz"))

        assertTrue(scrubbed.contains("Profile: Sub (***REDACTED***) active"))
        assertTrue(scrubbed.contains("Ipv4Sub: https://***REDACTED***"))
        assertTrue(scrubbed.contains("Ipv6Sub: https://***REDACTED***"))
        assertTrue(scrubbed.contains("ShortDomainPathSub: https://panel.example.com/s/***REDACTED***"))
        assertTrue(scrubbed.contains("LoopbackIpv6: https://[::1]:8443/s/***REDACTED***?***REDACTED***"))
        assertTrue(scrubbed.contains("Probe: http://www.gstatic.com/generate_204"))
    }

    @Test
    fun liveSnapshotSyncGateAvoidsSteadyStateChurnAndRespondsToRevisions() {
        val telemetryJson = """
            {
              "running": true,
              "mode": "rule",
              "routerEpoch": 3,
              "delaysRevision": 7,
              "effectiveOutbound": "HK-Node-01",
              "effectiveProtocol": "VLESS",
              "upTotal": 12000,
              "downTotal": 88000,
              "rssBytes": 42000000
            }
        """.trimIndent()
        val tel = UiJsonParsers.parseLiveTelemetry(telemetryJson)
        assertTrue(tel.running)
        assertEquals(3L, tel.routerEpoch)
        assertEquals(7L, tel.delaysRevision)
        assertEquals(42_000_000L, tel.rssBytes)

        val snapJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "routerEpoch": 3,
              "delaysRevision": 7,
              "activeProfileId": "default",
              "mode": "rule",
              "primaryGroup": "PROXY",
              "effectiveOutbound": "HK-Node-01",
              "effectiveProtocol": "VLESS"
            }
        """.trimIndent()
        val snap = UiJsonParsers.parseNodeManagerSnapshot(snapJson)
        assertTrue(snap.ok)
        assertTrue(snap.vpnRunning)
        assertEquals(3L, snap.routerEpoch)
        assertEquals(7L, snap.delaysRevision)

        // Steady-state browsing on HOME: traffic advances (100_000 != 50_000), but routerEpoch & delaysRevision match -> NO snapshot rebuild!
        assertFalse(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.HOME,
                telemetry = tel,
                lastSyncedRouterEpoch = 3L,
                lastSyncedDelaysRevision = 7L,
                lastRulesSyncedTrafficTotal = 50_000L,
            ),
        )

        // Router hot-reload (routerEpoch 3 != 2) -> MUST sync on any destination
        assertTrue(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.SETTINGS,
                telemetry = tel,
                lastSyncedRouterEpoch = 2L,
                lastSyncedDelaysRevision = 7L,
                lastRulesSyncedTrafficTotal = 100_000L,
            ),
        )

        // Delay probe update (delaysRevision 7 != 6) -> syncs on HOME and NODES, skips on SETTINGS
        assertTrue(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.NODES,
                telemetry = tel,
                lastSyncedRouterEpoch = 3L,
                lastSyncedDelaysRevision = 6L,
                lastRulesSyncedTrafficTotal = 100_000L,
            ),
        )
        assertFalse(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.SETTINGS,
                telemetry = tel,
                lastSyncedRouterEpoch = 3L,
                lastSyncedDelaysRevision = 6L,
                lastRulesSyncedTrafficTotal = 100_000L,
            ),
        )

        // RULES tab: syncs when traffic total advances (rule hits changed), skips when traffic is idle
        assertTrue(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.RULES,
                telemetry = tel,
                lastSyncedRouterEpoch = 3L,
                lastSyncedDelaysRevision = 7L,
                lastRulesSyncedTrafficTotal = 50_000L,
            ),
        )
        assertFalse(
            UiJsonParsers.shouldSyncLiveSnapshot(
                dest = io.github.rustclashlabs.rustclash.ui.model.MainDestination.RULES,
                telemetry = tel,
                lastSyncedRouterEpoch = 3L,
                lastSyncedDelaysRevision = 7L,
                lastRulesSyncedTrafficTotal = 100_000L,
            ),
        )
    }

    @Test
    fun debugSliceReportRendersDnsResolverCacheHitsFromSnapshotJson() {
        val window = io.github.rustclashlabs.rustclash.vpn.DebugLogManager.WindowTelemetryState(
            windowStartMs = 1_731_150_000_000L,
            capturedAtMs = 1_731_150_900_000L,
            sessionStartMs = 1_731_149_000_000L,
            screenOnMs = 600_000L,
            screenOffMs = 300_000L,
            startBatteryPct = 85,
            events = emptyList(),
        )
        val meta = io.github.rustclashlabs.rustclash.vpn.DebugLogManager.SystemMetadata(
            deviceManufacturer = "Google",
            deviceModel = "Pixel 8",
            androidRelease = "15",
            sdkInt = 35,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.4.3",
            appVersionCode = 19,
            battery = io.github.rustclashlabs.rustclash.vpn.DebugLogManager.BatterySnapshot(
                levelPct = 84,
                isCharging = false,
                temperatureCelsius = 31.5,
            ),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 16L * 1024L * 1024L,
            jvmMaxBytes = 256L * 1024L * 1024L,
            nativeHeapBytes = 24L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )
        val snapshotJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "mode": "rule",
              "routingPreset": "smart-cn",
              "effectiveOutbound": "HK-Node-01",
              "effectiveProtocol": "VLESS",
              "effectiveDelayMs": 42,
              "uptimeSecs": 900,
              "networkTransitions": 1,
              "isWifi": true,
              "dns": {
                "total_queries": 120,
                "fake_ip_hits": 75,
                "cache_hits": 30,
                "resolver_cache_hits": 19,
                "resolverCacheHits": 19,
                "suppressed_queries": 4,
                "nxdomain_hits": 2,
                "upstream_queries": 26,
                "upstream_errors": 0,
                "upstream_avg_ms": 28,
                "upstream_max_ms": 91,
                "active_fake_ip_entries": 64
              }
            }
        """.trimIndent()

        val report = io.github.rustclashlabs.rustclash.vpn.DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = meta,
            nativeSnapshotRawJson = snapshotJson,
            crashBreadcrumb = null,
        )
        assertTrue(
            "Expected DNS & Fake-IP line to include wireCacheHits and resolverCacheHits: $report",
            report.contains(
                "- DNS & Fake-IP: queries=`120` fakeIpHits=`75` wireCacheHits=`30` resolverCacheHits=`19` " +
                    "aaaaSuppressed=`4` nxdomainCached=`2` upstreamQueries=`26` upstreamErrors=`0` " +
                    "upstreamAvgMs=`28ms` upstreamMaxMs=`91ms` activeFakeIps=`64`",
            ),
        )

        val snakeOnlyJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "dns": {
                "total_queries": 10,
                "fake_ip_hits": 4,
                "cache_hits": 3,
                "resolver_cache_hits": 7,
                "suppressed_queries": 0,
                "upstream_queries": 3,
                "upstream_errors": 0,
                "upstream_avg_ms": 15,
                "upstream_max_ms": 20,
                "active_fake_ip_entries": 4
              }
            }
        """.trimIndent()
        val snakeOnlyReport = io.github.rustclashlabs.rustclash.vpn.DebugLogManager.formatSliceReport(
            trigger = "manual",
            window = window,
            systemMeta = meta,
            nativeSnapshotRawJson = snakeOnlyJson,
            crashBreadcrumb = null,
        )
        assertTrue(
            "Expected snake_case resolver_cache_hits fallback to render accurately: $snakeOnlyReport",
            snakeOnlyReport.contains("wireCacheHits=`3` resolverCacheHits=`7` aaaaSuppressed=`0`"),
        )
    }

    @Test
    fun underlyingNetworkTrackerHandlesConcurrentCellularWifiHandoffRssiAndFallback() {
        val netTracker = UnderlyingNetworkTracker()

        // 1. Initial Cellular baseline (handle=101, isCellular=true, isValidated=true, hasIpv6=true)
        val initCell = netTracker.onUnderlyingCandidate(
            networkHandle = 101L,
            isVpnTransport = false,
            isWifi = false,
            isCellular = true,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = true,
        )
        assertTrue(initCell.updateUnderlyingNetworks)
        assertFalse(initCell.triggerSessionRecovery)
        assertTrue(initCell.notifyNative)
        assertTrue(initCell.syncInitialBaselineToNative)
        assertEquals(101L, initCell.effectiveHandle)
        assertFalse(initCell.isWifi)
        assertTrue(initCell.hasIpv6)

        // 2. Concurrent IPv4-only Wi-Fi (handle=202) connects while Cellular (101) remains in candidates
        val wifiHandoff = netTracker.onUnderlyingCandidate(
            networkHandle = 202L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = false,
        )
        assertTrue(wifiHandoff.updateUnderlyingNetworks)
        assertTrue(wifiHandoff.triggerSessionRecovery)
        assertTrue(wifiHandoff.notifyNative)
        assertFalse(wifiHandoff.syncInitialBaselineToNative)
        assertEquals(202L, wifiHandoff.effectiveHandle)
        assertTrue(wifiHandoff.isWifi)
        assertFalse(wifiHandoff.hasIpv6)

        // 3. Background Cellular RSSI onCapabilitiesChanged(101) must NOT steal active handle from Wi-Fi (202)
        val cellRssi = netTracker.onUnderlyingCandidate(
            networkHandle = 101L,
            isVpnTransport = false,
            isWifi = false,
            isCellular = true,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = true,
        )
        assertFalse(cellRssi.updateUnderlyingNetworks)
        assertFalse(cellRssi.triggerSessionRecovery)
        assertFalse(cellRssi.notifyNative)
        assertEquals(202L, cellRssi.effectiveHandle)
        assertTrue(cellRssi.isWifi)
        assertFalse(cellRssi.hasIpv6)

        // 4. Losing Wi-Fi (202) immediately promotes still-connected Cellular (101) without dropping to 0L
        val fallbackCell = netTracker.onNetworkLost(202L)
        assertTrue(fallbackCell.updateUnderlyingNetworks)
        assertTrue(fallbackCell.triggerSessionRecovery)
        assertTrue(fallbackCell.notifyNative)
        assertEquals(101L, fallbackCell.effectiveHandle)
        assertFalse(fallbackCell.isWifi)
        assertTrue(fallbackCell.hasIpv6)
    }

    @Test
    fun underlyingNetworkTrackerUnvalidatedCaptivePortalWifiDoesNotClobberValidatedCellular() {
        val netTracker = UnderlyingNetworkTracker()

        // Validated Cellular (101) establishes baseline
        val initCell = netTracker.onUnderlyingCandidate(
            networkHandle = 101L,
            isVpnTransport = false,
            isWifi = false,
            isCellular = true,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = true,
        )
        assertEquals(101L, initCell.effectiveHandle)
        assertFalse(initCell.isWifi)

        // Unvalidated captive-portal Wi-Fi (202, isValidated=false) must NOT clobber working Cellular (101)
        val captiveWifi = netTracker.onUnderlyingCandidate(
            networkHandle = 202L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = false,
            hasIpv6 = false,
        )
        assertFalse(captiveWifi.updateUnderlyingNetworks)
        assertFalse(captiveWifi.triggerSessionRecovery)
        assertFalse(captiveWifi.notifyNative)
        assertEquals(101L, captiveWifi.effectiveHandle)
        assertFalse(captiveWifi.isWifi)
        assertTrue(captiveWifi.hasIpv6)

        // Once captive portal completes login and Wi-Fi becomes validated, Wi-Fi (202) wins cleanly
        val validatedWifi = netTracker.onUnderlyingCandidate(
            networkHandle = 202L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = false,
        )
        assertTrue(validatedWifi.updateUnderlyingNetworks)
        assertTrue(validatedWifi.triggerSessionRecovery)
        assertTrue(validatedWifi.notifyNative)
        assertEquals(202L, validatedWifi.effectiveHandle)
        assertTrue(validatedWifi.isWifi)
        assertFalse(validatedWifi.hasIpv6)
    }

    @Test
    fun underlyingNetworkTrackerLinkPropertiesIpv6LossAndGainAndGlobalUnicastCheck() {
        val netTracker = UnderlyingNetworkTracker()

        val initWifi = netTracker.onUnderlyingCandidate(
            networkHandle = 202L,
            isVpnTransport = false,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = true,
            hasIpv6 = true,
        )
        assertEquals(202L, initWifi.effectiveHandle)
        assertTrue(initWifi.hasIpv6)

        // Losing global IPv6 (true -> false) on active handle notifies native AND triggers session recovery
        val lostV6 = netTracker.onLinkPropertiesIpv6Changed(networkHandle = 202L, hasIpv6 = false)
        assertFalse(lostV6.updateUnderlyingNetworks)
        assertTrue(lostV6.notifyNative)
        assertTrue(lostV6.triggerSessionRecovery)
        assertEquals(202L, lostV6.effectiveHandle)
        assertFalse(lostV6.hasIpv6)

        // Duplicate false is ignored
        val dupFalse = netTracker.onLinkPropertiesIpv6Changed(networkHandle = 202L, hasIpv6 = false)
        assertFalse(dupFalse.notifyNative)
        assertFalse(dupFalse.triggerSessionRecovery)

        // Gaining global IPv6 (false -> true) notifies native WITHOUT tearing down healthy IPv4 sessions
        val gainedV6 = netTracker.onLinkPropertiesIpv6Changed(networkHandle = 202L, hasIpv6 = true)
        assertFalse(gainedV6.updateUnderlyingNetworks)
        assertTrue(gainedV6.notifyNative)
        assertFalse(gainedV6.triggerSessionRecovery)
        assertEquals(202L, gainedV6.effectiveHandle)
        assertTrue(gainedV6.hasIpv6)

        // RFC 4291 2000::/3 Global Unicast classifier accepts public IPv6 and rejects link-local / ULA / v4
        assertTrue(isGlobalUnicastIpv6Address(InetAddress.getByName("2408:8207:1234::1")))
        assertTrue(isGlobalUnicastIpv6Address(InetAddress.getByName("2001:4860:4860::8888")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("fe80::1")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("fd00::1")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("fc00::1")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("::1")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("::")))
        assertFalse(isGlobalUnicastIpv6Address(InetAddress.getByName("198.18.0.1")))
    }

    @Test
    fun vpnRoutePlannerExcludesPrivateLanMulticastLoopbackAndNeverEmitsBadAddressAcrossApiLevels() {
        fun matchesTun(ip: String, plan: VpnRoutePlan): Boolean =
            VpnRoutePlanner.matchesTun(ip, plan)

        // Simulate AOSP `android.net.VpnService.check(InetAddress, int)` + `IpPrefix` rules
        fun assertAospVpnBuilderSafe(route: io.github.rustclashlabs.rustclash.vpn.CidrRoute) {
            val addr = InetAddress.getByName(route.address)
            assertFalse(
                "Route ${route.cidr} is loopback and would throw IllegalArgumentException(\"Bad address\") in VpnService.Builder!",
                addr.isLoopbackAddress,
            )
            if (route.prefixLength > 0) {
                assertFalse("Route ${route.cidr} must not be unspecified/anyLocal", addr.isAnyLocalAddress)
                assertFalse("Route ${route.cidr} must not be link-local", addr.isLinkLocalAddress)
                assertFalse("Route ${route.cidr} must not be multicast", addr.isMulticastAddress)
            }
            assertTrue(
                "Route ${route.cidr} failed VpnRoutePlanner.isValidVpnBuilderRoute()",
                VpnRoutePlanner.isValidVpnBuilderRoute(route),
            )
        }

        // Regression guard for v0.4.5 P0 bug: loopback / unspecified / link-local / multicast prefixes MUST be rejected
        for (bad in listOf(
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("127.0.0.0", 8),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("127.0.0.1", 32),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("::1", 128),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("0.0.0.0", 8),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("::", 128),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("169.254.0.0", 16),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("fe80::", 10),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("224.0.0.0", 4),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("ff00::", 8),
            io.github.rustclashlabs.rustclash.vpn.CidrRoute("198.18.0.1", 15), // non-zero host bit
        )) {
            assertFalse(
                "Expected ${bad.cidr} to be rejected by isValidVpnBuilderRoute",
                VpnRoutePlanner.isValidVpnBuilderRoute(bad),
            )
        }

        val defaultCfg = VpnSessionConfig(enableIpv6 = true).validated()
        val api37Plan = VpnRoutePlanner.buildPlan(defaultCfg, sdkInt = 37)
        val api33Plan = VpnRoutePlanner.buildPlan(defaultCfg, sdkInt = 33)
        val api32Plan = VpnRoutePlanner.buildPlan(defaultCfg, sdkInt = 32)
        val api26Plan = VpnRoutePlanner.buildPlan(defaultCfg, sdkInt = 26)

        assertFalse(api37Plan.useExcludeRoutes)
        assertFalse(api33Plan.useExcludeRoutes)
        assertFalse(api32Plan.useExcludeRoutes)
        assertFalse(api26Plan.useExcludeRoutes)
        assertTrue(api37Plan.excludedIpv4.isEmpty())
        assertTrue(api37Plan.excludedIpv6.isEmpty())
        assertEquals(api37Plan, api33Plan)
        assertEquals(api33Plan, api32Plan)
        assertEquals(api32Plan, api26Plan)

        // Verify every emitted route passes AOSP VpnService.Builder checks and partitions 2^32 IPv4 space cleanly
        var includedIpCount = 0L
        var prevEnd: UInt? = null
        for (route in api37Plan.includedIpv4) {
            assertAospVpnBuilderSafe(route)
            val canonical = VpnRoutePlanner.canonicalizeIpv4Cidr(route.address, route.prefixLength)
            assertEquals("Route ${route.cidr} must have zero host bits", canonical, route)
            val range = VpnRoutePlanner.cidrToIpv4Range(route)!!
            if (prevEnd != null) {
                assertTrue("Included IPv4 routes must be strictly disjoint and sorted", prevEnd < range.first)
            }
            prevEnd = range.last
            includedIpCount += (1L shl (32 - route.prefixLength))
        }
        for (route in api37Plan.includedIpv6) {
            assertAospVpnBuilderSafe(route)
        }
        val excludedIpCount = VpnRoutePlanner.EXCLUDED_IPV4_PREFIXES.sumOf { 1L shl (32 - it.prefixLength) }
        assertEquals(1L shl 32, includedIpCount + excludedIpCount)

        val mustRouteIntoTunIpv4 = listOf(
            "198.18.0.1",     // TUN IPv4
            "198.18.0.42",    // Fake-IP
            "198.19.255.254", // TUN DNS
            "198.17.255.255",
            "198.20.0.1",
            "1.1.1.1",
            "8.8.8.8",
            "223.5.5.5",
            "36.155.182.57",
            "100.64.0.1",
            "172.15.255.254",
            "172.32.0.1",
            "192.167.255.254",
            "192.169.0.1",
        )
        val mustExcludeFromTunIpv4 = listOf(
            "192.168.0.1",
            "192.168.1.1",
            "192.168.31.254",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "127.0.0.1",
            "169.254.10.20",
            "224.0.0.251",     // mDNS
            "239.255.255.250", // SSDP
            "240.0.0.1",       // Class E reserved
            "255.255.255.255", // Limited broadcast
            "0.0.0.0",
        )

        for ((label, plan) in listOf("API37" to api37Plan, "API33" to api33Plan, "API26" to api26Plan)) {
            for (ip in mustRouteIntoTunIpv4) {
                assertTrue("[$label] Expected $ip to route into tun0", matchesTun(ip, plan))
            }
            for (ip in mustExcludeFromTunIpv4) {
                assertFalse("[$label] Expected $ip to be excluded from tun0", matchesTun(ip, plan))
            }

            // IPv6 inclusion & exclusion parity across API 26–37+
            for (v6In in listOf("2409:8c1e::1", "2606:4700:4700::1111", "fdfe:dcba:9876::1", "fdfe:dcba:9876::2")) {
                assertTrue("[$label] Expected IPv6 $v6In to route into tun0", matchesTun(v6In, plan))
            }
            for (v6Ex in listOf("::", "::1", "fe80::1", "ff02::fb", "fd00::1")) {
                assertFalse("[$label] Expected IPv6 $v6Ex to be excluded from tun0", matchesTun(v6Ex, plan))
            }
        }

        // IPv4-only session disables all IPv6 routes cleanly
        val v4OnlyCfg = VpnSessionConfig(enableIpv6 = false).validated()
        for (sdk in listOf(28, 34, 37)) {
            val v4Plan = VpnRoutePlanner.buildPlan(v4OnlyCfg, sdkInt = sdk)
            assertTrue(v4Plan.includedIpv6.isEmpty())
            assertTrue(v4Plan.excludedIpv6.isEmpty())
            assertFalse(matchesTun("2409:8c1e::1", v4Plan))
            assertTrue(matchesTun("198.18.0.42", v4Plan))
        }
    }

    @Test
    fun vpnRoutePlannerNeverExcludesCustomSessionTunSubnetOrDnsIpv4AndNeverEmitsLoopback() {
        val customCfg = VpnSessionConfig(
            ipv4Address = "10.0.0.1",
            ipv4PrefixLength = 24,
            dnsIpv4 = "192.168.50.53",
            enableIpv6 = true,
        ).validated()

        for (sdk in listOf(29, 34, 37)) {
            val plan = VpnRoutePlanner.buildPlan(customCfg, sdkInt = sdk)
            assertTrue("sdk=$sdk must route custom TUN address", plan.matchesTun("10.0.0.1"))
            assertTrue("sdk=$sdk must route custom TUN subnet peer", plan.matchesTun("10.0.0.42"))
            assertTrue("sdk=$sdk must route custom TUN DNS IPv4", plan.matchesTun("192.168.50.53"))
            assertFalse("sdk=$sdk must still exclude outside 10.0.0.0/24", plan.matchesTun("10.0.1.1"))
            assertFalse("sdk=$sdk must still exclude outside 192.168.50.53/32", plan.matchesTun("192.168.1.1"))
            for (r in plan.includedIpv4 + plan.includedIpv6) {
                assertTrue("Route ${r.cidr} must pass VpnService.Builder check", VpnRoutePlanner.isValidVpnBuilderRoute(r))
            }
        }

        // Even if a caller constructs a bogus loopback session config, buildPlan must NEVER emit a loopback route!
        val bogusLoopbackCfg = VpnSessionConfig(
            ipv4Address = "127.0.0.1",
            ipv4PrefixLength = 8,
            dnsIpv4 = "127.0.0.53",
            ipv6Address = "::1",
            ipv6PrefixLength = 126,
            enableIpv6 = true,
        )
        val safePlan = VpnRoutePlanner.buildPlan(bogusLoopbackCfg, sdkInt = 37)
        assertFalse(safePlan.matchesTun("127.0.0.1"))
        assertFalse(safePlan.matchesTun("::1"))
        for (r in safePlan.includedIpv4 + safePlan.includedIpv6) {
            assertTrue("Route ${r.cidr} must pass VpnService.Builder check", VpnRoutePlanner.isValidVpnBuilderRoute(r))
        }
    }

    @Test
    fun mainstreamProtocolsDeepLinkExtractionAndSnapshotParsingSupportVmessRealityHy2AndTuic() {
        for (uri in listOf(
            "vmess://eyJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCJ9",
            "hysteria2://hy2-secret@hy2.example.com:443?sni=hy2.example.com&mport=20000-50000#HK-Hy2",
            "hy2://hy2-secret@hy2.example.com:443?obfs=salamander&obfs-password=obfs-pass#SG-Hy2",
            "TUIC://550e8400-e29b-41d4-a716-446655440000:tuic-pass@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native#JP-TUIC",
        )) {
            assertEquals(
                uri,
                NodeImportSupport.extractImportPayloadFromIntent(
                    action = "android.intent.action.VIEW",
                    mimeType = null,
                    extraText = null,
                    dataUriString = uri,
                ),
            )
        }

        val rawSnapshotJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "effectiveOutbound": "HK-Hy2",
              "effectiveProtocol": "hysteria2",
              "nodes": [
                {
                  "name": "TOKYO-REALITY",
                  "type": "vless",
                  "server": "jp.example.com",
                  "port": 443,
                  "flow": "xtls-rprx-vision",
                  "servername": "www.microsoft.com",
                  "client-fingerprint": "chrome",
                  "reality-opts": {
                    "public-key": "***REDACTED***",
                    "short-id": "***REDACTED***"
                  }
                },
                {
                  "name": "US-VMess-WS",
                  "type": "vmess",
                  "server": "us.example.com",
                  "port": 443,
                  "cipher": "auto",
                  "tls": true,
                  "network": "ws",
                  "ws-opts": { "path": "/vmess" }
                },
                {
                  "name": "HK-Hy2",
                  "type": "hy2",
                  "server": "hk.example.com",
                  "port": 443,
                  "ports": "20000-40000",
                  "obfs": "salamander"
                },
                {
                  "name": "SG-TUIC",
                  "type": "tuic",
                  "server": "sg.example.com",
                  "port": 443,
                  "udp-relay-mode": "quic",
                  "congestion-controller": "bbr",
                  "zero-rtt-handshake": true
                }
              ],
              "groups": []
            }
        """.trimIndent()

        val snap = UiJsonParsers.parseNodeManagerSnapshot(rawSnapshotJson)
        assertTrue(snap.ok)
        assertEquals(4, snap.nodes.size)
        val uiState = AppUiState(
            effectiveOutbound = snap.effectiveOutbound,
            effectiveProtocol = snap.effectiveProtocol,
            nodes = snap.nodes,
        )
        assertEquals("Hy2", uiState.effectiveProtocolDisplay)
        assertEquals(
            "VMess",
            AppUiState(effectiveOutbound = "MissingNode", effectiveProtocol = "vmess").effectiveProtocolDisplay,
        )
        assertEquals(
            "TUIC",
            AppUiState(effectiveOutbound = "MissingNode", effectiveProtocol = "tuic").effectiveProtocolDisplay,
        )

        val realityNode = snap.nodes[0]
        assertTrue(realityNode.realityEnabled)
        assertEquals("xtls-rprx-vision", realityNode.flow)
        assertEquals("VLESS·REALITY", realityNode.protocolShortBadge)
        assertEquals("VLESS", realityNode.protocolDisplay)

        val vmessNode = snap.nodes[1]
        assertEquals("VMess·WS", vmessNode.protocolShortBadge)
        assertEquals("VMess", vmessNode.protocolDisplay)
        assertEquals("/vmess", vmessNode.wsPath)

        val hy2Node = snap.nodes[2]
        assertEquals("hysteria2", hy2Node.type)
        assertEquals("Hy2", hy2Node.protocolShortBadge)
        assertEquals("Hysteria2", hy2Node.protocolDisplay)
        assertEquals("20000-40000", hy2Node.ports)
        assertEquals("salamander", hy2Node.obfs)

        val tuicNode = snap.nodes[3]
        assertEquals("TUIC", tuicNode.protocolShortBadge)
        assertEquals("TUIC v5", tuicNode.protocolDisplay)
        assertEquals("quic", tuicNode.udpRelayMode)
        assertEquals("bbr", tuicNode.congestionController)
        assertTrue(tuicNode.zeroRttHandshake)
    }

    @Test
    fun freshStatusSnapshotReuseWindowPreventsDuplicateForegroundJniPolling() {
        try {
            RustClashVpnService.clearFreshStatusSnapshot()
            assertEquals(0L, RustClashVpnService.latestStatusUpdatedAtMs)
            assertFalse(RustClashVpnService.shouldReuseFreshStatus(nowMs = 10_000L, lastUpdatedMs = 0L))

            val token = 101L
            RustClashVpnService.activeNativeSessionToken.set(token)
            RustClashVpnService.stateTracker.onRunning()

            val sample = "{\"running\":true,\"downRate\":12345,\"upRate\":678}"
            assertTrue(
                RustClashVpnService.publishFreshStatusSnapshot(
                    rawJson = sample,
                    expectedToken = token,
                    nowMs = 50_000L,
                ),
            )
            assertEquals(sample, RustClashVpnService.latestStatusJson)
            assertEquals(50_000L, RustClashVpnService.latestStatusUpdatedAtMs)

            // Fresh within 2.5s window -> reuse without duplicate JNI call
            assertTrue(RustClashVpnService.shouldReuseFreshStatus(nowMs = 50_000L, lastUpdatedMs = 50_000L))
            assertTrue(RustClashVpnService.shouldReuseFreshStatus(nowMs = 51_200L, lastUpdatedMs = 50_000L))
            assertTrue(RustClashVpnService.shouldReuseFreshStatus(nowMs = 52_500L, lastUpdatedMs = 50_000L))

            // Expired past 2.5s or backward clock skew -> poll fresh from JNI
            assertFalse(RustClashVpnService.shouldReuseFreshStatus(nowMs = 52_501L, lastUpdatedMs = 50_000L))
            assertFalse(RustClashVpnService.shouldReuseFreshStatus(nowMs = 49_999L, lastUpdatedMs = 50_000L))

            RustClashVpnService.clearFreshStatusSnapshot()
            assertEquals("{\"running\":false}", RustClashVpnService.latestStatusJson)
            assertEquals(0L, RustClashVpnService.latestStatusUpdatedAtMs)
        } finally {
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.clearError()
            RustClashVpnService.stateTracker.onStopped()
            RustClashVpnService.clearFreshStatusSnapshot()
        }
    }

    @Test
    fun exitIpParserAndDisplayHelpersHandleVerifiedDemoFailedAndSnakeCase() {
        val verifiedJson = """
            {
              "ok": true,
              "verified": true,
              "demoMode": false,
              "ip": "203.0.113.42",
              "country": "Singapore",
              "countryCode": "SG",
              "isp": "DigitalOcean LLC",
              "asn": "AS14061",
              "ipType": "Datacenter / Hosting",
              "latencyMs": 124,
              "outbound": "SG-Edge-01",
              "protocol": "vless",
              "mode": "rule",
              "vpnRunning": true,
              "checkedAtMs": 1700000000000,
              "cached": false,
              "error": null
            }
        """.trimIndent()
        val verified = UiJsonParsers.parseExitIpResponse(verifiedJson)
        assertNotNull(verified)
        assertTrue(verified!!.verified)
        assertEquals("203.0.113.42", verified.ip)
        assertEquals("🇸🇬", verified.flagEmoji)
        assertEquals("新加坡", verified.countryDisplayZh)
        assertEquals("🇸🇬 新加坡", verified.countryWithFlag)
        assertEquals("数据中心 / 机房 IP", verified.ipTypeDisplayZh)
        assertEquals("🇸🇬 新加坡 · 203.0.113.42", verified.compactPillText)
        assertEquals(124L, verified.latencyMs)
        assertEquals("AS14061", verified.asn)
        assertNull(verified.error)

        val demoJson = """
            {
              "ok": true,
              "verified": true,
              "demoMode": true,
              "ip": "198.51.100.42",
              "country": "Demo Sandbox",
              "countryCode": "SG",
              "ipType": "Sandbox",
              "latencyMs": 18
            }
        """.trimIndent()
        val demo = UiJsonParsers.parseExitIpResponse(demoJson)
        assertNotNull(demo)
        assertTrue(demo!!.demoMode)
        assertEquals("新加坡（沙盒）", demo.countryDisplayZh)
        assertEquals("本地沙盒演示", demo.ipTypeDisplayZh)
        assertEquals("🇸🇬 新加坡（沙盒） · 198.51.100.42", demo.compactPillText)

        val snakeFailedJson = """
            {
              "ok": true,
              "verified": false,
              "ip": "--",
              "country_code": "jp",
              "ip_type": "blocked",
              "latency_ms": null,
              "error": "Outbound 'REJECT' blocks egress traffic"
            }
        """.trimIndent()
        val failed = UiJsonParsers.parseExitIpResponse(snakeFailedJson)
        assertNotNull(failed)
        assertFalse(failed!!.verified)
        assertEquals("🇯🇵", failed.flagEmoji)
        assertEquals("已拦截 (REJECT)", failed.ipTypeDisplayZh)
        assertEquals("落地 IP 检测失败 · 点击重试", failed.compactPillText)
        assertNotNull(failed.error)

        val errObj = UiJsonParsers.parseExitIpResponse("""{"ok":false,"error":"probe timeout"}""")
        assertNotNull(errObj)
        assertFalse(errObj!!.verified)
        assertEquals("probe timeout", errObj.error)

        val directManual = ExitIpUi(verified = true, ip = "198.51.100.9", country = "Japan", countryCode = "JP", ipType = "ISP / Broadband")
        assertEquals("运营商 / 宽带 IP", directManual.ipTypeDisplayZh)
        assertEquals("🇯🇵 日本 · 198.51.100.9", directManual.compactPillText)
    }

    @Test
    fun vpnServiceLifecycleCoordinatorRecoversAfterOnRevokeOnReusedServiceInstance() {
        val coord = VpnServiceLifecycleCoordinator()

        // 1. First session starts cleanly
        val startEpoch1 = coord.onStartRequested(startCommandId = 1)
        assertTrue(startEpoch1 > 0L)
        assertEquals(1, coord.lastDeliveredCommandId)
        assertFalse(coord.isDestroyed)
        assertFalse(coord.isRevokedForCurrentSession)
        assertFalse(coord.isStartSupersededOrCancelled(startEpoch1, startCommandId = 1))

        // 2. Android invokes onRevoke() -> cancels session 1 & captures commandId=1; duplicate onRevoke() is deduplicated
        val revoke1 = coord.onRevokeRequested()
        assertNotNull(revoke1)
        assertTrue(revoke1!!.epoch > startEpoch1)
        assertEquals(1, revoke1.capturedCommandId)
        assertTrue(coord.isRevokedForCurrentSession)
        assertTrue(coord.isStartSupersededOrCancelled(startEpoch1, startCommandId = 1))
        assertTrue(coord.shouldFinalizeFailedOrAbortedStart(startEpoch1, startCommandId = 1))
        assertNull("Duplicate onRevoke() in the same session must be deduplicated", coord.onRevokeRequested())
        assertFalse(coord.isStopSupersededByNewerStart(revoke1.epoch))

        // 3. Reused Service instance receives new ACTION_START_VPN before onDestroy() -> MUST NOT stay poisoned!
        val startEpoch2 = coord.onStartRequested(startCommandId = 2)
        assertTrue(startEpoch2 > revoke1.epoch)
        assertEquals(2, coord.lastDeliveredCommandId)
        assertFalse(coord.isRevokedForCurrentSession)
        assertFalse(coord.isStartSupersededOrCancelled(startEpoch2, startCommandId = 2))
        assertTrue(
            "Stale revoke teardown must recognize it was superseded by newer ACTION_START_VPN",
            coord.isStopSupersededByNewerStart(revoke1.epoch),
        )
        assertTrue(coord.hasPendingNewerStart(startEpoch1))
        assertFalse(
            "Aborted start #1 must NOT clobber newer start #2's foreground notification",
            coord.shouldFinalizeFailedOrAbortedStart(startEpoch1, startCommandId = 1),
        )

        // 4. Subsequent onRevoke() on the NEW session #2 must NOT be dropped by session #1's revoke!
        val revoke2 = coord.onRevokeRequested()
        assertNotNull(revoke2)
        assertTrue(revoke2!!.epoch > startEpoch2)
        assertEquals(2, revoke2.capturedCommandId)
        assertTrue(coord.isRevokedForCurrentSession)
        assertTrue(coord.isStartSupersededOrCancelled(startEpoch2, startCommandId = 2))

        // 5. onDestroy() permanently blocks any further start or revoke on the destroyed instance
        val destroyEpoch = coord.onDestroy()
        assertTrue(destroyEpoch > revoke2.epoch)
        assertTrue(coord.isDestroyed)
        assertEquals(0L, coord.onStartRequested(startCommandId = 3))
        assertNull(coord.onRevokeRequested())
        assertTrue(coord.isStartSupersededOrCancelled(startEpoch2, startCommandId = 2))
        assertFalse(coord.hasPendingNewerStart(startEpoch1))
    }

    @Test
    fun onRevokeRequestedCapturesDeliveredCommandIdAndAvoidsUnconditionalStopSelfRace() {
        // 1. Pure BIND_VPN_SERVICE startup (no onStartCommand delivered): capturedCommandId == 0
        //    must still clear foreground notification & state WITHOUT invoking unconditional stopSelf(),
        //    even if onStartCommand(startId = 1) races in right after notificationLock release.
        val bindOnlyCoord = VpnServiceLifecycleCoordinator()
        val bindOnlyTracker = VpnStateTracker()
        val bindOnlyLock = Any()
        assertEquals(0, bindOnlyCoord.lastDeliveredCommandId)
        val bindRevoke = bindOnlyCoord.onRevokeRequested()
        assertNotNull(bindRevoke)
        assertEquals(0, bindRevoke!!.capturedCommandId)
        bindOnlyTracker.onSystemRevoked()

        var bindSessionCleared = false
        var bindForegroundCleared = false
        var bindTileSynced = false
        var stopSelfWithResultCalls = 0
        val bindFinalized = RustClashVpnService.finalizeStopSession(
            notificationLock = bindOnlyLock,
            coordinator = bindOnlyCoord,
            stateTracker = bindOnlyTracker,
            expectedEpoch = bindRevoke.epoch,
            supersededAtEntry = false,
            stopStartId = bindRevoke.capturedCommandId.takeIf { it > 0 },
            isCurrentOrIdleGlobalSession = { true },
            onClearSessionState = { bindSessionCleared = true },
            stopForegroundAndClearNotification = { bindForegroundCleared = true },
            requestTileSync = {
                bindTileSynced = true
                // Simulate onStartCommand(startId = 1) arriving immediately after notificationLock
                // release while finalizeStopSession is about to complete outside the lock.
                val start1Reg = RustClashVpnService.registerStartAndPromoteForeground(
                    notificationLock = bindOnlyLock,
                    coordinator = bindOnlyCoord,
                    stateTracker = bindOnlyTracker,
                    startCommandId = 1,
                    promoteForeground = { true },
                    fgsRestrictedErrorMessage = "fgs restricted",
                )
                assertTrue(start1Reg.startEpoch > bindRevoke.epoch)
                assertTrue(start1Reg.promoted)
            },
            stopSelfWithResult = {
                stopSelfWithResultCalls++
                true
            },
        )
        assertTrue(bindFinalized)
        assertTrue(bindSessionCleared)
        assertTrue(bindForegroundCleared)
        assertTrue(bindTileSynced)
        assertEquals(
            "Pure BIND_VPN_SERVICE revoke (capturedCommandId == 0) must NEVER call stopSelf/stopSelfResult",
            0,
            stopSelfWithResultCalls,
        )
        assertEquals(VpnLifecycleState.STARTING, bindOnlyTracker.state)

        // 2. Normal start(1) -> onRevoke() captures commandId=1; concurrent start(2) supersedes stop finalization
        val coord = VpnServiceLifecycleCoordinator()
        val tracker = VpnStateTracker()
        val lock = Any()
        val start1 = coord.onStartRequested(startCommandId = 1)
        assertTrue(start1 > 0L)
        tracker.onStartRequested()
        tracker.onRunning()

        val revoke1 = coord.onRevokeRequested()
        assertNotNull(revoke1)
        assertEquals(1, revoke1!!.capturedCommandId)
        tracker.onSystemRevoked()

        // Concurrent onStartCommand(ACTION_START_VPN, startId = 2) arrives before stop finalization
        val start2Reg = RustClashVpnService.registerStartAndPromoteForeground(
            notificationLock = lock,
            coordinator = coord,
            stateTracker = tracker,
            startCommandId = 2,
            promoteForeground = { true },
            fgsRestrictedErrorMessage = "fgs restricted",
        )
        assertTrue(start2Reg.startEpoch > revoke1.epoch)
        assertTrue(start2Reg.promoted)
        assertTrue(coord.isStopSupersededByNewerStart(revoke1.epoch))
        assertEquals(VpnLifecycleState.STARTING, tracker.state)

        var foregroundCleared = false
        var stopResultArg: Int? = null
        val supersededFinalized = RustClashVpnService.finalizeStopSession(
            notificationLock = lock,
            coordinator = coord,
            stateTracker = tracker,
            expectedEpoch = revoke1.epoch,
            supersededAtEntry = false,
            stopStartId = revoke1.capturedCommandId.takeIf { it > 0 },
            isCurrentOrIdleGlobalSession = { true },
            onClearSessionState = {},
            stopForegroundAndClearNotification = { foregroundCleared = true },
            requestTileSync = {},
            stopSelfWithResult = { cmdId ->
                stopResultArg = cmdId
                true
            },
        )
        assertFalse("Superseded revoke finalizer must skip teardown", supersededFinalized)
        assertFalse(foregroundCleared)
        assertNull(stopResultArg)
        assertEquals(VpnLifecycleState.STARTING, tracker.state)

        // 3. Even if IO finalizer enters notificationLock BEFORE Main registers start(2), AMS already
        //    delivered startId=2 -> stopSelfResult(1) returns false and preserves Session 2 (NEVER stopSelf()).
        val coordPre = VpnServiceLifecycleCoordinator()
        val trackerPre = VpnStateTracker()
        val lockPre = Any()
        coordPre.onStartRequested(startCommandId = 1)
        trackerPre.onStartRequested()
        trackerPre.onRunning()
        val revokePre = coordPre.onRevokeRequested()!!
        assertEquals(1, revokePre.capturedCommandId)
        trackerPre.onSystemRevoked()

        val amsLatestDeliveredStartId = 2 // AMS has already dispatched startId = 2 to Main thread
        var amsServiceDestroyed = false
        var preStopResultCmdId: Int? = null
        val preFinalized = RustClashVpnService.finalizeStopSession(
            notificationLock = lockPre,
            coordinator = coordPre,
            stateTracker = trackerPre,
            expectedEpoch = revokePre.epoch,
            supersededAtEntry = false,
            stopStartId = revokePre.capturedCommandId.takeIf { it > 0 },
            isCurrentOrIdleGlobalSession = { true },
            onClearSessionState = {},
            stopForegroundAndClearNotification = {},
            requestTileSync = {},
            stopSelfWithResult = { cmdId ->
                preStopResultCmdId = cmdId
                if (cmdId == amsLatestDeliveredStartId) {
                    amsServiceDestroyed = true
                    true
                } else {
                    false
                }
            },
        )
        assertTrue(preFinalized)
        assertEquals(1, preStopResultCmdId)
        assertFalse("AMS must reject stopSelfResult(1) because startId=2 was already delivered", amsServiceDestroyed)

        // 4. recordDeliveredCommandId and onStopRequested monotonically track latest command ID
        val monoCoord = VpnServiceLifecycleCoordinator()
        monoCoord.onStartRequested(1)
        monoCoord.onStopRequested(2)
        monoCoord.recordDeliveredCommandId(5)
        monoCoord.recordDeliveredCommandId(3)
        monoCoord.recordDeliveredCommandId(0)
        monoCoord.recordDeliveredCommandId(-1)
        assertEquals(5, monoCoord.lastDeliveredCommandId)
        assertEquals(5, monoCoord.onRevokeRequested()!!.capturedCommandId)
    }

    @Test
    fun concurrentStartRegistrationAndStopOrAbortFinalizationPreserveSession2UnderContention() {
        val executor = Executors.newFixedThreadPool(2)
        try {
            // Phase 1: Main-thread registerStartAndPromoteForeground(startId=2) racing against
            // IO-thread finalizeStopSession(revokeEpoch, capturedCommandId=1) under shared notificationLock
            repeat(250) { round ->
                val notificationLock = Any()
                val coord = VpnServiceLifecycleCoordinator()
                val tracker = VpnStateTracker()

                val start1 = coord.onStartRequested(startCommandId = 1)
                assertTrue(start1 > 0L)
                tracker.onStartRequested()
                tracker.onRunning()

                val revoke1 = synchronized(notificationLock) {
                    val res = coord.onRevokeRequested()!!
                    tracker.onSystemRevoked()
                    res
                }
                assertEquals(1, revoke1.capturedCommandId)

                // AMS delivers startId=2 to Main thread while IO teardown is about to finalize revoke1
                val amsLatestStartId = 2
                val amsServiceDestroyed = AtomicBoolean(false)
                val foregroundActive = AtomicBoolean(true)
                val nonPositiveStopCalls = AtomicInteger(0)
                val barrier = CyclicBarrier(2)

                val mainFuture = executor.submit<RustClashVpnService.StartRegistrationResult> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.registerStartAndPromoteForeground(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        startCommandId = 2,
                        promoteForeground = {
                            foregroundActive.set(true)
                            true
                        },
                        fgsRestrictedErrorMessage = "fgs restricted",
                    )
                }

                val ioFuture = executor.submit<Boolean> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.finalizeStopSession(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        expectedEpoch = revoke1.epoch,
                        supersededAtEntry = false,
                        stopStartId = revoke1.capturedCommandId.takeIf { it > 0 },
                        isCurrentOrIdleGlobalSession = { true },
                        onClearSessionState = {},
                        stopForegroundAndClearNotification = {
                            foregroundActive.set(false)
                        },
                        requestTileSync = {},
                        stopSelfWithResult = { cmdId ->
                            if (cmdId <= 0) {
                                nonPositiveStopCalls.incrementAndGet()
                                amsServiceDestroyed.set(true)
                                true
                            } else if (cmdId == amsLatestStartId) {
                                amsServiceDestroyed.set(true)
                                true
                            } else {
                                false
                            }
                        },
                    )
                }

                val start2Reg = mainFuture.get(5, TimeUnit.SECONDS)
                ioFuture.get(5, TimeUnit.SECONDS)

                assertTrue("Round $round: Session 2 must register cleanly", start2Reg.startEpoch > revoke1.epoch)
                assertTrue("Round $round: Session 2 must promote foreground", start2Reg.promoted)
                assertEquals(
                    "Round $round: Session 2 STARTING state must NEVER be clobbered to DISCONNECTED/REVOKED",
                    VpnLifecycleState.STARTING,
                    tracker.state,
                )
                assertTrue(
                    "Round $round: Session 2 must NEVER lose its foreground notification",
                    foregroundActive.get(),
                )
                assertFalse(
                    "Round $round: AMS must NEVER destroy reused Service for Session 2",
                    amsServiceDestroyed.get(),
                )
                assertEquals(
                    "Round $round: stopSelfResult must NEVER be called with non-positive startId",
                    0,
                    nonPositiveStopCalls.get(),
                )
                assertFalse(coord.isRevokedForCurrentSession)
                assertFalse(coord.isStartSupersededOrCancelled(start2Reg.startEpoch, startCommandId = 2))
            }

            // Phase 2: Main-thread registerStartAndPromoteForeground(startId=2) racing against
            // IO-thread finalizeAbortedStartInternal(start1Epoch, startCommandId=1)
            repeat(250) { round ->
                val notificationLock = Any()
                val coord = VpnServiceLifecycleCoordinator()
                val tracker = VpnStateTracker()

                val start1 = coord.onStartRequested(startCommandId = 1)
                tracker.onStartRequested()
                synchronized(notificationLock) {
                    coord.onRevokeRequested()!!
                    tracker.onSystemRevoked()
                }

                val amsLatestStartId = 2
                val amsServiceDestroyed = AtomicBoolean(false)
                val foregroundActive = AtomicBoolean(true)
                val barrier = CyclicBarrier(2)

                val mainFuture = executor.submit<RustClashVpnService.StartRegistrationResult> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.registerStartAndPromoteForeground(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        startCommandId = 2,
                        promoteForeground = {
                            foregroundActive.set(true)
                            true
                        },
                        fgsRestrictedErrorMessage = "fgs restricted",
                    )
                }

                val ioFuture = executor.submit<Boolean> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.finalizeAbortedStartInternal(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        startEpoch = start1,
                        startCommandId = 1,
                        isCurrentOrIdleGlobalSession = { true },
                        onClearSessionState = {},
                        stopForegroundAndClearNotification = {
                            foregroundActive.set(false)
                        },
                        requestTileSync = {},
                        stopSelfWithResult = { cmdId ->
                            if (cmdId == amsLatestStartId) {
                                amsServiceDestroyed.set(true)
                                true
                            } else {
                                false
                            }
                        },
                    )
                }

                val start2Reg = mainFuture.get(5, TimeUnit.SECONDS)
                ioFuture.get(5, TimeUnit.SECONDS)

                assertTrue("Abort round $round: Session 2 must register cleanly", start2Reg.startEpoch > start1)
                assertTrue("Abort round $round: Session 2 must promote foreground", start2Reg.promoted)
                assertEquals(
                    "Abort round $round: Session 2 STARTING state must NEVER be clobbered",
                    VpnLifecycleState.STARTING,
                    tracker.state,
                )
                assertTrue(
                    "Abort round $round: Session 2 must NEVER lose its foreground notification",
                    foregroundActive.get(),
                )
                assertFalse(
                    "Abort round $round: AMS must NEVER destroy reused Service for Session 2",
                    amsServiceDestroyed.get(),
                )
            }

            // Phase 3: FGS promotion rollback, non-positive startCommandId guard, & post-onDestroy rejection
            val rollbackCoord = VpnServiceLifecycleCoordinator()
            val rollbackTracker = VpnStateTracker()
            val rollbackLock = Any()
            val failedProm = RustClashVpnService.registerStartAndPromoteForeground(
                notificationLock = rollbackLock,
                coordinator = rollbackCoord,
                stateTracker = rollbackTracker,
                startCommandId = 1,
                promoteForeground = { false },
                fgsRestrictedErrorMessage = "FGS blocked",
            )
            assertTrue(failedProm.startEpoch > 0L)
            assertFalse(failedProm.promoted)
            assertEquals(VpnLifecycleState.ERROR, rollbackTracker.state)
            assertEquals("FGS blocked", rollbackTracker.lastError)
            assertTrue(rollbackCoord.isStartSupersededOrCancelled(failedProm.startEpoch, startCommandId = 1))
            assertFalse(rollbackCoord.hasPendingNewerStart(0L))

            // finalizeAbortedStartInternal with startCommandId <= 0 must never invoke stopSelfResult
            val zeroCmdCoord = VpnServiceLifecycleCoordinator()
            val zeroCmdTracker = VpnStateTracker()
            val zeroCmdEpoch = zeroCmdCoord.onStartRequested(startCommandId = 0)
            zeroCmdCoord.onRevokeRequested()
            var zeroCmdStopCalls = 0
            assertTrue(
                RustClashVpnService.finalizeAbortedStartInternal(
                    notificationLock = Any(),
                    coordinator = zeroCmdCoord,
                    stateTracker = zeroCmdTracker,
                    startEpoch = zeroCmdEpoch,
                    startCommandId = 0,
                    isCurrentOrIdleGlobalSession = { true },
                    onClearSessionState = {},
                    stopForegroundAndClearNotification = {},
                    requestTileSync = {},
                    stopSelfWithResult = {
                        zeroCmdStopCalls++
                        true
                    },
                ),
            )
            assertEquals(0, zeroCmdStopCalls)

            rollbackCoord.onDestroy()
            var promoteCalledAfterDestroy = false
            val afterDestroy = RustClashVpnService.registerStartAndPromoteForeground(
                notificationLock = rollbackLock,
                coordinator = rollbackCoord,
                stateTracker = rollbackTracker,
                startCommandId = 2,
                promoteForeground = {
                    promoteCalledAfterDestroy = true
                    true
                },
                fgsRestrictedErrorMessage = "FGS blocked",
            )
            assertEquals(0L, afterDestroy.startEpoch)
            assertFalse(afterDestroy.promoted)
            assertFalse(promoteCalledAfterDestroy)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun pureBindOnlyRevokeNeverInvokesStopSelfAndPreservesRacingStart1() {
        val executor = Executors.newFixedThreadPool(2)
        try {
            repeat(200) { round ->
                val notificationLock = Any()
                val coord = VpnServiceLifecycleCoordinator()
                val tracker = VpnStateTracker()

                // Pure BIND_VPN_SERVICE instance: no onStartCommand delivered -> capturedCommandId == 0
                val bindRevoke = synchronized(notificationLock) {
                    val res = coord.onRevokeRequested()!!
                    tracker.onSystemRevoked()
                    res
                }
                assertEquals(0, bindRevoke.capturedCommandId)

                val foregroundActive = AtomicBoolean(false)
                val stopSelfCalls = AtomicInteger(0)
                val barrier = CyclicBarrier(2)

                val mainFuture = executor.submit<RustClashVpnService.StartRegistrationResult> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.registerStartAndPromoteForeground(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        startCommandId = 1,
                        promoteForeground = {
                            foregroundActive.set(true)
                            true
                        },
                        fgsRestrictedErrorMessage = "fgs restricted",
                    )
                }

                val ioFuture = executor.submit<Boolean> {
                    barrier.await(5, TimeUnit.SECONDS)
                    RustClashVpnService.finalizeStopSession(
                        notificationLock = notificationLock,
                        coordinator = coord,
                        stateTracker = tracker,
                        expectedEpoch = bindRevoke.epoch,
                        supersededAtEntry = false,
                        stopStartId = bindRevoke.capturedCommandId.takeIf { it > 0 },
                        isCurrentOrIdleGlobalSession = { true },
                        onClearSessionState = {},
                        stopForegroundAndClearNotification = {
                            foregroundActive.set(false)
                        },
                        requestTileSync = {},
                        stopSelfWithResult = {
                            stopSelfCalls.incrementAndGet()
                            true
                        },
                    )
                }

                val start1Reg = mainFuture.get(5, TimeUnit.SECONDS)
                ioFuture.get(5, TimeUnit.SECONDS)

                assertTrue("Round $round: start(1) must succeed", start1Reg.startEpoch > bindRevoke.epoch)
                assertTrue("Round $round: start(1) must promote foreground", start1Reg.promoted)
                assertEquals(
                    "Round $round: pure-bind revoke must NEVER invoke stopSelf/stopSelfResult",
                    0,
                    stopSelfCalls.get(),
                )
                assertEquals(
                    "Round $round: racing start(1) STARTING state must be preserved",
                    VpnLifecycleState.STARTING,
                    tracker.state,
                )
                assertTrue(
                    "Round $round: racing start(1) foreground notification must remain active",
                    foregroundActive.get(),
                )
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun abortedNewerStartDoesNotSupersedeStopNotificationCleanupAndPreservesErrorState() {
        // 1. Interleaving F (Subcase A1 & A2): Start(1) -> Stop(2) -> Start(3, promoteForeground=false)
        //    Start(3) aborts before launch via onStartAbortedBeforeLaunch(3) and sets state=ERROR.
        //    Stop(2) must NOT treat aborted Start(3) as a superseding start; it MUST clear the
        //    foreground notification & session state (zero zombie notification) while preserving ERROR.
        for (stopEnteredAfterAbortedStart3 in listOf(false, true)) {
            val lock = Any()
            val coord = VpnServiceLifecycleCoordinator()
            val tracker = VpnStateTracker()
            var foregroundActive = false

            val start1Reg = RustClashVpnService.registerStartAndPromoteForeground(
                notificationLock = lock,
                coordinator = coord,
                stateTracker = tracker,
                startCommandId = 1,
                promoteForeground = {
                    foregroundActive = true
                    true
                },
                fgsRestrictedErrorMessage = "FGS blocked",
            )
            assertTrue(start1Reg.promoted)
            assertTrue(foregroundActive)
            tracker.onRunning()

            val stop2Epoch = synchronized(lock) {
                val epoch = coord.onStopRequested(stopCommandId = 2)
                tracker.onStopRequested()
                epoch
            }
            assertEquals(VpnLifecycleState.STOPPING, tracker.state)

            val start3Reg = RustClashVpnService.registerStartAndPromoteForeground(
                notificationLock = lock,
                coordinator = coord,
                stateTracker = tracker,
                startCommandId = 3,
                promoteForeground = { false },
                fgsRestrictedErrorMessage = "FGS blocked",
            )
            assertTrue(start3Reg.startEpoch > stop2Epoch)
            assertFalse(start3Reg.promoted)
            assertEquals(VpnLifecycleState.ERROR, tracker.state)
            assertEquals("FGS blocked", tracker.lastError)

            assertFalse(
                "Aborted Start(3) must NOT supersede Stop(2)",
                coord.isStopSupersededByNewerStart(stop2Epoch),
            )
            assertFalse(coord.hasPendingNewerStart(stop2Epoch))

            if (stopEnteredAfterAbortedStart3) {
                // Subcase A2: stopVpnSessionInternal enters notificationLock AFTER Start(3) failed
                synchronized(lock) {
                    val superseded = coord.isStopSupersededByNewerStart(stop2Epoch)
                    assertFalse(superseded)
                    tracker.onStopRequested()
                }
                assertEquals(
                    "onStopRequested() must preserve ERROR set by Start(3)'s FGS failure",
                    VpnLifecycleState.ERROR,
                    tracker.state,
                )
            }

            var sessionStateCleared = false
            var tileSynced = false
            var stopResultCmdId: Int? = null
            val finalized = RustClashVpnService.finalizeStopSession(
                notificationLock = lock,
                coordinator = coord,
                stateTracker = tracker,
                expectedEpoch = stop2Epoch,
                supersededAtEntry = false,
                stopStartId = 2,
                isCurrentOrIdleGlobalSession = { true },
                onClearSessionState = { sessionStateCleared = true },
                stopForegroundAndClearNotification = { foregroundActive = false },
                requestTileSync = { tileSynced = true },
                stopSelfWithResult = { cmdId ->
                    stopResultCmdId = cmdId
                    false // AMS already delivered startId = 3
                },
            )
            assertTrue("Stop(2) must finalize cleanup after aborted Start(3)", finalized)
            assertFalse("Zombie foreground notification MUST be cleared", foregroundActive)
            assertTrue("Session state (activeOutboundLabel/snapshot) MUST be cleared", sessionStateCleared)
            assertTrue("Tile sync MUST be requested", tileSynced)
            assertEquals(2, stopResultCmdId)
            assertEquals(
                "ERROR state from Start(3)'s failed FGS promotion must be preserved",
                VpnLifecycleState.ERROR,
                tracker.state,
            )
            assertEquals("FGS blocked", tracker.lastError)
        }

        // 2. Start(1) -> onRevoke() -> Start(2, promoteForeground=false) -> revoke teardown clears notification
        //    and preserves Start(2)'s FGS ERROR rather than overwriting with REVOKED or leaving zombie notification.
        val revLock = Any()
        val revCoord = VpnServiceLifecycleCoordinator()
        val revTracker = VpnStateTracker()
        var revForegroundActive = false

        RustClashVpnService.registerStartAndPromoteForeground(
            notificationLock = revLock,
            coordinator = revCoord,
            stateTracker = revTracker,
            startCommandId = 1,
            promoteForeground = {
                revForegroundActive = true
                true
            },
            fgsRestrictedErrorMessage = "FGS blocked",
        )
        revTracker.onRunning()

        val revoke1 = synchronized(revLock) {
            val res = revCoord.onRevokeRequested()!!
            revTracker.onSystemRevoked()
            res
        }
        val failedStart2 = RustClashVpnService.registerStartAndPromoteForeground(
            notificationLock = revLock,
            coordinator = revCoord,
            stateTracker = revTracker,
            startCommandId = 2,
            promoteForeground = { false },
            fgsRestrictedErrorMessage = "FGS blocked",
        )
        assertFalse(failedStart2.promoted)
        assertFalse(revCoord.isRevokedForCurrentSession)
        assertFalse(revCoord.isStopSupersededByNewerStart(revoke1.epoch))

        val revFinalized = RustClashVpnService.finalizeStopSession(
            notificationLock = revLock,
            coordinator = revCoord,
            stateTracker = revTracker,
            expectedEpoch = revoke1.epoch,
            supersededAtEntry = false,
            stopStartId = revoke1.capturedCommandId.takeIf { it > 0 },
            isCurrentOrIdleGlobalSession = { true },
            onClearSessionState = {},
            stopForegroundAndClearNotification = { revForegroundActive = false },
            requestTileSync = {},
            stopSelfWithResult = { false },
        )
        assertTrue(revFinalized)
        assertFalse("Foreground notification must be cleared after revoke + aborted Start(2)", revForegroundActive)
        assertEquals(VpnLifecycleState.ERROR, revTracker.state)
        assertEquals("FGS blocked", revTracker.lastError)

        // 3. VpnStateTracker ERROR preservation & explicit recovery via clearError() / onStartRequested()
        val stateTracker = VpnStateTracker()
        stateTracker.onError("boom")
        stateTracker.onStopRequested()
        assertEquals(VpnLifecycleState.ERROR, stateTracker.state)
        stateTracker.onStopped()
        assertEquals(VpnLifecycleState.ERROR, stateTracker.state)
        assertEquals("boom", stateTracker.lastError)
        stateTracker.clearError()
        assertEquals(VpnLifecycleState.DISCONNECTED, stateTracker.state)
        assertNull(stateTracker.lastError)
    }

    @Test
    fun vpnServiceLifecycleCoordinatorHandlesStopAndAbortedLaunchWithoutClobberingNewerStart() {
        val coord = VpnServiceLifecycleCoordinator()

        val start1 = coord.onStartRequested(startCommandId = 1)
        val stop2 = coord.onStopRequested(stopCommandId = 2)
        assertTrue(stop2 > start1)
        assertTrue(coord.isStartSupersededOrCancelled(start1, startCommandId = 1))
        assertTrue(coord.shouldFinalizeFailedOrAbortedStart(start1, startCommandId = 1))
        assertFalse(coord.isStopSupersededByNewerStart(stop2))

        // Newer start arrives after stop -> stop is superseded, new start proceeds
        val start3 = coord.onStartRequested(startCommandId = 3)
        assertTrue(start3 > stop2)
        assertTrue(coord.isStopSupersededByNewerStart(stop2))
        assertFalse(coord.isStartSupersededOrCancelled(start3, startCommandId = 3))

        // If promoteForeground fails on start3, onStartAbortedBeforeLaunch invalidates start3 cleanly
        // so stop2 is no longer superseded and can clear the foreground notification.
        coord.onStartAbortedBeforeLaunch(start3)
        assertTrue(coord.isStartSupersededOrCancelled(start3, startCommandId = 3))
        assertFalse(coord.hasPendingNewerStart(start1))
        assertFalse(coord.hasPendingNewerStart(stop2))
        assertFalse(coord.isStopSupersededByNewerStart(stop2))

        // Subsequent foreground start recovers cleanly and supersedes stop2 again
        val start4 = coord.onStartRequested(startCommandId = 4)
        assertTrue(start4 > start3)
        assertFalse(coord.isStartSupersededOrCancelled(start4, startCommandId = 4))
        assertTrue(coord.isStopSupersededByNewerStart(stop2))
    }

    @Test
    fun tokenGatedStatusSnapshotAndNotificationGuardBlockPostStopZombieUpdates() {
        try {
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.clearError()
            RustClashVpnService.stateTracker.onStopped()
            RustClashVpnService.clearFreshStatusSnapshot()

            val runningJson = "{\"running\":true,\"downRate\":8192,\"upRate\":2048}"

            // 1. Disconnected / zero token must reject snapshot writes
            assertFalse(RustClashVpnService.publishFreshStatusSnapshot(runningJson, expectedToken = 0L, nowMs = 1_000L))
            assertFalse(RustClashVpnService.publishFreshStatusSnapshot(runningJson, expectedToken = 77L, nowMs = 1_000L))
            assertEquals("{\"running\":false}", RustClashVpnService.latestStatusJson)
            assertEquals(0L, RustClashVpnService.latestStatusUpdatedAtMs)

            // 2. Active RUNNING session accepts matching token only
            RustClashVpnService.activeNativeSessionToken.set(77L)
            RustClashVpnService.stateTracker.onRunning()
            assertFalse(RustClashVpnService.publishFreshStatusSnapshot(runningJson, expectedToken = 76L, nowMs = 2_000L))
            assertTrue(RustClashVpnService.publishFreshStatusSnapshot(runningJson, expectedToken = 77L, nowMs = 2_000L))
            assertEquals(runningJson, RustClashVpnService.latestStatusJson)
            assertEquals(2_000L, RustClashVpnService.latestStatusUpdatedAtMs)

            // 3. After stop clears token and snapshot, late in-flight JNI writes with old token 77L are dropped
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.onStopped()
            RustClashVpnService.clearFreshStatusSnapshot()
            assertFalse(RustClashVpnService.publishFreshStatusSnapshot(runningJson, expectedToken = 77L, nowMs = 3_000L))
            assertEquals("{\"running\":false}", RustClashVpnService.latestStatusJson)
            assertEquals(0L, RustClashVpnService.latestStatusUpdatedAtMs)

            // 4. Notification guard rejects stopped, cancelled, destroyed, or token-mismatched ticks
            assertTrue(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = false,
                    instanceToken = 88L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RUNNING,
                ),
            )
            assertTrue(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = false,
                    instanceToken = 88L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RECONNECTING,
                ),
            )
            assertFalse(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = false,
                    serviceDestroyed = false,
                    instanceToken = 88L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RUNNING,
                ),
            )
            assertFalse(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = true,
                    instanceToken = 88L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RUNNING,
                ),
            )
            assertFalse(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = false,
                    instanceToken = 0L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RUNNING,
                ),
            )
            assertFalse(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = false,
                    instanceToken = 88L,
                    activeGlobalToken = 89L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.RUNNING,
                ),
            )
            assertFalse(
                RustClashVpnService.canPostSessionNotification(
                    coroutineActive = true,
                    serviceDestroyed = false,
                    instanceToken = 88L,
                    activeGlobalToken = 88L,
                    expectedToken = 88L,
                    lifecycleState = VpnLifecycleState.STOPPING,
                ),
            )

            // 5. ViewModel post-IO reconciliation forces {"running":false} if VPN stopped or token rotated mid-IO
            assertEquals(
                runningJson,
                RustClashViewModel.resolveEffectivePolledStatusJson(
                    postIoState = VpnLifecycleState.RUNNING,
                    capturedToken = 88L,
                    postIoToken = 88L,
                    polledRawJson = runningJson,
                ),
            )
            assertEquals(
                "{\"running\":false}",
                RustClashViewModel.resolveEffectivePolledStatusJson(
                    postIoState = VpnLifecycleState.DISCONNECTED,
                    capturedToken = 88L,
                    postIoToken = 0L,
                    polledRawJson = runningJson,
                ),
            )
            assertEquals(
                "{\"running\":false}",
                RustClashViewModel.resolveEffectivePolledStatusJson(
                    postIoState = VpnLifecycleState.REVOKED,
                    capturedToken = 88L,
                    postIoToken = 0L,
                    polledRawJson = runningJson,
                ),
            )
            assertEquals(
                "{\"running\":false}",
                RustClashViewModel.resolveEffectivePolledStatusJson(
                    postIoState = VpnLifecycleState.RUNNING,
                    capturedToken = 88L,
                    postIoToken = 89L,
                    polledRawJson = runningJson,
                ),
            )
        } finally {
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.clearError()
            RustClashVpnService.stateTracker.onStopped()
            RustClashVpnService.clearFreshStatusSnapshot()
        }
    }

    @Test
    fun safeServiceStartAndStopHelpersCatchBackgroundRestrictionsAndReconcileStaleState() {
        try {
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.clearError()
            RustClashVpnService.stateTracker.onStopped()

            // 1. runSafeServiceCall catches IllegalStateException & SecurityException (FGS/background limits)
            assertTrue(RustClashVpnService.runSafeServiceCall { /* ok */ })
            assertFalse(
                RustClashVpnService.runSafeServiceCall {
                    throw IllegalStateException("Background start not allowed")
                },
            )
            assertFalse(
                RustClashVpnService.runSafeServiceCall {
                    throw SecurityException("Missing FGS permission")
                },
            )
            try {
                RustClashVpnService.runSafeServiceCall {
                    throw IllegalArgumentException("Unrelated programmer error")
                }
                fail("Unrelated IllegalArgumentException should not be swallowed")
            } catch (_: IllegalArgumentException) {
                // expected
            }

            // 2. safeRequestStopVpnInternal: direct startService succeeds without touching fallback
            var fallbackInvoked = false
            assertTrue(
                RustClashVpnService.safeRequestStopVpnInternal(
                    startStopIntent = { /* ok */ },
                    stopServiceFallback = {
                        fallbackInvoked = true
                        true
                    },
                ),
            )
            assertFalse(fallbackInvoked)

            // 3. Background startService throws -> falls back to stopService() when service is running
            assertTrue(
                RustClashVpnService.safeRequestStopVpnInternal(
                    startStopIntent = { throw IllegalStateException("BackgroundServiceStartNotAllowed") },
                    stopServiceFallback = {
                        fallbackInvoked = true
                        true
                    },
                ),
            )
            assertTrue(fallbackInvoked)

            // 4. Background startService throws AND service is no longer running -> reconciles stale STARTING to DISCONNECTED
            RustClashVpnService.stateTracker.onStartRequested()
            assertEquals(VpnLifecycleState.STARTING, RustClashVpnService.stateTracker.state)
            assertFalse(
                RustClashVpnService.safeRequestStopVpnInternal(
                    startStopIntent = { throw IllegalStateException("BackgroundServiceStartNotAllowed") },
                    stopServiceFallback = { false },
                ),
            )
            assertEquals(VpnLifecycleState.DISCONNECTED, RustClashVpnService.stateTracker.state)
        } finally {
            RustClashVpnService.activeNativeSessionToken.set(0L)
            RustClashVpnService.stateTracker.clearError()
            RustClashVpnService.stateTracker.onStopped()
        }
    }

    @Test
    fun perAppAllowlistFailsClosedWhenEmptySelfOnlyOrAllPackagesUninstalled() {
        val selfPkg = "io.github.rustclashlabs.rustclash"

        // 1. Empty allowlist populates blockingError
        val emptyAllowPlan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.ALLOWLIST,
            selectedPackages = emptySet(),
            selfPackageName = selfPkg,
            isLockdownEnabled = false,
        )
        assertNotNull(emptyAllowPlan.blockingError)
        assertTrue(emptyAllowPlan.allowedPackages.isEmpty())

        // 2. Self-only allowlist (stripped to empty) ALSO populates blockingError
        val selfOnlyAllowPlan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.ALLOWLIST,
            selectedPackages = setOf(selfPkg, "   "),
            selfPackageName = selfPkg,
            isLockdownEnabled = true,
        )
        assertNotNull(selfOnlyAllowPlan.blockingError)
        assertTrue(selfOnlyAllowPlan.allowedPackages.isEmpty())
        assertTrue(selfOnlyAllowPlan.lockdownConflictWarning!!.contains("Lockdown"))

        // 3. Valid allowlist, ALL_APPS, and BLOCKLIST have null blockingError
        val validAllowPlan = PerAppVpnPolicy.buildPlan(
            mode = PerAppMode.ALLOWLIST,
            selectedPackages = setOf("org.mozilla.firefox", "com.missing.app"),
            selfPackageName = selfPkg,
            isLockdownEnabled = false,
        )
        assertNull(validAllowPlan.blockingError)
        assertNull(
            PerAppVpnPolicy.buildPlan(PerAppMode.ALL_APPS, emptySet(), selfPkg, false).blockingError,
        )
        assertNull(
            PerAppVpnPolicy.buildPlan(PerAppMode.BLOCKLIST, emptySet(), selfPkg, false).blockingError,
        )

        // 4. applyPackagesFailClosed throws IllegalStateException (NOT IllegalArgumentException) when empty
        try {
            PerAppVpnPolicy.applyPackagesFailClosed(
                plan = emptyAllowPlan,
                addAllowed = { fail("Must not call addAllowed for blocked empty allowlist") },
                addDisallowed = { fail("Must not call addDisallowed for allowlist") },
            )
            fail("Expected IllegalStateException for empty allowlist")
        } catch (e: IllegalStateException) {
            assertFalse(e is IllegalArgumentException)
        }

        // 5. applyPackagesFailClosed fails closed with IllegalStateException when ALL allowlisted apps are uninstalled
        try {
            PerAppVpnPolicy.applyPackagesFailClosed(
                plan = validAllowPlan,
                addAllowed = { pkg -> throw PackageManager.NameNotFoundException(pkg) },
                addDisallowed = { fail("Must not call addDisallowed for allowlist") },
            )
            fail("Expected IllegalStateException when 0 allowlisted packages resolve")
        } catch (e: IllegalStateException) {
            assertFalse(e is IllegalArgumentException)
        }

        // 6. Partial uninstall leaves remaining installed app active and succeeds
        val applied = mutableListOf<String>()
        val count = PerAppVpnPolicy.applyPackagesFailClosed(
            plan = validAllowPlan,
            addAllowed = { pkg ->
                if (pkg == "com.missing.app") {
                    throw PackageManager.NameNotFoundException(pkg)
                }
                applied.add(pkg)
            },
            addDisallowed = { fail("Must not call addDisallowed for allowlist") },
        )
        assertEquals(1, count)
        assertEquals(listOf("org.mozilla.firefox"), applied)

        // 7. validateAppliedAllowlistCount rejects 0 for ALLOWLIST only
        PerAppVpnPolicy.validateAppliedAllowlistCount(PerAppMode.ALL_APPS, 0)
        PerAppVpnPolicy.validateAppliedAllowlistCount(PerAppMode.BLOCKLIST, 0)
        try {
            PerAppVpnPolicy.validateAppliedAllowlistCount(PerAppMode.ALLOWLIST, 0)
            fail("Expected IllegalStateException for ALLOWLIST with 0 applied packages")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    @Test
    fun androidKeystoreVaultDecryptIsReadOnlyRefusesAliasOverwriteAndRemovesKeyWithoutKeystore() {
        // 1. Pure-JVM unwrapMasterKey safely returns null (no Keystore available, never throws)
        assertNull(AndroidKeystoreVault.unwrapMasterKey(ByteArray(8)))
        assertNull(AndroidKeystoreVault.unwrapMasterKey(ByteArray(44)))

        // 2. Fake KeyStore exercising missing alias, existing SecretKeyEntry, and transient unavailable alias
        val secretKey = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val entries = mutableMapOf<String, KeyStore.Entry?>()
        val fakeSpi = object : KeyStoreSpi() {
            override fun engineGetKey(alias: String?, password: CharArray?): Key? =
                (entries[alias] as? KeyStore.SecretKeyEntry)?.secretKey

            override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
            override fun engineGetCertificate(alias: String?): Certificate? = null
            override fun engineGetCreationDate(alias: String?): Date? = null
            override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {}
            override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {}
            override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {}
            override fun engineDeleteEntry(alias: String?) {
                entries.remove(alias)
            }

            override fun engineAliases(): Enumeration<String> = Collections.enumeration(entries.keys)
            override fun engineContainsAlias(alias: String?): Boolean = alias != null && entries.containsKey(alias)
            override fun engineSize(): Int = entries.size
            override fun engineIsKeyEntry(alias: String?): Boolean = entries[alias] is KeyStore.SecretKeyEntry
            override fun engineIsCertificateEntry(alias: String?): Boolean = false
            override fun engineGetCertificateAlias(cert: Certificate?): String? = null
            override fun engineStore(stream: OutputStream?, password: CharArray?) {}
            override fun engineLoad(stream: InputStream?, password: CharArray?) {}
            override fun engineGetEntry(alias: String?, protParam: KeyStore.ProtectionParameter?): KeyStore.Entry? =
                entries[alias]
        }
        val fakeKeyStore = object : KeyStore(fakeSpi, null, "FakeKeyStore") {}.apply { load(null) }

        // Read-only lookup on missing alias returns null
        assertNull(AndroidKeystoreVault.resolveExistingSecretKey(fakeKeyStore, "missing_alias"))

        // resolveOrCreateSecretKey generates ONLY when alias is absent, and reuses existing SecretKeyEntry
        var generatedCount = 0
        val created = AndroidKeystoreVault.resolveOrCreateSecretKey(fakeKeyStore, "vault_key") {
            generatedCount++
            entries["vault_key"] = KeyStore.SecretKeyEntry(secretKey)
            secretKey
        }
        assertSame(secretKey, created)
        assertEquals(1, generatedCount)

        val reused = AndroidKeystoreVault.resolveOrCreateSecretKey(fakeKeyStore, "vault_key") {
            generatedCount++
            SecretKeySpec(ByteArray(32) { 9 }, "AES")
        }
        assertSame(secretKey, reused)
        assertEquals(1, generatedCount)
        assertSame(secretKey, AndroidKeystoreVault.resolveExistingSecretKey(fakeKeyStore, "vault_key"))

        // Critical P1 #30 regression: alias exists in KeyStore, yet getEntry returns null (e.g., locked TEE / non-SecretKeyEntry).
        // Read-only lookup MUST return null, and resolveOrCreateSecretKey MUST throw instead of overwriting!
        entries["existing_but_unreadable"] = null
        assertNull(AndroidKeystoreVault.resolveExistingSecretKey(fakeKeyStore, "existing_but_unreadable"))
        try {
            AndroidKeystoreVault.resolveOrCreateSecretKey(fakeKeyStore, "existing_but_unreadable") {
                generatedCount++
                SecretKeySpec(ByteArray(32) { 7 }, "AES")
            }
            fail("Must throw IllegalStateException instead of overwriting an existing unreadable alias")
        } catch (_: IllegalStateException) {
            // expected
        }
        assertEquals("Generator must NEVER be called for an existing alias", 1, generatedCount)

        // 3. removeEncryptedKey removes SharedPreferences key cleanly without touching Keystore or Cipher
        val backingStore = mutableMapOf<String, Any?>(
            RustClashVpnService.VAULT_KEY_ACTIVE_YAML to "iv_b64:ciphertext_b64",
            "other_key" to "keep_me",
        )
        val fakePrefs = object : SharedPreferences {
            override fun getAll(): MutableMap<String, *> = backingStore.toMutableMap()
            override fun getString(key: String?, defValue: String?): String? =
                (backingStore[key] as? String) ?: defValue
            override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
            override fun getInt(key: String?, defValue: Int): Int = defValue
            override fun getLong(key: String?, defValue: Long): Long = defValue
            override fun getFloat(key: String?, defValue: Float): Float = defValue
            override fun getBoolean(key: String?, defValue: Boolean): Boolean = defValue
            override fun contains(key: String?): Boolean = backingStore.containsKey(key)
            override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
                private val removals = mutableSetOf<String>()
                override fun putString(key: String?, value: String?): SharedPreferences.Editor = this
                override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
                override fun putInt(key: String?, value: Int): SharedPreferences.Editor = this
                override fun putLong(key: String?, value: Long): SharedPreferences.Editor = this
                override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = this
                override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = this
                override fun remove(key: String?): SharedPreferences.Editor {
                    if (key != null) removals.add(key)
                    return this
                }
                override fun clear(): SharedPreferences.Editor = this
                override fun commit(): Boolean {
                    removals.forEach { backingStore.remove(it) }
                    return true
                }
                override fun apply() {
                    removals.forEach { backingStore.remove(it) }
                }
            }
        }
        val fakeContext = object : ContextWrapper(null) {
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = fakePrefs
        }

        AndroidKeystoreVault.removeEncryptedKey(fakeContext, RustClashVpnService.VAULT_KEY_ACTIVE_YAML)
        assertFalse(backingStore.containsKey(RustClashVpnService.VAULT_KEY_ACTIVE_YAML))
        assertEquals("keep_me", backingStore["other_key"])
    }

    @Test
    fun nativeBridgeNonBlockingFastCheckAndOrderedEnsureLoadedContract() {
        // 1. Production singleton on pure JVM (no libproxy_ffi.so): fast checks are non-blocking
        //    and never throw; ensureLoaded() caches false cleanly on UnsatisfiedLinkError.
        assertFalse(NativeBridge.isLoadedFast)
        assertFalse(NativeBridge.isNativeLoaded)
        assertFalse(NativeBridge.ensureLoaded())
        assertFalse(NativeBridge.isLoadedFast)
        assertFalse(NativeBridge.isNativeLoaded)

        // 2. Non-blocking fast check NEVER invokes blocking loader or vault registrar, and stays
        //    false until BOTH loadLibrary() AND registerVaultKeyWrapper() have completed!
        val loadCalls = AtomicInteger(0)
        val vaultCalls = AtomicInteger(0)
        val enteredVaultRegistration = CountDownLatch(1)
        val allowVaultFinish = CountDownLatch(1)
        val orderLog = Collections.synchronizedList(mutableListOf<String>())

        val loader = NativeLibraryLoader(
            loadLibrary = {
                loadCalls.incrementAndGet()
                orderLog.add("load")
                true
            },
            registerVaultKeyWrapper = {
                vaultCalls.incrementAndGet()
                orderLog.add("vault-enter")
                enteredVaultRegistration.countDown()
                assertTrue(allowVaultFinish.await(5, TimeUnit.SECONDS))
                orderLog.add("vault-exit")
            },
        )

        assertFalse(loader.isLoadedFast)
        assertEquals("isLoadedFast must never invoke loadLibrary", 0, loadCalls.get())
        assertEquals("isLoadedFast must never invoke registerVaultKeyWrapper", 0, vaultCalls.get())

        val executor = Executors.newFixedThreadPool(6)
        try {
            val barrier = CyclicBarrier(6)
            val futures = (0 until 6).map {
                executor.submit<Boolean> {
                    barrier.await(5, TimeUnit.SECONDS)
                    loader.ensureLoaded()
                }
            }
            assertTrue(enteredVaultRegistration.await(5, TimeUnit.SECONDS))
            // While thread #1 is blocked inside vault registration holding loadLock, isLoadedFast
            // must return false IMMEDIATELY without blocking on loadLock!
            assertFalse(
                "isLoadedFast must stay false until vault registration completes",
                loader.isLoadedFast,
            )
            allowVaultFinish.countDown()

            val results = futures.map { it.get(5, TimeUnit.SECONDS) }
            assertTrue("All concurrent ensureLoaded() callers must see true", results.all { it })
            assertTrue(loader.isLoadedFast)
            assertEquals("loadLibrary must run exactly once", 1, loadCalls.get())
            assertEquals("registerVaultKeyWrapper must run exactly once", 1, vaultCalls.get())
            assertEquals(listOf("load", "vault-enter", "vault-exit"), orderLog)
        } finally {
            executor.shutdownNow()
        }

        // 3. UnsatisfiedLinkError caches false cleanly without invoking vault registration
        val failedLoadCalls = AtomicInteger(0)
        val failedVaultCalls = AtomicInteger(0)
        val missingLibLoader = NativeLibraryLoader(
            loadLibrary = {
                failedLoadCalls.incrementAndGet()
                throw UnsatisfiedLinkError("libproxy_ffi.so missing")
            },
            registerVaultKeyWrapper = {
                failedVaultCalls.incrementAndGet()
            },
        )
        assertFalse(missingLibLoader.isLoadedFast)
        assertFalse(missingLibLoader.ensureLoaded())
        assertFalse(missingLibLoader.ensureLoaded())
        assertFalse(missingLibLoader.isLoadedFast)
        assertEquals(1, failedLoadCalls.get())
        assertEquals(0, failedVaultCalls.get())

        // 4. Non-fatal vault registration failure is caught safely while library stays loaded
        val flakyVaultLoader = NativeLibraryLoader(
            loadLibrary = { true },
            registerVaultKeyWrapper = { throw IllegalStateException("Keystore unavailable") },
        )
        assertTrue(flakyVaultLoader.ensureLoaded())
        assertTrue(flakyVaultLoader.isLoadedFast)
    }

    @Test
    fun networkCallbackLifecycleRunsOnDedicatedBackgroundThreadAndTearsDownIdempotently() {
        assertEquals("rc-net-cb", RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME)

        class FakeWorkerThread(name: String) {
            private val queue = LinkedBlockingQueue<Runnable>()
            private val running = AtomicBoolean(true)
            val quitCount = AtomicInteger(0)
            val thread: Thread = Thread(
                {
                    while (running.get() || queue.isNotEmpty()) {
                        val task = queue.poll(20, TimeUnit.MILLISECONDS) ?: continue
                        task.run()
                    }
                },
                name,
            ).apply { isDaemon = true }

            fun start(): FakeWorkerThread {
                thread.start()
                return this
            }

            fun post(action: () -> Unit) {
                if (running.get()) {
                    queue.offer(Runnable(action))
                }
            }

            fun quitSafely() {
                quitCount.incrementAndGet()
                running.set(false)
            }

            fun joinClosed() {
                thread.join(3_000L)
                assertFalse("Background callback thread must terminate after quitSafely()", thread.isAlive)
            }
        }

        val callingThreadId = Thread.currentThread().id
        val lifecycle = NetworkCallbackLifecycle<Long, FakeWorkerThread>()
        val startedThreads = mutableListOf<FakeWorkerThread>()
        val unregisteredGens = mutableListOf<Long>()
        val deliveredOnThreadNames = Collections.synchronizedList(mutableListOf<String>())
        val deliveredOrder = Collections.synchronizedList(mutableListOf<Int>())

        // 1. First registration creates a dedicated background thread named "rc-net-cb" (not caller/main)
        var firstGen = 0L
        var firstThread: FakeWorkerThread? = null
        val reg1 = lifecycle.register(
            createAndStartThread = {
                FakeWorkerThread(RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME).start().also {
                    startedThreads.add(it)
                    firstThread = it
                }
            },
            buildCallback = { gen ->
                firstGen = gen
                gen
            },
            registerWithOs = { _, _ -> true },
            unregisterWithOs = { gen -> unregisteredGens.add(gen) },
            quitThread = { it.quitSafely() },
        )
        assertTrue(reg1)
        assertTrue(lifecycle.hasActiveRegistration)
        assertTrue(lifecycle.isGenerationActive(firstGen))

        // Dispatch FIFO network events on the dedicated background thread
        val fifoLatch = CountDownLatch(3)
        for (seq in 1..3) {
            firstThread!!.post {
                if (lifecycle.isGenerationActive(firstGen)) {
                    assertNotEquals(callingThreadId, Thread.currentThread().id)
                    deliveredOnThreadNames.add(Thread.currentThread().name)
                    deliveredOrder.add(seq)
                }
                fifoLatch.countDown()
            }
        }
        assertTrue(fifoLatch.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("rc-net-cb", "rc-net-cb", "rc-net-cb"), deliveredOnThreadNames)
        assertEquals(listOf(1, 2, 3), deliveredOrder)

        // 2. Clean teardown unregisters callback ONCE, quits thread ONCE, invalidates generation, and is idempotent
        assertTrue(
            lifecycle.unregister(
                markDestroyed = false,
                unregisterWithOs = { unregisteredGens.add(it) },
                quitThread = { it.quitSafely() },
            ),
        )
        assertFalse(lifecycle.hasActiveRegistration)
        assertFalse(lifecycle.isGenerationActive(firstGen))
        assertEquals(listOf(firstGen), unregisteredGens)
        assertEquals(1, firstThread!!.quitCount.get())
        firstThread!!.joinClosed()

        // Repeated unregister calls are strict no-ops
        assertFalse(
            lifecycle.unregister(
                markDestroyed = false,
                unregisterWithOs = { unregisteredGens.add(it) },
                quitThread = { it.quitSafely() },
            ),
        )
        assertEquals(listOf(firstGen), unregisteredGens)
        assertEquals(1, firstThread!!.quitCount.get())

        // 3. Failed OS registration (SecurityException / RuntimeException / false) quits thread with ZERO leak
        var failedThread1: FakeWorkerThread? = null
        assertFalse(
            lifecycle.register(
                createAndStartThread = {
                    FakeWorkerThread(RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME).start().also {
                        failedThread1 = it
                    }
                },
                buildCallback = { it },
                registerWithOs = { _, _ -> throw SecurityException("denied") },
                unregisterWithOs = { fail("Must not unregister a callback that failed to register") },
                quitThread = { it.quitSafely() },
            ),
        )
        assertFalse(lifecycle.hasActiveRegistration)
        assertEquals(1, failedThread1!!.quitCount.get())
        failedThread1!!.joinClosed()

        var failedThread2: FakeWorkerThread? = null
        assertFalse(
            lifecycle.register(
                createAndStartThread = {
                    FakeWorkerThread(RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME).start().also {
                        failedThread2 = it
                    }
                },
                buildCallback = { it },
                registerWithOs = { _, _ -> false },
                unregisterWithOs = { fail("Must not unregister when registerWithOs returned false") },
                quitThread = { it.quitSafely() },
            ),
        )
        assertEquals(1, failedThread2!!.quitCount.get())
        failedThread2!!.joinClosed()

        // 4. Service reuse works until markDestroyed = true (onDestroy), after which registration is blocked
        var secondThread: FakeWorkerThread? = null
        var secondGen = 0L
        assertTrue(
            lifecycle.register(
                createAndStartThread = {
                    FakeWorkerThread(RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME).start().also {
                        secondThread = it
                    }
                },
                buildCallback = { gen ->
                    secondGen = gen
                    gen
                },
                registerWithOs = { _, _ -> true },
                unregisterWithOs = { unregisteredGens.add(it) },
                quitThread = { it.quitSafely() },
            ),
        )
        assertTrue(secondGen > firstGen)
        assertTrue(lifecycle.isGenerationActive(secondGen))

        assertTrue(
            lifecycle.unregister(
                markDestroyed = true,
                unregisterWithOs = { unregisteredGens.add(it) },
                quitThread = { it.quitSafely() },
            ),
        )
        assertTrue(lifecycle.isDestroyed)
        assertFalse(lifecycle.isGenerationActive(secondGen))
        secondThread!!.joinClosed()

        val postDestroyThreadStarts = AtomicInteger(0)
        assertFalse(
            lifecycle.register(
                createAndStartThread = {
                    postDestroyThreadStarts.incrementAndGet()
                    FakeWorkerThread(RustClashVpnService.NETWORK_CALLBACK_THREAD_NAME).start()
                },
                buildCallback = { it },
                registerWithOs = { _, _ -> true },
                unregisterWithOs = {},
                quitThread = { it.quitSafely() },
            ),
        )
        assertEquals("Must never spawn a thread after onDestroy()", 0, postDestroyThreadStarts.get())

        // 5. Concurrent register() vs onDestroy() stress test: zero leaked threads or OS callbacks
        val executor = Executors.newFixedThreadPool(2)
        try {
            repeat(100) { round ->
                val raceLifecycle = NetworkCallbackLifecycle<Int, AtomicBoolean>()
                val startedCount = AtomicInteger(0)
                val quitCount = AtomicInteger(0)
                val osRegisteredCount = AtomicInteger(0)
                val osUnregisteredCount = AtomicInteger(0)
                val barrier = CyclicBarrier(2)

                val f1 = executor.submit {
                    barrier.await(5, TimeUnit.SECONDS)
                    raceLifecycle.register(
                        createAndStartThread = {
                            startedCount.incrementAndGet()
                            AtomicBoolean(true)
                        },
                        buildCallback = { it.toInt() },
                        registerWithOs = { _, _ ->
                            osRegisteredCount.incrementAndGet()
                            true
                        },
                        unregisterWithOs = { osUnregisteredCount.incrementAndGet() },
                        quitThread = { t ->
                            if (t.compareAndSet(true, false)) {
                                quitCount.incrementAndGet()
                            }
                        },
                    )
                }
                val f2 = executor.submit {
                    barrier.await(5, TimeUnit.SECONDS)
                    raceLifecycle.unregister(
                        markDestroyed = true,
                        unregisterWithOs = { osUnregisteredCount.incrementAndGet() },
                        quitThread = { t ->
                            if (t.compareAndSet(true, false)) {
                                quitCount.incrementAndGet()
                            }
                        },
                    )
                }

                f1.get(5, TimeUnit.SECONDS)
                f2.get(5, TimeUnit.SECONDS)

                assertTrue("Round $round: lifecycle must be destroyed", raceLifecycle.isDestroyed)
                assertFalse("Round $round: must not retain active registration", raceLifecycle.hasActiveRegistration)
                assertEquals("Round $round: every started thread must be quit", startedCount.get(), quitCount.get())
                assertEquals(
                    "Round $round: every OS callback registered must be unregistered",
                    osRegisteredCount.get(),
                    osUnregisteredCount.get(),
                )
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun mainActivityPendingFilePathsPersistUnconditionallyAndFailExportOnNullOutputStream() {
        val tempDir = Files.createTempDirectory("rc-main-activity-state-test-").toFile()
        try {
            val qrFile = File(tempDir, "qr_captures/qr_scan_123.jpg")
            val debugFile = File(tempDir, "debug_logs/report_456.txt")
            val yamlContent = "mixed-port: 7890\nproxies:\n  - name: HK-01\n    type: ss\n    password: ***REDACTED***\n"

            // 1. Stage pending YAML to private cache file and verify stale file pruning
            val unrelatedFile = File(tempDir, "keep_unrelated.txt").apply { writeText("keep") }
            val oldStaleYaml = File(
                tempDir,
                "${MainActivity.PENDING_YAML_EXPORT_PREFIX}1000_stale${MainActivity.PENDING_YAML_EXPORT_SUFFIX}",
            ).apply {
                writeText("old-stale")
                setLastModified(1_000L)
            }

            val stagedYamlFile = MainActivity.stagePendingYamlExportFile(
                cacheDir = tempDir,
                yamlContent = yamlContent,
                previousPendingFile = null,
                nowMs = 10_000_000L,
            )
            assertTrue(stagedYamlFile.isFile)
            assertTrue(stagedYamlFile.name.startsWith(MainActivity.PENDING_YAML_EXPORT_PREFIX))
            assertTrue(stagedYamlFile.name.endsWith(MainActivity.PENDING_YAML_EXPORT_SUFFIX))
            assertEquals(yamlContent, stagedYamlFile.readText(Charsets.UTF_8))
            assertFalse("Stale pending YAML file must be cleaned up on new stage", oldStaleYaml.exists())
            assertTrue("Unrelated cache files must never be deleted", unrelatedFile.isFile)

            // Blank YAML must be rejected without creating a temp file
            try {
                MainActivity.stagePendingYamlExportFile(cacheDir = tempDir, yamlContent = "   ")
                fail("Expected IllegalArgumentException for blank YAML")
            } catch (_: IllegalArgumentException) {
                // expected
            }

            // 2. Pending file paths roundtrip unconditionally (all 3 paths saved & restored cleanly)
            val savedStore = mutableMapOf<String, String>()
            val originalPending = MainActivity.PendingActivityFiles(
                cameraQrFile = qrFile,
                exportDebugFile = debugFile,
                exportYamlFile = stagedYamlFile,
            )
            MainActivity.savePendingFilePaths(
                putString = { k, v -> savedStore[k] = v },
                pendingFiles = originalPending,
            )
            assertEquals(3, savedStore.size)
            assertEquals(qrFile.absolutePath, savedStore[MainActivity.KEY_PENDING_CAMERA_QR_PATH])
            assertEquals(debugFile.absolutePath, savedStore[MainActivity.KEY_PENDING_EXPORT_DEBUG_PATH])
            assertEquals(stagedYamlFile.absolutePath, savedStore[MainActivity.KEY_PENDING_EXPORT_YAML_PATH])

            val restored = MainActivity.restorePendingFilePaths(
                getString = { k -> savedStore[k] },
            )
            assertEquals(qrFile.absolutePath, restored.cameraQrFile?.absolutePath)
            assertEquals(debugFile.absolutePath, restored.exportDebugFile?.absolutePath)
            assertEquals(stagedYamlFile.absolutePath, restored.exportYamlFile?.absolutePath)

            // Empty/blank/null store restores cleanly to all nulls
            val emptyRestored = MainActivity.restorePendingFilePaths(
                getString = { key -> if (key == MainActivity.KEY_PENDING_CAMERA_QR_PATH) "   " else null },
            )
            assertNull(emptyRestored.cameraQrFile)
            assertNull(emptyRestored.exportDebugFile)
            assertNull(emptyRestored.exportYamlFile)

            // 3. Stale cleanup preserves active restored pending YAML file AND fresh files, deletes expired ones
            val expiredYaml = File(
                tempDir,
                "${MainActivity.PENDING_YAML_EXPORT_PREFIX}500_old${MainActivity.PENDING_YAML_EXPORT_SUFFIX}",
            ).apply {
                writeText("expired")
                setLastModified(1_000L)
            }
            val recentYaml = File(
                tempDir,
                "${MainActivity.PENDING_YAML_EXPORT_PREFIX}999_recent${MainActivity.PENDING_YAML_EXPORT_SUFFIX}",
            ).apply {
                writeText("recent")
                setLastModified(9_999_000L)
            }
            stagedYamlFile.setLastModified(1_000L) // Even if old, keepFile must NEVER be deleted!
            MainActivity.cleanupStalePendingYamlExports(
                cacheDir = tempDir,
                keepFile = stagedYamlFile,
                nowMs = 10_000_000L,
                maxAgeMs = 3_600_000L,
            )
            assertTrue("Active keepFile must be preserved", stagedYamlFile.isFile)
            assertTrue("Fresh staged file within maxAgeMs must be preserved", recentYaml.isFile)
            assertFalse("Expired staged file must be deleted", expiredYaml.exists())
            assertTrue("Unrelated file must remain untouched", unrelatedFile.isFile)

            // 4. copyPendingFileToOutputStream: null OutputStream MUST return false (no false success toast!)
            assertFalse(
                "Null OutputStream from ContentResolver must fail export cleanly",
                MainActivity.copyPendingFileToOutputStream(
                    srcFile = stagedYamlFile,
                    openOutputStream = { null },
                ),
            )

            // Failing OutputStream (IOException) returns false cleanly
            assertFalse(
                "IOException during write must fail export cleanly",
                MainActivity.copyPendingFileToOutputStream(
                    srcFile = stagedYamlFile,
                    openOutputStream = {
                        object : OutputStream() {
                            override fun write(b: Int) {
                                throw IOException("simulated disk full")
                            }
                        }
                    },
                ),
            )

            // Missing source file returns false cleanly
            assertFalse(
                "Missing source file must fail export cleanly",
                MainActivity.copyPendingFileToOutputStream(
                    srcFile = File(tempDir, "does_not_exist.yaml"),
                    openOutputStream = { ByteArrayOutputStream() },
                ),
            )

            // Valid OutputStream succeeds and copies exact UTF-8 YAML bytes
            val sink = ByteArrayOutputStream()
            assertTrue(
                "Valid OutputStream must export staged YAML cleanly",
                MainActivity.copyPendingFileToOutputStream(
                    srcFile = stagedYamlFile,
                    openOutputStream = { sink },
                ),
            )
            assertEquals(yamlContent, sink.toString(Charsets.UTF_8.name()))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun yamlExportRapidDoubleTapIsSingleFlightPreservesStagedFileAndLaunchesSafOnce() {
        val tempDir = Files.createTempDirectory("rc-yaml-export-reentrancy-").toFile()
        val mainExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "test-main") }
        val ioExecutor = Executors.newFixedThreadPool(2) { r -> Thread(r, "test-io") }
        val mainDispatcher = mainExecutor.asCoroutineDispatcher()
        val ioDispatcher = ioExecutor.asCoroutineDispatcher()
        val vmScope = CoroutineScope(SupervisorJob() + mainDispatcher)
        val activityScope = CoroutineScope(SupervisorJob() + mainDispatcher)

        fun <T> onMain(block: () -> T): T = mainExecutor.submit(block).get(5, TimeUnit.SECONDS)

        try {
            val yamlPayload = "mixed-port: 7890\nproxies:\n  - name: JP-01\n    type: ss\n    password: ***REDACTED***\n"
            val yamlJson = """{"ok":true,"yaml":"mixed-port: 7890\nproxies:\n  - name: JP-01\n    type: ss\n    password: ***REDACTED***\n"}"""

            val fetchCount = AtomicInteger(0)
            val stageCount = AtomicInteger(0)
            val safLaunchCount = AtomicInteger(0)
            val messages = Collections.synchronizedList(mutableListOf<String>())

            val ioEntered = AtomicReference(CountDownLatch(1))
            val allowIoFinish = AtomicReference(CountDownLatch(1))
            val stagingEntered = AtomicReference(CountDownLatch(1))
            val allowStagingFinish = AtomicReference(CountDownLatch(1))
            val safLaunched = AtomicReference(CountDownLatch(1))

            val isStagingDuringLaunch = AtomicBoolean(false)
            val pendingFileDuringLaunch = AtomicReference<File?>(null)
            val launchedFileNames = Collections.synchronizedList(mutableListOf<String>())

            val runner = ActiveYamlExportRunner(
                scope = vmScope,
                ioDispatcher = ioDispatcher,
                ensureNativeLoaded = { true },
                fetchActiveYamlJson = {
                    fetchCount.incrementAndGet()
                    ioEntered.get().countDown()
                    assertTrue(allowIoFinish.get().await(5, TimeUnit.SECONDS))
                    yamlJson
                },
                emitMessage = { messages.add(it) },
            )

            lateinit var coordinator: YamlExportSafCoordinator
            coordinator = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { false },
                requestActiveYaml = { onReady, onFailure ->
                    runner.start(onReady = onReady, onFailure = onFailure)
                },
                launchSafPicker = { suggestedName ->
                    safLaunchCount.incrementAndGet()
                    launchedFileNames.add(suggestedName)
                    isStagingDuringLaunch.set(coordinator.isStagingYamlExport)
                    pendingFileDuringLaunch.set(coordinator.pendingExportYamlFile)
                    safLaunched.get().countDown()
                },
                emitMessage = { messages.add(it) },
                stageFile = { dir, content, prev ->
                    stageCount.incrementAndGet()
                    stagingEntered.get().countDown()
                    assertTrue(allowStagingFinish.get().await(5, TimeUnit.SECONDS))
                    MainActivity.stagePendingYamlExportFile(
                        cacheDir = dir,
                        yamlContent = content,
                        previousPendingFile = prev,
                    )
                },
            )

            // 1. Tap 1 sets isStagingYamlExport synchronously BEFORE IO finishes
            onMain {
                coordinator.onExportYamlClicked()
                assertTrue(
                    "isStagingYamlExport must be set synchronously on first tap",
                    coordinator.isStagingYamlExport,
                )
                assertTrue(
                    "ActiveYamlExportRunner must be marked in-flight synchronously",
                    runner.isExportInFlight,
                )
            }
            assertTrue("First IO fetch must start", ioEntered.get().await(5, TimeUnit.SECONDS))

            // 2. Rapid double-tap & triple-tap while ViewModel IO is still running MUST be dropped
            val directRejectReady = AtomicInteger(0)
            val directRejectFailure = AtomicInteger(0)
            onMain {
                coordinator.onExportYamlClicked()
                coordinator.onExportYamlClicked()
                val directAccepted = runner.start(
                    onReady = { directRejectReady.incrementAndGet() },
                    onFailure = { directRejectFailure.incrementAndGet() },
                )
                assertFalse("Direct overlapping ViewModel export must be rejected", directAccepted)
            }
            assertEquals("Overlapping taps must NOT launch second IO fetch", 1, fetchCount.get())
            assertEquals(0, directRejectReady.get())
            assertEquals(0, directRejectFailure.get())

            // 3. Let ViewModel IO finish; block inside disk staging and fire another rapid tap
            allowIoFinish.get().countDown()
            assertTrue("Disk staging must start", stagingEntered.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertTrue(
                    "isStagingYamlExport must remain true while staging YAML to cacheDir",
                    coordinator.isStagingYamlExport,
                )
                coordinator.onExportYamlClicked()
            }
            assertEquals("Tap during disk staging must NOT trigger second fetch", 1, fetchCount.get())
            assertEquals("Tap during disk staging must NOT trigger second stage", 1, stageCount.get())

            // 4. Release staging and wait for SAF picker launch
            allowStagingFinish.get().countDown()
            assertTrue("SAF picker must be launched", safLaunched.get().await(5, TimeUnit.SECONDS))
            // Drain main executor so finally block after launchSafPicker has executed
            onMain { /* fence */ }

            assertTrue(
                "isStagingYamlExport must STILL be true during safExportYamlLauncher.launch(...)",
                isStagingDuringLaunch.get(),
            )
            assertEquals(listOf("rustclash-config.yaml"), launchedFileNames)
            assertEquals(1, fetchCount.get())
            assertEquals(1, stageCount.get())
            assertEquals(1, safLaunchCount.get())

            val stagedFile1 = pendingFileDuringLaunch.get()
            assertNotNull("Staged YAML file must be assigned before launching SAF picker", stagedFile1)
            assertTrue("stagedFile1 must exist on disk", stagedFile1!!.isFile)
            assertEquals(yamlPayload, stagedFile1.readText(Charsets.UTF_8))

            // 5. After launchSafPicker returns: isStagingYamlExport is false, isSafPickerPending is true,
            //    and a rapid tap right before onPause() MUST NOT delete stagedFile1 or stack a duplicate picker!
            onMain {
                assertFalse("isStagingYamlExport must reset in finally after launch", coordinator.isStagingYamlExport)
                assertTrue("isSafPickerPending must guard the post-launch window", coordinator.isSafPickerPending)
                assertSame(stagedFile1, coordinator.pendingExportYamlFile)

                coordinator.onExportYamlClicked()

                assertSame("stagedFile1 must remain assigned for onSaveInstanceState", stagedFile1, coordinator.pendingExportYamlFile)
            }
            assertTrue("stagedFile1 must NEVER be deleted by rejected rapid tap", stagedFile1.isFile)
            assertEquals(1, fetchCount.get())
            assertEquals(1, stageCount.get())
            assertEquals("SAF picker must have been launched strictly once", 1, safLaunchCount.get())

            // 6. SAF result callback consumes stagedFile1 and writes exact bytes
            val consumedFile = onMain { coordinator.consumePendingFileForSafResult() }
            assertSame(stagedFile1, consumedFile)
            onMain {
                assertNull(coordinator.pendingExportYamlFile)
                assertFalse(coordinator.isSafPickerPending)
            }
            val exportedBytes = ByteArrayOutputStream()
            assertTrue(
                MainActivity.copyPendingFileToOutputStream(
                    srcFile = consumedFile!!,
                    openOutputStream = { exportedBytes },
                ),
            )
            assertEquals(yamlPayload, exportedBytes.toString(Charsets.UTF_8.name()))

            // 7. After SAF completes, a new user tap succeeds cleanly
            ioEntered.set(CountDownLatch(1))
            allowIoFinish.set(CountDownLatch(0))
            stagingEntered.set(CountDownLatch(1))
            allowStagingFinish.set(CountDownLatch(0))
            safLaunched.set(CountDownLatch(1))

            onMain { coordinator.onExportYamlClicked() }
            assertTrue("Second export after completion must launch SAF", safLaunched.get().await(5, TimeUnit.SECONDS))
            onMain { /* fence */ }
            assertEquals(2, fetchCount.get())
            assertEquals(2, stageCount.get())
            assertEquals(2, safLaunchCount.get())
            assertNotNull(onMain { coordinator.pendingExportYamlFile })

            // 8. If SAF picker is abandoned without a callback, onActivityResumed() releases the pending-picker guard
            safLaunched.set(CountDownLatch(1))
            onMain {
                assertTrue(coordinator.isSafPickerPending)
                coordinator.onActivityResumed()
                assertFalse(coordinator.isSafPickerPending)
                coordinator.onExportYamlClicked()
            }
            assertTrue("Export after onActivityResumed() recovery must succeed", safLaunched.get().await(5, TimeUnit.SECONDS))
            onMain { /* fence */ }
            assertEquals(3, safLaunchCount.get())
            assertTrue("No error messages expected on happy paths: $messages", messages.isEmpty())
        } finally {
            activityScope.cancel()
            vmScope.cancel()
            mainDispatcher.close()
            ioDispatcher.close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun yamlExportFailuresEmptyPayloadExceptionsAndActivityDestructionResetGuardsCleanly() {
        val tempDir = Files.createTempDirectory("rc-yaml-export-recovery-").toFile()
        val mainExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "test-main-rec") }
        val ioExecutor = Executors.newFixedThreadPool(2) { r -> Thread(r, "test-io-rec") }
        val mainDispatcher = mainExecutor.asCoroutineDispatcher()
        val ioDispatcher = ioExecutor.asCoroutineDispatcher()
        val vmScope = CoroutineScope(SupervisorJob() + mainDispatcher)
        val activityScope = CoroutineScope(SupervisorJob() + mainDispatcher)

        fun <T> onMain(block: () -> T): T = mainExecutor.submit(block).get(5, TimeUnit.SECONDS)

        try {
            val nativeLoaded = AtomicBoolean(false)
            val fetchBehavior = AtomicReference<() -> String> { """{"ok":true,"yaml":"port: 7890\n"}""" }
            val activityInvalid = AtomicBoolean(false)
            val throwOnLaunch = AtomicBoolean(false)
            val messages = Collections.synchronizedList(mutableListOf<String>())
            val safLaunchCount = AtomicInteger(0)
            val failureNotified = AtomicReference(CountDownLatch(1))
            val safLaunched = AtomicReference(CountDownLatch(1))

            val runner = ActiveYamlExportRunner(
                scope = vmScope,
                ioDispatcher = ioDispatcher,
                ensureNativeLoaded = { nativeLoaded.get() },
                fetchActiveYamlJson = { fetchBehavior.get().invoke() },
                emitMessage = { messages.add(it) },
            )

            val coordinator = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { activityInvalid.get() },
                requestActiveYaml = { onReady, onFailure ->
                    runner.start(
                        onReady = onReady,
                        onFailure = {
                            onFailure()
                            failureNotified.get().countDown()
                        },
                    )
                },
                launchSafPicker = {
                    if (throwOnLaunch.get()) {
                        throw IllegalStateException("No SAF handler installed")
                    }
                    safLaunchCount.incrementAndGet()
                    safLaunched.get().countDown()
                },
                emitMessage = { messages.add(it) },
            )

            // Case A: Native library not loaded -> invokes onFailure, resets guards, never launches SAF
            failureNotified.set(CountDownLatch(1))
            onMain { coordinator.onExportYamlClicked() }
            assertTrue(failureNotified.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse("Guard must reset when native library fails to load", coordinator.isStagingYamlExport)
                assertFalse(coordinator.isSafPickerPending)
                assertFalse(runner.isExportInFlight)
                assertNull(coordinator.pendingExportYamlFile)
            }
            assertEquals(0, safLaunchCount.get())
            assertEquals("Rust 核心库未加载", messages.last())

            // Case B: Empty / blank YAML payload -> invokes onFailure, resets guards
            nativeLoaded.set(true)
            fetchBehavior.set { """{"ok":true,"yaml":"   "}""" }
            failureNotified.set(CountDownLatch(1))
            onMain { coordinator.onExportYamlClicked() }
            assertTrue(failureNotified.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse("Guard must reset on blank YAML", coordinator.isStagingYamlExport)
                assertFalse(runner.isExportInFlight)
            }
            assertEquals(0, safLaunchCount.get())
            assertEquals("无法导出当前 YAML 配置", messages.last())

            // Case B2: Backend ok=false with explicit error message
            fetchBehavior.set { """{"ok":false,"error":"profile not ready"}""" }
            failureNotified.set(CountDownLatch(1))
            onMain { coordinator.onExportYamlClicked() }
            assertTrue(failureNotified.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse(coordinator.isStagingYamlExport)
                assertFalse(runner.isExportInFlight)
            }
            assertEquals("profile not ready", messages.last())

            // Case C: IO exception thrown by native bridge -> caught cleanly, resets guards
            fetchBehavior.set { throw RuntimeException("simulated JNI IO failure") }
            failureNotified.set(CountDownLatch(1))
            onMain { coordinator.onExportYamlClicked() }
            assertTrue(failureNotified.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse("Guard must reset after IO exception", coordinator.isStagingYamlExport)
                assertFalse(runner.isExportInFlight)
            }
            assertEquals("无法导出当前 YAML 配置", messages.last())

            // Case D: launchSafPicker throws -> deletes staged temp file, clears pendingExportYamlFile & guards
            fetchBehavior.set { """{"ok":true,"yaml":"mixed-port: 7890\n"}""" }
            throwOnLaunch.set(true)
            val launchFailureMsg = CountDownLatch(1)
            val failingLaunchCoordinator = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { false },
                requestActiveYaml = { onReady, onFailure ->
                    runner.start(onReady = onReady, onFailure = onFailure)
                },
                launchSafPicker = { throw IllegalStateException("ActivityNotFoundException") },
                emitMessage = {
                    messages.add(it)
                    launchFailureMsg.countDown()
                },
            )
            onMain { failingLaunchCoordinator.onExportYamlClicked() }
            assertTrue(launchFailureMsg.await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse(failingLaunchCoordinator.isStagingYamlExport)
                assertFalse(failingLaunchCoordinator.isSafPickerPending)
                assertNull(failingLaunchCoordinator.pendingExportYamlFile)
            }
            val leftoverAfterLaunchFail = tempDir.listFiles { f ->
                f.name.startsWith(MainActivity.PENDING_YAML_EXPORT_PREFIX)
            }.orEmpty()
            assertEquals("Staged file must be deleted when SAF launch fails", 0, leftoverAfterLaunchFail.size)

            // Retry after all prior failures MUST now succeed cleanly
            throwOnLaunch.set(false)
            safLaunched.set(CountDownLatch(1))
            onMain { coordinator.onExportYamlClicked() }
            assertTrue("Subsequent retry after failures must succeed", safLaunched.get().await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse(coordinator.isStagingYamlExport)
                assertTrue(coordinator.isSafPickerPending)
                assertNotNull(coordinator.pendingExportYamlFile)
                coordinator.consumePendingFileForSafResult()?.delete()
            }
            assertEquals(1, safLaunchCount.get())

            // Case E: Activity becomes isFinishing/isDestroyed mid-staging -> deletes staged file, never launches SAF
            val stagingStarted = CountDownLatch(1)
            val allowStageComplete = CountDownLatch(1)
            val orphanDeleted = CountDownLatch(1)
            val midDestroyInvalid = AtomicBoolean(false)
            val midDestroySafCount = AtomicInteger(0)
            val createdStagedRef = AtomicReference<File?>(null)

            val midDestroyCoordinator = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { midDestroyInvalid.get() },
                requestActiveYaml = { onReady, onFailure ->
                    runner.start(onReady = onReady, onFailure = onFailure)
                },
                launchSafPicker = { midDestroySafCount.incrementAndGet() },
                emitMessage = { messages.add(it) },
                stageFile = { dir, content, prev ->
                    val file = MainActivity.stagePendingYamlExportFile(dir, content, prev)
                    createdStagedRef.set(file)
                    stagingStarted.countDown()
                    assertTrue(allowStageComplete.await(5, TimeUnit.SECONDS))
                    file
                },
                deleteFile = { f ->
                    f.delete()
                    orphanDeleted.countDown()
                },
            )
            onMain { midDestroyCoordinator.onExportYamlClicked() }
            assertTrue(stagingStarted.await(5, TimeUnit.SECONDS))
            midDestroyInvalid.set(true)
            allowStageComplete.countDown()
            assertTrue("Orphan staged file must be deleted on Activity invalidation", orphanDeleted.await(5, TimeUnit.SECONDS))
            // deleteFile runs on ioDispatcher inside withContext(NonCancellable + ioDispatcher);
            // join activityScope's child coroutine(s) so finally { isStagingYamlExport = false }
            // completes deterministically on mainDispatcher before asserting guard state.
            runBlocking {
                withTimeout(5_000) {
                    activityScope.coroutineContext[Job]!!.children.toList().forEach { it.join() }
                }
            }
            onMain {
                assertFalse(midDestroyCoordinator.isStagingYamlExport)
                assertFalse(midDestroyCoordinator.isSafPickerPending)
                assertNull(midDestroyCoordinator.pendingExportYamlFile)
            }
            assertEquals("SAF picker must NOT launch after Activity invalidation", 0, midDestroySafCount.get())
            assertFalse("Staged file must no longer exist on disk", createdStagedRef.get()!!.exists())

            // Case F: Activity scope cancelled mid-staging -> NonCancellable deletes orphan file, resets guard
            val cancelScope = CoroutineScope(SupervisorJob() + mainDispatcher)
            val cancelStageStarted = CountDownLatch(1)
            val cancelIssued = CountDownLatch(1)
            val cancelOrphanDeleted = CountDownLatch(1)
            val cancelSafCount = AtomicInteger(0)
            val cancelFileRef = AtomicReference<File?>(null)
            val cancelCoordinator = YamlExportSafCoordinator(
                scope = cancelScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { false },
                requestActiveYaml = { onReady, onFailure ->
                    runner.start(onReady = onReady, onFailure = onFailure)
                },
                launchSafPicker = { cancelSafCount.incrementAndGet() },
                emitMessage = { messages.add(it) },
                stageFile = { dir, content, prev ->
                    val file = MainActivity.stagePendingYamlExportFile(dir, content, prev)
                    cancelFileRef.set(file)
                    cancelStageStarted.countDown()
                    assertTrue(cancelIssued.await(5, TimeUnit.SECONDS))
                    file
                },
                deleteFile = { f ->
                    f.delete()
                    cancelOrphanDeleted.countDown()
                },
            )
            onMain { cancelCoordinator.onExportYamlClicked() }
            assertTrue(cancelStageStarted.await(5, TimeUnit.SECONDS))
            cancelScope.cancel()
            cancelIssued.countDown()
            assertTrue("Orphan staged file must be deleted when scope cancels mid-staging", cancelOrphanDeleted.await(5, TimeUnit.SECONDS))
            // deleteFile runs on ioDispatcher inside withContext(NonCancellable + ioDispatcher);
            // join cancelScope's cancelled Job so the staging coroutine's finally block completes
            // deterministically on mainDispatcher before asserting guard state.
            runBlocking {
                withTimeout(5_000) {
                    cancelScope.coroutineContext[Job]!!.join()
                }
            }
            onMain {
                assertFalse(cancelCoordinator.isStagingYamlExport)
                assertNull(cancelCoordinator.pendingExportYamlFile)
            }
            assertEquals(0, cancelSafCount.get())
            assertFalse(cancelFileRef.get()!!.exists())

            // Case G: Cross-Activity rotation where runner is still busy from Activity1:
            //         Activity2 tap must be rejected cleanly WITHOUT leaving Activity2.isStagingYamlExport stuck!
            val slowIoEntered = CountDownLatch(1)
            val allowSlowIoFinish = CountDownLatch(1)
            val slowRunner = ActiveYamlExportRunner(
                scope = vmScope,
                ioDispatcher = ioDispatcher,
                ensureNativeLoaded = { true },
                fetchActiveYamlJson = {
                    slowIoEntered.countDown()
                    assertTrue(allowSlowIoFinish.await(5, TimeUnit.SECONDS))
                    """{"ok":true,"yaml":"port: 7890\n"}"""
                },
                emitMessage = { messages.add(it) },
            )
            val activity1Invalid = AtomicBoolean(false)
            val activity1ReadyHandled = CountDownLatch(1)
            val activity1 = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = {
                    val invalid = activity1Invalid.get()
                    if (invalid) activity1ReadyHandled.countDown()
                    invalid
                },
                requestActiveYaml = { onReady, onFailure -> slowRunner.start(onReady, onFailure) },
                launchSafPicker = { fail("Destroyed Activity1 must never launch SAF") },
                emitMessage = { messages.add(it) },
            )
            val activity2SafLaunched = CountDownLatch(1)
            val activity2 = YamlExportSafCoordinator(
                scope = activityScope,
                ioDispatcher = ioDispatcher,
                cacheDirProvider = { tempDir },
                isActivityInvalid = { false },
                requestActiveYaml = { onReady, onFailure -> slowRunner.start(onReady, onFailure) },
                launchSafPicker = { activity2SafLaunched.countDown() },
                emitMessage = { messages.add(it) },
            )
            onMain { activity1.onExportYamlClicked() }
            assertTrue(slowIoEntered.await(5, TimeUnit.SECONDS))
            activity1Invalid.set(true)

            onMain {
                // Activity2 taps while Activity1's ViewModel job is still active
                activity2.onExportYamlClicked()
                assertFalse(
                    "Activity2 must reset isStagingYamlExport when runner rejects overlapping request",
                    activity2.isStagingYamlExport,
                )
            }
            allowSlowIoFinish.countDown()
            assertTrue(activity1ReadyHandled.await(5, TimeUnit.SECONDS))
            onMain {
                assertFalse(activity1.isStagingYamlExport)
                assertFalse(slowRunner.isExportInFlight)
                activity2.onExportYamlClicked()
            }
            assertTrue("Activity2 retry after Activity1 IO completes must succeed", activity2SafLaunched.await(5, TimeUnit.SECONDS))
            onMain { activity2.consumePendingFileForSafResult()?.delete() }

            // Case H: stagePendingYamlExportFile preserves an active in-flight SAF copy file while pruning orphans
            val activeCopy = MainActivity.stagePendingYamlExportFile(
                cacheDir = tempDir,
                yamlContent = "active: copy\n",
                nowMs = 1_000L,
            )
            val staleOrphan = File(
                tempDir,
                "${MainActivity.PENDING_YAML_EXPORT_PREFIX}500_orphan${MainActivity.PENDING_YAML_EXPORT_SUFFIX}",
            ).apply { writeText("orphan") }
            val nextStaged = MainActivity.stagePendingYamlExportFile(
                cacheDir = tempDir,
                yamlContent = "next: export\n",
                previousPendingFile = null,
                nowMs = 2_000L,
                keepActiveCopyFile = activeCopy,
            )
            assertTrue("In-flight copy file must be preserved while staging next export", activeCopy.isFile)
            assertTrue("Newly staged file must exist", nextStaged.isFile)
            assertFalse("Unrelated stale pending YAML must still be pruned", staleOrphan.exists())
        } finally {
            activityScope.cancel()
            vmScope.cancel()
            mainDispatcher.close()
            ioDispatcher.close()
            tempDir.deleteRecursively()
        }
    }
}
