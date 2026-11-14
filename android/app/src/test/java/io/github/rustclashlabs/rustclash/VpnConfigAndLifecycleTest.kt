package io.github.rustclashlabs.rustclash

import io.github.rustclashlabs.rustclash.ui.model.DiagnosticsFilter
import io.github.rustclashlabs.rustclash.ui.model.ProxyNodeItem
import io.github.rustclashlabs.rustclash.ui.model.RoutingPresetUi
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference
import io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.PerAppMode
import io.github.rustclashlabs.rustclash.vpn.PerAppVpnPolicy
import io.github.rustclashlabs.rustclash.vpn.RustClashVpnService
import io.github.rustclashlabs.rustclash.vpn.UnderlyingNetworkTracker
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import io.github.rustclashlabs.rustclash.vpn.VpnSessionConfig
import io.github.rustclashlabs.rustclash.vpn.VpnStateTracker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

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
}

