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
}
