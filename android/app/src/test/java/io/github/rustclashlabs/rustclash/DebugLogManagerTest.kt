package io.github.rustclashlabs.rustclash

import io.github.rustclashlabs.rustclash.vpn.DebugLogManager
import io.github.rustclashlabs.rustclash.vpn.MobileTimelineEvent
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class DebugLogManagerTest {

    @Test
    fun redactSecretsScrubsSubscriptionPathAndQueryTokensWhilePreservingDomainsRulesAndNodes() {
        val raw = buildString {
            appendLine("Visited: api.bilibili.com:443 -> GeoSite(cn) -> DIRECT")
            appendLine("Visited: www.google.com:443 -> GeoSite(geolocation-!cn) -> 🇭🇰 香港-IPLC-01")
            appendLine("Probe: http://www.gstatic.com/generate_204")
            appendLine("QuerySub: https://sub.example.com/api/v1/client/subscribe?token=SUPER_SECRET_QUERY_TOKEN_111&flag=clash")
            appendLine("PathSub1: https://panel.example.com/s/9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c")
            appendLine("PathSub2: https://panel.example.com/link/AbCdEfGhIjKlMnOpQrSt")
            appendLine("YamlSub: https://cdn.example.com/9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c.yaml")
            appendLine("NodeLeak: vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?encryption=mlkem768x25519plus.PQ_SECRET_KEY_222#HK")
            appendLine("InlineAuth: password=NODE_PASS_333 auth_str:HY2_AUTH_444")
        }

        val scrubbed = NodeImportSupport.redactSecretsForUi(raw)

        // 1. Visited domains, routing rules, benign probe URL, and node names MUST remain intact
        assertTrue(scrubbed.contains("api.bilibili.com:443"))
        assertTrue(scrubbed.contains("GeoSite(cn)"))
        assertTrue(scrubbed.contains("www.google.com:443"))
        assertTrue(scrubbed.contains("🇭🇰 香港-IPLC-01"))
        assertTrue(scrubbed.contains("http://www.gstatic.com/generate_204"))

        // 2. All credentials, UUIDs, PQ keys, and subscription tokens MUST be scrubbed
        assertFalse(scrubbed.contains("SUPER_SECRET_QUERY_TOKEN_111"))
        assertFalse(scrubbed.contains("9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"))
        assertFalse(scrubbed.contains("AbCdEfGhIjKlMnOpQrSt"))
        assertFalse(scrubbed.contains("550e8400-e29b-41d4-a716-446655440000"))
        assertFalse(scrubbed.contains("PQ_SECRET_KEY_222"))
        assertFalse(scrubbed.contains("NODE_PASS_333"))
        assertFalse(scrubbed.contains("HY2_AUTH_444"))

        assertTrue(scrubbed.contains("https://sub.example.com/api/v1/client/subscribe?***REDACTED***"))
        assertTrue(scrubbed.contains("https://panel.example.com/s/***REDACTED***"))
        assertTrue(scrubbed.contains("https://panel.example.com/link/***REDACTED***"))
        assertTrue(scrubbed.contains("https://cdn.example.com/***REDACTED***"))
        assertTrue(scrubbed.contains("vless://***REDACTED***"))
        assertTrue(scrubbed.contains("password=***REDACTED***"))
        assertTrue(scrubbed.contains("auth_str:***REDACTED***"))
    }

    @Test
    fun retentionPolicyEnforcesMaxFileCountAndMaxTotalBytesOldestFirst() {
        val tempDir = Files.createTempDirectory("rc-debug-retention-test").toFile()
        try {
            // Create 5 chronological slice files (~1000 bytes each)
            val names = listOf(
                "rustclash-slice-20261113-100000-000-periodic.log",
                "rustclash-slice-20261113-103000-000-periodic.log",
                "rustclash-slice-20261113-110000-000-screen-on.log",
                "rustclash-slice-20261113-113000-000-disconnect.log",
                "rustclash-slice-20261113-120000-000-manual.log",
            )
            names.forEachIndexed { idx, name ->
                val f = File(tempDir, name)
                f.writeText("slice-$idx-" + "x".repeat(1000), Charsets.UTF_8)
                f.setLastModified(1_700_000_000_000L + idx * 60_000L)
            }
            // Crash breadcrumb must NOT be treated as a rolling slice
            val crashFile = File(tempDir, DebugLogManager.CRASH_BREADCRUMB_FILE)
            crashFile.writeText("stacktrace", Charsets.UTF_8)

            assertEquals("periodic", DebugLogManager.parseTriggerFromFileName(names[0]))
            assertEquals("screen-on", DebugLogManager.parseTriggerFromFileName(names[2]))
            assertEquals("disconnect", DebugLogManager.parseTriggerFromFileName(names[3]))

            // 1. Cap maxFiles = 4 -> oldest file (100000) is evicted
            DebugLogManager.enforceRetentionPolicy(tempDir, maxFiles = 4, maxTotalBytes = 100_000L)
            val afterCountCap = DebugLogManager.listSliceFilesNewestFirst(tempDir)
            assertEquals(4, afterCountCap.size)
            assertFalse(File(tempDir, names[0]).exists())
            assertTrue(crashFile.exists())

            // 2. Cap maxTotalBytes = 2500 -> keeps newest 2 files (120000 and 113000), evicting 103000 & 110000
            DebugLogManager.enforceRetentionPolicy(tempDir, maxFiles = 12, maxTotalBytes = 2_500L)
            val summary = DebugLogManager.buildStorageSummaryFromDir(
                dir = tempDir,
                enabled = true,
                sliceIntervalSecs = 1800L,
            )
            assertEquals(2, summary.sliceCount)
            assertTrue(summary.hasCrashBreadcrumb)
            assertEquals(names[4], summary.recentSlices[0].fileName)
            assertEquals("manual", summary.recentSlices[0].trigger)
            assertEquals(names[3], summary.recentSlices[1].fileName)
            assertEquals("disconnect", summary.recentSlices[1].trigger)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun formatSliceAndCombinedBundleIncludeMobileMetricsDomainsHandshakesAndScrubSecrets() {
        val sliceDir = Files.createTempDirectory("rc-debug-slices").toFile()
        val exportDir = Files.createTempDirectory("rc-debug-exports").toFile()
        try {
            val t0 = 1_763_000_000_000L
            val t1 = t0 + 1_800_000L
            val window = DebugLogManager.WindowTelemetryState(
                windowStartMs = t0,
                capturedAtMs = t1,
                sessionStartMs = t0,
                screenOnMs = 600_000L,
                screenOffMs = 1_200_000L,
                startBatteryPct = 86,
                events = listOf(
                    MobileTimelineEvent(t0 + 1_000L, "VPN_START", "interactive=true demo=false ipv6=true battery=86%"),
                    MobileTimelineEvent(t0 + 300_000L, "SCREEN_OFF", "interactive=false"),
                    MobileTimelineEvent(t0 + 900_000L, "NET_LOST", "handle=100 activeUnderlyingLost=true"),
                    MobileTimelineEvent(
                        t0 + 900_420L,
                        "NET_AVAILABLE",
                        "handle=200 transport=CELLULAR validated=true unmetered=false bw=50000/15000kbps handoff=true recoveryGapMs=420",
                    ),
                ),
            )
            val sysMeta = DebugLogManager.SystemMetadata(
                deviceManufacturer = "Xiaomi",
                deviceModel = "24031PN0DC",
                androidRelease = "15",
                sdkInt = 35,
                primaryAbi = "arm64-v8a",
                appVersionName = "0.3.8",
                appVersionCode = 14,
                battery = DebugLogManager.BatterySnapshot(levelPct = 83, isCharging = false, temperatureCelsius = 34.5),
                isInteractive = true,
                isPowerSaveMode = false,
                isDeviceIdleDoze = false,
                ignoringBatteryOptimizations = false,
                jvmUsedBytes = 24L * 1024L * 1024L,
                jvmMaxBytes = 256L * 1024L * 1024L,
                nativeHeapBytes = 18L * 1024L * 1024L,
                perAppMode = "ALL_APPS",
                selectedPackagesCount = 0,
                enableIpv6 = true,
                demoMode = false,
                recentProcessExits = listOf("[2026-11-13] reason=OTHER_OEM_KILL importance=125 pss=42000KB rss=58000KB desc=miui_cleaner"),
            )
            val sampleNativeJson = """
                {
                  "ok": true,
                  "vpnRunning": true,
                  "debugMode": true,
                  "uptimeSecs": 1800,
                  "rssBytes": 48234496,
                  "mode": "rule",
                  "routingPreset": "smart-cn",
                  "effectiveOutbound": "HK-IPLC-01",
                  "effectiveProtocol": "VLESS",
                  "effectiveDelayMs": 32,
                  "networkTransitions": 1,
                  "isWifi": false,
                  "activeProfile": {
                    "name": "主力订阅",
                    "kind": "subscription",
                    "proxyCount": 24,
                    "manualProxyCount": 2,
                    "ruleCount": 120,
                    "autoUpdateIntervalSecs": 21600,
                    "subscriptionHost": "https://sub.example.com/api/v1?token=LEAKED_SUB_TOKEN_777"
                  },
                  "traffic": {
                    "upTotal": 2097152,
                    "downTotal": 52428800,
                    "activeConnections": 6,
                    "totalConnections": 140,
                    "establishedConnections": 136,
                    "failedConnections": 4,
                    "zeroRxClosedConnections": 2
                  },
                  "tun": {
                    "rxPackets": 18500,
                    "txPackets": 24100,
                    "rxBytes": 2300000,
                    "txBytes": 54000000,
                    "txWriteDrops": 0,
                    "protectedTcpSockets": 142,
                    "protectedUdpSockets": 38,
                    "protectFailures": 0
                  },
                  "dns": {
                    "total_queries": 310,
                    "fake_ip_hits": 260,
                    "cache_hits": 35,
                    "upstream_queries": 15,
                    "upstream_errors": 1,
                    "upstream_avg_ms": 28,
                    "upstream_max_ms": 185,
                    "active_fake_ip_entries": 94
                  },
                  "outboundStats": [
                    {
                      "outbound": "HK-IPLC-01",
                      "protocol": "VLESS",
                      "exitType": "PROXY",
                      "latestProbeDelayMs": 32,
                      "connections": 95,
                      "failures": 4,
                      "zeroRxCount": 2,
                      "handshakeSamples": 91,
                      "handshakeP50Ms": 48,
                      "handshakeP95Ms": 310,
                      "handshakeMaxMs": 890,
                      "uploadBytes": 1800000,
                      "downloadBytes": 48000000
                    }
                  ],
                  "topRules": [
                    { "type": "GeoSite", "payload": "geolocation-!cn", "proxy": "PROXY", "hits": 95 },
                    { "type": "GeoSite", "payload": "cn", "proxy": "DIRECT", "hits": 45 }
                  ],
                  "topDomains": [
                    {
                      "host": "googlevideo.com",
                      "connections": 28,
                      "failures": 1,
                      "uploadBytes": 512000,
                      "downloadBytes": 38000000,
                      "primaryRule": "GeoSite,geolocation-!cn",
                      "primaryOutbound": "HK-IPLC-01"
                    }
                  ],
                  "failedConnections": [
                    {
                      "host": "chat.openai.com",
                      "destinationPort": 443,
                      "network": "tcp",
                      "fakeIp": "198.18.0.42",
                      "rule": "GeoSite",
                      "rulePayload": "geolocation-!cn",
                      "effectiveOutbound": "HK-IPLC-01",
                      "effectiveProtocol": "VLESS",
                      "error": "tls handshake eof with uuid=12345678-1234-4321-abcd-9876543210ff",
                      "startEpochMs": 1763000900100
                    }
                  ],
                  "slowConnections": [
                    {
                      "host": "www.youtube.com",
                      "destinationPort": 443,
                      "network": "tcp",
                      "rule": "GeoSite",
                      "rulePayload": "geolocation-!cn",
                      "effectiveOutbound": "HK-IPLC-01",
                      "connectDurationMs": 890,
                      "upload": 4096,
                      "download": 1048576,
                      "status": "closed"
                    }
                  ]
                }
            """.trimIndent()

            val slice1 = DebugLogManager.formatSliceReport(
                trigger = "periodic",
                window = window,
                systemMeta = sysMeta,
                nativeSnapshotRawJson = sampleNativeJson,
                crashBreadcrumb = null,
            )

            File(sliceDir, "rustclash-slice-20261113-120000-000-periodic.log").writeText(slice1, Charsets.UTF_8)
            File(sliceDir, "rustclash-slice-20261113-123000-000-disconnect.log").writeText(
                slice1.replace("(`periodic`)", "(`disconnect`)"),
                Charsets.UTF_8,
            )

            val combined = DebugLogManager.assembleCombinedExportFromSlices(
                sliceDir = sliceDir,
                exportDir = exportDir,
                nowMs = t1 + 60_000L,
            )
            assertNotNull(combined)
            val bundleText = combined!!.readText(Charsets.UTF_8)

            // Chronological order: periodic (120000) appears BEFORE disconnect (123000)
            val idxPeriodic = bundleText.indexOf("120000-000-periodic.log")
            val idxDisconnect = bundleText.indexOf("123000-000-disconnect.log")
            assertTrue(idxPeriodic in 0 until idxDisconnect)

            // Mobile telemetry, domains, rules, handshakes, and OEM kill diagnostics preserved
            assertTrue(bundleText.contains("86% -> 83% (-3%)"))
            assertTrue(bundleText.contains("screenOn=`600s` screenOff=`1200s`"))
            assertTrue(bundleText.contains("recoveryGapMs=420"))
            assertTrue(bundleText.contains("OTHER_OEM_KILL"))
            assertTrue(bundleText.contains("HK-IPLC-01"))
            assertTrue(bundleText.contains("48ms / 310ms / 890ms"))
            assertTrue(bundleText.contains("googlevideo.com"))
            assertTrue(bundleText.contains("chat.openai.com:443"))
            assertTrue(bundleText.contains("www.youtube.com:443"))

            // Secrets inside native JSON or error strings are scrubbed
            assertFalse(bundleText.contains("LEAKED_SUB_TOKEN_777"))
            assertFalse(bundleText.contains("12345678-1234-4321-abcd-9876543210ff"))

            // Interval normalization & slice timestamp formatting check
            assertEquals(900L, DebugLogManager.normalizeSliceIntervalSecs(600L))
            assertEquals(1800L, DebugLogManager.normalizeSliceIntervalSecs(1800L))
            assertEquals(3600L, DebugLogManager.normalizeSliceIntervalSecs(7200L))
            assertEquals("-", io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers.formatEpochTime(0L))
            assertTrue(io.github.rustclashlabs.rustclash.ui.model.UiJsonParsers.formatEpochTime(t1).contains(":"))
        } finally {
            sliceDir.deleteRecursively()
            exportDir.deleteRecursively()
        }
    }

    @Test
    fun formatSliceReportHandlesNullSubHostIpv6EndpointsDnsCountersAndRuleWindowDeltas() {
        val t0 = 1_763_000_000_000L
        val t1 = t0 + 900_000L
        val window = DebugLogManager.WindowTelemetryState(
            windowStartMs = t0,
            capturedAtMs = t1,
            sessionStartMs = t0 - 900_000L,
            screenOnMs = 300_000L,
            screenOffMs = 600_000L,
            startBatteryPct = 80,
            events = emptyList(),
        )
        val sysMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "HONOR",
            deviceModel = "PGT-AN10",
            androidRelease = "15",
            sdkInt = 35,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.3.9",
            appVersionCode = 15,
            battery = DebugLogManager.BatterySnapshot(levelPct = 79, isCharging = false, temperatureCelsius = 32.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = false,
            jvmUsedBytes = 20L * 1024L * 1024L,
            jvmMaxBytes = 256L * 1024L * 1024L,
            nativeHeapBytes = 16L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )
        val nativeJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "debugMode": true,
              "uptimeSecs": 1800,
              "rssBytes": 41943040,
              "mode": "rule",
              "routingPreset": "smart-cn",
              "effectiveOutbound": "HK-Node-01",
              "effectiveProtocol": "VLESS",
              "effectiveDelayMs": 38,
              "networkTransitions": 0,
              "isWifi": true,
              "activeProfile": {
                "name": "Sub (203.0.113.124)",
                "kind": "subscription",
                "proxyCount": 16,
                "manualProxyCount": 0,
                "ruleCount": 80,
                "autoUpdateIntervalSecs": 86400,
                "subscriptionHost": null
              },
              "traffic": {
                "upTotal": 1048576,
                "downTotal": 10485760,
                "activeConnections": 5,
                "carryOverActiveConnections": 3,
                "totalConnections": 60,
                "establishedConnections": 58,
                "failedConnections": 2,
                "zeroRxClosedConnections": 0
              },
              "dns": {
                "total_queries": 120,
                "fake_ip_hits": 60,
                "cache_hits": 10,
                "suppressed_queries": 35,
                "nxdomain_hits": 5,
                "upstream_queries": 10,
                "upstream_errors": 0,
                "upstream_avg_ms": 22,
                "upstream_max_ms": 90,
                "active_fake_ip_entries": 48
              },
              "topRules": [
                { "type": "GeoSite", "payload": "cn", "proxy": "DIRECT", "hits": 100 },
                { "type": "GeoSite", "payload": "geolocation-!cn", "proxy": "PROXY", "hits": 120 }
              ],
              "failedConnections": [
                {
                  "host": "2001:4860:4864:4:8000::",
                  "destinationPort": 3478,
                  "network": "udp",
                  "rule": "Match",
                  "rulePayload": "",
                  "effectiveOutbound": "HK-Node-01",
                  "effectiveProtocol": "VLESS",
                  "error": "udp relay timeout",
                  "startEpochMs": 1763000100000
                }
              ],
              "slowConnections": [
                {
                  "host": "2408:8756:c50:101d::443",
                  "destinationPort": 443,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "connectDurationMs": 620,
                  "upload": 1024,
                  "download": 8192,
                  "status": "closed"
                }
              ],
              "recentConnections": [
                {
                  "host": "2408:8756::443",
                  "destinationPort": 443,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "connectDurationMs": 24,
                  "upload": 512,
                  "download": 2048,
                  "status": "active",
                  "startEpochMs": 1763000200000
                }
              ]
            }
        """.trimIndent()

        val previousHits = mapOf(
            "GeoSite,cn->DIRECT" to 90L,
            "GeoSite,geolocation-!cn->PROXY" to 60L,
        )

        val report = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = nativeJson,
            crashBreadcrumb = null,
            previousRuleHits = previousHits,
        )

        // 1. JSONObject.NULL subscriptionHost renders as `-`, never `null`, and Sub (<ip>) is scrubbed
        assertTrue(report.contains("subHost=`-`"))
        assertFalse(report.contains("subHost=`null`"))
        assertTrue(report.contains("name=`Sub (***REDACTED***)`"))
        assertFalse(report.contains("203.0.113.124"))

        // 2. Carry-over active connections & DNS suppressed/NXDOMAIN counters are included
        assertTrue(report.contains("carryOverActive=`3`"))
        assertTrue(report.contains("aaaaSuppressed=`35`"))
        assertTrue(report.contains("nxdomainCached=`5`"))

        // 3. Bare IPv6 literals are bracketed cleanly in failed, slow, and recent connections
        assertTrue(report.contains("`[2001:4860:4864:4:8000::]:3478`"))
        assertTrue(report.contains("`[2408:8756:c50:101d::443]:443`"))
        assertTrue(report.contains("`[2408:8756::443]:443`"))

        // 4. Window rule hit deltas sort `geolocation-!cn` (delta=60) ahead of `cn` (delta=10)
        val idxNonCn = report.indexOf("`GeoSite,geolocation-!cn` -> `PROXY` (hits=`60` (total=`120`))")
        val idxCn = report.indexOf("`GeoSite,cn` -> `DIRECT` (hits=`10` (total=`100`))")
        assertTrue(idxNonCn >= 0 && idxCn > idxNonCn)
    }

    @Test
    fun formatSliceReportRendersWireCacheHitsCoalescedMultipliersAndClearPreservesBaseline() {
        val nowMs = 1_763_100_000_000L

        // 1. Prime network fingerprint dedup, then clear while RUNNING -> preserves LOG_CLEARED & resets dedup
        DebugLogManager.onNetworkCandidateObserved(
            eventType = "NET_CAPS",
            networkHandle = 777L,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = true,
            isNotMetered = true,
            downBandwidthKbps = 100_000,
            upBandwidthKbps = 50_000,
            triggeredHandoff = false,
            hasIpv6 = true,
        )
        val runningBaseline = DebugLogManager.resetTimelineWindowOnClear(
            nowMs = nowMs,
            batteryPct = 82,
            vpnState = VpnLifecycleState.RUNNING,
            activeNode = "HK-IPLC-01",
        )
        assertEquals(1, runningBaseline.size)
        assertEquals("LOG_CLEARED", runningBaseline[0].category)
        assertTrue(runningBaseline[0].detail.contains("logs reset while state=running"))
        assertTrue(runningBaseline[0].detail.contains("node=HK-IPLC-01"))

        // Re-observing the exact same network fingerprint after clear MUST record fresh NET_CAPS
        DebugLogManager.onNetworkCandidateObserved(
            eventType = "NET_CAPS",
            networkHandle = 777L,
            isWifi = true,
            isCellular = false,
            isEthernet = false,
            isValidated = true,
            isNotMetered = true,
            downBandwidthKbps = 100_000,
            upBandwidthKbps = 50_000,
            triggeredHandoff = false,
            hasIpv6 = true,
        )
        val afterNetReobserve = DebugLogManager.snapshotTimelineEventsForTest()
        assertEquals(2, afterNetReobserve.size)
        assertEquals("NET_CAPS", afterNetReobserve[1].category)

        // Clearing while DISCONNECTED leaves timeline empty
        val disconnectedBaseline = DebugLogManager.resetTimelineWindowOnClear(
            nowMs = nowMs + 5_000L,
            batteryPct = 82,
            vpnState = VpnLifecycleState.DISCONNECTED,
            activeNode = "",
        )
        assertTrue(disconnectedBaseline.isEmpty())

        // 2. Verify wireCacheHits= and coalescedCount (x4) on failedConnections & recentConnections
        val window = DebugLogManager.WindowTelemetryState(
            windowStartMs = nowMs,
            capturedAtMs = nowMs + 600_000L,
            sessionStartMs = nowMs - 5_000L,
            screenOnMs = 600_000L,
            screenOffMs = 0L,
            startBatteryPct = 82,
            events = runningBaseline,
        )
        val sysMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "Google",
            deviceModel = "Pixel 9",
            androidRelease = "15",
            sdkInt = 35,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.4.5",
            appVersionCode = 21,
            battery = DebugLogManager.BatterySnapshot(levelPct = 81, isCharging = false, temperatureCelsius = 31.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 18L * 1024L * 1024L,
            jvmMaxBytes = 256L * 1024L * 1024L,
            nativeHeapBytes = 20L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )
        val coalescedJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 605,
              "mode": "rule",
              "routingPreset": "smart-cn",
              "effectiveOutbound": "HK-IPLC-01",
              "effectiveProtocol": "VLESS",
              "effectiveDelayMs": 31,
              "isWifi": true,
              "dns": {
                "total_queries": 50,
                "fake_ip_hits": 40,
                "cache_hits": 6,
                "resolverCacheHits": 14,
                "suppressed_queries": 2,
                "upstream_queries": 4,
                "upstream_errors": 0,
                "upstream_avg_ms": 19,
                "upstream_max_ms": 42,
                "active_fake_ip_entries": 32
              },
              "failedConnections": [
                {
                  "host": "chat.openai.com",
                  "destinationPort": 443,
                  "network": "udp",
                  "fakeIp": "198.18.0.42",
                  "rule": "GeoSite",
                  "rulePayload": "geolocation-!cn",
                  "effectiveOutbound": "HK-IPLC-01",
                  "effectiveProtocol": "VLESS",
                  "error": "quic udp blocked",
                  "coalescedCount": 4,
                  "startEpochMs": 1763100010000
                },
                {
                  "host": "single-fail.example.org",
                  "destinationPort": 443,
                  "network": "tcp",
                  "rule": "Match",
                  "rulePayload": "",
                  "effectiveOutbound": "HK-IPLC-01",
                  "effectiveProtocol": "VLESS",
                  "error": "connection reset",
                  "coalescedCount": 1,
                  "startEpochMs": 1763100020000
                }
              ],
              "recentConnections": [
                {
                  "host": "chat.openai.com",
                  "destinationPort": 443,
                  "network": "udp",
                  "rule": "GeoSite",
                  "rulePayload": "geolocation-!cn",
                  "effectiveOutbound": "HK-IPLC-01",
                  "connectDurationMs": null,
                  "upload": 0,
                  "download": 0,
                  "status": "failed",
                  "coalescedCount": 4,
                  "startEpochMs": 1763100010000
                }
              ]
            }
        """.trimIndent()

        val report = DebugLogManager.formatSliceReport(
            trigger = "manual",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = coalescedJson,
            crashBreadcrumb = null,
        )
        assertTrue(report.contains("wireCacheHits=`6` resolverCacheHits=`14`"))
        assertFalse(report.contains(" cacheHits=`"))
        assertTrue(report.contains("#### Failed Connections (2 entries, 5 total)"))
        assertTrue(report.contains("error=`quic udp blocked` (x4)"))
        assertTrue(report.contains("error=`connection reset`"))
        assertFalse(report.contains("(x1)"))
        assertTrue(report.contains("status=`failed` (x4)"))
        assertTrue(report.contains("**LOG_CLEARED**: logs reset while state=running"))
    }
}

