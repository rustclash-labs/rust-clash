package io.github.rustclashlabs.rustclash

import io.github.rustclashlabs.rustclash.vpn.DebugAnomalyAlertUi
import io.github.rustclashlabs.rustclash.vpn.DebugLogManager
import io.github.rustclashlabs.rustclash.vpn.MobileTimelineEvent
import io.github.rustclashlabs.rustclash.vpn.NodeImportSupport
import io.github.rustclashlabs.rustclash.vpn.VpnLifecycleState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    @Test
    fun formatSliceReportRendersCarryOverConnectionsWhenPresentAndOmitsWhenAbsentOrEmpty() {
        val t0 = 1_763_200_000_000L
        val t1 = t0 + 900_000L
        val window = DebugLogManager.WindowTelemetryState(
            windowStartMs = t0,
            capturedAtMs = t1,
            sessionStartMs = t0 - 1_800_000L,
            screenOnMs = 900_000L,
            screenOffMs = 0L,
            startBatteryPct = 90,
            events = emptyList(),
        )
        val sysMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "Google",
            deviceModel = "Pixel 9",
            androidRelease = "15",
            sdkInt = 35,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.4.6",
            appVersionCode = 22,
            battery = DebugLogManager.BatterySnapshot(levelPct = 88, isCharging = false, temperatureCelsius = 33.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 20L * 1024L * 1024L,
            jvmMaxBytes = 256L * 1024L * 1024L,
            nativeHeapBytes = 22L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )

        // 1. Present & non-empty carryOverConnections -> renders Carry-Over Streams section cleanly
        val withCarryOverJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 2700,
              "mode": "rule",
              "routingPreset": "smart-cn",
              "effectiveOutbound": "HK-IPLC-01",
              "effectiveProtocol": "VLESS",
              "effectiveDelayMs": 29,
              "isWifi": true,
              "traffic": {
                "upTotal": 5242880,
                "downTotal": 62914560,
                "activeConnections": 1,
                "carryOverStreams": 48,
                "carryOverActiveConnections": 1,
                "totalConnections": 90,
                "establishedConnections": 88,
                "failedConnections": 2,
                "zeroRxClosedConnections": 0
              },
              "outboundStats": [
                {
                  "outbound": "HK-IPLC-01",
                  "protocol": "VLESS",
                  "exitType": "PROXY",
                  "latestProbeDelayMs": 0,
                  "connections": 12,
                  "failures": 0,
                  "zeroRxCount": 0,
                  "handshakeSamples": 12,
                  "handshakeP50Ms": 140,
                  "handshakeP95Ms": 220,
                  "handshakeMaxMs": 260,
                  "uploadBytes": 4096,
                  "downloadBytes": 65536
                }
              ],
              "topDomains": [
                {
                  "host": "upos-sz-upcdn.bilivideo.com",
                  "connections": 1,
                  "failures": 0,
                  "uploadBytes": 82375475,
                  "downloadBytes": 4096,
                  "primaryRule": "GeoSite,cn",
                  "primaryOutbound": "DIRECT"
                }
              ],
              "carryOverConnections": [
                {
                  "host": "upos-sz-mirrorcos.bilivideo.com",
                  "port": 443,
                  "network": "tcp",
                  "status": "active",
                  "rule": "GeoSite,cn",
                  "effectiveOutbound": "DIRECT",
                  "uploadBytes": 1048576,
                  "downloadBytes": 40579891,
                  "ageMs": 1245000
                },
                {
                  "host": "240e:97c:2f::1",
                  "port": 443,
                  "network": "udp",
                  "status": "closed",
                  "rule": "GeoSite,geolocation-!cn",
                  "effectiveOutbound": "Sub (203.0.113.124)",
                  "uploadBytes": 524288,
                  "downloadBytes": 12582912,
                  "ageMs": 750
                }
              ]
            }
        """.trimIndent()

        val reportWithCarry = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = withCarryOverJson,
            crashBreadcrumb = null,
        )
        assertTrue(reportWithCarry.contains("carryOver=`48` carryOverActive=`1`"))
        assertTrue(reportWithCarry.contains("probe=`N/A`"))
        assertFalse(reportWithCarry.contains("probe=`0ms`"))
        assertTrue(reportWithCarry.contains("#### Carry-Over Streams (2)"))
        assertTrue(
            reportWithCarry.contains(
                "- `upos-sz-mirrorcos.bilivideo.com:443` (tcp, active) -> `DIRECT` [GeoSite,cn] " +
                    "totalUp=`1.00 MB` totalDown=`38.70 MB` age=`1245s`",
            ),
        )
        assertTrue(
            reportWithCarry.contains(
                "- `[240e:97c:2f::1]:443` (udp, closed) -> `Sub (***REDACTED***)` [GeoSite,geolocation-!cn] " +
                    "totalUp=`512.0 KB` totalDown=`12.00 MB` age=`750ms`",
            ),
        )
        assertFalse(reportWithCarry.contains("203.0.113.124"))

        // 2. Empty carryOverConnections array -> omits Carry-Over Streams section cleanly
        val emptyCarryJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 900,
              "mode": "rule",
              "effectiveOutbound": "DIRECT",
              "effectiveProtocol": "DIRECT",
              "carryOverConnections": []
            }
        """.trimIndent()
        val reportEmptyCarry = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = emptyCarryJson,
            crashBreadcrumb = null,
        )
        assertFalse(reportEmptyCarry.contains("Carry-Over Streams"))

        // 3. Absent carryOverConnections key -> omits Carry-Over Streams section cleanly
        val absentCarryJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 900,
              "mode": "rule",
              "effectiveOutbound": "DIRECT",
              "effectiveProtocol": "DIRECT"
            }
        """.trimIndent()
        val reportAbsentCarry = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = absentCarryJson,
            crashBreadcrumb = null,
        )
        assertFalse(reportAbsentCarry.contains("Carry-Over Streams"))
    }

    @Test
    fun anomalySentinelIgnoresBenignDirectTimeoutsApkUpdatesManualStopsAndStaleHistoricalKills() {
        val nowMs = 1_794_906_078_000L // 2026-11-17
        val baseMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "HONOR",
            deviceModel = "PGT-AN10",
            androidRelease = "16",
            sdkInt = 36,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.5.2",
            appVersionCode = 31,
            battery = DebugLogManager.BatterySnapshot(levelPct = 95, isCharging = false, temperatureCelsius = 27.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 9L * 1024L * 1024L,
            jvmMaxBytes = 512L * 1024L * 1024L,
            nativeHeapBytes = 15L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )

        // Realistic 7.3-hour healthy snapshot with domestic PCDN DIRECT timeouts + shared Zygote vmRss ~217 MB
        val healthyDailyJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 26397,
              "rssBytes": 83319808,
              "vmRssBytes": ${217L * 1024L * 1024L},
              "tun": {
                "rxPackets": 100516,
                "txPackets": 113189,
                "txWriteDrops": 2,
                "protectFailures": 0
              },
              "outboundStats": [
                {
                  "outbound": "DIRECT",
                  "protocol": "DIRECT",
                  "exitType": "DIRECT",
                  "connections": 115,
                  "failures": 18,
                  "handshakeSamples": 97,
                  "handshakeP50Ms": 40,
                  "handshakeP95Ms": 6200
                },
                {
                  "outbound": "REJECT",
                  "protocol": "REJECT",
                  "exitType": "REJECT",
                  "connections": 6,
                  "failures": 6
                },
                {
                  "outbound": "po0-sh-nube-sg-lg",
                  "protocol": "VLESS",
                  "exitType": "PROXY",
                  "connections": 76,
                  "failures": 1,
                  "handshakeSamples": 75,
                  "handshakeP50Ms": 119,
                  "handshakeP95Ms": 1544
                }
              ]
            }
        """.trimIndent()

        // 1. Recent Tasks "Clean All" (USER_STOPPED) -> benign, no false alarm
        val cleanAllExit = "[${DebugLogManager.formatTimestamp(nowMs - 30_000L)}] " +
            "reason=USER_STOPPED importance=125 pss=50040KB rss=159600KB desc=clean up"
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "periodic",
                capturedAtMs = nowMs,
                sessionStartMs = nowMs - 3_600_000L,
                systemMeta = baseMeta.copy(recentProcessExits = listOf(cleanAllExit)),
                nativeSnapshotRawJson = healthyDailyJson,
                crashBreadcrumb = null,
            ),
        )

        // 2. APK in-place upgrade (killDueToPackageUpdate) -> benign, no false alarm
        val apkUpdateExit = "[${DebugLogManager.formatTimestamp(nowMs - 60_000L)}] " +
            "reason=REASON_16 importance=125 pss=53291KB rss=164036KB desc=stop io.github.rustclashlabs.rustclash due to killDueToPackageUpdate"
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "debug-on",
                capturedAtMs = nowMs,
                sessionStartMs = nowMs - 60_000L,
                systemMeta = baseMeta.copy(recentProcessExits = listOf(apkUpdateExit)),
                nativeSnapshotRawJson = healthyDailyJson,
                crashBreadcrumb = null,
            ),
        )

        // 3. Stale OEM kill from 3 days ago (> 24h) -> ignored so enabling Debug mode today doesn't false-alarm
        val staleOemExit = "[${DebugLogManager.formatTimestamp(nowMs - 3L * 86_400_000L)}] " +
            "reason=OTHER_OEM_KILL importance=125 pss=48000KB rss=140000KB desc=iAware clean"
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "startup-check",
                capturedAtMs = nowMs,
                sessionStartMs = 0L,
                systemMeta = baseMeta.copy(recentProcessExits = listOf(staleOemExit)),
                nativeSnapshotRawJson = healthyDailyJson,
                crashBreadcrumb = null,
            ),
        )

        // 4. Single transient tail spike on proxy when median latency is fast (p50=120ms, p95=4100ms) -> no false alarm
        val transientTailJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "rssBytes": 75497472,
              "outboundStats": [
                {
                  "outbound": "SG-Node-01",
                  "protocol": "VLESS",
                  "exitType": "PROXY",
                  "connections": 20,
                  "failures": 1,
                  "handshakeSamples": 19,
                  "handshakeP50Ms": 120,
                  "handshakeP95Ms": 4100
                }
              ]
            }
        """.trimIndent()
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "periodic",
                capturedAtMs = nowMs,
                sessionStartMs = nowMs - 1_800_000L,
                systemMeta = baseMeta,
                nativeSnapshotRawJson = transientTailJson,
                crashBreadcrumb = null,
            ),
        )
    }

    @Test
    fun anomalySentinelDetectsCrashesAbnormalExitsProtectFailuresRevokesProxyOutagesAndHighRssWithRedaction() {
        val nowMs = 1_794_906_078_000L
        val sessStart = nowMs - 900_000L

        // 1. Crash breadcrumb (critical + secret scrubbing)
        val crashAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "startup-check",
            capturedAtMs = nowMs,
            sessionStartMs = 0L,
            systemMeta = null,
            nativeSnapshotRawJson = null,
            crashBreadcrumb = "[2026-11-17 12:00:00.000 +0800] Thread=main\n" +
                "java.lang.IllegalStateException: uuid=12345678-1234-4321-abcd-9876543210ff failed",
        )
        assertNotNull(crashAlert)
        assertEquals("critical", crashAlert!!.severity)
        assertEquals("JVM_CRASH_BREADCRUMB", crashAlert.code)
        assertFalse(crashAlert.detailZh.contains("12345678-1234-4321-abcd-9876543210ff"))

        // 2. Fresh OEM background kill within 24h (critical)
        val recentOemKill = "[${DebugLogManager.formatTimestamp(nowMs - 120_000L)}] " +
            "reason=OTHER_OEM_KILL importance=125 pss=48000KB rss=140000KB desc=powergenie kill"
        val exitAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "startup-check",
            capturedAtMs = nowMs,
            sessionStartMs = 0L,
            systemMeta = null,
            nativeSnapshotRawJson = null,
            crashBreadcrumb = null,
            recentProcessExitsOverride = listOf(recentOemKill),
        )
        assertNotNull(exitAlert)
        assertEquals("critical", exitAlert!!.severity)
        assertEquals("PROCESS_EXIT_ABNORMAL", exitAlert.code)
        assertTrue(exitAlert.id.endsWith(":OTHER_OEM_KILL:imp125"))
        assertTrue(exitAlert.detailZh.contains("系统后台省电管控强杀"))

        // 2b. Routine LMK / OEM reclaim of an idle cached UI process (`importance >= 400`) after VPN stop -> ignored
        for (reason in listOf("LOW_MEMORY_LMK", "OTHER_OEM_KILL", "EXCESSIVE_RESOURCE")) {
            val cachedReclaim = "[${DebugLogManager.formatTimestamp(nowMs - 90_000L)}] " +
                "reason=$reason importance=400 pss=0KB rss=158300KB"
            assertNull(
                DebugLogManager.evaluateSliceAnomalies(
                    trigger = "startup-check",
                    capturedAtMs = nowMs,
                    sessionStartMs = 0L,
                    systemMeta = null,
                    nativeSnapshotRawJson = null,
                    crashBreadcrumb = null,
                    recentProcessExitsOverride = listOf(cachedReclaim),
                ),
            )
        }

        // 2c. Foreground VPN service LMK (`importance=125`) and cached-state real crashes (`NATIVE_CRASH importance=400`) MUST still alert
        val fgServiceLmk = "[${DebugLogManager.formatTimestamp(nowMs - 60_000L)}] " +
            "reason=LOW_MEMORY_LMK importance=125 pss=62000KB rss=162000KB"
        val fgLmkAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "startup-check",
            capturedAtMs = nowMs,
            sessionStartMs = 0L,
            systemMeta = null,
            nativeSnapshotRawJson = null,
            crashBreadcrumb = null,
            recentProcessExitsOverride = listOf(fgServiceLmk),
        )
        assertNotNull(fgLmkAlert)
        assertEquals("PROCESS_EXIT_ABNORMAL", fgLmkAlert!!.code)
        assertTrue(fgLmkAlert.id.endsWith(":LOW_MEMORY_LMK:imp125"))

        val cachedNativeCrash = "[${DebugLogManager.formatTimestamp(nowMs - 45_000L)}] " +
            "reason=NATIVE_CRASH importance=400 pss=24000KB rss=120000KB desc=SIGSEGV"
        val cachedCrashAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "startup-check",
            capturedAtMs = nowMs,
            sessionStartMs = 0L,
            systemMeta = null,
            nativeSnapshotRawJson = null,
            crashBreadcrumb = null,
            recentProcessExitsOverride = listOf(cachedNativeCrash),
        )
        assertNotNull(cachedCrashAlert)
        assertEquals("PROCESS_EXIT_ABNORMAL", cachedCrashAlert!!.code)
        assertTrue(cachedCrashAlert.id.endsWith(":NATIVE_CRASH:imp400"))

        // 3. Socket protect failure (critical)
        val protectFailJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "tun": { "protectFailures": 3, "txWriteDrops": 0 }
            }
        """.trimIndent()
        val protectAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "anomaly",
            capturedAtMs = nowMs,
            sessionStartMs = sessStart,
            systemMeta = null,
            nativeSnapshotRawJson = protectFailJson,
            crashBreadcrumb = null,
        )
        assertNotNull(protectAlert)
        assertEquals("critical", protectAlert!!.severity)
        assertEquals("SOCKET_PROTECT_FAIL", protectAlert.code)

        // 4. System VPN Revoke (warning)
        val revokeAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "revoked",
            capturedAtMs = nowMs,
            sessionStartMs = sessStart,
            systemMeta = null,
            nativeSnapshotRawJson = """{"ok":true,"vpnRunning":false}""",
            crashBreadcrumb = null,
            windowEvents = listOf(MobileTimelineEvent(nowMs - 500L, "VPN_REVOKE", "system revoked VPN tunnel")),
        )
        assertNotNull(revokeAlert)
        assertEquals("warning", revokeAlert!!.severity)
        assertEquals("VPN_REVOKED", revokeAlert.code)

        // 5. Proxy high failure rate (warning + node IP redaction)
        val proxyFailJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "rssBytes": 73400320,
              "outboundStats": [
                {
                  "outbound": "Sub (203.0.113.88)",
                  "protocol": "Hysteria2",
                  "exitType": "PROXY",
                  "connections": 6,
                  "failures": 4,
                  "handshakeSamples": 2,
                  "handshakeP50Ms": 180,
                  "handshakeP95Ms": 320
                }
              ]
            }
        """.trimIndent()
        val proxyFailAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "anomaly",
            capturedAtMs = nowMs,
            sessionStartMs = sessStart,
            systemMeta = null,
            nativeSnapshotRawJson = proxyFailJson,
            crashBreadcrumb = null,
        )
        assertNotNull(proxyFailAlert)
        assertEquals("warning", proxyFailAlert!!.severity)
        assertEquals("PROXY_HIGH_FAIL_RATE", proxyFailAlert.code)
        assertTrue(proxyFailAlert.detailZh.contains("4/6"))
        assertFalse(proxyFailAlert.detailZh.contains("203.0.113.88"))

        // 6. Proxy sustained slow handshake (warning)
        val slowProxyJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "rssBytes": 73400320,
              "outboundStats": [
                {
                  "outbound": "US-TUIC-01",
                  "protocol": "TUIC",
                  "exitType": "PROXY",
                  "connections": 8,
                  "failures": 0,
                  "handshakeSamples": 8,
                  "handshakeP50Ms": 1150,
                  "handshakeP95Ms": 4650
                }
              ]
            }
        """.trimIndent()
        val slowAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "periodic",
            capturedAtMs = nowMs,
            sessionStartMs = sessStart,
            systemMeta = null,
            nativeSnapshotRawJson = slowProxyJson,
            crashBreadcrumb = null,
        )
        assertNotNull(slowAlert)
        assertEquals("PROXY_SLOW_HANDSHAKE", slowAlert!!.code)

        // 7. Foreground Compose UI private rssBytes=145 MB + shared Zygote vmRssBytes=275 MB -> NO false alarm
        val foregroundUiMemoryJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "rssBytes": ${145L * 1024L * 1024L},
              "vmRssBytes": ${275L * 1024L * 1024L}
            }
        """.trimIndent()
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "anomaly",
                capturedAtMs = nowMs,
                sessionStartMs = sessStart,
                systemMeta = null,
                nativeSnapshotRawJson = foregroundUiMemoryJson,
                crashBreadcrumb = null,
            ),
        )

        // 8. Genuine high private RSS memory >= 256 MB (warning) + embedded TriggeredAnomaly slice header
        val highRssJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "rssBytes": ${265L * 1024L * 1024L},
              "vmRssBytes": ${395L * 1024L * 1024L}
            }
        """.trimIndent()
        val rssAlert = DebugLogManager.evaluateSliceAnomalies(
            trigger = "anomaly",
            capturedAtMs = nowMs,
            sessionStartMs = sessStart,
            systemMeta = null,
            nativeSnapshotRawJson = highRssJson,
            crashBreadcrumb = null,
        )
        assertNotNull(rssAlert)
        assertEquals("HIGH_MEMORY_RSS", rssAlert!!.code)
        assertTrue(rssAlert.detailZh.contains("265.00 MB"))
        assertTrue(rssAlert.detailZh.contains("阈值 256 MB"))

        val sliceBody = DebugLogManager.formatSliceReport(
            trigger = "anomaly",
            window = DebugLogManager.WindowTelemetryState(
                windowStartMs = nowMs - 300_000L,
                capturedAtMs = nowMs,
                sessionStartMs = sessStart,
                screenOnMs = 120_000L,
                screenOffMs = 180_000L,
                startBatteryPct = 80,
                events = emptyList(),
            ),
            systemMeta = DebugLogManager.SystemMetadata(
                deviceManufacturer = "HONOR",
                deviceModel = "BVL-AN00",
                androidRelease = "17",
                sdkInt = 37,
                primaryAbi = "arm64-v8a",
                appVersionName = "0.5.2",
                appVersionCode = 31,
                battery = DebugLogManager.BatterySnapshot(79, false, 35.0),
                isInteractive = true,
                isPowerSaveMode = false,
                isDeviceIdleDoze = false,
                ignoringBatteryOptimizations = true,
                jvmUsedBytes = 12L * 1024L * 1024L,
                jvmMaxBytes = 384L * 1024L * 1024L,
                nativeHeapBytes = 40L * 1024L * 1024L,
                perAppMode = "ALL_APPS",
                selectedPackagesCount = 0,
                enableIpv6 = true,
                demoMode = false,
                recentProcessExits = emptyList(),
            ),
            nativeSnapshotRawJson = proxyFailJson,
            crashBreadcrumb = null,
            detectedAnomaly = proxyFailAlert,
        )
        assertTrue(sliceBody.contains("- TriggeredAnomaly: `[WARNING/PROXY_HIGH_FAIL_RATE]` 代理节点出现异常断流"))
        assertFalse(sliceBody.contains("203.0.113.88"))
    }

    @Test
    fun anomalySerializationDismissalBoundingRetentionProtectionAndExportHeaderWorkEndToEnd() {
        val sliceDir = Files.createTempDirectory("rc-anomaly-slices").toFile()
        val exportDir = Files.createTempDirectory("rc-anomaly-export").toFile()
        try {
            val alert = DebugAnomalyAlertUi(
                id = "proxy_fail:100:SG-01:500",
                detectedAtMs = 1_794_900_000_000L,
                severity = "warning",
                code = "PROXY_HIGH_FAIL_RATE",
                headlineZh = "代理节点出现异常断流",
                detailZh = "节点 SG-01 近期连接失败 5/6 次 (83%)",
            )
            val encoded = DebugLogManager.serializeAnomalyJson(alert)
            val decoded = DebugLogManager.parseAnomalyJson(encoded)
            assertEquals(alert, decoded)

            // Dismissed IDs deduplicate and cap to maxEntries
            var dismissedRaw: String? = null
            for (i in 1..6) {
                dismissedRaw = DebugLogManager.appendDismissedIdJson(dismissedRaw, "id-$i", maxEntries = 4)
            }
            dismissedRaw = DebugLogManager.appendDismissedIdJson(dismissedRaw, "id-5", maxEntries = 4)
            assertEquals(listOf("id-3", "id-4", "id-6", "id-5"), DebugLogManager.parseDismissedIdsJson(dismissedRaw))

            // Retention protection preserves the anomaly slice when newer periodic slices exceed maxFiles
            val anomalyFile = File(sliceDir, "rustclash-slice-20261117-100000-000-anomaly.log")
            anomalyFile.writeText("### RustClash Android Diagnostic Slice (`anomaly`)\nANOMALY_EVIDENCE\n")
            for (idx in 1..4) {
                File(sliceDir, "rustclash-slice-20261117-1${idx}0000-000-periodic.log")
                    .writeText("### RustClash Android Diagnostic Slice (`periodic`)\nPERIODIC_$idx\n")
            }
            DebugLogManager.enforceRetentionPolicy(
                dir = sliceDir,
                maxFiles = 3,
                maxTotalBytes = 1024L * 1024L,
                protectLatestAnomalySlice = true,
            )
            val retainedNames = DebugLogManager.listSliceFilesNewestFirst(sliceDir).map { it.name }
            assertEquals(3, retainedNames.size)
            assertTrue(retainedNames.contains(anomalyFile.name))
            assertTrue(retainedNames.contains("rustclash-slice-20261117-140000-000-periodic.log"))
            assertTrue(retainedNames.contains("rustclash-slice-20261117-130000-000-periodic.log"))

            // Combined export embeds DetectedAnomaly summary in header and includes preserved anomaly slice
            val exported = DebugLogManager.assembleCombinedExportFromSlices(
                sliceDir = sliceDir,
                exportDir = exportDir,
                nowMs = 1_794_905_000_000L,
                activeAnomaly = alert,
            )
            assertNotNull(exported)
            val text = exported!!.readText(Charsets.UTF_8)
            assertTrue(text.contains("- DetectedAnomaly: [WARNING/PROXY_HIGH_FAIL_RATE] 代理节点出现异常断流"))
            assertTrue(text.contains("ANOMALY_EVIDENCE"))
        } finally {
            sliceDir.deleteRecursively()
            exportDir.deleteRecursively()
        }
    }

    @Test
    fun assembleCombinedExportReservesBudgetForOlderAnomalySliceAndContextUnderCap() {
        val sliceDir = Files.createTempDirectory("rc-export-budget-slices").toFile()
        val exportDir = Files.createTempDirectory("rc-export-budget-out").toFile()
        try {
            val alert = DebugAnomalyAlertUi(
                id = "protect_fail:100:2",
                detectedAtMs = 1_794_901_000_000L,
                severity = "critical",
                code = "SOCKET_PROTECT_FAIL",
                headlineZh = "底层套接字保护失败",
                detailZh = "检测到 2 次 protectSocket 失败",
            )
            val entries = listOf(
                "rustclash-slice-20261118-100000-000-periodic.log" to "OLDEST_1000",
                "rustclash-slice-20261118-103000-000-periodic.log" to "PRE_CONTEXT_1030",
                "rustclash-slice-20261118-104500-000-anomaly.log" to "INCIDENT_SCENE_1045",
                "rustclash-slice-20261118-110000-000-periodic.log" to "POST_CONTEXT_1100",
                "rustclash-slice-20261118-113000-000-periodic.log" to "NEWER_1130",
                "rustclash-slice-20261118-120000-000-manual.log" to "LATEST_STATE_1200",
            )
            entries.forEach { (name, marker) ->
                val trigger = DebugLogManager.parseTriggerFromFileName(name)
                val body = buildString {
                    appendLine("### RustClash Android Diagnostic Slice (`$trigger`)")
                    if (trigger == "anomaly") {
                        appendLine("- TriggeredAnomaly: `[CRITICAL/SOCKET_PROTECT_FAIL]` 底层套接字保护失败")
                    }
                    appendLine("MARKER=$marker")
                    appendLine("payload=" + "x".repeat(900))
                }
                File(sliceDir, name).writeText(body, Charsets.UTF_8)
            }

            // Cap export at 4,600 bytes: all 6 slices (~7,800 bytes) cannot fit; budget allows ~3 slices.
            // Exporter MUST keep INCIDENT_SCENE_1045 + LATEST_STATE_1200 + PRE_CONTEXT_1030 in chronological order.
            val maxBytes = 4_600
            val exported = DebugLogManager.assembleCombinedExportFromSlices(
                sliceDir = sliceDir,
                exportDir = exportDir,
                nowMs = 1_794_905_000_000L,
                maxBytes = maxBytes,
                activeAnomaly = alert,
            )
            assertNotNull(exported)
            assertTrue("Exported bundle (${exported!!.length()}B) must stay <= $maxBytes", exported.length() <= maxBytes)
            val bundle = exported.readText(Charsets.UTF_8)
            val idxPre = bundle.indexOf("MARKER=PRE_CONTEXT_1030")
            val idxAnomaly = bundle.indexOf("MARKER=INCIDENT_SCENE_1045")
            val idxLatest = bundle.indexOf("MARKER=LATEST_STATE_1200")
            assertTrue("Pre-anomaly context slice should be included", idxPre >= 0)
            assertTrue("Protected anomaly slice must be preserved", idxAnomaly > idxPre)
            assertTrue("Newest slice must follow anomaly slice chronologically", idxLatest > idxAnomaly)
            assertFalse("Unrelated middle slice should yield budget to incident scene", bundle.contains("MARKER=NEWER_1130"))
        } finally {
            sliceDir.deleteRecursively()
            exportDir.deleteRecursively()
        }
    }

    @Test
    fun deviceIdleDozeTransitionsRecordEnterExitWithDurationAndDeduplicate() {
        DebugLogManager.resetTimelineStateForTest(initialDoze = false)
        val t0 = 1_795_000_000_000L
        // Redundant non-doze broadcast must be ignored
        DebugLogManager.onDeviceIdleModeChangedAt(isDoze = false, interactive = false, nowMs = t0)
        assertTrue(DebugLogManager.snapshotTimelineEventsForTest().isEmpty())

        // Enter Doze, ignore duplicate enter, then exit Doze after 1800s
        DebugLogManager.onDeviceIdleModeChangedAt(isDoze = true, interactive = false, nowMs = t0 + 10_000L)
        DebugLogManager.onDeviceIdleModeChangedAt(isDoze = true, interactive = false, nowMs = t0 + 20_000L)
        DebugLogManager.onDeviceIdleModeChangedAt(isDoze = false, interactive = true, nowMs = t0 + 1_810_000L)
        DebugLogManager.onDeviceIdleModeChangedAt(isDoze = false, interactive = true, nowMs = t0 + 1_820_000L)

        val events = DebugLogManager.snapshotTimelineEventsForTest()
        assertEquals(2, events.size)
        assertEquals("DOZE_ENTER", events[0].category)
        assertEquals("doze=true interactive=false", events[0].detail)
        assertEquals("DOZE_EXIT", events[1].category)
        assertEquals("doze=false interactive=true durationMs=1800000", events[1].detail)
    }

    @Test
    fun formatSliceReportDisplaysCancelledDialsAndTruncatedWindowSamplingHeader() {
        val t0 = 1_795_000_000_000L
        val t1 = t0 + 1_800_000L
        val window = DebugLogManager.WindowTelemetryState(
            windowStartMs = t0,
            capturedAtMs = t1,
            sessionStartMs = t0 - 3_600_000L,
            screenOnMs = 900_000L,
            screenOffMs = 900_000L,
            startBatteryPct = 80,
            events = emptyList(),
        )
        val sysMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "HONOR",
            deviceModel = "BVL-AN00",
            androidRelease = "17",
            sdkInt = 37,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.5.5",
            appVersionCode = 34,
            battery = DebugLogManager.BatterySnapshot(77, false, 35.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 12L * 1024L * 1024L,
            jvmMaxBytes = 384L * 1024L * 1024L,
            nativeHeapBytes = 40L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )
        val truncatedJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 5400,
              "mode": "rule",
              "routingPreset": "smart-cn",
              "effectiveOutbound": "SG-01",
              "effectiveProtocol": "VLESS",
              "effectiveDelayMs": 105,
              "traffic": {
                "upTotal": 10485760,
                "downTotal": 524288000,
                "activeConnections": 3,
                "totalConnections": 5000,
                "establishedConnections": 4910,
                "failedConnections": 56,
                "cancelledConnections": 31,
                "zeroRxClosedConnections": 14
              },
              "windowSummary": {
                "connections": 3000,
                "tcpConnections": 2600,
                "udpConnections": 400,
                "failedConnections": 12,
                "cancelledConnections": 19,
                "zeroRxClosedConnections": 5,
                "fakeIpRestoredConnections": 2500,
                "sampledSnapshots": 3000,
                "ringCapacity": 3000,
                "truncated": true,
                "ringEvictedInWindow": true
              },
              "outboundStats": [
                {
                  "outbound": "DIRECT",
                  "protocol": "Direct",
                  "exitType": "DIRECT",
                  "connections": 2800,
                  "failures": 12,
                  "cancelled": 19,
                  "zeroRxCount": 5,
                  "handshakeSamples": 2400,
                  "handshakeP50Ms": 62,
                  "handshakeP95Ms": 210,
                  "handshakeMaxMs": 1400,
                  "uploadBytes": 4000000,
                  "downloadBytes": 150000000
                }
              ]
            }
        """.trimIndent()

        // With previousTotalConnections = 1200, expected delta in window is 3800 conns vs 3000 sampled
        val reportWithDelta = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = truncatedJson,
            crashBreadcrumb = null,
            previousTotalConnections = 1200L,
        )
        assertTrue(reportWithDelta.contains("established=`4910` failed=`56` cancelled=`31` zeroRxClosed=`14`"))
        assertTrue(reportWithDelta.contains("#### Outbound Node Performance (Window, sampled 3000/3800 conns, cap=3000)"))
        assertTrue(reportWithDelta.contains("zeroRx=`5` cancelled=`19` probe=`N/A`"))

        // Without previousTotalConnections, still reports explicit truncation at ring cap
        val reportWithoutDelta = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = truncatedJson,
            crashBreadcrumb = null,
            previousTotalConnections = null,
        )
        assertTrue(reportWithoutDelta.contains("#### Outbound Node Performance (Window, truncated, cap=3000, sampled 3000 newest conns)"))
    }

    @Test
    fun formatExitReasonNameMapsApi30To37ExitCodesAndSuppressesBenignPackageUpdateExits() {
        assertEquals("EXIT_SELF", DebugLogManager.formatExitReasonName(1))
        assertEquals("SIGNALED(9)", DebugLogManager.formatExitReasonName(2, 9))
        assertEquals("LOW_MEMORY_LMK", DebugLogManager.formatExitReasonName(3))
        assertEquals("JVM_CRASH", DebugLogManager.formatExitReasonName(4))
        assertEquals("NATIVE_CRASH", DebugLogManager.formatExitReasonName(5))
        assertEquals("ANR", DebugLogManager.formatExitReasonName(6))
        assertEquals("INIT_FAILURE", DebugLogManager.formatExitReasonName(7))
        assertEquals("PERMISSION_CHANGE", DebugLogManager.formatExitReasonName(8))
        assertEquals("EXCESSIVE_RESOURCE", DebugLogManager.formatExitReasonName(9))
        assertEquals("USER_STOPPED", DebugLogManager.formatExitReasonName(10))
        assertEquals("USER_FORCE_STOP", DebugLogManager.formatExitReasonName(11))
        assertEquals("DEPENDENCY_DIED", DebugLogManager.formatExitReasonName(12))
        assertEquals("OTHER_OEM_KILL", DebugLogManager.formatExitReasonName(13))
        assertEquals("FREEZER", DebugLogManager.formatExitReasonName(14))
        assertEquals("PACKAGE_STATE_CHANGE", DebugLogManager.formatExitReasonName(15))
        assertEquals("PACKAGE_UPDATED", DebugLogManager.formatExitReasonName(16))
        assertEquals("REASON_99", DebugLogManager.formatExitReasonName(99))

        val nowMs = 1_795_000_000_000L
        val healthyJson = """{"ok":true,"vpnRunning":true,"rssBytes":75497472,"outboundStats":[]}"""
        val meta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "HONOR",
            deviceModel = "BVL-AN00",
            androidRelease = "17",
            sdkInt = 37,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.5.16",
            appVersionCode = 45,
            battery = DebugLogManager.BatterySnapshot(85, false, 30.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 8L * 1024L * 1024L,
            jvmMaxBytes = 384L * 1024L * 1024L,
            nativeHeapBytes = 48L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = listOf(
                "[${DebugLogManager.formatTimestamp(nowMs - 30_000L)}] reason=PACKAGE_UPDATED importance=125 pss=0KB rss=200000KB desc=upgrade",
            ),
        )
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "startup-check",
                capturedAtMs = nowMs,
                sessionStartMs = 0L,
                systemMeta = meta,
                nativeSnapshotRawJson = healthyJson,
                crashBreadcrumb = null,
            ),
        )
        assertNull(
            DebugLogManager.evaluateSliceAnomalies(
                trigger = "startup-check",
                capturedAtMs = nowMs,
                sessionStartMs = 0L,
                systemMeta = meta.copy(
                    recentProcessExits = listOf(
                        "[${DebugLogManager.formatTimestamp(nowMs - 30_000L)}] reason=PACKAGE_STATE_CHANGE importance=125 pss=0KB rss=200000KB desc=disabled",
                    ),
                ),
                nativeSnapshotRawJson = healthyJson,
                crashBreadcrumb = null,
            ),
        )
    }

    @Test
    fun formatSliceReportFoldsBurstOfTcpPort7ReachabilityProbesWhileKeepingRealFailuresVerbatim() {
        val t0 = 1_795_000_000_000L
        val t1 = t0 + 900_000L
        val window = DebugLogManager.WindowTelemetryState(
            windowStartMs = t0,
            capturedAtMs = t1,
            sessionStartMs = t0,
            screenOnMs = 600_000L,
            screenOffMs = 300_000L,
            startBatteryPct = 88,
            events = emptyList(),
        )
        val sysMeta = DebugLogManager.SystemMetadata(
            deviceManufacturer = "HONOR",
            deviceModel = "BVL-AN00",
            androidRelease = "17",
            sdkInt = 37,
            primaryAbi = "arm64-v8a",
            appVersionName = "0.5.18",
            appVersionCode = 47,
            battery = DebugLogManager.BatterySnapshot(87, false, 31.0),
            isInteractive = true,
            isPowerSaveMode = false,
            isDeviceIdleDoze = false,
            ignoringBatteryOptimizations = true,
            jvmUsedBytes = 10L * 1024L * 1024L,
            jvmMaxBytes = 384L * 1024L * 1024L,
            nativeHeapBytes = 32L * 1024L * 1024L,
            perAppMode = "ALL_APPS",
            selectedPackagesCount = 0,
            enableIpv6 = true,
            demoMode = false,
            recentProcessExits = emptyList(),
        )

        // Case 1: >= 3 TCP :7 entries -> fold into one summary line while preserving real failure verbatim
        val burstJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 900,
              "mode": "rule",
              "failedConnections": [
                {
                  "host": "api.weixin.qq.com",
                  "destinationPort": 443,
                  "network": "tcp",
                  "rule": "GeoSite",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection reset by peer",
                  "coalescedCount": 1,
                  "startEpochMs": ${t0 + 10_000L}
                },
                {
                  "host": "120.240.130.165",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection refused",
                  "coalescedCount": 2,
                  "startEpochMs": ${t0 + 11_000L}
                },
                {
                  "host": "157.255.174.129",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection refused",
                  "coalescedCount": 2,
                  "startEpochMs": ${t0 + 12_000L}
                },
                {
                  "host": "183.3.226.35",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection refused",
                  "coalescedCount": 2,
                  "startEpochMs": ${t0 + 13_000L}
                },
                {
                  "host": "220.181.38.148",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "timed out",
                  "coalescedCount": 2,
                  "startEpochMs": ${t0 + 14_000L}
                }
              ]
            }
        """.trimIndent()

        val burstReport = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = burstJson,
            crashBreadcrumb = null,
        )
        assertTrue(burstReport.contains("#### Failed Connections (5 entries, 9 total)"))
        assertTrue(burstReport.contains("`api.weixin.qq.com:443`"))
        assertFalse(burstReport.contains("120.240.130.165:7"))
        assertFalse(burstReport.contains("157.255.174.129:7"))
        assertTrue(
            burstReport.contains(
                "- `TCP *:7` reachability probes (`InetAddress.isReachable`, folded): " +
                    "total=`8` hosts=`4` · outbounds=`DIRECT x8` · errors=`connection refused` x6, `timed out` x2",
            ),
        )

        // Case 2: < 3 TCP :7 entries -> keep every entry verbatim without folding
        val smallJson = """
            {
              "ok": true,
              "vpnRunning": true,
              "uptimeSecs": 900,
              "mode": "rule",
              "failedConnections": [
                {
                  "host": "120.240.130.165",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection refused",
                  "coalescedCount": 1,
                  "startEpochMs": ${t0 + 11_000L}
                },
                {
                  "host": "157.255.174.129",
                  "destinationPort": 7,
                  "network": "tcp",
                  "rule": "GeoIP",
                  "rulePayload": "cn",
                  "effectiveOutbound": "DIRECT",
                  "effectiveProtocol": "Direct",
                  "error": "connection refused",
                  "coalescedCount": 1,
                  "startEpochMs": ${t0 + 12_000L}
                }
              ]
            }
        """.trimIndent()

        val smallReport = DebugLogManager.formatSliceReport(
            trigger = "periodic",
            window = window,
            systemMeta = sysMeta,
            nativeSnapshotRawJson = smallJson,
            crashBreadcrumb = null,
        )
        assertTrue(smallReport.contains("#### Failed Connections (2)"))
        assertTrue(smallReport.contains("`120.240.130.165:7`"))
        assertTrue(smallReport.contains("`157.255.174.129:7`"))
        assertFalse(smallReport.contains("reachability probes (`InetAddress.isReachable`, folded)"))
    }
}
