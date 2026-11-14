package io.github.rustclashlabs.rustclash.vpn

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.Debug
import android.os.PowerManager
import androidx.annotation.RequiresApi
import io.github.rustclashlabs.rustclash.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

data class DebugSliceItemUi(
    val fileName: String,
    val trigger: String,
    val createdAtMs: Long,
    val sizeBytes: Long,
)

data class DebugLogSummaryUi(
    val enabled: Boolean = false,
    val sliceIntervalSecs: Long = DebugLogManager.DEFAULT_SLICE_INTERVAL_SECS,
    val sliceCount: Int = 0,
    val totalBytes: Long = 0L,
    val latestSliceTimeMs: Long = 0L,
    val hasCrashBreadcrumb: Boolean = false,
    val recentSlices: List<DebugSliceItemUi> = emptyList(),
)

data class MobileTimelineEvent(
    val timestampMs: Long,
    val category: String,
    val detail: String,
)

/**
 * Android-specific periodic diagnostic collector, mobile lifecycle/battery/handoff recorder,
 * rolling slice manager, and credential-redacted report exporter.
 */
object DebugLogManager {
    const val KEY_DEBUG_LOG_ENABLED = "debug_log_enabled"
    const val KEY_DEBUG_SLICE_INTERVAL_SECS = "debug_slice_interval_secs"
    const val DEFAULT_SLICE_INTERVAL_SECS = 1800L

    internal const val DEBUG_DIR_NAME = "debug_logs"
    internal const val EXPORT_CACHE_DIR_NAME = "debug_exports"
    internal const val CRASH_BREADCRUMB_FILE = "last_jvm_crash.log"
    internal const val SLICE_PREFIX = "rustclash-slice-"
    internal const val SLICE_SUFFIX = ".log"

    internal const val MAX_SLICE_FILES = 12
    internal const val MAX_TOTAL_SLICE_BYTES = 8L * 1024L * 1024L
    internal const val MAX_TIMELINE_EVENTS = 250
    internal const val MAX_COMBINED_EXPORT_BYTES = 2_400_000

    val SLICE_INTERVAL_CHOICES = listOf(900L, 1800L, 3600L)

    private val crashHookInstalled = AtomicBoolean(false)
    private val SAFE_TRIGGER_REGEX = Regex("[^a-z0-9_-]")
    private const val SLICE_REPORT_HEADER_PREFIX = "### RustClash Android Diagnostic Slice ("
    private val lock = Any()
    private val sliceWriteLock = Any()

    private var windowStartMs: Long = System.currentTimeMillis()
    private var sessionStartMs: Long = 0L
    private var screenOnAccumMs: Long = 0L
    private var screenOffAccumMs: Long = 0L
    private var lastScreenTransitionMs: Long = System.currentTimeMillis()
    private var currentScreenInteractive: Boolean = true
    private var windowStartBatteryPct: Int? = null
    private var lastNetworkLostMs: Long = 0L
    private var lastNetStateFingerprint: String = ""
    private var lastCumulativeRuleHits: Map<String, Long> = emptyMap()
    private val timelineEvents = ArrayDeque<MobileTimelineEvent>(MAX_TIMELINE_EVENTS)

    fun isEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        return prefs.getBoolean(KEY_DEBUG_LOG_ENABLED, false)
    }

    fun getSliceIntervalSecs(context: Context): Long {
        val prefs = context.getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        return normalizeSliceIntervalSecs(prefs.getLong(KEY_DEBUG_SLICE_INTERVAL_SECS, DEFAULT_SLICE_INTERVAL_SECS))
    }

    fun normalizeSliceIntervalSecs(rawSecs: Long): Long =
        when {
            rawSecs <= 900L -> 900L
            rawSecs <= 1800L -> 1800L
            else -> 3600L
        }

    fun setEnabled(context: Context, enabled: Boolean) {
        val prefs = context.getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_DEBUG_LOG_ENABLED, enabled).apply()
        if (NativeBridge.ensureLoaded()) {
            runCatching { NativeBridge.nativeSetDebugLogging(enabled) }
        }
        val now = System.currentTimeMillis()
        val batteryNow = readBatterySnapshot(context).levelPct
        synchronized(lock) {
            if (enabled) {
                windowStartMs = now
                screenOnAccumMs = 0L
                screenOffAccumMs = 0L
                lastScreenTransitionMs = now
                windowStartBatteryPct = batteryNow
            }
            pushEventLocked(
                now,
                "DEBUG_MODE",
                if (enabled) "enabled (interval=${getSliceIntervalSecs(context)}s)" else "disabled",
            )
        }
    }

    fun setSliceIntervalSecs(context: Context, intervalSecs: Long): Long {
        val normalized = normalizeSliceIntervalSecs(intervalSecs)
        val prefs = context.getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putLong(KEY_DEBUG_SLICE_INTERVAL_SECS, normalized).apply()
        recordEvent("SLICE_INTERVAL", "updated to ${normalized}s")
        return normalized
    }

    fun syncNativeDebugFlag(context: Context): Boolean {
        val enabled = isEnabled(context)
        if (NativeBridge.ensureLoaded()) {
            runCatching { NativeBridge.nativeSetDebugLogging(enabled) }
        }
        return enabled
    }

    fun installCrashBreadcrumbHook(context: Context) {
        if (!crashHookInstalled.compareAndSet(false, true)) return
        val appCtx = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val dir = File(appCtx.filesDir, DEBUG_DIR_NAME).apply { mkdirs() }
                val crashFile = File(dir, CRASH_BREADCRUMB_FILE)
                val ts = formatTimestamp(System.currentTimeMillis())
                val rawTrace = throwable.stackTraceToString().take(12_000)
                val safeTrace = NodeImportSupport.redactSecretsForUi(rawTrace)
                crashFile.writeText(
                    "[$ts] Thread=${thread.name}\n$safeTrace\n",
                    Charsets.UTF_8,
                )
            }
            previous?.uncaughtException(thread, throwable)
        }
    }

    fun onVpnSessionStarted(context: Context, isInteractive: Boolean, demoMode: Boolean, enableIpv6: Boolean) {
        val now = System.currentTimeMillis()
        val battery = readBatterySnapshot(context)
        synchronized(lock) {
            sessionStartMs = now
            windowStartMs = now
            screenOnAccumMs = 0L
            screenOffAccumMs = 0L
            lastScreenTransitionMs = now
            currentScreenInteractive = isInteractive
            windowStartBatteryPct = battery.levelPct
            lastNetworkLostMs = 0L
            lastNetStateFingerprint = ""
            lastCumulativeRuleHits = emptyMap()
            pushEventLocked(
                now,
                "VPN_START",
                "interactive=$isInteractive demo=$demoMode ipv6=$enableIpv6 battery=${battery.levelPct ?: -1}%",
            )
        }
    }

    fun onVpnSessionStopping(revokedBySystem: Boolean) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            flushScreenDurationLocked(now)
            pushEventLocked(
                now,
                if (revokedBySystem) "VPN_REVOKE" else "VPN_STOP",
                if (revokedBySystem) "system revoked VPN tunnel" else "user/service stop requested",
            )
        }
    }

    fun onVpnSessionError(rawMessage: String) {
        recordEvent("VPN_ERROR", NodeImportSupport.redactSecretsForUi(rawMessage))
    }

    fun onScreenInteractiveChanged(interactive: Boolean) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            flushScreenDurationLocked(now)
            currentScreenInteractive = interactive
            pushEventLocked(now, if (interactive) "SCREEN_ON" else "SCREEN_OFF", "interactive=$interactive")
        }
    }

    fun onNetworkCandidateObserved(
        eventType: String,
        networkHandle: Long,
        isWifi: Boolean,
        isCellular: Boolean,
        isEthernet: Boolean,
        isValidated: Boolean,
        isNotMetered: Boolean,
        downBandwidthKbps: Int,
        upBandwidthKbps: Int,
        triggeredHandoff: Boolean,
        hasIpv6: Boolean? = null,
    ) {
        val now = System.currentTimeMillis()
        val transport = when {
            isWifi -> "WIFI"
            isCellular -> "CELLULAR"
            isEthernet -> "ETHERNET"
            else -> "OTHER"
        }
        val stateFp = "$networkHandle|$transport|$isValidated|$isNotMetered|${hasIpv6 ?: "-"}"
        synchronized(lock) {
            if ((eventType == "NET_CAPS" || eventType == "NET_AVAILABLE") &&
                !triggeredHandoff &&
                lastNetworkLostMs == 0L &&
                stateFp == lastNetStateFingerprint
            ) {
                return
            }
            lastNetStateFingerprint = stateFp
            val gapNote = if (lastNetworkLostMs > 0L) {
                val gap = (now - lastNetworkLostMs).coerceAtLeast(0L)
                lastNetworkLostMs = 0L
                " recoveryGapMs=$gap"
            } else {
                ""
            }
            val ipv6Note = if (hasIpv6 != null) " ipv6=$hasIpv6" else ""
            pushEventLocked(
                now,
                eventType,
                "handle=$networkHandle transport=$transport validated=$isValidated unmetered=$isNotMetered " +
                    "bw=${downBandwidthKbps}/${upBandwidthKbps}kbps handoff=$triggeredHandoff$ipv6Note$gapNote",
            )
        }
    }

    fun onNetworkLinkIpv6Changed(
        networkHandle: Long,
        transportLabel: String,
        hasIpv6: Boolean,
        handoffTriggered: Boolean,
    ) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            lastNetStateFingerprint = ""
            pushEventLocked(
                now,
                "NET_LINK_IPV6",
                "handle=$networkHandle transport=$transportLabel ipv6=$hasIpv6 handoff=$handoffTriggered",
            )
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun onNetworkLinkIpv6Changed(
        context: Context,
        networkHandle: Long,
        transportLabel: String,
        hasIpv6: Boolean,
        handoffTriggered: Boolean,
    ) {
        onNetworkLinkIpv6Changed(
            networkHandle = networkHandle,
            transportLabel = transportLabel,
            hasIpv6 = hasIpv6,
            handoffTriggered = handoffTriggered,
        )
    }

    fun onNetworkLostObserved(
        networkHandle: Long,
        lostActiveUnderlying: Boolean,
        fallbackHandle: Long = 0L,
    ) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            if (lostActiveUnderlying && fallbackHandle == 0L) {
                lastNetworkLostMs = now
                lastNetStateFingerprint = ""
            } else if (fallbackHandle != 0L) {
                lastNetStateFingerprint = ""
            }
            val fallbackNote = if (fallbackHandle != 0L) " fallbackHandle=$fallbackHandle" else ""
            pushEventLocked(
                now,
                "NET_LOST",
                "handle=$networkHandle activeUnderlyingLost=$lostActiveUnderlying$fallbackNote",
            )
        }
    }

    fun recordEvent(category: String, detail: String) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            pushEventLocked(now, category, NodeImportSupport.redactSecretsForUi(detail))
        }
    }

    fun currentWindowAgeMs(nowMs: Long = System.currentTimeMillis()): Long =
        synchronized(lock) { (nowMs - windowStartMs).coerceAtLeast(0L) }

    fun getStorageSummary(context: Context): DebugLogSummaryUi {
        val dir = File(context.filesDir, DEBUG_DIR_NAME)
        return buildStorageSummaryFromDir(
            dir = dir,
            enabled = isEnabled(context),
            sliceIntervalSecs = getSliceIntervalSecs(context),
        )
    }

    internal fun buildStorageSummaryFromDir(
        dir: File,
        enabled: Boolean,
        sliceIntervalSecs: Long,
    ): DebugLogSummaryUi {
        val sliceFiles = listSliceFilesNewestFirst(dir)
        val totalBytes = sliceFiles.sumOf { it.length() }
        val crashPresent = File(dir, CRASH_BREADCRUMB_FILE).isFile
        val items = sliceFiles.take(10).map { f ->
            DebugSliceItemUi(
                fileName = f.name,
                trigger = parseTriggerFromFileName(f.name),
                createdAtMs = f.lastModified(),
                sizeBytes = f.length(),
            )
        }
        return DebugLogSummaryUi(
            enabled = enabled,
            sliceIntervalSecs = sliceIntervalSecs,
            sliceCount = sliceFiles.size,
            totalBytes = totalBytes,
            latestSliceTimeMs = sliceFiles.firstOrNull()?.lastModified() ?: 0L,
            hasCrashBreadcrumb = crashPresent,
            recentSlices = items,
        )
    }

    /**
     * Captures a diagnostic slice covering `[windowStartMs, now]`, writes it to `filesDir/debug_logs`,
     * advances the rolling window, and enforces retention limits (`<= 12` files, `<= 8 MB`).
     */
    fun captureSlice(
        context: Context,
        stateDir: String = context.filesDir.absolutePath,
        trigger: String,
    ): File? = synchronized(sliceWriteLock) {
        val batteryEnd = readBatterySnapshot(context)
        val systemMeta = collectSystemMetadata(context, batteryEnd)

        val (windowSnap, prevRuleHitsSnap) = synchronized(lock) {
            val now = System.currentTimeMillis()
            flushScreenDurationLocked(now)
            val snap = WindowTelemetryState(
                windowStartMs = windowStartMs,
                capturedAtMs = now,
                sessionStartMs = sessionStartMs,
                screenOnMs = screenOnAccumMs,
                screenOffMs = screenOffAccumMs,
                startBatteryPct = windowStartBatteryPct,
                events = timelineEvents.filter { it.timestampMs >= windowStartMs },
            )
            windowStartMs = now
            screenOnAccumMs = 0L
            screenOffAccumMs = 0L
            lastScreenTransitionMs = now
            windowStartBatteryPct = batteryEnd.levelPct
            snap to lastCumulativeRuleHits
        }

        val nativeJsonStr = if (NativeBridge.ensureLoaded()) {
            runCatching {
                NativeBridge.nativeCollectDebugSnapshotJson(
                    stateDir,
                    windowSnap.windowStartMs,
                    windowSnap.capturedAtMs,
                )
            }.getOrDefault("{\"ok\":false,\"error\":\"nativeCollectDebugSnapshotJson threw\"}")
        } else {
            "{\"ok\":false,\"vpnRunning\":false,\"error\":\"native library not loaded\"}"
        }

        extractCumulativeRuleHits(nativeJsonStr)?.let { latestHits ->
            synchronized(lock) {
                lastCumulativeRuleHits = latestHits
            }
        }

        val dir = File(context.filesDir, DEBUG_DIR_NAME).apply { mkdirs() }
        val crashBreadcrumb = File(dir, CRASH_BREADCRUMB_FILE)
            .takeIf { it.isFile }
            ?.let { runCatching { it.readText(Charsets.UTF_8) }.getOrNull() }

        val formatted = formatSliceReport(
            trigger = trigger,
            window = windowSnap,
            systemMeta = systemMeta,
            nativeSnapshotRawJson = nativeJsonStr,
            crashBreadcrumb = crashBreadcrumb,
            previousRuleHits = prevRuleHitsSnap,
        )

        val safeTrigger = trigger.lowercase(Locale.ROOT)
            .replace(SAFE_TRIGGER_REGEX, "-")
            .trim('-')
            .ifEmpty { "slice" }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.US).format(Date(windowSnap.capturedAtMs))
        val outFile = File(dir, "$SLICE_PREFIX$stamp-$safeTrigger$SLICE_SUFFIX")
        val tmpFile = File(dir, "${outFile.name}.tmp")
        return runCatching {
            tmpFile.writeText(formatted, Charsets.UTF_8)
            if (!tmpFile.renameTo(outFile)) {
                outFile.writeText(formatted, Charsets.UTF_8)
                runCatching { tmpFile.delete() }
            }
            enforceRetentionPolicy(dir, MAX_SLICE_FILES, MAX_TOTAL_SLICE_BYTES)
            outFile
        }.onFailure {
            runCatching { tmpFile.delete() }
        }.getOrNull()
    }

    /**
     * Flushes a fresh live slice first (unless one was captured within the last 15 seconds),
     * then builds a single combined report file in `cacheDir/debug_exports`
     * suitable for Android Share Sheet (`FileProvider`) or SAF Save (`CreateDocument`).
     */
    fun buildCombinedReportFile(
        context: Context,
        stateDir: String = context.filesDir.absolutePath,
    ): File? {
        val sliceDir = File(context.filesDir, DEBUG_DIR_NAME)
        val newest = listSliceFilesNewestFirst(sliceDir).firstOrNull()
        if (newest == null || System.currentTimeMillis() - newest.lastModified() >= 15_000L) {
            captureSlice(context = context, stateDir = stateDir, trigger = "export")
        }
        val exportDir = File(context.cacheDir, EXPORT_CACHE_DIR_NAME).apply { mkdirs() }
        // Clean up stale export files older than 1 hour
        val cutoff = System.currentTimeMillis() - 3_600_000L
        exportDir.listFiles()?.forEach { f ->
            if (f.isFile && f.lastModified() < cutoff) {
                runCatching { f.delete() }
            }
        }
        return assembleCombinedExportFromSlices(
            sliceDir = sliceDir,
            exportDir = exportDir,
            nowMs = System.currentTimeMillis(),
            maxBytes = MAX_COMBINED_EXPORT_BYTES,
        )
    }

    internal fun assembleCombinedExportFromSlices(
        sliceDir: File,
        exportDir: File,
        nowMs: Long,
        maxBytes: Int = MAX_COMBINED_EXPORT_BYTES,
    ): File? {
        val newestFirst = listSliceFilesNewestFirst(sliceDir)
        if (newestFirst.isEmpty()) return null
        exportDir.mkdirs()

        val header = buildString {
            appendLine("# RustClash Android Diagnostic Report Bundle")
            appendLine("- GeneratedAt: ${formatTimestamp(nowMs)}")
            appendLine("- IncludedSlicesAvailable: ${newestFirst.size}")
            appendLine("- RedactionPolicy: Visited domains, rules & node names preserved; passwords/UUIDs/subscription URLs redacted")
            appendLine()
        }

        val selectedBodies = ArrayList<Pair<String, String>>()
        var usedBytes = header.toByteArray(Charsets.UTF_8).size
        val separatorBytes = 200
        for (file in newestFirst) {
            val content = runCatching { file.readText(Charsets.UTF_8) }.getOrNull() ?: continue
            // Slices written by formatSliceReport are already scrubbed once on disk; avoid a second full-file regex pass
            val sanitized = if (content.startsWith(SLICE_REPORT_HEADER_PREFIX)) {
                content
            } else {
                NodeImportSupport.redactSecretsForUi(content)
            }
            val sanitizedUtf8Bytes = sanitized.toByteArray(Charsets.UTF_8)
            if (selectedBodies.isNotEmpty() && usedBytes + sanitizedUtf8Bytes.size + separatorBytes > maxBytes) {
                break
            }
            val (bounded, boundedByteLen) = if (usedBytes + sanitizedUtf8Bytes.size + separatorBytes > maxBytes) {
                val suffix = "\n...[truncated]...\n"
                val suffixByteLen = suffix.toByteArray(Charsets.UTF_8).size
                val budgetBytes = (maxBytes - usedBytes - separatorBytes - suffixByteLen).coerceAtLeast(1024)
                val truncated = truncateUtf8BytesSafe(sanitizedUtf8Bytes, budgetBytes) + suffix
                truncated to truncated.toByteArray(Charsets.UTF_8).size
            } else {
                sanitized to sanitizedUtf8Bytes.size
            }
            selectedBodies.add(file.name to bounded)
            usedBytes += boundedByteLen + separatorBytes
        }

        // Order chronologically (oldest -> newest among selected recent slices) for natural timeline analysis
        selectedBodies.reverse()

        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(nowMs))
        val outFile = File(exportDir, "rustclash-android-diag-$stamp.log")
        return runCatching {
            outFile.bufferedWriter(Charsets.UTF_8).use { writer ->
                writer.write(header)
                selectedBodies.forEachIndexed { idx, (name, body) ->
                    writer.write("================================================================================\n")
                    writer.write("## Slice [${idx + 1}/${selectedBodies.size}]: $name\n")
                    writer.write("================================================================================\n\n")
                    writer.write(body)
                    if (!body.endsWith("\n")) writer.write("\n")
                    writer.write("\n")
                }
            }
            outFile
        }.getOrNull()
    }

    private fun truncateUtf8BytesSafe(bytes: ByteArray, maxBytes: Int): String {
        if (bytes.size <= maxBytes) {
            return String(bytes, Charsets.UTF_8)
        }
        var end = maxBytes.coerceAtLeast(0)
        while (end > 0 && (bytes[end].toInt() and 0xC0) == 0x80) {
            end--
        }
        return String(bytes, 0, end, Charsets.UTF_8)
    }

    private fun extractCumulativeRuleHits(nativeSnapshotRawJson: String): Map<String, Long>? {
        val obj = runCatching { JSONObject(nativeSnapshotRawJson) }.getOrNull() ?: return null
        if (!obj.optBoolean("ok", false)) return null
        val arr = obj.optJSONArray("topRules") ?: return emptyMap()
        val map = LinkedHashMap<String, Long>(arr.length() * 2)
        for (i in 0 until arr.length()) {
            val r = arr.optJSONObject(i) ?: continue
            val type = r.optString("type")
            val payload = r.optString("payload")
            val proxy = r.optString("proxy")
            val label = if (payload.isEmpty()) type else "$type,$payload"
            val hits = r.optLong("hits", 0L)
            map["$label->$proxy"] = hits
            map.putIfAbsent(label, hits)
        }
        return map
    }

    fun clearAllLogs(context: Context) {
        synchronized(sliceWriteLock) {
            val dir = File(context.filesDir, DEBUG_DIR_NAME)
            dir.listFiles()?.forEach { runCatching { it.delete() } }
            val exportDir = File(context.cacheDir, EXPORT_CACHE_DIR_NAME)
            exportDir.listFiles()?.forEach { runCatching { it.delete() } }
        }
        val now = System.currentTimeMillis()
        val batteryNow = readBatterySnapshot(context).levelPct
        resetTimelineWindowOnClear(
            nowMs = now,
            batteryPct = batteryNow,
            vpnState = RustClashVpnService.stateTracker.state,
            activeNode = RustClashVpnService.activeOutboundLabel,
        )
        if (NativeBridge.isNativeLoaded) {
            runCatching { NativeBridge.nativeClearDiagnostics() }
        }
    }

    internal fun resetTimelineWindowOnClear(
        nowMs: Long,
        batteryPct: Int? = null,
        vpnState: VpnLifecycleState = RustClashVpnService.stateTracker.state,
        activeNode: String = RustClashVpnService.activeOutboundLabel,
    ): List<MobileTimelineEvent> = synchronized(lock) {
        timelineEvents.clear()
        windowStartMs = nowMs
        screenOnAccumMs = 0L
        screenOffAccumMs = 0L
        lastScreenTransitionMs = nowMs
        if (batteryPct != null) {
            windowStartBatteryPct = batteryPct
        }
        lastNetStateFingerprint = ""
        lastCumulativeRuleHits = emptyMap()
        if (vpnState != VpnLifecycleState.DISCONNECTED) {
            pushEventLocked(
                nowMs,
                "LOG_CLEARED",
                "logs reset while state=${vpnState.name.lowercase(Locale.ROOT)} interactive=$currentScreenInteractive" +
                    if (activeNode.isNotBlank()) " node=$activeNode" else "",
            )
        }
        timelineEvents.toList()
    }

    internal fun snapshotTimelineEventsForTest(): List<MobileTimelineEvent> =
        synchronized(lock) { timelineEvents.toList() }

    internal fun listSliceFilesNewestFirst(dir: File): List<File> {
        if (!dir.isDirectory) return emptyList()
        return dir.listFiles { f ->
            f.isFile && f.name.startsWith(SLICE_PREFIX) && f.name.endsWith(SLICE_SUFFIX)
        }?.sortedWith(
            compareByDescending<File> { it.name }.thenByDescending { it.lastModified() },
        ) ?: emptyList()
    }

    internal fun enforceRetentionPolicy(
        dir: File,
        maxFiles: Int,
        maxTotalBytes: Long,
    ) {
        val filesNewestFirst = listSliceFilesNewestFirst(dir).toMutableList()
        while (filesNewestFirst.size > maxFiles) {
            val oldest = filesNewestFirst.removeAt(filesNewestFirst.lastIndex)
            runCatching { oldest.delete() }
        }
        var total = filesNewestFirst.sumOf { it.length() }
        while (filesNewestFirst.size > 1 && total > maxTotalBytes) {
            val oldest = filesNewestFirst.removeAt(filesNewestFirst.lastIndex)
            total -= oldest.length()
            runCatching { oldest.delete() }
        }
    }

    internal fun parseTriggerFromFileName(fileName: String): String {
        val core = fileName.removePrefix(SLICE_PREFIX).removeSuffix(SLICE_SUFFIX)
        // Format: yyyyMMdd-HHmmss-SSS-<trigger>
        val parts = core.split('-', limit = 4)
        return if (parts.size >= 4) parts[3] else "slice"
    }

    private fun flushScreenDurationLocked(nowMs: Long) {
        val delta = (nowMs - lastScreenTransitionMs).coerceAtLeast(0L)
        if (currentScreenInteractive) {
            screenOnAccumMs += delta
        } else {
            screenOffAccumMs += delta
        }
        lastScreenTransitionMs = nowMs
    }

    private fun pushEventLocked(timestampMs: Long, category: String, detail: String) {
        while (timelineEvents.size >= MAX_TIMELINE_EVENTS) {
            timelineEvents.removeFirst()
        }
        timelineEvents.addLast(
            MobileTimelineEvent(
                timestampMs = timestampMs,
                category = category,
                detail = NodeImportSupport.redactSecretsForUi(detail),
            ),
        )
    }

    internal data class BatterySnapshot(
        val levelPct: Int?,
        val isCharging: Boolean,
        val temperatureCelsius: Double?,
    )

    internal data class WindowTelemetryState(
        val windowStartMs: Long,
        val capturedAtMs: Long,
        val sessionStartMs: Long,
        val screenOnMs: Long,
        val screenOffMs: Long,
        val startBatteryPct: Int?,
        val events: List<MobileTimelineEvent>,
    )

    internal data class SystemMetadata(
        val deviceManufacturer: String,
        val deviceModel: String,
        val androidRelease: String,
        val sdkInt: Int,
        val primaryAbi: String,
        val appVersionName: String,
        val appVersionCode: Int,
        val battery: BatterySnapshot,
        val isInteractive: Boolean,
        val isPowerSaveMode: Boolean,
        val isDeviceIdleDoze: Boolean,
        val ignoringBatteryOptimizations: Boolean,
        val jvmUsedBytes: Long,
        val jvmMaxBytes: Long,
        val nativeHeapBytes: Long,
        val perAppMode: String,
        val selectedPackagesCount: Int,
        val enableIpv6: Boolean,
        val demoMode: Boolean,
        val recentProcessExits: List<String>,
    )

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun readBatterySnapshot(context: Context): BatterySnapshot = runCatching {
        val sticky = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        if (sticky == null) {
            return BatterySnapshot(null, false, null)
        }
        val level = sticky.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = sticky.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val pct = if (level >= 0 && scale > 0) ((level * 100f) / scale).toInt() else null
        val status = sticky.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        val tempTenths = sticky.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
        val tempC = if (tempTenths > 0) tempTenths / 10.0 else null
        BatterySnapshot(pct, charging, tempC)
    }.getOrDefault(BatterySnapshot(null, false, null))

    private fun collectSystemMetadata(context: Context, battery: BatterySnapshot): SystemMetadata {
        val pm = context.getSystemService(PowerManager::class.java)
        val interactive = pm?.isInteractive ?: true
        val powerSave = pm?.isPowerSaveMode ?: false
        val deviceIdle = pm?.isDeviceIdleMode ?: false
        val ignoringBatOpt = runCatching {
            pm?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        }.getOrDefault(false)

        val rt = Runtime.getRuntime()
        val jvmUsed = (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
        val jvmMax = rt.maxMemory().coerceAtLeast(0L)
        val nativeHeap = runCatching { Debug.getNativeHeapAllocatedSize() }.getOrDefault(0L)

        val prefs = context.getSharedPreferences(RustClashVpnService.PREFS_VPN_SETTINGS, Context.MODE_PRIVATE)
        val perAppMode = prefs.getString(RustClashVpnService.KEY_PER_APP_MODE, "ALL_APPS") ?: "ALL_APPS"
        val selectedPkgCount = prefs.getStringSet(RustClashVpnService.KEY_SELECTED_PACKAGES, emptySet())?.size ?: 0
        val enableIpv6 = prefs.getBoolean(RustClashVpnService.KEY_ENABLE_IPV6, true)
        val demoMode = prefs.getBoolean(RustClashVpnService.KEY_DEMO_MODE, false)

        val exitReasons = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Api30ExitInfoHelper.readRecentExitReasons(context)
        } else {
            emptyList()
        }

        return SystemMetadata(
            deviceManufacturer = Build.MANUFACTURER ?: "unknown",
            deviceModel = Build.MODEL ?: "unknown",
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            sdkInt = Build.VERSION.SDK_INT,
            primaryAbi = Build.SUPPORTED_ABIS?.firstOrNull() ?: "unknown",
            appVersionName = BuildConfig.VERSION_NAME,
            appVersionCode = BuildConfig.VERSION_CODE,
            battery = battery,
            isInteractive = interactive,
            isPowerSaveMode = powerSave,
            isDeviceIdleDoze = deviceIdle,
            ignoringBatteryOptimizations = ignoringBatOpt,
            jvmUsedBytes = jvmUsed,
            jvmMaxBytes = jvmMax,
            nativeHeapBytes = nativeHeap,
            perAppMode = perAppMode,
            selectedPackagesCount = selectedPkgCount,
            enableIpv6 = enableIpv6,
            demoMode = demoMode,
            recentProcessExits = exitReasons,
        )
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private object Api30ExitInfoHelper {
        fun readRecentExitReasons(context: Context): List<String> = runCatching {
            val am = context.getSystemService(ActivityManager::class.java)
            am?.getHistoricalProcessExitReasons(context.packageName, 0, 5)
                ?.map { info -> formatExitInfo(info) }
                .orEmpty()
        }.getOrDefault(emptyList())

        private fun formatExitInfo(info: ApplicationExitInfo): String {
            val reasonName = when (info.reason) {
                ApplicationExitInfo.REASON_ANR -> "ANR"
                ApplicationExitInfo.REASON_CRASH -> "JVM_CRASH"
                ApplicationExitInfo.REASON_CRASH_NATIVE -> "NATIVE_CRASH"
                ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "EXCESSIVE_RESOURCE"
                ApplicationExitInfo.REASON_LOW_MEMORY -> "LOW_MEMORY_LMK"
                ApplicationExitInfo.REASON_OTHER -> "OTHER_OEM_KILL"
                ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "PERMISSION_CHANGE"
                ApplicationExitInfo.REASON_SIGNALED -> "SIGNALED(${info.status})"
                ApplicationExitInfo.REASON_USER_REQUESTED -> "USER_STOPPED"
                ApplicationExitInfo.REASON_USER_STOPPED -> "USER_FORCE_STOP"
                else -> "REASON_${info.reason}"
            }
            val ts = formatTimestamp(info.timestamp)
            val desc = NodeImportSupport.redactSecretsForUi(info.description ?: "")
            return "[$ts] reason=$reasonName importance=${info.importance} pss=${info.pss}KB rss=${info.rss}KB desc=$desc"
        }
    }

    internal fun formatSliceReport(
        trigger: String,
        window: WindowTelemetryState,
        systemMeta: SystemMetadata,
        nativeSnapshotRawJson: String,
        crashBreadcrumb: String?,
        previousRuleHits: Map<String, Long> = emptyMap(),
    ): String {
        val windowDurationSecs = ((window.capturedAtMs - window.windowStartMs).coerceAtLeast(0L)) / 1000L
        val nativeObj = runCatching { JSONObject(nativeSnapshotRawJson) }.getOrNull()
        val sb = StringBuilder(16_384)

        sb.appendLine("### RustClash Android Diagnostic Slice (`$trigger`)")
        sb.appendLine("- Window: `${formatTimestamp(window.windowStartMs)}` -> `${formatTimestamp(window.capturedAtMs)}` (${windowDurationSecs}s)")
        sb.appendLine(
            "- App & Device: `v${systemMeta.appVersionName} (${systemMeta.appVersionCode})` · " +
                "`${systemMeta.deviceManufacturer} ${systemMeta.deviceModel}` · " +
                "Android `${systemMeta.androidRelease}` (API ${systemMeta.sdkInt}, `${systemMeta.primaryAbi}`)",
        )

        val batStart = window.startBatteryPct
        val batEnd = systemMeta.battery.levelPct
        val batDeltaStr = if (batStart != null && batEnd != null) {
            val diff = batEnd - batStart
            val sign = if (diff > 0) "+" else ""
            "$batStart% -> $batEnd% (${sign}${diff}%)"
        } else {
            "${batEnd ?: -1}%"
        }
        val tempStr = systemMeta.battery.temperatureCelsius?.let { String.format(Locale.US, "%.1f°C", it) } ?: "N/A"
        sb.appendLine(
            "- Battery & Power: level=`$batDeltaStr` charging=`${systemMeta.battery.isCharging}` temp=`$tempStr` " +
                "doze=`${systemMeta.isDeviceIdleDoze}` powerSave=`${systemMeta.isPowerSaveMode}` " +
                "batteryOptWhitelisted=`${systemMeta.ignoringBatteryOptimizations}`",
        )
        sb.appendLine(
            "- Screen Activity: screenOn=`${window.screenOnMs / 1000}s` screenOff=`${window.screenOffMs / 1000}s` " +
                "currentlyInteractive=`${systemMeta.isInteractive}`",
        )
        val vmRssBytes = nativeObj?.optLong("vmRssBytes", 0L) ?: 0L
        val vmRssNote = if (vmRssBytes > 0L) " vmRss=`${formatBytesCompact(vmRssBytes)}`" else ""
        sb.appendLine(
            "- Memory & Policy: rss=`${formatBytesCompact(nativeObj?.optLong("rssBytes", 0L) ?: 0L)}`$vmRssNote " +
                "nativeHeap=`${formatBytesCompact(systemMeta.nativeHeapBytes)}` " +
                "jvmHeap=`${formatBytesCompact(systemMeta.jvmUsedBytes)} / ${formatBytesCompact(systemMeta.jvmMaxBytes)}` " +
                "perApp=`${systemMeta.perAppMode}(${systemMeta.selectedPackagesCount})` ipv6=`${systemMeta.enableIpv6}` demo=`${systemMeta.demoMode}`",
        )

        if (systemMeta.recentProcessExits.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("#### Historical Process Exits (Android OS / LMK / OEM)")
            systemMeta.recentProcessExits.forEach { line ->
                sb.appendLine("- $line")
            }
        }

        if (!crashBreadcrumb.isNullOrBlank()) {
            sb.appendLine()
            sb.appendLine("#### Last JVM Crash Breadcrumb")
            sb.appendLine("```text")
            sb.appendLine(crashBreadcrumb.trim())
            sb.appendLine("```")
        }

        if (nativeObj != null && nativeObj.optBoolean("ok", false)) {
            val vpnRunning = nativeObj.optBoolean("vpnRunning", false)
            val mode = nativeObj.optString("mode", "rule")
            val preset = nativeObj.optString("routingPreset", "")
            val effOut = nativeObj.optString("effectiveOutbound", "DIRECT")
            val effProto = nativeObj.optString("effectiveProtocol", "-")
            val effDelay = nativeObj.optLong("effectiveDelayMs", -1L)
            val uptime = nativeObj.optLong("uptimeSecs", 0L)
            val netTrans = nativeObj.optLong("networkTransitions", 0L)
            val isWifi = nativeObj.optBoolean("isWifi", true)
            val hasIpv6 = if (nativeObj.has("hasIpv6") && !nativeObj.isNull("hasIpv6")) {
                nativeObj.optBoolean("hasIpv6", true)
            } else {
                null
            }
            val ipv6RoutePart = if (hasIpv6 != null) " ipv6Route=`$hasIpv6`" else ""

            sb.appendLine()
            sb.appendLine("#### Rust Engine & Tunnel Summary")
            sb.appendLine(
                "- State: vpnRunning=`$vpnRunning` uptime=`${uptime}s` mode=`$mode` preset=`${preset.ifEmpty { "-" }}` " +
                    "activeNode=`$effOut ($effProto, delay=${if (effDelay > 0) "${effDelay}ms" else "N/A"})` " +
                    "net=`${if (isWifi) "WIFI" else "CELLULAR"}` transitions=`$netTrans`$ipv6RoutePart",
            )

            nativeObj.optJSONObject("activeProfile")?.let { prof ->
                val rawSubHost = if (prof.isNull("subscriptionHost")) {
                    "-"
                } else {
                    prof.optString("subscriptionHost", "-").ifBlank { "-" }
                }
                sb.appendLine(
                    "- Active Profile: name=`${prof.optString("name")}` " +
                        "kind=`${prof.optString("kind")}` nodes=`${prof.optInt("proxyCount")}` " +
                        "manualNodes=`${prof.optInt("manualProxyCount")}` rules=`${prof.optInt("ruleCount")}` " +
                        "autoUpdateSecs=`${prof.optLong("autoUpdateIntervalSecs", 0L)}` " +
                        "subHost=`$rawSubHost`",
                )
            }

            nativeObj.optJSONObject("traffic")?.let { tr ->
                val carryOver = tr.optLong("carryOverActiveConnections", 0L)
                val carryOverPart = if (carryOver > 0L) " carryOverActive=`$carryOver`" else ""
                sb.appendLine(
                    "- Session Traffic & Conns: upTotal=`${formatBytesCompact(tr.optLong("upTotal"))}` " +
                        "downTotal=`${formatBytesCompact(tr.optLong("downTotal"))}` " +
                        "activeConns=`${tr.optInt("activeConnections")}` totalConns=`${tr.optLong("totalConnections")}` " +
                        "established=`${tr.optLong("establishedConnections")}` failed=`${tr.optLong("failedConnections")}` " +
                        "zeroRxClosed=`${tr.optLong("zeroRxClosedConnections")}`$carryOverPart",
                )
            }

            nativeObj.optJSONObject("tun")?.let { tun ->
                sb.appendLine(
                    "- TUN & Socket Protect: rxPkts=`${tun.optLong("rxPackets")}` (${formatBytesCompact(tun.optLong("rxBytes"))}) " +
                        "txPkts=`${tun.optLong("txPackets")}` (${formatBytesCompact(tun.optLong("txBytes"))}) " +
                        "txWriteDrops=`${tun.optLong("txWriteDrops")}` " +
                        "protectedTcp=`${tun.optLong("protectedTcpSockets")}` protectedUdp=`${tun.optLong("protectedUdpSockets")}` " +
                        "protectFailures=`${tun.optLong("protectFailures")}`",
                )
            }

            nativeObj.optJSONObject("dns")?.let { dns ->
                val cacheHits = when {
                    dns.has("wireCacheHits") -> dns.optLong("wireCacheHits", 0L)
                    dns.has("wire_cache_hits") -> dns.optLong("wire_cache_hits", 0L)
                    dns.has("cache_hits") -> dns.optLong("cache_hits", 0L)
                    else -> dns.optLong("cacheHits", 0L)
                }
                val resolverCacheHits = if (dns.has("resolverCacheHits")) {
                    dns.optLong("resolverCacheHits", 0L)
                } else {
                    dns.optLong("resolver_cache_hits", 0L)
                }
                val nxdomainHits = dns.optLong("nxdomain_hits", 0L)
                val nxdomainPart = if (nxdomainHits > 0L) " nxdomainCached=`$nxdomainHits`" else ""
                sb.appendLine(
                    "- DNS & Fake-IP: queries=`${dns.optLong("total_queries")}` fakeIpHits=`${dns.optLong("fake_ip_hits")}` " +
                        "wireCacheHits=`$cacheHits` resolverCacheHits=`$resolverCacheHits` " +
                        "aaaaSuppressed=`${dns.optLong("suppressed_queries", 0L)}`$nxdomainPart " +
                        "upstreamQueries=`${dns.optLong("upstream_queries")}` " +
                        "upstreamErrors=`${dns.optLong("upstream_errors")}` " +
                        "upstreamAvgMs=`${dns.optLong("upstream_avg_ms")}ms` upstreamMaxMs=`${dns.optLong("upstream_max_ms")}ms` " +
                        "activeFakeIps=`${dns.optInt("active_fake_ip_entries")}`",
                )
            }

            appendOutboundStatsSection(sb, nativeObj.optJSONArray("outboundStats"))
            appendTopRulesSection(sb, nativeObj.optJSONArray("topRules"), previousRuleHits)
            appendTopDomainsSection(sb, nativeObj.optJSONArray("topDomains"))
            appendFailedConnectionsSection(sb, nativeObj.optJSONArray("failedConnections"))
            appendSlowConnectionsSection(sb, nativeObj.optJSONArray("slowConnections"))
            appendRecentConnectionsSection(sb, nativeObj.optJSONArray("recentConnections"))
            appendEngineLogsSection(sb, nativeObj.optJSONArray("engineLogs"))
        } else {
            sb.appendLine()
            sb.appendLine("#### Rust Engine Snapshot")
            sb.appendLine("- Unavailable: `$nativeSnapshotRawJson`")
        }

        if (window.events.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("#### Mobile Lifecycle, Screen & Network Handoff Timeline (${window.events.size})")
            window.events.takeLast(120).forEach { ev ->
                sb.appendLine("- `[${formatShortTime(ev.timestampMs)}]` **${ev.category}**: ${ev.detail}")
            }
        }

        return NodeImportSupport.redactSecretsForUi(sb.toString())
    }

    private fun appendOutboundStatsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Outbound Node Performance (Window)")
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val name = o.optString("outbound")
            val proto = o.optString("protocol")
            val probe = if (o.isNull("latestProbeDelayMs")) "N/A" else "${o.optLong("latestProbeDelayMs")}ms"
            val p50 = if (o.isNull("handshakeP50Ms")) "-" else "${o.optLong("handshakeP50Ms")}ms"
            val p95 = if (o.isNull("handshakeP95Ms")) "-" else "${o.optLong("handshakeP95Ms")}ms"
            val maxHs = if (o.isNull("handshakeMaxMs")) "-" else "${o.optLong("handshakeMaxMs")}ms"
            sb.appendLine(
                "- `$name` ($proto): conns=`${o.optInt("connections")}` fail=`${o.optInt("failures")}` " +
                    "zeroRx=`${o.optInt("zeroRxCount")}` probe=`$probe` handshake(p50/p95/max)=`$p50 / $p95 / $maxHs` " +
                    "up=`${formatBytesCompact(o.optLong("uploadBytes"))}` down=`${formatBytesCompact(o.optLong("downloadBytes"))}`",
            )
        }
    }

    private data class RuleWindowEntry(
        val label: String,
        val proxy: String,
        val windowHits: Long,
        val cumulativeHits: Long,
        val hasPriorBaseline: Boolean,
    )

    private fun appendTopRulesSection(
        sb: StringBuilder,
        arr: JSONArray?,
        previousRuleHits: Map<String, Long>,
    ) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Top Matched Routing Rules")
        if (previousRuleHits.isEmpty()) {
            for (i in 0 until arr.length()) {
                val r = arr.optJSONObject(i) ?: continue
                val type = r.optString("type")
                val payload = r.optString("payload")
                val label = if (payload.isEmpty()) type else "$type,$payload"
                sb.appendLine("- `$label` -> `${r.optString("proxy")}` (hits=`${r.optLong("hits")}`)")
            }
            return
        }

        val entries = ArrayList<RuleWindowEntry>(arr.length())
        for (i in 0 until arr.length()) {
            val r = arr.optJSONObject(i) ?: continue
            val type = r.optString("type")
            val payload = r.optString("payload")
            val proxy = r.optString("proxy")
            val label = if (payload.isEmpty()) type else "$type,$payload"
            val cumHits = r.optLong("hits", 0L)
            val prevHits = previousRuleHits["$label->$proxy"] ?: previousRuleHits[label]
            val hasValidBaseline = prevHits != null && cumHits >= prevHits
            val windowHits = if (hasValidBaseline) {
                (cumHits - prevHits!!).coerceAtLeast(0L)
            } else {
                cumHits
            }
            entries.add(
                RuleWindowEntry(
                    label = label,
                    proxy = proxy,
                    windowHits = windowHits,
                    cumulativeHits = cumHits,
                    hasPriorBaseline = hasValidBaseline && prevHits!! > 0L,
                ),
            )
        }
        entries.sortWith(
            compareByDescending<RuleWindowEntry> { it.windowHits }
                .thenByDescending { it.cumulativeHits },
        )
        for (entry in entries) {
            if (entry.hasPriorBaseline) {
                sb.appendLine(
                    "- `${entry.label}` -> `${entry.proxy}` (hits=`${entry.windowHits}` (total=`${entry.cumulativeHits}`))",
                )
            } else {
                sb.appendLine("- `${entry.label}` -> `${entry.proxy}` (hits=`${entry.windowHits}`)")
            }
        }
    }

    private fun appendTopDomainsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Top Visited Domains (Window)")
        for (i in 0 until arr.length()) {
            val d = arr.optJSONObject(i) ?: continue
            sb.appendLine(
                "- `${d.optString("host")}`: conns=`${d.optInt("connections")}` fail=`${d.optInt("failures")}` " +
                    "rule=`${d.optString("primaryRule")}` node=`${d.optString("primaryOutbound")}` " +
                    "up=`${formatBytesCompact(d.optLong("uploadBytes"))}` down=`${formatBytesCompact(d.optLong("downloadBytes"))}`",
            )
        }
    }

    private fun readCoalescedCount(c: JSONObject): Long {
        val raw = if (c.has("coalescedCount")) {
            c.optLong("coalescedCount", 1L)
        } else {
            c.optLong("coalesced_count", 1L)
        }
        return raw.coerceAtLeast(1L)
    }

    private fun appendFailedConnectionsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        var totalFailedCount = 0L
        for (i in 0 until arr.length()) {
            val c = arr.optJSONObject(i) ?: continue
            totalFailedCount += readCoalescedCount(c)
        }
        sb.appendLine()
        if (totalFailedCount > arr.length().toLong()) {
            sb.appendLine("#### Failed Connections (${arr.length()} entries, $totalFailedCount total)")
        } else {
            sb.appendLine("#### Failed Connections (${arr.length()})")
        }
        for (i in 0 until arr.length()) {
            val c = arr.optJSONObject(i) ?: continue
            val coalesced = readCoalescedCount(c)
            val coalescedSuffix = if (coalesced > 1L) " (x$coalesced)" else ""
            val rulePayload = c.optString("rulePayload")
            val ruleDesc = if (rulePayload.isEmpty()) c.optString("rule") else "${c.optString("rule")}($rulePayload)"
            val fakeNote = c.optString("fakeIp").takeIf { it.isNotEmpty() && it != "null" }?.let { " fakeIp=$it" } ?: ""
            val hostPort = NodeImportSupport.formatHostPort(c.optString("host"), c.optInt("destinationPort"))
            sb.appendLine(
                "- `[${formatShortTime(c.optLong("startEpochMs"))}]` `${c.optString("network").uppercase(Locale.ROOT)}` " +
                    "`$hostPort`$fakeNote · rule=`$ruleDesc` -> " +
                    "`${c.optString("effectiveOutbound")}` (${c.optString("effectiveProtocol")}) · " +
                    "error=`${c.optString("error", "unknown")}`$coalescedSuffix",
            )
        }
    }

    private fun appendSlowConnectionsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Slowest Outbound Handshakes")
        for (i in 0 until minOf(arr.length(), 25)) {
            val c = arr.optJSONObject(i) ?: continue
            val ms = c.optLong("connectDurationMs", -1L)
            if (ms < 0L) continue
            val rulePayload = c.optString("rulePayload")
            val ruleDesc = if (rulePayload.isEmpty()) c.optString("rule") else "${c.optString("rule")}($rulePayload)"
            val hostPort = NodeImportSupport.formatHostPort(c.optString("host"), c.optInt("destinationPort"))
            sb.appendLine(
                "- `${ms}ms` · `${c.optString("network").uppercase(Locale.ROOT)}` `$hostPort` · " +
                    "rule=`$ruleDesc` -> `${c.optString("effectiveOutbound")}` · " +
                    "up=`${formatBytesCompact(c.optLong("upload"))}` down=`${formatBytesCompact(c.optLong("download"))}` (${c.optString("status")})",
            )
        }
    }

    private fun appendRecentConnectionsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Recent Connections Sample (${minOf(arr.length(), 50)})")
        for (i in 0 until minOf(arr.length(), 50)) {
            val c = arr.optJSONObject(i) ?: continue
            val coalesced = readCoalescedCount(c)
            val coalescedSuffix = if (coalesced > 1L) " (x$coalesced)" else ""
            val hs = if (c.isNull("connectDurationMs")) "-" else "${c.optLong("connectDurationMs")}ms"
            val rulePayload = c.optString("rulePayload")
            val ruleDesc = if (rulePayload.isEmpty()) c.optString("rule") else "${c.optString("rule")}($rulePayload)"
            val hostPort = NodeImportSupport.formatHostPort(c.optString("host"), c.optInt("destinationPort"))
            sb.appendLine(
                "- `[${formatShortTime(c.optLong("startEpochMs"))}]` `${c.optString("network").uppercase(Locale.ROOT)}` " +
                    "`$hostPort` · `$ruleDesc` -> `${c.optString("effectiveOutbound")}` · " +
                    "hs=`$hs` up=`${formatBytesCompact(c.optLong("upload"))}` down=`${formatBytesCompact(c.optLong("download"))}` status=`${c.optString("status")}`$coalescedSuffix",
            )
        }
    }

    private fun appendEngineLogsSection(sb: StringBuilder, arr: JSONArray?) {
        if (arr == null || arr.length() == 0) return
        sb.appendLine()
        sb.appendLine("#### Rust Engine Logs (${arr.length()})")
        for (i in 0 until arr.length()) {
            val e = arr.optJSONObject(i) ?: continue
            val lvl = e.optString("level", "info").uppercase(Locale.ROOT)
            val msg = e.optString("payload")
            sb.appendLine("- `[${formatShortTime(e.optLong("timestampMs"))}]` [$lvl] $msg")
        }
    }

    internal fun formatTimestamp(epochMs: Long): String {
        if (epochMs <= 0L) return "-"
        return SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS Z", Locale.US).format(Date(epochMs))
    }

    private fun formatShortTime(epochMs: Long): String {
        if (epochMs <= 0L) return "-"
        return SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date(epochMs))
    }

    internal fun formatBytesCompact(bytes: Long): String =
        when {
            bytes >= 1_073_741_824L -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
            bytes >= 1_048_576L -> String.format(Locale.US, "%.2f MB", bytes / 1_048_576.0)
            bytes >= 1_024L -> String.format(Locale.US, "%.1f KB", bytes / 1_024.0)
            else -> "$bytes B"
        }
}
