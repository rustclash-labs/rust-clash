package io.github.rustclashlabs.rustclash.vpn

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Pure-JVM helpers for Android Share Menu / Deep-Link extraction, offline ZXing QR Code
 * decoding & encoding, and defense-in-depth UI secret redaction.
 */
object NodeImportSupport {
    private val SUPPORTED_VIEW_SCHEMES = setOf(
        "ss",
        "vless",
        "anytls",
        "trojan",
        "socks5",
        "socks",
        "http-proxy",
        "https-proxy",
        "clash",
    )

    /**
     * Extracts an importable proxy payload from an Android `ACTION_SEND` or `ACTION_VIEW` intent.
     */
    fun extractImportPayloadFromIntent(
        action: String?,
        mimeType: String?,
        extraText: String?,
        dataUriString: String?,
    ): String? {
        when (action) {
            "android.intent.action.SEND" -> {
                if (mimeType == null || mimeType.startsWith("text/", ignoreCase = true)) {
                    val trimmed = extraText?.trim()
                    if (!trimmed.isNullOrEmpty()) {
                        return trimmed
                    }
                }
            }
            "android.intent.action.VIEW" -> {
                val uri = dataUriString?.trim()
                if (!uri.isNullOrEmpty()) {
                    val scheme = uri.substringBefore("://", missingDelimiterValue = "").lowercase()
                    if (scheme in SUPPORTED_VIEW_SCHEMES) {
                        return uri
                    }
                }
            }
        }
        return null
    }

    /**
     * Decodes a QR Code payload from ARGB_8888 pixels using pure-JVM ZXing (no Google Play Services required).
     * Falls back to inverted luminance so white-on-dark QR codes from dark-mode screens decode reliably.
     */
    fun decodeQrCodeFromArgbPixels(
        argbPixels: IntArray,
        width: Int,
        height: Int,
    ): String? {
        if (width <= 0 || height <= 0 || argbPixels.size < width * height) {
            return null
        }
        val source = RGBLuminanceSource(width, height, argbPixels)
        val inverted = source.invert()
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
            DecodeHintType.TRY_HARDER to java.lang.Boolean.TRUE,
        )
        val reader = MultiFormatReader().apply { setHints(hints) }
        val candidates = listOf(
            BinaryBitmap(HybridBinarizer(source)),
            BinaryBitmap(GlobalHistogramBinarizer(source)),
            BinaryBitmap(HybridBinarizer(inverted)),
            BinaryBitmap(GlobalHistogramBinarizer(inverted)),
        )
        try {
            for (bitmap in candidates) {
                try {
                    val text = reader.decodeWithState(bitmap).text?.trim()
                    if (!text.isNullOrEmpty()) {
                        return text
                    }
                } catch (_: Exception) {
                    reader.reset()
                }
            }
            return null
        } finally {
            reader.reset()
        }
    }

    /**
     * Encodes UTF-8 text into ARGB_8888 QR pixels (`Pair(pixels, dimension)`).
     */
    fun encodeQrCodeToArgbPixels(
        content: String,
        dimension: Int = 256,
    ): Pair<IntArray, Int> {
        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.MARGIN to 1,
        )
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, dimension, dimension, hints)
        val w = matrix.width
        val h = matrix.height
        val pixels = IntArray(w * h)
        for (y in 0 until h) {
            val rowOffset = y * w
            for (x in 0 until w) {
                pixels[rowOffset + x] = if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
            }
        }
        return pixels to w
    }

    private const val SENSITIVE_KEY_PATTERN =
        "(?:[a-z0-9_-]*[_-])?(?:password|passwd|uuid|client_secret|client-secret|secret|" +
            "api_key|apikey|api-key|access_token|access-token|refresh_token|token|" +
            "bearer|auth_str|auth-str|auth|pbk|public-key|public_key|publickey|" +
            "private-key|private_key|privatekey|psk|short-id|short_id|shortid|" +
            "encryption|decryption|sid|signature|sign)"

    private val PROXY_SHARE_SCHEME_REGEX = Regex(
        """(?i)\b(ss|ssr|ssd|vless|vmess|anytls|trojan|socks5|socks5s|socks5h|socks|http-proxy|https-proxy|hysteria2|hy2|hysteria|tuic|wireguard|wg|snell)://[^\s"'`<>\]})]+""",
    )

    private val ESCAPED_DOUBLE_QUOTED_SECRET_REGEX = Regex(
        """(?i)(\\\x22|\b)($SENSITIVE_KEY_PATTERN)(\\\x22)?(\s*[=:]\s*)\\\x22(?:[^\x22\\\r\n]|\\[^\x22\r\n])+\\\x22""",
    )

    private val DOUBLE_QUOTED_SECRET_REGEX = Regex(
        """(?i)(\x22|\b)($SENSITIVE_KEY_PATTERN)(\x22)?(\s*[=:]\s*)\x22(?:[^\x22\\\r\n]|\\.)+\x22""",
    )

    private val SINGLE_QUOTED_SECRET_REGEX = Regex(
        """(?i)('|\b)($SENSITIVE_KEY_PATTERN)(')?(\s*[=:]\s*)'(?:[^'\\\r\n]|\\.|'')+'""",
    )

    private val UNQUOTED_SECRET_REGEX = Regex(
        """(?i)(\x22|\b|')($SENSITIVE_KEY_PATTERN)(\x22|')?(\s*[=:]\s*)(?![\x22']|\\\x22)([^\s,;\x22'`)\]}>\\]+)""",
    )

    enum class ExternalImportKind {
        REMOTE_SUBSCRIPTION,
        PROXY_SHARE_URIS,
        BASE64_SUBSCRIPTION,
        YAML_CONFIG,
        UNKNOWN,
    }

    data class ExternalImportPreview(
        val kind: ExternalImportKind,
        val isRemoteSubscription: Boolean,
        val targetHost: String?,
        val profileDisplayHint: String?,
        val proxyUriCount: Int,
        val protocols: List<String>,
        val sanitizedSummary: String,
        val sanitizedPayloadPreview: String,
        val securityWarning: String?,
    )

    /**
     * Classifies and sanitizes an incoming external `ACTION_VIEW` deep link or `ACTION_SEND` payload
     * so the user can inspect what is being imported (target subscription host, warning about routing/node
     * control, or proxy node count & protocols) before confirming.
     */
    fun classifyExternalImportPreview(rawPayload: String): ExternalImportPreview {
        val trimmed = rawPayload.trim()
        if (trimmed.isEmpty()) {
            return ExternalImportPreview(
                kind = ExternalImportKind.UNKNOWN,
                isRemoteSubscription = false,
                targetHost = null,
                profileDisplayHint = null,
                proxyUriCount = 0,
                protocols = emptyList(),
                sanitizedSummary = "空白导入内容",
                sanitizedPayloadPreview = "",
                securityWarning = null,
            )
        }

        // 1. clash:// deep link (e.g., clash://install-config?url=...&name=...)
        if (trimmed.startsWith("clash://", ignoreCase = true)) {
            val queryPart = trimmed.substringAfter('?', missingDelimiterValue = "")
                .substringBefore('#')
            var embeddedUrl: String? = null
            var nameHint: String? = null
            if (queryPart.isNotEmpty()) {
                for (pair in queryPart.split('&')) {
                    if (pair.isEmpty()) continue
                    val key = urlDecodeSafe(pair.substringBefore('=')).lowercase()
                    val value = urlDecodeSafe(pair.substringAfter('=', missingDelimiterValue = "")).trim()
                    if (value.isEmpty()) continue
                    when (key) {
                        "url", "config", "sub" -> if (embeddedUrl == null) embeddedUrl = value
                        "name", "title", "remarks" -> if (nameHint == null) nameHint = redactSecretsForUi(value).take(64)
                    }
                }
            }
            val host = embeddedUrl?.let(::extractSafeHost)
            val usesCleartext = embeddedUrl?.startsWith("http://", ignoreCase = true) == true
            val safeUrlPreview = if (!embeddedUrl.isNullOrBlank()) {
                redactSecretsForUi(embeddedUrl)
            } else {
                "clash://install-config?***REDACTED***"
            }
            val hostDisplay = host ?: "未知远程主机"
            val cleartextWarn = if (usesCleartext) "该链接使用明文 HTTP，易受中间人篡改！" else ""
            return ExternalImportPreview(
                kind = ExternalImportKind.REMOTE_SUBSCRIPTION,
                isRemoteSubscription = true,
                targetHost = host,
                profileDisplayHint = nameHint,
                proxyUriCount = 0,
                protocols = emptyList(),
                sanitizedSummary = "远程 Clash 订阅链接（目标主机：$hostDisplay）",
                sanitizedPayloadPreview = safeUrlPreview.take(240),
                securityWarning = "${cleartextWarn}远程订阅可下发并控制您的代理节点与分流规则，请仅导入您完全信任的订阅来源（$hostDisplay）。",
            )
        }

        // 2. Direct https:// or http:// subscription URL (single-line external share)
        val nonBlankLines = trimmed.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (nonBlankLines.size == 1 &&
            (trimmed.startsWith("https://", ignoreCase = true) || trimmed.startsWith("http://", ignoreCase = true))
        ) {
            val host = extractSafeHost(trimmed)
            val hostDisplay = host ?: "未知远程主机"
            val usesCleartext = trimmed.startsWith("http://", ignoreCase = true)
            val cleartextWarn = if (usesCleartext) "该链接使用明文 HTTP，易受中间人篡改！" else ""
            return ExternalImportPreview(
                kind = ExternalImportKind.REMOTE_SUBSCRIPTION,
                isRemoteSubscription = true,
                targetHost = host,
                profileDisplayHint = null,
                proxyUriCount = 0,
                protocols = emptyList(),
                sanitizedSummary = "远程订阅地址（目标主机：$hostDisplay）",
                sanitizedPayloadPreview = redactSecretsForUi(trimmed).take(240),
                securityWarning = "${cleartextWarn}远程订阅可下发并控制您的代理节点与分流规则，请仅导入您完全信任的订阅来源（$hostDisplay）。",
            )
        }

        // 3. Direct proxy share URI(s) (`ss://`, `vless://`, `anytls://`, `trojan://`, `socks5://`, etc.)
        val directMatches = PROXY_SHARE_SCHEME_REGEX.findAll(trimmed).toList()
        if (directMatches.isNotEmpty()) {
            val protocols = directMatches
                .map { normalizeProtocolLabel(it.groupValues[1]) }
                .distinct()
            val count = directMatches.size
            val previewLines = directMatches.take(4).map { m ->
                val proto = m.groupValues[1].lowercase()
                val rawFrag = m.value.substringAfter('#', missingDelimiterValue = "")
                val safeFrag = urlDecodeSafe(rawFrag).trim().let(::redactSecretsForUi).take(40)
                if (safeFrag.isNotEmpty()) {
                    "$proto://***REDACTED*** #$safeFrag"
                } else {
                    "$proto://***REDACTED***"
                }
            }
            val moreSuffix = if (count > previewLines.size) "\n… 另有 ${count - previewLines.size} 个节点链接" else ""
            return ExternalImportPreview(
                kind = ExternalImportKind.PROXY_SHARE_URIS,
                isRemoteSubscription = false,
                targetHost = null,
                profileDisplayHint = null,
                proxyUriCount = count,
                protocols = protocols,
                sanitizedSummary = "共 $count 个代理节点分享链接（${protocols.joinToString(" / ")}）",
                sanitizedPayloadPreview = previewLines.joinToString("\n") + moreSuffix,
                securityWarning = "外部应用请求向您的配置中添加代理节点，请确认来源可信后再导入。",
            )
        }

        // 4. Base64-encoded proxy URI list
        val compact = trimmed.filterNot { it.isWhitespace() }
        if (compact.length >= 24 && compact.all { it.isLetterOrDigit() || it in "+/=-_" }) {
            val decoded = decodeBase64Utf8Safe(compact)
            if (decoded != null) {
                val decodedMatches = PROXY_SHARE_SCHEME_REGEX.findAll(decoded).toList()
                if (decodedMatches.isNotEmpty()) {
                    val protocols = decodedMatches
                        .map { normalizeProtocolLabel(it.groupValues[1]) }
                        .distinct()
                    val count = decodedMatches.size
                    val previewLines = decodedMatches.take(4).map { "${it.groupValues[1].lowercase()}://***REDACTED***" }
                    val moreSuffix = if (count > previewLines.size) "\n… 另有 ${count - previewLines.size} 个节点链接" else ""
                    return ExternalImportPreview(
                        kind = ExternalImportKind.BASE64_SUBSCRIPTION,
                        isRemoteSubscription = false,
                        targetHost = null,
                        profileDisplayHint = null,
                        proxyUriCount = count,
                        protocols = protocols,
                        sanitizedSummary = "Base64 节点列表：共 $count 个代理节点（${protocols.joinToString(" / ")}）",
                        sanitizedPayloadPreview = previewLines.joinToString("\n") + moreSuffix,
                        securityWarning = "外部应用请求批量导入 Base64 编码节点，密钥已脱敏隐藏，请确认来源可信后再导入。",
                    )
                }
            }
        }

        // 5. Clash YAML configuration snippet / document
        if (nonBlankLines.any {
                it.startsWith("proxies:") ||
                    it.startsWith("proxy-groups:") ||
                    it.startsWith("rules:") ||
                    it.startsWith("mixed-port:")
            }
        ) {
            val hasRules = nonBlankLines.any { it.startsWith("rules:") }
            val safeLines = nonBlankLines.take(5).joinToString("\n") { redactSecretsForUi(it) }
            return ExternalImportPreview(
                kind = ExternalImportKind.YAML_CONFIG,
                isRemoteSubscription = false,
                targetHost = null,
                profileDisplayHint = null,
                proxyUriCount = 0,
                protocols = emptyList(),
                sanitizedSummary = if (hasRules) "YAML 配置文件（含代理节点与分流规则）" else "YAML 节点配置片段",
                sanitizedPayloadPreview = safeLines.take(260),
                securityWarning = "YAML 配置文件可同时修改代理节点与分流规则，请确认来源可信后再导入。",
            )
        }

        // 6. Fallback unknown text: redact secrets and mask opaque single-token blobs
        val redacted = redactSecretsForUi(trimmed)
        val safePreview = if (!redacted.contains(' ') && !redacted.contains('\n') && redacted.length > 24 && !redacted.contains("***REDACTED***")) {
            redacted.take(10) + "…***REDACTED***"
        } else {
            redacted.take(200)
        }
        return ExternalImportPreview(
            kind = ExternalImportKind.UNKNOWN,
            isRemoteSubscription = false,
            targetHost = null,
            profileDisplayHint = null,
            proxyUriCount = 0,
            protocols = emptyList(),
            sanitizedSummary = "外部导入文本内容",
            sanitizedPayloadPreview = safePreview,
            securityWarning = "请确认该外部导入内容来源可信后再继续。",
        )
    }

    /**
     * Scrubs proxy credentials, UUIDs, Reality PBKs, PQ keys, quoted/unquoted YAML & JSON secrets,
     * and subscription URL paths/query tokens from UI & debug strings.
     */
    fun redactSecretsForUi(raw: String): String {
        var out = raw
        // Redact proxy share URIs (including Trojan, SOCKS5, HTTP-Proxy, VMess, Hysteria2, TUIC, WireGuard)
        out = Regex("""(?i)\b(ss|ssr|ssd|vless|vmess|anytls|trojan|socks5|socks5s|socks5h|socks|http-proxy|https-proxy|hysteria2|hy2|hysteria|tuic|wireguard|wg|snell|clash)://[^\s"'`<>\]})]*""")
            .replace(out) { m -> "${m.groupValues[1].lowercase()}://***REDACTED***" }
        // Redact HTTP(S) subscription URLs: scrub userinfo, query/fragment tokens, and secret path segments
        out = Regex("""(?i)\b(https?)://([^\s/"'`<>@]+@)?([^\s/?#"'>`\])}]+)(/[^\s?#"'>`\])}]*)?(\?[^\s"'<>`\])}]*)?(#[^\s"'<>`\])}]*)?""")
            .replace(out) { m ->
                val scheme = m.groupValues[1].lowercase()
                val hasUserInfo = m.groupValues[2].isNotEmpty()
                val hostPort = m.groupValues[3]
                val safePath = sanitizeHttpUrlPath(m.groupValues[4])
                val hasQuery = m.groupValues[5].isNotEmpty()
                val hasFragment = m.groupValues[6].isNotEmpty()
                val authPrefix = if (hasUserInfo) "***REDACTED***@" else ""
                if (hasQuery || hasFragment) {
                    "$scheme://$authPrefix$hostPort$safePath?***REDACTED***"
                } else {
                    "$scheme://$authPrefix$hostPort$safePath"
                }
            }
        // Redact Xray/VLESS post-quantum key specs
        out = Regex("""mlkem768x25519plus\.[^\s"'`&#)\]}>]+""")
            .replace(out, "mlkem768x25519plus.***REDACTED***")
        // Redact escaped double-quoted, double-quoted, single-quoted, and unquoted key=value / key: value secrets
        out = ESCAPED_DOUBLE_QUOTED_SECRET_REGEX.replace(out) { m ->
            "${m.groupValues[1]}${m.groupValues[2]}${m.groupValues[3]}${m.groupValues[4]}\\\"***REDACTED***\\\""
        }
        out = DOUBLE_QUOTED_SECRET_REGEX.replace(out) { m ->
            "${m.groupValues[1]}${m.groupValues[2]}${m.groupValues[3]}${m.groupValues[4]}\"***REDACTED***\""
        }
        out = SINGLE_QUOTED_SECRET_REGEX.replace(out) { m ->
            "${m.groupValues[1]}${m.groupValues[2]}${m.groupValues[3]}${m.groupValues[4]}'***REDACTED***'"
        }
        out = UNQUOTED_SECRET_REGEX.replace(out) { m ->
            "${m.groupValues[1]}${m.groupValues[2]}${m.groupValues[3]}${m.groupValues[4]}***REDACTED***"
        }
        // Redact standalone non-nil UUIDs
        out = Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")
            .replace(out) { m ->
                if (m.value == "00000000-0000-0000-0000-000000000000") m.value else "***REDACTED***"
            }
        return out
    }

    private fun extractSafeHost(rawUrl: String): String? {
        val candidate = rawUrl.trim()
        runCatching {
            val parsed = java.net.URI(candidate)
            val h = parsed.host?.trim()?.lowercase()
            if (!h.isNullOrEmpty()) {
                val p = parsed.port
                return if (p > 0 && p != 80 && p != 443) "$h:$p" else h
            }
        }
        val m = Regex("""(?i)^[a-z][a-z0-9+.-]*://(?:[^\s/"'`<>@]+@)?([^\s/?#"'>`\])}]+)""").find(candidate)
        return m?.groupValues?.getOrNull(1)?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
    }

    private fun urlDecodeSafe(raw: String): String =
        runCatching { java.net.URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)

    private fun decodeBase64Utf8Safe(compact: String): String? = runCatching {
        val normalized = compact.replace('-', '+').replace('_', '/')
        val padLen = (4 - normalized.length % 4) % 4
        val padded = normalized + "=".repeat(padLen)
        String(java.util.Base64.getDecoder().decode(padded), Charsets.UTF_8)
    }.getOrNull()

    private fun normalizeProtocolLabel(rawScheme: String): String =
        when (rawScheme.lowercase()) {
            "ss", "ssr", "ssd" -> "Shadowsocks"
            "vless" -> "VLESS"
            "vmess" -> "VMess"
            "anytls" -> "AnyTLS"
            "trojan" -> "Trojan"
            "socks5", "socks5s", "socks5h", "socks" -> "SOCKS5"
            "http-proxy", "https-proxy" -> "HTTP"
            "hysteria2", "hy2", "hysteria" -> "Hysteria2"
            "tuic" -> "TUIC"
            "wireguard", "wg" -> "WireGuard"
            else -> rawScheme.uppercase()
        }

    private val SECRET_PATH_PREFIX_SEGMENTS = setOf("s", "sub", "subs", "link", "token", "raw", "d")

    private fun sanitizeHttpUrlPath(path: String): String {
        if (path.isEmpty() || path == "/") return path
        val segments = path.removePrefix("/").split('/')
        var prevLower = ""
        val sanitized = segments.map { seg ->
            if (seg.isEmpty()) {
                prevLower = ""
                ""
            } else {
                val base = seg.substringBefore('.')
                val isBenignKnown = base.equals("generate_204", ignoreCase = true)
                val looksLikeToken = !isBenignKnown && (
                    (prevLower in SECRET_PATH_PREFIX_SEGMENTS && base.length >= 6) ||
                        base.length >= 20 ||
                        (base.length >= 16 && base.any { it.isDigit() || it.isUpperCase() }) ||
                        seg.contains('=') ||
                        seg.contains('@')
                    )
                prevLower = seg.lowercase()
                if (looksLikeToken) "***REDACTED***" else seg
            }
        }
        return "/" + sanitized.joinToString("/")
    }
}
