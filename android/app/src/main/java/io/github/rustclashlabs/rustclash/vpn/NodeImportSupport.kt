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

    /**
     * Scrubs proxy credentials, UUIDs, Reality PBKs, PQ keys, and subscription URL paths/query tokens from UI & debug strings.
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
        // Redact sensitive key=value or key: value pairs
        out = Regex("""(?i)\b(password|passwd|uuid|secret|api_key|apikey|token|access_token|auth|auth_str|auth-str|pbk|public-key|public_key|publickey|private-key|private_key|psk|encryption|decryption|sid|signature|sign)\s*([=:])\s*([^\s,;"'`)\]}>]+)""")
            .replace(out) { m -> "${m.groupValues[1]}${m.groupValues[2]}***REDACTED***" }
        // Redact standalone non-nil UUIDs
        out = Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")
            .replace(out) { m ->
                if (m.value == "00000000-0000-0000-0000-000000000000") m.value else "***REDACTED***"
            }
        return out
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
