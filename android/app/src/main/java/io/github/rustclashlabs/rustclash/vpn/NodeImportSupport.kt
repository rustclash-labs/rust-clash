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
     * Scrubs proxy credentials, UUIDs, Reality PBKs, and subscription URL query tokens from UI strings.
     */
    fun redactSecretsForUi(raw: String): String {
        var out = raw
        // Redact proxy share URIs (including Trojan, SOCKS5, HTTP-Proxy)
        out = Regex("""(?i)\b(ss|vless|anytls|trojan|socks5|socks|http-proxy|https-proxy|clash)://[^\s"'<>]*""")
            .replace(out) { m -> "${m.groupValues[1].lowercase()}://***REDACTED***" }
        // Redact HTTP(S) query strings and userinfo
        out = Regex("""(?i)\b(https?)://([^\s/"'<>@]+@)?([^\s?#"'>]+)(\?[^\s"'<>]*)?""")
            .replace(out) { m ->
                val scheme = m.groupValues[1].lowercase()
                val hasUserInfo = m.groupValues[2].isNotEmpty()
                val hostPath = m.groupValues[3]
                val hasQuery = m.groupValues[4].isNotEmpty()
                val authPrefix = if (hasUserInfo) "***REDACTED***@" else ""
                if (hasQuery) "$scheme://$authPrefix$hostPath?***REDACTED***" else "$scheme://$authPrefix$hostPath"
            }
        // Redact sensitive key=value or key: value pairs
        out = Regex("""(?i)\b(password|passwd|uuid|secret|token|auth|pbk|public-key|encryption|decryption)\s*([=:])\s*([^\s,;"')\]}]+)""")
            .replace(out) { m -> "${m.groupValues[1]}${m.groupValues[2]}***REDACTED***" }
        return out
    }
}
