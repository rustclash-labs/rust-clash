package io.github.rustclashlabs.rustclash.ui.theme

import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.unit.dp
import java.util.Locale
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * Returns a short Chinese landmark caption matching the vector skyline drawn by
 * [ExitCountryLandmarkCanvas] for an ISO-3166 alpha-2 region code.
 */
fun landmarkCaptionFor(countryCode: String): String = when (countryCode.trim().uppercase(Locale.ROOT)) {
    "SG" -> "滨海湾金沙 · 摩天轮"
    "HK" -> "维多利亚港 · 中银与 IFC"
    "MO" -> "大三巴 · 澳门旅游塔"
    "JP" -> "富士山 · 东京塔"
    "TW" -> "台北 101 · 信义天际线"
    "US" -> "金门大桥 · 湾区剪影"
    "GB" -> "大本钟 · 伦敦眼"
    "KR" -> "N 首尔塔 · 乐天大厦"
    "FR" -> "埃菲尔铁塔 · 塞纳河"
    "DE" -> "法兰克福 · 勃兰登堡门"
    "NL" -> "阿姆斯特丹运河 · 风车"
    "AU" -> "悉尼歌剧院 · 海港大桥"
    "CA" -> "多伦多 CN 塔 · 安大略湖"
    "CN" -> "陆家嘴 · 东方明珠"
    else -> "加密出口 · 全球节点"
}

private data class LandmarkPalette(
    val skyGlow: Color,
    val mistFar: Color,
    val layerMid: Color,
    val layerMain: Color,
    val layerAccent: Color,
    val highlight: Color,
    val cutout: Color,
    val waterTop: Color,
    val waterRipple: Color,
)

private fun buildLandmarkPalette(
    extColors: RustClashExtendedColors,
    isConnected: Boolean,
): LandmarkPalette {
    val activeFactor = if (isConnected) 1f else 0.62f
    return if (extColors.isDark) {
        val base = extColors.emeraldBright
        LandmarkPalette(
            skyGlow = extColors.emerald.copy(alpha = 0.16f * activeFactor),
            mistFar = base.copy(alpha = 0.08f * activeFactor),
            layerMid = base.copy(alpha = 0.17f * activeFactor),
            layerMain = base.copy(alpha = 0.30f * activeFactor),
            layerAccent = base.copy(alpha = 0.44f * activeFactor),
            highlight = Color(0xFFA7F3D0).copy(alpha = 0.32f * activeFactor),
            cutout = extColors.cardSurface.copy(alpha = 0.72f),
            waterTop = base.copy(alpha = 0.14f * activeFactor),
            waterRipple = Color(0xFFA7F3D0).copy(alpha = 0.16f * activeFactor),
        )
    } else {
        val base = extColors.emerald
        LandmarkPalette(
            skyGlow = Color(0xFF10B981).copy(alpha = 0.13f * activeFactor),
            mistFar = base.copy(alpha = 0.07f * activeFactor),
            layerMid = base.copy(alpha = 0.16f * activeFactor),
            layerMain = base.copy(alpha = 0.28f * activeFactor),
            layerAccent = base.copy(alpha = 0.42f * activeFactor),
            highlight = Color.White.copy(alpha = 0.68f),
            cutout = Color.White.copy(alpha = 0.72f),
            waterTop = base.copy(alpha = 0.12f * activeFactor),
            waterRipple = Color.White.copy(alpha = 0.58f),
        )
    }
}

/**
 * Pure Jetpack Compose vector skyline illustration for the Home Exit IP showcase card.
 * Draws layered mint-emerald architectural silhouettes with mirrored waterfront reflections
 * and smoothly crossfades whenever the detected exit country changes.
 */
@Composable
fun ExitCountryLandmarkCanvas(
    countryCode: String,
    isConnected: Boolean,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    val normalizedCode = countryCode.trim().uppercase(Locale.ROOT)
    val palette = buildLandmarkPalette(extColors = extColors, isConnected = isConnected)

    Crossfade(
        targetState = normalizedCode,
        animationSpec = tween(durationMillis = 360),
        modifier = modifier,
        label = "exitLandmarkCrossfade",
    ) { code ->
        Canvas(modifier = Modifier.fillMaxSize()) {
            if (size.width <= 1f || size.height <= 1f) return@Canvas
            val waterlineY = size.height * 0.78f

            // Soft atmospheric sky wash behind the skyline
            drawSkyAtmosphere(palette = palette, waterlineY = waterlineY)

            val drawScene: DrawScope.(LandmarkPalette, Float) -> Unit = when (code) {
                "SG" -> { p, wy -> drawSingaporeSkyline(p, wy) }
                "HK" -> { p, wy -> drawHongKongSkyline(p, wy) }
                "JP" -> { p, wy -> drawJapanSkyline(p, wy) }
                "TW" -> { p, wy -> drawTaiwanSkyline(p, wy) }
                "US" -> { p, wy -> drawUsaSkyline(p, wy) }
                "GB" -> { p, wy -> drawUkSkyline(p, wy) }
                "KR" -> { p, wy -> drawKoreaSkyline(p, wy) }
                "FR" -> { p, wy -> drawFranceSkyline(p, wy) }
                "DE" -> { p, wy -> drawGermanySkyline(p, wy) }
                "NL" -> { p, wy -> drawNetherlandsSkyline(p, wy) }
                "AU" -> { p, wy -> drawAustraliaSkyline(p, wy) }
                "CA" -> { p, wy -> drawCanadaSkyline(p, wy) }
                "CN" -> { p, wy -> drawChinaSkyline(p, wy) }
                else -> { p, wy -> drawGlobalHorizon(p, wy) }
            }

            if (code in setOf("SG", "HK", "JP", "TW", "US", "GB", "KR", "FR", "DE", "NL", "AU", "CA", "CN")) {
                // 1. Primary skyline above the waterline
                clipRect(left = 0f, top = 0f, right = size.width, bottom = waterlineY + 1f) {
                    drawScene(palette, waterlineY)
                }

                // 2. Waterfront mirror reflection below the waterline
                val reflectionPalette = palette.copy(
                    mistFar = palette.mistFar.copy(alpha = palette.mistFar.alpha * 0.45f),
                    layerMid = palette.layerMid.copy(alpha = palette.layerMid.alpha * 0.55f),
                    layerMain = palette.layerMain.copy(alpha = palette.layerMain.alpha * 0.52f),
                    layerAccent = palette.layerAccent.copy(alpha = palette.layerAccent.alpha * 0.45f),
                    highlight = palette.highlight.copy(alpha = palette.highlight.alpha * 0.35f),
                )
                clipRect(left = 0f, top = waterlineY, right = size.width, bottom = size.height) {
                    drawRect(
                        brush = Brush.verticalGradient(
                            colors = listOf(palette.waterTop, Color.Transparent),
                            startY = waterlineY,
                            endY = size.height,
                        ),
                        topLeft = Offset(0f, waterlineY),
                        size = Size(size.width, size.height - waterlineY),
                    )
                    withTransform({
                        scale(scaleX = 1f, scaleY = -0.38f, pivot = Offset(0f, waterlineY))
                    }) {
                        drawScene(reflectionPalette, waterlineY)
                    }
                    // Gentle horizontal shimmer ripples across the mirrored water
                    drawWaterRipples(palette = palette, waterlineY = waterlineY)
                }

                // Crisp promenade shoreline
                drawLine(
                    color = palette.layerMid,
                    start = Offset(0f, waterlineY),
                    end = Offset(size.width, waterlineY),
                    strokeWidth = 0.9.dp.toPx(),
                )
            } else {
                drawScene(palette, waterlineY)
            }
        }
    }
}

private fun DrawScope.drawSkyAtmosphere(palette: LandmarkPalette, waterlineY: Float) {
    val w = size.width
    val h = size.height
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(palette.skyGlow, Color.Transparent),
            center = Offset(w * 0.50f, waterlineY * 0.72f),
            radius = maxOf(w * 0.58f, h * 1.1f),
        ),
        radius = maxOf(w * 0.58f, h * 1.1f),
        center = Offset(w * 0.50f, waterlineY * 0.72f),
    )
    // Soft low mist bank behind horizon
    val mist = Path().apply {
        moveTo(0f, waterlineY)
        lineTo(0f, waterlineY * 0.78f)
        cubicTo(
            w * 0.22f, waterlineY * 0.52f,
            w * 0.42f, waterlineY * 0.74f,
            w * 0.62f, waterlineY * 0.60f,
        )
        cubicTo(
            w * 0.78f, waterlineY * 0.48f,
            w * 0.90f, waterlineY * 0.68f,
            w, waterlineY * 0.62f,
        )
        lineTo(w, waterlineY)
        close()
    }
    drawPath(mist, color = palette.mistFar)
}

private fun DrawScope.drawWaterRipples(palette: LandmarkPalette, waterlineY: Float) {
    val w = size.width
    val waterH = (size.height - waterlineY).coerceAtLeast(1f)
    val strokeW = 1.dp.toPx()
    val bands = listOf(
        Triple(0.08f, 0.28f, 0.22f),
        Triple(0.32f, 0.66f, 0.26f),
        Triple(0.74f, 0.94f, 0.24f),
        Triple(0.18f, 0.46f, 0.54f),
        Triple(0.52f, 0.80f, 0.58f),
        Triple(0.36f, 0.62f, 0.80f),
    )
    bands.forEach { (x1, x2, yFrac) ->
        val y = waterlineY + waterH * yFrac
        drawLine(
            color = palette.waterRipple,
            start = Offset(w * x1, y),
            end = Offset(w * x2, y),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
        )
    }
}

/**
 * Singapore Marina Bay Panorama:
 * - Distant CBD towers & waterfront greenery
 * - Sculpted 7-petal ArtScience Museum lotus (left)
 * - Marina Bay Sands with 3 twin-leg A-frame curved towers, subtle architectural louver lines,
 *   cantilevered SkyPark hull deck & miniature rooftop palms (center hero)
 * - 28-capsule Singapore Flyer with 16 fine tensile spokes & A-frame base (right)
 */
private fun DrawScope.drawSingaporeSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    // 1. Distant CBD skyline silhouettes (left & right-center framing)
    val bgTowers = listOf(
        Triple(0.030f, 0.032f, 0.36f),
        Triple(0.068f, 0.036f, 0.48f),
        Triple(0.110f, 0.026f, 0.30f),
        Triple(0.675f, 0.032f, 0.38f),
        Triple(0.713f, 0.026f, 0.28f),
    )
    bgTowers.forEach { (xFrac, wFrac, hFrac) ->
        val tw = w * wFrac
        val th = h * hFrac
        drawRoundRect(
            color = p.mistFar.copy(alpha = (p.mistFar.alpha * 1.6f).coerceAtMost(0.24f)),
            topLeft = Offset(w * xFrac, wy - th),
            size = Size(tw, th),
            cornerRadius = CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()),
        )
    }

    // 2. ArtScience Museum — blooming 7-petal lotus sculpture (left foreground)
    val lotusCx = w * 0.195f
    val lotusBaseY = wy
    val lotusScale = minOf(w * 0.088f, h * 0.42f)

    // Back petals (softer layerMid for depth)
    val backPetalAngles = listOf(-56f, -20f, 22f, 58f)
    backPetalAngles.forEach { deg ->
        val rad = deg * PI / 180.0
        val tipX = lotusCx + (sin(rad) * lotusScale * 1.04f).toFloat()
        val tipY = lotusBaseY - lotusScale * 0.26f - (cos(rad) * lotusScale * 0.86f).toFloat()
        val spread = lotusScale * 0.22f
        val perpX = (cos(rad) * spread).toFloat()
        val perpY = (sin(rad) * spread).toFloat()
        val petal = Path().apply {
            moveTo(lotusCx - lotusScale * 0.18f, lotusBaseY - lotusScale * 0.16f)
            quadraticTo(
                (lotusCx + tipX) * 0.5f - perpX,
                (lotusBaseY + tipY) * 0.5f - perpY,
                tipX,
                tipY,
            )
            quadraticTo(
                (lotusCx + tipX) * 0.5f + perpX,
                (lotusBaseY + tipY) * 0.5f + perpY,
                lotusCx + lotusScale * 0.18f,
                lotusBaseY - lotusScale * 0.16f,
            )
            close()
        }
        drawPath(petal, color = p.layerMid)
    }
    // Front sculpted petals (layerMain + crisp highlight rim)
    val frontPetalAngles = listOf(-40f, 0f, 40f)
    frontPetalAngles.forEach { deg ->
        val rad = deg * PI / 180.0
        val tipX = lotusCx + (sin(rad) * lotusScale * 0.96f).toFloat()
        val tipY = lotusBaseY - lotusScale * 0.24f - (cos(rad) * lotusScale * 0.92f).toFloat()
        val spread = lotusScale * 0.24f
        val perpX = (cos(rad) * spread).toFloat()
        val perpY = (sin(rad) * spread).toFloat()
        val petal = Path().apply {
            moveTo(lotusCx - lotusScale * 0.20f, lotusBaseY - lotusScale * 0.12f)
            quadraticTo(
                (lotusCx + tipX) * 0.5f - perpX,
                (lotusBaseY + tipY) * 0.5f - perpY,
                tipX,
                tipY,
            )
            quadraticTo(
                (lotusCx + tipX) * 0.5f + perpX,
                (lotusBaseY + tipY) * 0.5f + perpY,
                lotusCx + lotusScale * 0.20f,
                lotusBaseY - lotusScale * 0.12f,
            )
            close()
        }
        drawPath(petal, color = p.layerMain)
        drawPath(
            petal,
            color = p.highlight,
            style = Stroke(width = 0.7.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round),
        )
    }
    // Lotus podium base
    val lotusBase = Path().apply {
        moveTo(lotusCx - lotusScale * 0.42f, wy)
        lineTo(lotusCx - lotusScale * 0.30f, wy - lotusScale * 0.20f)
        lineTo(lotusCx + lotusScale * 0.30f, wy - lotusScale * 0.20f)
        lineTo(lotusCx + lotusScale * 0.42f, wy)
        close()
    }
    drawPath(lotusBase, color = p.layerAccent)

    // 3. Marina Bay Sands — 3 Twin-Leg Curved A-Frame Towers (center hero)
    val towerCenters = listOf(0.375f, 0.485f, 0.595f)
    val towerTopY = h * 0.27f
    val towerH = wy - towerTopY
    val towerBrush = Brush.verticalGradient(
        colors = listOf(p.layerAccent, p.layerMain),
        startY = towerTopY,
        endY = wy,
    )

    towerCenters.forEach { cxFrac ->
        val cx = w * cxFrac
        val topHalfW = w * 0.025f
        val botOuterLeft = cx - w * 0.044f
        val botOuterRight = cx + w * 0.036f

        // Curved asymmetric A-frame tower silhouette
        val towerPath = Path().apply {
            moveTo(botOuterLeft, wy)
            // Left iconic sweeping curved leg
            quadraticTo(
                cx - w * 0.030f,
                towerTopY + towerH * 0.46f,
                cx - topHalfW,
                towerTopY,
            )
            lineTo(cx + topHalfW, towerTopY)
            // Right gently sloping leg
            quadraticTo(
                cx + w * 0.032f,
                towerTopY + towerH * 0.52f,
                botOuterRight,
                wy,
            )
            close()
        }
        drawPath(towerPath, brush = towerBrush)

        // Central recessed atrium gap (signature twin-slab architecture)
        val atriumPath = Path().apply {
            moveTo(cx - w * 0.008f, wy)
            quadraticTo(cx - w * 0.003f, towerTopY + towerH * 0.54f, cx, towerTopY + towerH * 0.34f)
            quadraticTo(cx + w * 0.005f, towerTopY + towerH * 0.56f, cx + w * 0.009f, wy)
            close()
        }
        drawPath(atriumPath, color = p.cutout)

        // Delicate architectural horizontal louver bands
        val louverStroke = 0.65.dp.toPx()
        for (floor in 1..6) {
            val t = floor / 7.5f
            val y = towerTopY + towerH * t
            val leftX = (cx - topHalfW) + (botOuterLeft - (cx - topHalfW)) * t * 0.86f
            val rightX = (cx + topHalfW) + (botOuterRight - (cx + topHalfW)) * t * 0.86f
            drawLine(
                color = p.highlight.copy(alpha = p.highlight.alpha * 0.52f),
                start = Offset(leftX + 1.dp.toPx(), y),
                end = Offset(rightX - 1.dp.toPx(), y),
                strokeWidth = louverStroke,
            )
        }
    }

    // Sands SkyPark cantilevered cruise-ship roof deck (dramatic overhang on the left!)
    val deckLeftX = w * 0.275f
    val deckRightX = w * 0.652f
    val deckTopY = h * 0.175f
    val deckMidY = h * 0.255f
    val deckBotY = h * 0.285f

    val skyParkHull = Path().apply {
        moveTo(deckLeftX, deckTopY + h * 0.025f)
        // Gently curved upper infinity-pool deck
        cubicTo(
            w * 0.38f, deckTopY - h * 0.015f,
            w * 0.54f, deckTopY - h * 0.010f,
            deckRightX, deckTopY + h * 0.032f,
        )
        // Stern taper down to Tower 3 top
        lineTo(deckRightX - w * 0.012f, deckBotY)
        // Flat structural belly across all 3 towers
        lineTo(w * 0.348f, deckBotY)
        // Sweeping cantilevered prow curve on the left
        quadraticTo(w * 0.305f, deckMidY, deckLeftX, deckTopY + h * 0.025f)
        close()
    }
    drawPath(
        skyParkHull,
        brush = Brush.verticalGradient(
            colors = listOf(p.layerAccent, p.layerMain),
            startY = deckTopY,
            endY = deckBotY,
        ),
    )
    // Bright crisp top rim of SkyPark
    val deckRim = Path().apply {
        moveTo(deckLeftX + 1.dp.toPx(), deckTopY + h * 0.025f)
        cubicTo(
            w * 0.38f, deckTopY - h * 0.015f,
            w * 0.54f, deckTopY - h * 0.010f,
            deckRightX - 1.dp.toPx(), deckTopY + h * 0.032f,
        )
    }
    drawPath(deckRim, color = p.highlight, style = Stroke(width = 1.dp.toPx(), cap = StrokeCap.Round))

    // Subtle SkyPark rooftop greenery clusters tucked neatly along the infinity deck
    val canopyClusters = listOf(
        Triple(0.365f, 0.018f, 0.022f),
        Triple(0.392f, 0.022f, 0.028f),
        Triple(0.458f, 0.020f, 0.024f),
        Triple(0.486f, 0.024f, 0.030f),
        Triple(0.556f, 0.020f, 0.025f),
        Triple(0.582f, 0.017f, 0.020f),
    )
    canopyClusters.forEach { (xFrac, rxFrac, ryFrac) ->
        val cxPalm = w * xFrac
        val baseY = deckTopY + h * 0.012f
        val rx = w * rxFrac
        val ry = h * ryFrac
        val tuft = Path().apply {
            moveTo(cxPalm - rx, baseY)
            quadraticTo(cxPalm - rx * 0.45f, baseY - ry * 1.15f, cxPalm, baseY - ry * 0.85f)
            quadraticTo(cxPalm + rx * 0.45f, baseY - ry * 1.15f, cxPalm + rx, baseY)
            close()
        }
        drawPath(tuft, color = p.layerMain)
    }

    // 4. Singapore Flyer — high-precision Ferris wheel with 28 capsules & 16 fine spokes (right)
    val wheelCx = w * 0.845f
    val wheelR = minOf(h * 0.32f, w * 0.095f)
    val wheelCy = wy - wheelR * 1.24f

    // Terminal building at Flyer base
    drawRoundRect(
        color = p.layerMid,
        topLeft = Offset(wheelCx - wheelR * 0.72f, wy - h * 0.11f),
        size = Size(wheelR * 1.44f, h * 0.11f),
        cornerRadius = CornerRadius(2.dp.toPx(), 2.dp.toPx()),
    )

    // 16 fine radial cable spokes
    val spokeStroke = 0.65.dp.toPx()
    val spokeCount = 16
    for (i in 0 until spokeCount) {
        val angle = (2.0 * PI * i) / spokeCount
        val endX = wheelCx + (cos(angle) * wheelR * 0.96f).toFloat()
        val endY = wheelCy + (sin(angle) * wheelR * 0.96f).toFloat()
        drawLine(
            color = p.layerMid,
            start = Offset(wheelCx, wheelCy),
            end = Offset(endX, endY),
            strokeWidth = spokeStroke,
        )
    }

    // Outer & inner concentric wheel rims
    drawCircle(
        color = p.layerAccent,
        radius = wheelR,
        center = Offset(wheelCx, wheelCy),
        style = Stroke(width = 1.6.dp.toPx()),
    )
    drawCircle(
        color = p.layerMain,
        radius = wheelR * 0.84f,
        center = Offset(wheelCx, wheelCy),
        style = Stroke(width = 0.85.dp.toPx()),
    )

    // 28 observation capsules orbiting the outer rim
    val capsuleCount = 28
    val capsuleRadius = maxOf(1.1.dp.toPx(), wheelR * 0.048f)
    for (i in 0 until capsuleCount) {
        val angle = (2.0 * PI * i) / capsuleCount
        val cxPod = wheelCx + (cos(angle) * (wheelR + capsuleRadius * 0.9f)).toFloat()
        val cyPod = wheelCy + (sin(angle) * (wheelR + capsuleRadius * 0.9f)).toFloat()
        drawCircle(
            color = p.layerAccent,
            radius = capsuleRadius,
            center = Offset(cxPod, cyPod),
        )
    }

    // Tapered A-frame support legs + central hub
    val legStroke = 1.8.dp.toPx()
    drawLine(
        color = p.layerAccent,
        start = Offset(wheelCx - wheelR * 0.44f, wy),
        end = Offset(wheelCx, wheelCy),
        strokeWidth = legStroke,
        cap = StrokeCap.Round,
    )
    drawLine(
        color = p.layerAccent,
        start = Offset(wheelCx + wheelR * 0.44f, wy),
        end = Offset(wheelCx, wheelCy),
        strokeWidth = legStroke,
        cap = StrokeCap.Round,
    )
    drawCircle(
        color = p.layerAccent,
        radius = wheelR * 0.14f,
        center = Offset(wheelCx, wheelCy),
    )
    drawCircle(
        color = p.highlight,
        radius = wheelR * 0.06f,
        center = Offset(wheelCx, wheelCy),
    )

    // 5. Subtle waterfront promenade foliage clusters on far left & far right
    val foliage = listOf(
        Triple(0.055f, 0.045f, 0.040f),
        Triple(0.095f, 0.036f, 0.032f),
        Triple(0.285f, 0.030f, 0.026f),
        Triple(0.725f, 0.038f, 0.032f),
        Triple(0.945f, 0.044f, 0.038f),
    )
    foliage.forEach { (xFrac, rxFrac, ryFrac) ->
        drawOval(
            color = p.layerMid,
            topLeft = Offset(w * (xFrac - rxFrac), wy - h * ryFrac * 1.4f),
            size = Size(w * rxFrac * 2f, h * ryFrac * 2f),
        )
    }
}

/**
 * Hong Kong Victoria Harbour:
 * Victoria Peak misty backdrop + Two IFC tapered crown + Bank of China geometric glass prisms
 * with signature white diagonal bracing + HKCEC sweeping curved wing.
 */
private fun DrawScope.drawHongKongSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    // Victoria Peak mountain ridge
    val peak = Path().apply {
        moveTo(0f, wy)
        cubicTo(w * 0.18f, h * 0.34f, w * 0.36f, h * 0.44f, w * 0.56f, h * 0.62f)
        cubicTo(w * 0.72f, h * 0.74f, w * 0.86f, h * 0.44f, w, h * 0.50f)
        lineTo(w, wy)
        close()
    }
    drawPath(peak, color = p.mistFar)

    // Framing skyscrapers
    val sideBuildings = listOf(
        Triple(0.07f, 0.048f, 0.42f),
        Triple(0.13f, 0.056f, 0.56f),
        Triple(0.20f, 0.042f, 0.38f),
        Triple(0.73f, 0.052f, 0.46f),
        Triple(0.80f, 0.046f, 0.34f),
        Triple(0.86f, 0.058f, 0.54f),
    )
    sideBuildings.forEach { (x, bw, bh) ->
        drawRoundRect(
            color = p.layerMid,
            topLeft = Offset(w * x, wy - h * bh),
            size = Size(w * bw, h * bh),
            cornerRadius = CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()),
        )
    }

    // Two IFC (left-center hero)
    val ifcL = w * 0.285f
    val ifcR = w * 0.362f
    val ifcTop = h * 0.18f
    val ifc = Path().apply {
        moveTo(ifcL, wy)
        lineTo(ifcL, ifcTop + h * 0.07f)
        lineTo(ifcL + (ifcR - ifcL) * 0.18f, ifcTop)
        lineTo(ifcR - (ifcR - ifcL) * 0.18f, ifcTop)
        lineTo(ifcR, ifcTop + h * 0.07f)
        lineTo(ifcR, wy)
        close()
    }
    drawPath(ifc, color = p.layerMain)
    val ifcW = ifcR - ifcL
    for (i in 1..3) {
        val x = ifcL + ifcW * (i / 4f)
        drawLine(
            color = p.highlight.copy(alpha = p.highlight.alpha * 0.55f),
            start = Offset(x, ifcTop + h * 0.04f),
            end = Offset(x, wy),
            strokeWidth = 0.75.dp.toPx(),
        )
    }

    // Bank of China Tower (center hero: asymmetric diagonal glass prisms + twin spires)
    val bocL = w * 0.465f
    val bocR = w * 0.565f
    val bocMid = (bocL + bocR) * 0.5f
    val boc = Path().apply {
        moveTo(bocL, wy)
        lineTo(bocL, h * 0.30f)
        lineTo(bocMid, h * 0.22f)
        lineTo(bocR, h * 0.12f)
        lineTo(bocR, wy)
        close()
    }
    drawPath(
        boc,
        brush = Brush.verticalGradient(
            colors = listOf(p.layerAccent, p.layerMain),
            startY = h * 0.12f,
            endY = wy,
        ),
    )
    // Twin spires
    drawLine(
        color = p.layerAccent,
        start = Offset(bocMid + (bocR - bocMid) * 0.28f, h * 0.18f),
        end = Offset(bocMid + (bocR - bocMid) * 0.28f, h * 0.03f),
        strokeWidth = 1.2.dp.toPx(),
        cap = StrokeCap.Round,
    )
    drawLine(
        color = p.layerAccent,
        start = Offset(bocR - (bocR - bocMid) * 0.22f, h * 0.14f),
        end = Offset(bocR - (bocR - bocMid) * 0.22f, h * 0.02f),
        strokeWidth = 1.2.dp.toPx(),
        cap = StrokeCap.Round,
    )
    // Iconic diagonal structural cross-bracing
    val braceStroke = 1.1.dp.toPx()
    val tiers = listOf(0.30f to 0.52f, 0.52f to 0.74f, 0.74f to 0.96f)
    tiers.forEach { (y1, y2) ->
        drawLine(p.highlight, Offset(bocL, h * y1), Offset(bocR, h * y2), braceStroke)
        drawLine(p.highlight, Offset(bocR, h * y1), Offset(bocL, h * y2), braceStroke)
    }

    // HKCEC layered sweeping waterfront roof (right of BoC)
    val hkcecBase = Path().apply {
        moveTo(w * 0.585f, wy)
        lineTo(w * 0.592f, h * 0.84f)
        quadraticTo(w * 0.652f, h * 0.72f, w * 0.718f, h * 0.84f)
        lineTo(w * 0.724f, wy)
        close()
    }
    drawPath(hkcecBase, color = p.layerMain)
    val hkcecUpperArc = Path().apply {
        moveTo(w * 0.602f, h * 0.82f)
        quadraticTo(w * 0.652f, h * 0.74f, w * 0.706f, h * 0.82f)
    }
    drawPath(hkcecUpperArc, color = p.highlight, style = Stroke(width = 0.9.dp.toPx(), cap = StrokeCap.Round))
}

/**
 * Japan Scenic Horizon:
 * Soft rising sun glow + symmetrical Mt. Fuji with crisp snow cap + detailed lattice Tokyo Tower
 * + lakeside Torii gate.
 */
private fun DrawScope.drawJapanSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    // Soft rising sun glow perched cleanly off Mt. Fuji's left shoulder
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                p.layerMid.copy(alpha = (p.layerMid.alpha * 0.95f).coerceAtMost(0.20f)),
                Color.Transparent,
            ),
            center = Offset(w * 0.285f, h * 0.30f),
            radius = h * 0.24f,
        ),
        radius = h * 0.24f,
        center = Offset(w * 0.285f, h * 0.30f),
    )
    drawCircle(
        color = p.mistFar.copy(alpha = (p.mistFar.alpha * 1.45f).coerceAtMost(0.18f)),
        radius = h * 0.13f,
        center = Offset(w * 0.285f, h * 0.30f),
    )

    // Mount Fuji sweeping slopes
    val fuji = Path().apply {
        moveTo(w * 0.06f, wy)
        quadraticTo(w * 0.28f, h * 0.84f, w * 0.375f, h * 0.32f)
        lineTo(w * 0.465f, h * 0.32f)
        quadraticTo(w * 0.56f, h * 0.84f, w * 0.78f, wy)
        close()
    }
    drawPath(
        fuji,
        brush = Brush.verticalGradient(
            colors = listOf(p.layerMain, p.layerMid),
            startY = h * 0.32f,
            endY = wy,
        ),
    )
    // Sculpted snow cap
    val snow = Path().apply {
        moveTo(w * 0.375f, h * 0.32f)
        lineTo(w * 0.465f, h * 0.32f)
        lineTo(w * 0.502f, h * 0.50f)
        lineTo(w * 0.465f, h * 0.45f)
        lineTo(w * 0.438f, h * 0.52f)
        lineTo(w * 0.415f, h * 0.44f)
        lineTo(w * 0.386f, h * 0.51f)
        lineTo(w * 0.344f, h * 0.48f)
        close()
    }
    drawPath(snow, color = p.highlight)

    // Tokyo Tower (right hero with dual decks & antenna spire)
    val ttCx = w * 0.81f
    val ttBaseHalf = w * 0.068f
    val tower = Path().apply {
        moveTo(ttCx - ttBaseHalf, wy)
        quadraticTo(ttCx - w * 0.018f, h * 0.64f, ttCx - w * 0.008f, h * 0.16f)
        lineTo(ttCx + w * 0.008f, h * 0.16f)
        quadraticTo(ttCx + w * 0.018f, h * 0.64f, ttCx + ttBaseHalf, wy)
        lineTo(ttCx + ttBaseHalf * 0.56f, wy)
        quadraticTo(ttCx, h * 0.74f, ttCx - ttBaseHalf * 0.56f, wy)
        close()
    }
    drawPath(tower, color = p.layerAccent)
    // Spire
    drawLine(
        color = p.layerAccent,
        start = Offset(ttCx, h * 0.16f),
        end = Offset(ttCx, h * 0.03f),
        strokeWidth = 1.5.dp.toPx(),
        cap = StrokeCap.Round,
    )
    // Main & upper observation decks
    drawRoundRect(
        color = p.layerAccent,
        topLeft = Offset(ttCx - w * 0.032f, h * 0.56f),
        size = Size(w * 0.064f, h * 0.06f),
        cornerRadius = CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()),
    )
    drawRoundRect(
        color = p.layerAccent,
        topLeft = Offset(ttCx - w * 0.020f, h * 0.34f),
        size = Size(w * 0.040f, h * 0.045f),
        cornerRadius = CornerRadius(1.dp.toPx(), 1.dp.toPx()),
    )

    // Foreground Torii Gate (left)
    val tgCx = w * 0.155f
    val tgW = w * 0.095f
    val tgTop = h * 0.68f
    val kasagi = Path().apply {
        moveTo(tgCx - tgW * 0.56f, tgTop)
        quadraticTo(tgCx, tgTop + h * 0.065f, tgCx + tgW * 0.56f, tgTop)
        lineTo(tgCx + tgW * 0.50f, tgTop + h * 0.048f)
        quadraticTo(tgCx, tgTop + h * 0.095f, tgCx - tgW * 0.50f, tgTop + h * 0.048f)
        close()
    }
    drawPath(kasagi, color = p.layerAccent)
    drawRect(p.layerAccent, Offset(tgCx - tgW * 0.34f, tgTop + h * 0.05f), Size(w * 0.011f, wy - (tgTop + h * 0.05f)))
    drawRect(p.layerAccent, Offset(tgCx + tgW * 0.23f, tgTop + h * 0.05f), Size(w * 0.011f, wy - (tgTop + h * 0.05f)))
    drawRect(p.layerAccent, Offset(tgCx - tgW * 0.42f, tgTop + h * 0.12f), Size(tgW * 0.84f, h * 0.032f))
}

/**
 * Taiwan: Taipei 101 8-tier flared pagoda silhouette + Elephant Mountain ridge.
 */
private fun DrawScope.drawTaiwanSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    val mtn = Path().apply {
        moveTo(0f, wy)
        cubicTo(w * 0.22f, h * 0.48f, w * 0.44f, h * 0.78f, w * 0.72f, h * 0.56f)
        quadraticTo(w * 0.88f, h * 0.48f, w, h * 0.66f)
        lineTo(w, wy)
        close()
    }
    drawPath(mtn, color = p.mistFar)

    // Neighboring Xinyi towers
    listOf(
        Triple(0.22f, 0.052f, 0.38f),
        Triple(0.29f, 0.058f, 0.50f),
        Triple(0.64f, 0.055f, 0.44f),
        Triple(0.72f, 0.048f, 0.32f),
    ).forEach { (x, bw, bh) ->
        drawRoundRect(p.layerMid, Offset(w * x, wy - h * bh), Size(w * bw, h * bh), CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()))
    }

    // Taipei 101 stacked flared bamboo-box tiers
    val cx = w * 0.50f
    val podiumH = h * 0.24f
    val podium = Path().apply {
        moveTo(cx - w * 0.044f, wy)
        lineTo(cx - w * 0.034f, wy - podiumH)
        lineTo(cx + w * 0.034f, wy - podiumH)
        lineTo(cx + w * 0.044f, wy)
        close()
    }
    drawPath(podium, color = p.layerMain)

    val tiersCount = 6
    val tierH = h * 0.095f
    val tierBaseY = wy - podiumH
    for (i in 0 until tiersCount) {
        val yBot = tierBaseY - i * tierH
        val yTop = yBot - tierH
        val narrow = w * 0.028f
        val flare = w * 0.038f
        val tier = Path().apply {
            moveTo(cx - narrow, yBot)
            lineTo(cx - flare, yTop)
            lineTo(cx + flare, yTop)
            lineTo(cx + narrow, yBot)
            close()
        }
        drawPath(tier, color = if (i % 2 == 0) p.layerAccent else p.layerMain)
        drawLine(p.highlight, Offset(cx - flare, yTop), Offset(cx + flare, yTop), 0.7.dp.toPx())
    }
    val crownY = tierBaseY - tiersCount * tierH
    drawRoundRect(
        color = p.layerAccent,
        topLeft = Offset(cx - w * 0.018f, crownY - h * 0.065f),
        size = Size(w * 0.036f, h * 0.065f),
        cornerRadius = CornerRadius(1.dp.toPx(), 1.dp.toPx()),
    )
    drawLine(
        color = p.layerAccent,
        start = Offset(cx, crownY - h * 0.065f),
        end = Offset(cx, h * 0.03f),
        strokeWidth = 1.6.dp.toPx(),
        cap = StrokeCap.Round,
    )
}

/**
 * USA: Golden Gate Bridge Art Deco towers, sweeping parabolic cables & fine vertical suspenders.
 */
private fun DrawScope.drawUsaSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    val hills = Path().apply {
        moveTo(0f, wy)
        quadraticTo(w * 0.16f, h * 0.56f, w * 0.36f, h * 0.78f)
        quadraticTo(w * 0.72f, h * 0.90f, w * 0.88f, h * 0.62f)
        lineTo(w, h * 0.70f)
        lineTo(w, wy)
        close()
    }
    drawPath(hills, color = p.mistFar)

    val deckY = h * 0.74f
    val t1x = w * 0.30f
    val t2x = w * 0.70f
    val towerTopY = h * 0.16f

    // Main catenary suspension cables
    val cable = Path().apply {
        moveTo(w * 0.04f, deckY)
        quadraticTo(w * 0.18f, deckY - h * 0.06f, t1x, towerTopY + h * 0.02f)
        quadraticTo(w * 0.50f, deckY + h * 0.10f, t2x, towerTopY + h * 0.02f)
        quadraticTo(w * 0.82f, deckY - h * 0.06f, w * 0.96f, deckY)
    }
    drawPath(cable, color = p.layerAccent, style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round))

    // Fine vertical suspender lines along main span and side spans
    val suspStroke = 0.75.dp.toPx()
    for (i in 1..9) {
        val u = i / 10f
        val x = t1x + (t2x - t1x) * u
        // Quadratic Bezier y at u between P0=(t1x, towerTopY), P1=(0.5w, deckY+0.1h), P2=(t2x, towerTopY)
        val oneMinus = 1f - u
        val cy = oneMinus * oneMinus * (towerTopY + h * 0.02f) +
            2f * oneMinus * u * (deckY + h * 0.10f) +
            u * u * (towerTopY + h * 0.02f)
        if (cy < deckY) {
            drawLine(p.layerMid, Offset(x, cy), Offset(x, deckY), suspStroke)
        }
    }

    // Art Deco twin bridge towers
    listOf(t1x, t2x).forEach { cx ->
        val colW = w * 0.015f
        val gap = w * 0.022f
        drawRect(p.layerAccent, Offset(cx - gap * 0.5f - colW, towerTopY), Size(colW, wy - towerTopY))
        drawRect(p.layerAccent, Offset(cx + gap * 0.5f, towerTopY), Size(colW, wy - towerTopY))
        listOf(0.24f, 0.42f, 0.58f).forEach { yFrac ->
            drawRect(
                p.layerAccent,
                Offset(cx - gap * 0.5f - colW, h * yFrac),
                Size(gap + colW * 2f, h * 0.045f),
            )
        }
    }

    // Bridge road deck
    drawRoundRect(
        color = p.layerAccent,
        topLeft = Offset(w * 0.03f, deckY),
        size = Size(w * 0.94f, h * 0.052f),
        cornerRadius = CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()),
    )
}

/**
 * UK: Big Ben (Elizabeth Tower) + 24-capsule London Eye + The Shard glass spire.
 */
private fun DrawScope.drawUkSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    // Westminster Palace base
    drawRect(p.layerMid, Offset(w * 0.09f, h * 0.68f), Size(w * 0.28f, wy - h * 0.68f))

    // Big Ben (Elizabeth Tower)
    val bbCx = w * 0.22f
    val bbHalf = w * 0.028f
    drawRect(p.layerAccent, Offset(bbCx - bbHalf, h * 0.30f), Size(bbHalf * 2f, wy - h * 0.30f))
    val bbRoof = Path().apply {
        moveTo(bbCx - bbHalf * 1.18f, h * 0.30f)
        lineTo(bbCx, h * 0.06f)
        lineTo(bbCx + bbHalf * 1.18f, h * 0.30f)
        close()
    }
    drawPath(bbRoof, color = p.layerAccent)
    drawCircle(p.cutout, radius = bbHalf * 0.56f, center = Offset(bbCx, h * 0.44f))

    // London Eye (center)
    val eyeCx = w * 0.53f
    val eyeR = minOf(h * 0.33f, w * 0.10f)
    val eyeCy = wy - eyeR * 1.18f
    for (i in 0 until 12) {
        val a = (2.0 * PI * i) / 12
        drawLine(
            p.layerMid,
            Offset(eyeCx, eyeCy),
            Offset(eyeCx + (cos(a) * eyeR).toFloat(), eyeCy + (sin(a) * eyeR).toFloat()),
            0.65.dp.toPx(),
        )
    }
    drawCircle(p.layerAccent, eyeR, Offset(eyeCx, eyeCy), style = Stroke(1.6.dp.toPx()))
    drawCircle(p.layerMain, eyeR * 0.84f, Offset(eyeCx, eyeCy), style = Stroke(0.8.dp.toPx()))
    val podR = maxOf(1.dp.toPx(), eyeR * 0.048f)
    for (i in 0 until 24) {
        val a = (2.0 * PI * i) / 24
        drawCircle(
            p.layerAccent,
            podR,
            Offset(eyeCx + (cos(a) * (eyeR + podR)).toFloat(), eyeCy + (sin(a) * (eyeR + podR)).toFloat()),
        )
    }
    drawLine(p.layerAccent, Offset(eyeCx - eyeR * 0.42f, wy), Offset(eyeCx, eyeCy), 1.8.dp.toPx(), StrokeCap.Round)
    drawLine(p.layerAccent, Offset(eyeCx + eyeR * 0.42f, wy), Offset(eyeCx, eyeCy), 1.8.dp.toPx(), StrokeCap.Round)

    // The Shard (right)
    val shCx = w * 0.81f
    val shard = Path().apply {
        moveTo(shCx - w * 0.045f, wy)
        lineTo(shCx, h * 0.09f)
        lineTo(shCx + w * 0.045f, wy)
        close()
    }
    drawPath(shard, color = p.layerMain)
    drawLine(p.highlight, Offset(shCx, h * 0.12f), Offset(shCx + w * 0.014f, wy), 0.9.dp.toPx())
}

/**
 * South Korea: Namsan Mountain + N Seoul Tower + slender Lotte World Tower.
 */
private fun DrawScope.drawKoreaSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    val namsan = Path().apply {
        moveTo(w * 0.04f, wy)
        quadraticTo(w * 0.30f, h * 0.40f, w * 0.58f, wy)
        close()
    }
    drawPath(namsan, color = p.mistFar.copy(alpha = (p.mistFar.alpha * 1.5f).coerceAtMost(0.24f)))

    // N Seoul Tower
    val ntCx = w * 0.30f
    drawRect(p.layerAccent, Offset(ntCx - w * 0.009f, h * 0.36f), Size(w * 0.018f, h * 0.36f))
    val pod = Path().apply {
        moveTo(ntCx - w * 0.036f, h * 0.28f)
        lineTo(ntCx + w * 0.036f, h * 0.28f)
        lineTo(ntCx + w * 0.026f, h * 0.38f)
        lineTo(ntCx - w * 0.026f, h * 0.38f)
        close()
    }
    drawPath(pod, color = p.layerAccent)
    drawLine(p.layerAccent, Offset(ntCx, h * 0.28f), Offset(ntCx, h * 0.06f), 1.5.dp.toPx(), StrokeCap.Round)

    // Lotte World Tower (slender curved taper)
    val ltCx = w * 0.74f
    val lotte = Path().apply {
        moveTo(ltCx - w * 0.045f, wy)
        quadraticTo(ltCx - w * 0.024f, h * 0.44f, ltCx - w * 0.008f, h * 0.08f)
        lineTo(ltCx + w * 0.008f, h * 0.08f)
        quadraticTo(ltCx + w * 0.024f, h * 0.44f, ltCx + w * 0.045f, wy)
        close()
    }
    drawPath(lotte, color = p.layerMain)
    drawLine(p.highlight, Offset(ltCx, h * 0.10f), Offset(ltCx, wy), 0.9.dp.toPx())
    drawRoundRect(p.layerMid, Offset(w * 0.61f, h * 0.62f), Size(w * 0.052f, wy - h * 0.62f), CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()))
    drawRoundRect(p.layerMid, Offset(w * 0.82f, h * 0.66f), Size(w * 0.056f, wy - h * 0.66f), CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()))
}

/**
 * France: Eiffel Tower sweeping iron arch & decks + Haussmann roofs.
 */
private fun DrawScope.drawFranceSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    val cx = w * 0.50f
    // Haussmann framing blocks
    drawRect(p.layerMid, Offset(w * 0.08f, h * 0.66f), Size(w * 0.22f, wy - h * 0.66f))
    drawRect(p.layerMid, Offset(w * 0.70f, h * 0.68f), Size(w * 0.22f, wy - h * 0.68f))

    val tower = Path().apply {
        moveTo(cx - w * 0.095f, wy)
        quadraticTo(cx - w * 0.026f, h * 0.62f, cx - w * 0.009f, h * 0.10f)
        lineTo(cx + w * 0.009f, h * 0.10f)
        quadraticTo(cx + w * 0.026f, h * 0.62f, cx + w * 0.095f, wy)
        lineTo(cx + w * 0.052f, wy)
        quadraticTo(cx, h * 0.72f, cx - w * 0.052f, wy)
        close()
    }
    drawPath(tower, color = p.layerAccent)
    drawLine(p.layerAccent, Offset(cx, h * 0.10f), Offset(cx, h * 0.02f), 1.4.dp.toPx(), StrokeCap.Round)
    drawRect(p.layerAccent, Offset(cx - w * 0.062f, h * 0.68f), Size(w * 0.124f, h * 0.045f))
    drawRect(p.layerAccent, Offset(cx - w * 0.036f, h * 0.45f), Size(w * 0.072f, h * 0.04f))
}

/**
 * Germany: Brandenburg Gate columns + Frankfurt financial skyline.
 */
private fun DrawScope.drawGermanySkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy

    // Brandenburg Gate (left-center)
    val bgL = w * 0.16f
    val bgW = w * 0.28f
    val topY = h * 0.48f
    drawRect(p.layerAccent, Offset(bgL, topY), Size(bgW, h * 0.08f))
    drawRect(p.layerAccent, Offset(bgL + bgW * 0.24f, topY - h * 0.09f), Size(bgW * 0.52f, h * 0.09f))
    for (i in 0..5) {
        val x = bgL + bgW * (0.04f + i * 0.175f)
        drawRect(p.layerMain, Offset(x, topY + h * 0.08f), Size(bgW * 0.07f, wy - (topY + h * 0.08f)))
    }

    // Frankfurt financial towers (right)
    drawRoundRect(p.layerMid, Offset(w * 0.56f, h * 0.44f), Size(w * 0.055f, wy - h * 0.44f), CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()))
    val messeturm = Path().apply {
        moveTo(w * 0.65f, wy)
        lineTo(w * 0.65f, h * 0.26f)
        lineTo(w * 0.685f, h * 0.14f)
        lineTo(w * 0.72f, h * 0.26f)
        lineTo(w * 0.72f, wy)
        close()
    }
    drawPath(messeturm, color = p.layerAccent)
    val commerz = Path().apply {
        moveTo(w * 0.76f, wy)
        lineTo(w * 0.76f, h * 0.24f)
        lineTo(w * 0.83f, h * 0.16f)
        lineTo(w * 0.83f, wy)
        close()
    }
    drawPath(commerz, color = p.layerMain)
}

/**
 * Netherlands: Amsterdam stepped-gable canal houses + traditional Dutch windmill.
 */
private fun DrawScope.drawNetherlandsSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    // Stepped canal houses (left & center)
    val houses = listOf(0.12f to 0.44f, 0.21f to 0.52f, 0.30f to 0.48f, 0.39f to 0.56f, 0.48f to 0.46f)
    houses.forEachIndexed { idx, (x, bh) ->
        val hw = w * 0.082f
        val yTop = wy - h * bh
        val gable = Path().apply {
            moveTo(w * x, wy)
            lineTo(w * x, yTop + h * 0.09f)
            lineTo(w * x + hw * 0.22f, yTop + h * 0.09f)
            lineTo(w * x + hw * 0.22f, yTop + h * 0.04f)
            lineTo(w * x + hw * 0.50f, yTop)
            lineTo(w * x + hw * 0.78f, yTop + h * 0.04f)
            lineTo(w * x + hw * 0.78f, yTop + h * 0.09f)
            lineTo(w * x + hw, yTop + h * 0.09f)
            lineTo(w * x + hw, wy)
            close()
        }
        drawPath(gable, color = if (idx % 2 == 0) p.layerMain else p.layerMid)
    }
    // Windmill (right)
    val wmCx = w * 0.77f
    val mill = Path().apply {
        moveTo(wmCx - w * 0.055f, wy)
        lineTo(wmCx - w * 0.025f, h * 0.38f)
        lineTo(wmCx + w * 0.025f, h * 0.38f)
        lineTo(wmCx + w * 0.055f, wy)
        close()
    }
    drawPath(mill, color = p.layerAccent)
    val hub = Offset(wmCx, h * 0.38f)
    val bladeLen = minOf(h * 0.32f, w * 0.095f)
    listOf(40.0, 130.0, 220.0, 310.0).forEach { deg ->
        val rad = deg * PI / 180.0
        drawLine(
            p.layerAccent,
            hub,
            Offset(hub.x + (cos(rad) * bladeLen).toFloat(), hub.y + (sin(rad) * bladeLen).toFloat()),
            2.2.dp.toPx(),
            StrokeCap.Round,
        )
    }
}

/**
 * Australia: Sydney Opera House sculptural shells + Harbour Bridge arch.
 */
private fun DrawScope.drawAustraliaSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    // Steel Harbour Bridge arch (left-background)
    val arch = Path().apply {
        moveTo(w * 0.05f, h * 0.74f)
        quadraticTo(w * 0.30f, h * 0.14f, w * 0.55f, h * 0.74f)
    }
    drawPath(arch, color = p.layerMid, style = Stroke(2.2.dp.toPx(), cap = StrokeCap.Round))
    drawLine(p.layerMid, Offset(w * 0.04f, h * 0.74f), Offset(w * 0.56f, h * 0.74f), 2.dp.toPx())

    // Sydney Opera House overlapping white-mint shells (right hero)
    val shells = listOf(
        Triple(0.46f, 0.58f, 0.44f),
        Triple(0.55f, 0.72f, 0.24f),
        Triple(0.67f, 0.84f, 0.30f),
        Triple(0.79f, 0.92f, 0.50f),
    )
    shells.forEachIndexed { idx, (x1, x2, topFrac) ->
        val shell = Path().apply {
            moveTo(w * x1, wy)
            quadraticTo(w * (x1 + (x2 - x1) * 0.26f), h * topFrac, w * x2, wy)
            close()
        }
        drawPath(shell, color = if (idx % 2 == 1) p.layerAccent else p.layerMain)
        drawPath(shell, color = p.highlight, style = Stroke(0.8.dp.toPx()))
    }
}

/**
 * Canada: Toronto CN Tower slender spire & SkyPod + downtown towers.
 */
private fun DrawScope.drawCanadaSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    listOf(
        Triple(0.18f, 0.056f, 0.42f),
        Triple(0.26f, 0.062f, 0.54f),
        Triple(0.62f, 0.060f, 0.48f),
        Triple(0.70f, 0.052f, 0.36f),
    ).forEach { (x, bw, bh) ->
        drawRoundRect(p.layerMid, Offset(w * x, wy - h * bh), Size(w * bw, h * bh), CornerRadius(1.5.dp.toPx(), 1.5.dp.toPx()))
    }
    val cx = w * 0.48f
    val shaft = Path().apply {
        moveTo(cx - w * 0.022f, wy)
        lineTo(cx - w * 0.007f, h * 0.22f)
        lineTo(cx + w * 0.007f, h * 0.22f)
        lineTo(cx + w * 0.022f, wy)
        close()
    }
    drawPath(shaft, color = p.layerAccent)
    drawOval(p.layerAccent, Offset(cx - w * 0.038f, h * 0.26f), Size(w * 0.076f, h * 0.09f))
    drawLine(p.layerAccent, Offset(cx, h * 0.22f), Offset(cx, h * 0.03f), 1.5.dp.toPx(), StrokeCap.Round)
}

/**
 * China Mainland (e.g. Direct mode): Shanghai Lujiazui Oriental Pearl + Shanghai Tower.
 */
private fun DrawScope.drawChinaSkyline(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = wy
    // Oriental Pearl Tower (left-center)
    val opCx = w * 0.36f
    drawLine(p.layerAccent, Offset(opCx - w * 0.042f, wy), Offset(opCx - w * 0.012f, h * 0.56f), 1.8.dp.toPx(), StrokeCap.Round)
    drawLine(p.layerAccent, Offset(opCx + w * 0.042f, wy), Offset(opCx + w * 0.012f, h * 0.56f), 1.8.dp.toPx(), StrokeCap.Round)
    drawRect(p.layerMain, Offset(opCx - w * 0.010f, h * 0.24f), Size(w * 0.020f, wy - h * 0.24f))
    drawCircle(p.layerAccent, radius = minOf(h * 0.11f, w * 0.034f), center = Offset(opCx, h * 0.62f))
    drawCircle(p.layerAccent, radius = minOf(h * 0.085f, w * 0.026f), center = Offset(opCx, h * 0.34f))
    drawLine(p.layerAccent, Offset(opCx, h * 0.24f), Offset(opCx, h * 0.06f), 1.4.dp.toPx(), StrokeCap.Round)

    // Shanghai Tower (curving slender peak)
    val stCx = w * 0.60f
    val st = Path().apply {
        moveTo(stCx - w * 0.046f, wy)
        quadraticTo(stCx - w * 0.032f, h * 0.42f, stCx - w * 0.010f, h * 0.10f)
        lineTo(stCx + w * 0.022f, h * 0.15f)
        quadraticTo(stCx + w * 0.036f, h * 0.46f, stCx + w * 0.046f, wy)
        close()
    }
    drawPath(st, color = p.layerMain)

    // SWFC (bottle-opener silhouette on right)
    val swL = w * 0.70f
    drawRect(p.layerMid, Offset(swL, h * 0.22f), Size(w * 0.056f, wy - h * 0.22f))
    drawRect(p.cutout, Offset(swL + w * 0.014f, h * 0.28f), Size(w * 0.028f, h * 0.07f))
}

/**
 * Minimalist Global Horizon fallback for other regions / unprobed state.
 */
private fun DrawScope.drawGlobalHorizon(p: LandmarkPalette, wy: Float) {
    val w = size.width
    val h = size.height

    val globeFill = Path().apply {
        moveTo(-w * 0.06f, h)
        quadraticTo(w * 0.50f, h * 0.34f, w * 1.06f, h)
        close()
    }
    drawPath(globeFill, color = p.mistFar)

    val outerArc = Path().apply {
        moveTo(w * 0.04f, h)
        quadraticTo(w * 0.50f, h * 0.46f, w * 0.96f, h)
    }
    drawPath(outerArc, color = p.layerMid, style = Stroke(width = 1.2.dp.toPx()))

    val innerLat = Path().apply {
        moveTo(w * 0.20f, h)
        quadraticTo(w * 0.50f, h * 0.62f, w * 0.80f, h)
    }
    drawPath(
        innerLat,
        color = p.layerMid,
        style = Stroke(
            width = 0.9.dp.toPx(),
            pathEffect = PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 5.dp.toPx())),
        ),
    )

    // Encrypted proxy flight arc + terminal beacon
    val routeStart = Offset(w * 0.22f, h * 0.66f)
    val routeEnd = Offset(w * 0.78f, h * 0.52f)
    val route = Path().apply {
        moveTo(routeStart.x, routeStart.y)
        quadraticTo(w * 0.50f, h * 0.14f, routeEnd.x, routeEnd.y)
    }
    drawPath(
        route,
        color = p.layerAccent,
        style = Stroke(
            width = 1.4.dp.toPx(),
            cap = StrokeCap.Round,
            pathEffect = PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 4.dp.toPx())),
        ),
    )
    drawCircle(p.layerMain, radius = 3.2.dp.toPx(), center = routeStart)
    drawCircle(p.layerMid, radius = 7.dp.toPx(), center = routeEnd)
    drawCircle(p.layerAccent, radius = 3.2.dp.toPx(), center = routeEnd)
}
