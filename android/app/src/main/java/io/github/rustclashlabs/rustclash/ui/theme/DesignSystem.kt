package io.github.rustclashlabs.rustclash.ui.theme

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Renders the original RustClash Emerald geometric 'R' + Split-Routing Stream icon
 * using identical 108x108 coordinates to `ic_launcher_background.xml` & `ic_launcher_foreground.xml`.
 */
@Composable
fun RustClashBrandIcon(
    modifier: Modifier = Modifier,
    size: Dp = 56.dp,
    isRound: Boolean = false,
    isMonochrome: Boolean = false,
) {
    val shape = if (isRound) CircleShape else RoundedCornerShape(size * 0.24f)
    val bgModifier = if (isMonochrome) {
        modifier
            .size(size)
            .clip(shape)
            .background(Color(0xFFEFF6F3))
    } else {
        modifier
            .size(size)
            .clip(shape)
    }

    Canvas(modifier = bgModifier) {
        val sx = this.size.width / 108f
        val sy = this.size.height / 108f

        if (!isMonochrome) {
            drawRect(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF10B981),
                        Color(0xFF059669),
                        Color(0xFF064E3B),
                    ),
                    start = Offset(12f * sx, 8f * sy),
                    end = Offset(96f * sx, 100f * sy),
                ),
            )

            val topArc = Path().apply {
                moveTo(-6f * sx, 42f * sy)
                cubicTo(22f * sx, 14f * sy, 62f * sx, 6f * sy, 102f * sx, 22f * sy)
                lineTo(108f * sx, 0f)
                lineTo(0f, 0f)
                close()
            }
            drawPath(topArc, color = Color.White.copy(alpha = 0.08f))

            val bottomArc = Path().apply {
                moveTo(16f * sx, 108f * sy)
                cubicTo(44f * sx, 78f * sy, 78f * sx, 68f * sy, 114f * sx, 74f * sy)
                lineTo(114f * sx, 114f * sy)
                lineTo(16f * sx, 114f * sy)
                close()
            }
            drawPath(bottomArc, color = Color(0xFF022C22).copy(alpha = 0.22f))
        }

        val rColor = if (isMonochrome) Color(0xFF065F46) else Color.White
        val upperR = Path().apply {
            fillType = PathFillType.EvenOdd
            moveTo(36.2f * sx, 50.5f * sy)
            lineTo(40.1f * sx, 30.0f * sy)
            lineTo(61.5f * sx, 30.0f * sy)
            cubicTo(70.2f * sx, 30.0f * sy, 74.8f * sx, 34.4f * sy, 73.4f * sx, 41.2f * sy)
            cubicTo(72.1f * sx, 47.3f * sy, 67.0f * sx, 50.5f * sy, 59.2f * sx, 50.5f * sy)
            close()

            moveTo(47.2f * sx, 37.0f * sy)
            lineTo(59.0f * sx, 37.0f * sy)
            cubicTo(62.6f * sx, 37.0f * sy, 64.4f * sx, 38.6f * sy, 63.8f * sx, 41.2f * sy)
            cubicTo(63.2f * sx, 43.8f * sy, 60.9f * sx, 44.9f * sy, 57.4f * sx, 44.9f * sy)
            lineTo(45.7f * sx, 44.9f * sy)
            close()
        }
        drawPath(upperR, color = rColor)

        val lowerR = Path().apply {
            moveTo(34.5f * sx, 59.5f * sy)
            lineTo(44.1f * sx, 59.5f * sy)
            lineTo(41.2f * sx, 74.5f * sy)
            lineTo(31.6f * sx, 74.5f * sy)
            close()

            moveTo(52.5f * sx, 59.5f * sy)
            lineTo(62.8f * sx, 59.5f * sy)
            lineTo(71.4f * sx, 74.5f * sy)
            lineTo(60.6f * sx, 74.5f * sy)
            close()
        }
        drawPath(lowerR, color = rColor)

        val arrowPath = Path().apply {
            moveTo(28.0f * sx, 57.3f * sy)
            lineTo(29.2f * sx, 52.7f * sy)
            lineTo(66.8f * sx, 52.7f * sy)
            lineTo(65.4f * sx, 48.8f * sy)
            lineTo(79.6f * sx, 55.0f * sy)
            lineTo(65.4f * sx, 61.2f * sy)
            lineTo(66.8f * sx, 57.3f * sy)
            close()
        }
        if (isMonochrome) {
            drawPath(arrowPath, color = Color(0xFF059669))
        } else {
            drawPath(
                path = arrowPath,
                brush = Brush.horizontalGradient(
                    colors = listOf(Color(0xFF6EE7B7), Color(0xFFA7F3D0)),
                    startX = 28f * sx,
                    endX = 80f * sx,
                ),
            )
        }
    }
}

/**
 * Smooth Emerald cubic Bezier waveform area chart for real-time traffic visualization on the Home screen.
 */
@Composable
fun TrafficWaveformGraph(
    samples: List<Long>,
    isConnected: Boolean,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current

    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        if (w <= 4f || h <= 4f) return@Canvas

        // Build normalized points in [0.14 .. 0.86] of canvas height (0 = top, 1 = bottom)
        val rawPoints: List<Float> = if (!isConnected) {
            listOf(0.82f, 0.80f, 0.82f, 0.79f, 0.82f, 0.81f, 0.82f, 0.80f)
        } else {
            val padded = if (samples.size >= 10) {
                samples.takeLast(12)
            } else {
                List(10 - samples.size) { 0L } + samples
            }
            val maxVal = (padded.maxOrNull() ?: 0L).coerceAtLeast(8_192L).toFloat()
            val hasNonZero = padded.any { it > 0L }
            if (!hasNonZero) {
                // Honest flat baseline when 0 B/s
                List(10) { 0.82f }
            } else {
                padded.map { v ->
                    val ratio = (v.toFloat() / maxVal).coerceIn(0f, 1f)
                    0.82f - (ratio * 0.64f)
                }
            }
        }

        val count = rawPoints.size
        val stepX = w / (count - 1).coerceAtLeast(1)
        val coords = rawPoints.mapIndexed { idx, ny ->
            Offset(x = idx * stepX, y = ny * h)
        }

        val strokePath = Path().apply {
            moveTo(coords.first().x, coords.first().y)
            for (i in 0 until coords.size - 1) {
                val p0 = coords[i]
                val p1 = coords[i + 1]
                val cx = (p0.x + p1.x) * 0.5f
                cubicTo(cx, p0.y, cx, p1.y, p1.x, p1.y)
            }
        }

        val fillPath = Path().apply {
            addPath(strokePath)
            lineTo(w, h)
            lineTo(0f, h)
            close()
        }

        val activeAlpha = if (isConnected) 1f else 0.38f
        drawPath(
            path = fillPath,
            brush = Brush.verticalGradient(
                colors = listOf(
                    extColors.waveformFillTop.copy(alpha = extColors.waveformFillTop.alpha * activeAlpha),
                    extColors.waveformFillBottom,
                ),
                startY = 0f,
                endY = h,
            ),
        )

        drawPath(
            path = strokePath,
            color = extColors.waveformStroke.copy(alpha = if (isConnected) 0.95f else 0.45f),
            style = Stroke(
                width = 2.2.dp.toPx(),
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
            ),
        )
    }
}

@Composable
fun LatencyPill(
    delayMs: Long?,
    isProbing: Boolean,
    isSelected: Boolean = false,
    onClick: (() -> Unit)? = null,
) {
    val extColors = LocalRustClashColors.current
    val (bgColor, fgColor, text) = when {
        isProbing -> Triple(extColors.emeraldContainer, extColors.onEmeraldContainer, "…")
        delayMs != null && delayMs > 0L -> when {
            delayMs <= 180L -> Triple(
                extColors.emeraldContainer,
                extColors.onEmeraldContainer,
                "$delayMs ms",
            )
            delayMs <= 420L -> Triple(
                extColors.amberContainer,
                extColors.onAmberContainer,
                "$delayMs ms",
            )
            else -> Triple(
                extColors.dangerContainer,
                extColors.onDangerContainer,
                "$delayMs ms",
            )
        }
        else -> Triple(
            if (isSelected) extColors.emeraldContainer.copy(alpha = 0.7f) else MaterialTheme.colorScheme.surfaceVariant,
            if (isSelected) extColors.onEmeraldContainer else MaterialTheme.colorScheme.onSurfaceVariant,
            "测速",
        )
    }

    val pillMod = if (onClick != null && !isProbing) {
        Modifier
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
    } else {
        Modifier
    }

    Surface(
        modifier = pillMod,
        shape = RoundedCornerShape(8.dp),
        color = bgColor,
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        ) {
            if (isProbing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(12.dp),
                    strokeWidth = 1.8.dp,
                    color = fgColor,
                )
            } else {
                Text(
                    text = text,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = fgColor,
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
fun ProtocolBadge(
    protocol: String,
    isSelected: Boolean = false,
) {
    val extColors = LocalRustClashColors.current
    val bg = if (isSelected) {
        extColors.emeraldContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val fg = if (isSelected) {
        extColors.onEmeraldContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bg,
    ) {
        Text(
            text = protocol,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = fg,
            maxLines = 1,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
        )
    }
}

/**
 * Full-width equal-weight segmented selector that guarantees single-line labels without line wrapping.
 */
@Composable
fun <T> SegmentedSelectorRow(
    items: List<T>,
    selectedItem: T,
    labelOf: (T) -> String,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(1.dp, extColors.hairline),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items.forEach { item ->
                val selected = item == selectedItem
                val itemBg by animateColorAsState(
                    targetValue = if (selected) extColors.emerald else Color.Transparent,
                    animationSpec = tween(180),
                    label = "segBg",
                )
                val itemFg by animateColorAsState(
                    targetValue = if (selected) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                    animationSpec = tween(180),
                    label = "segFg",
                )

                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(9.dp))
                        .background(itemBg)
                        .clickable { onSelect(item) }
                        .padding(horizontal = 6.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = labelOf(item),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                        color = itemFg,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

@Composable
fun SettingsGroupContainer(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val extColors = LocalRustClashColors.current
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = extColors.cardSurface,
        border = BorderStroke(1.dp, extColors.hairline),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            content = content,
        )
    }
}

@Composable
fun SettingsGroupDivider() {
    val extColors = LocalRustClashColors.current
    HorizontalDivider(
        modifier = Modifier.padding(start = 64.dp, end = 16.dp),
        thickness = 0.8.dp,
        color = extColors.hairline,
    )
}

@Composable
fun SettingsRowItem(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    trailingBadge: String? = null,
    iconTint: Color? = null,
) {
    val extColors = LocalRustClashColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            shape = RoundedCornerShape(11.dp),
            color = extColors.iconBadgeBg,
            modifier = Modifier.size(38.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = iconTint ?: extColors.iconBadgeTint,
                    modifier = Modifier.size(20.dp),
                )
            }
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        if (!trailingBadge.isNullOrBlank()) {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = trailingBadge,
                style = MaterialTheme.typography.labelMedium,
                color = extColors.emerald,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
            )
        }

        Spacer(modifier = Modifier.width(4.dp))
        Icon(
            imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
    }
}

/**
 * High-contrast inline error banner rendered directly inside modal sheets and dialogs
 * so users never have to shrink or dismiss a modal to read Snackbar errors behind the scrim.
 */
@Composable
fun ModalInlineErrorBanner(
    message: String,
    onDismiss: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val extColors = LocalRustClashColors.current
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = extColors.dangerContainer,
        border = BorderStroke(1.dp, extColors.danger.copy(alpha = 0.4f)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, top = 10.dp, bottom = 10.dp, end = if (onDismiss != null) 6.dp else 12.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(
                imageVector = Icons.Rounded.ErrorOutline,
                contentDescription = "错误提示",
                tint = extColors.danger,
                modifier = Modifier
                    .padding(top = 1.dp)
                    .size(18.dp),
            )
            Spacer(modifier = Modifier.width(8.dp))
            SelectionContainer(modifier = Modifier.weight(1f)) {
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                    color = extColors.onDangerContainer,
                )
            }
            if (onDismiss != null) {
                Spacer(modifier = Modifier.width(4.dp))
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.size(26.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Clear,
                        contentDescription = "关闭错误提示",
                        tint = extColors.onDangerContainer.copy(alpha = 0.8f),
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}
