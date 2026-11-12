package io.github.rustclashlabs.rustclash.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import io.github.rustclashlabs.rustclash.ui.model.ThemePreference

@Immutable
data class RustClashExtendedColors(
    val isDark: Boolean,
    val emerald: Color,
    val emeraldBright: Color,
    val emeraldContainer: Color,
    val onEmeraldContainer: Color,
    val selectedCardBg: Color,
    val selectedCardBorder: Color,
    val cardSurface: Color,
    val cardSubtle: Color,
    val iconBadgeBg: Color,
    val iconBadgeTint: Color,
    val amber: Color,
    val amberContainer: Color,
    val onAmberContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    val onDangerContainer: Color,
    val infoContainer: Color,
    val onInfoContainer: Color,
    val hairline: Color,
    val waveformStroke: Color,
    val waveformFillTop: Color,
    val waveformFillBottom: Color,
)

val LocalRustClashColors = staticCompositionLocalOf {
    LightExtendedColors
}

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF059669),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD1FAE5),
    onPrimaryContainer = Color(0xFF064E3B),
    secondary = Color(0xFF334155),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFF1F5F9),
    onSecondaryContainer = Color(0xFF0F172A),
    tertiary = Color(0xFF0284C7),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF6F8F9),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = Color(0xFF64748B),
    outline = Color(0xFFCBD5E1),
    outlineVariant = Color(0xFFE2E8F0),
    error = Color(0xFFDC2626),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF991B1B),
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF10B981),
    onPrimary = Color(0xFF022C22),
    primaryContainer = Color(0xFF064E3B),
    onPrimaryContainer = Color(0xFFA7F3D0),
    secondary = Color(0xFF94A3B8),
    onSecondary = Color(0xFF0F172A),
    secondaryContainer = Color(0xFF1A282E),
    onSecondaryContainer = Color(0xFFE2E8F0),
    tertiary = Color(0xFF38BDF8),
    onTertiary = Color(0xFF082F49),
    background = Color(0xFF0A1114),
    onBackground = Color(0xFFF1F5F9),
    surface = Color(0xFF121C20),
    onSurface = Color(0xFFF1F5F9),
    surfaceVariant = Color(0xFF17242A),
    onSurfaceVariant = Color(0xFF94A3B8),
    outline = Color(0xFF2D4048),
    outlineVariant = Color(0xFF1E2D34),
    error = Color(0xFFF87171),
    onError = Color(0xFF450A0A),
    errorContainer = Color(0xFF450A0A),
    onErrorContainer = Color(0xFFFECACA),
)

val LightExtendedColors = RustClashExtendedColors(
    isDark = false,
    emerald = Color(0xFF059669),
    emeraldBright = Color(0xFF10B981),
    emeraldContainer = Color(0xFFDCFCE7),
    onEmeraldContainer = Color(0xFF047857),
    selectedCardBg = Color(0xFFECFDF5),
    selectedCardBorder = Color(0xFF10B981),
    cardSurface = Color(0xFFFFFFFF),
    cardSubtle = Color(0xFFF8FAFC),
    iconBadgeBg = Color(0xFFF1F5F9),
    iconBadgeTint = Color(0xFF334155),
    amber = Color(0xFFD97706),
    amberContainer = Color(0xFFFEF3C7),
    onAmberContainer = Color(0xFF92400E),
    danger = Color(0xFFDC2626),
    dangerContainer = Color(0xFFFEE2E2),
    onDangerContainer = Color(0xFF991B1B),
    infoContainer = Color(0xFFE0F2FE),
    onInfoContainer = Color(0xFF0369A1),
    hairline = Color(0xFFE5E9F0),
    waveformStroke = Color(0xFF10B981),
    waveformFillTop = Color(0x5510B981),
    waveformFillBottom = Color(0x0510B981),
)

val DarkExtendedColors = RustClashExtendedColors(
    isDark = true,
    emerald = Color(0xFF10B981),
    emeraldBright = Color(0xFF34D399),
    emeraldContainer = Color(0xFF064E3B),
    onEmeraldContainer = Color(0xFF6EE7B7),
    selectedCardBg = Color(0xFF0B2922),
    selectedCardBorder = Color(0xFF10B981),
    cardSurface = Color(0xFF121C20),
    cardSubtle = Color(0xFF162228),
    iconBadgeBg = Color(0xFF1B2A32),
    iconBadgeTint = Color(0xFFCBD5E1),
    amber = Color(0xFFFBBF24),
    amberContainer = Color(0xFF451A03),
    onAmberContainer = Color(0xFFFDE68A),
    danger = Color(0xFFF87171),
    dangerContainer = Color(0xFF450A0A),
    onDangerContainer = Color(0xFFFCA5A5),
    infoContainer = Color(0xFF0C4A6E),
    onInfoContainer = Color(0xFF7DD3FC),
    hairline = Color(0xFF1E2D34),
    waveformStroke = Color(0xFF34D399),
    waveformFillTop = Color(0x6610B981),
    waveformFillBottom = Color(0x0510B981),
)

val RustClashShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

fun buildRustClashTypography(fontFamily: FontFamily = FontFamily.Default): Typography = Typography(
    headlineMedium = TextStyle(
        fontFamily = fontFamily,
        fontSize = 24.sp,
        lineHeight = 30.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.3).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = fontFamily,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.2).sp,
    ),
    titleLarge = TextStyle(
        fontFamily = fontFamily,
        fontSize = 19.sp,
        lineHeight = 25.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleMedium = TextStyle(
        fontFamily = fontFamily,
        fontSize = 15.5.sp,
        lineHeight = 21.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleSmall = TextStyle(
        fontFamily = fontFamily,
        fontSize = 14.sp,
        lineHeight = 19.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    bodyLarge = TextStyle(
        fontFamily = fontFamily,
        fontSize = 15.sp,
        lineHeight = 21.sp,
        fontWeight = FontWeight.Normal,
    ),
    bodyMedium = TextStyle(
        fontFamily = fontFamily,
        fontSize = 13.5.sp,
        lineHeight = 19.sp,
        fontWeight = FontWeight.Normal,
    ),
    bodySmall = TextStyle(
        fontFamily = fontFamily,
        fontSize = 12.5.sp,
        lineHeight = 17.5.sp,
        fontWeight = FontWeight.Normal,
    ),
    labelLarge = TextStyle(
        fontFamily = fontFamily,
        fontSize = 13.sp,
        lineHeight = 18.sp,
        fontWeight = FontWeight.Medium,
    ),
    labelMedium = TextStyle(
        fontFamily = fontFamily,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        fontWeight = FontWeight.Medium,
    ),
    labelSmall = TextStyle(
        fontFamily = fontFamily,
        fontSize = 11.sp,
        lineHeight = 15.sp,
        fontWeight = FontWeight.Medium,
    ),
)

@Composable
fun RustClashTheme(
    themePreference: ThemePreference = ThemePreference.SYSTEM,
    fontFamily: FontFamily = FontFamily.Default,
    content: @Composable () -> Unit,
) {
    val useDark = when (themePreference) {
        ThemePreference.SYSTEM -> isSystemInDarkTheme()
        ThemePreference.LIGHT -> false
        ThemePreference.DARK -> true
    }
    val colorScheme = if (useDark) DarkColorScheme else LightColorScheme
    val extendedColors = if (useDark) DarkExtendedColors else LightExtendedColors
    val typography = androidx.compose.runtime.remember(fontFamily) {
        buildRustClashTypography(fontFamily)
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = !useDark
            controller.isAppearanceLightNavigationBars = !useDark
        }
    }

    CompositionLocalProvider(LocalRustClashColors provides extendedColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = typography,
            shapes = RustClashShapes,
            content = content,
        )
    }
}
