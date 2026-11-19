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
    val sky: Color,
    val skyContainer: Color,
    val onSkyContainer: Color,
    val violet: Color,
    val violetContainer: Color,
    val onVioletContainer: Color,
    val selectedCardBg: Color,
    val selectedCardBorder: Color,
    val cardSurface: Color,
    val cardSubtle: Color,
    val tonalTrack: Color,
    val tonalThumb: Color,
    val heroGradientStart: Color,
    val heroGradientEnd: Color,
    val ambientGlowTop: Color,
    val ambientGlowMid: Color,
    val navBarSurface: Color,
    val navIndicator: Color,
    val onNavSelected: Color,
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
    primary = Color(0xFF007352),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC6F4DB),
    onPrimaryContainer = Color(0xFF004731),
    secondary = Color(0xFF3E5248),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE7F0EB),
    onSecondaryContainer = Color(0xFF121D18),
    tertiary = Color(0xFF0284C7),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF3F7F5),
    onBackground = Color(0xFF121D18),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF121D18),
    surfaceVariant = Color(0xFFE7F0EB),
    onSurfaceVariant = Color(0xFF5B6D64),
    outline = Color(0xFFCBD8D1),
    outlineVariant = Color(0xFFE1EAE5),
    error = Color(0xFFDC2626),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF991B1B),
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF6CDBAC),
    onPrimary = Color(0xFF003826),
    primaryContainer = Color(0xFF0D4A36),
    onPrimaryContainer = Color(0xFFA7F3D0),
    secondary = Color(0xFF8CA196),
    onSecondary = Color(0xFF121D18),
    secondaryContainer = Color(0xFF1B2822),
    onSecondaryContainer = Color(0xFFE3ECE7),
    tertiary = Color(0xFF38BDF8),
    onTertiary = Color(0xFF082F49),
    background = Color(0xFF0C1310),
    onBackground = Color(0xFFECF3EF),
    surface = Color(0xFF151F1B),
    onSurface = Color(0xFFECF3EF),
    surfaceVariant = Color(0xFF1B2822),
    onSurfaceVariant = Color(0xFF8CA196),
    outline = Color(0xFF2D4037),
    outlineVariant = Color(0xFF1F2E27),
    error = Color(0xFFF87171),
    onError = Color(0xFF450A0A),
    errorContainer = Color(0xFF450A0A),
    onErrorContainer = Color(0xFFFECACA),
)

val LightExtendedColors = RustClashExtendedColors(
    isDark = false,
    emerald = Color(0xFF007352),
    emeraldBright = Color(0xFF10B981),
    emeraldContainer = Color(0xFFC6F4DB),
    onEmeraldContainer = Color(0xFF004731),
    sky = Color(0xFF0284C7),
    skyContainer = Color(0xFFE0F2FE),
    onSkyContainer = Color(0xFF0369A1),
    violet = Color(0xFF7C3AED),
    violetContainer = Color(0xFFEDE9FE),
    onVioletContainer = Color(0xFF5B21B6),
    selectedCardBg = Color(0xFFE0F7EB),
    selectedCardBorder = Color(0xFF10B981),
    cardSurface = Color(0xFFFFFFFF),
    cardSubtle = Color(0xFFEDF4F0),
    tonalTrack = Color(0xFFE7F0EB),
    tonalThumb = Color(0xFFFFFFFF),
    heroGradientStart = Color(0xFF058C65),
    heroGradientEnd = Color(0xFF046C4E),
    ambientGlowTop = Color(0x3310B981),
    ambientGlowMid = Color(0x1434D399),
    navBarSurface = Color(0xFFFFFFFF),
    navIndicator = Color(0xFFC6F4DB),
    onNavSelected = Color(0xFF00573D),
    iconBadgeBg = Color(0xFFEAF2EE),
    iconBadgeTint = Color(0xFF2D4037),
    amber = Color(0xFFD97706),
    amberContainer = Color(0xFFFEF3C7),
    onAmberContainer = Color(0xFF92400E),
    danger = Color(0xFFDC2626),
    dangerContainer = Color(0xFFFEE2E2),
    onDangerContainer = Color(0xFF991B1B),
    infoContainer = Color(0xFFE0F2FE),
    onInfoContainer = Color(0xFF0369A1),
    hairline = Color(0xFFE4ECE7),
    waveformStroke = Color(0xFF007352),
    waveformFillTop = Color(0x47007352),
    waveformFillBottom = Color(0x00007352),
)

val DarkExtendedColors = RustClashExtendedColors(
    isDark = true,
    emerald = Color(0xFF0E9F6E),
    emeraldBright = Color(0xFF6CDBAC),
    emeraldContainer = Color(0xFF0D4A36),
    onEmeraldContainer = Color(0xFFA7F3D0),
    sky = Color(0xFF38BDF8),
    skyContainer = Color(0xFF0C3A57),
    onSkyContainer = Color(0xFF7DD3FC),
    violet = Color(0xFFA78BFA),
    violetContainer = Color(0xFF2E1A5C),
    onVioletContainer = Color(0xFFDDD6FE),
    selectedCardBg = Color(0xFF10372A),
    selectedCardBorder = Color(0xFF22C58B),
    cardSurface = Color(0xFF151F1B),
    cardSubtle = Color(0xFF1B2822),
    tonalTrack = Color(0xFF1B2822),
    tonalThumb = Color(0xFF24352E),
    heroGradientStart = Color(0xFF065F46),
    heroGradientEnd = Color(0xFF0A382B),
    ambientGlowTop = Color(0x3810B981),
    ambientGlowMid = Color(0x1210B981),
    navBarSurface = Color(0xFF111915),
    navIndicator = Color(0xFF0D4A36),
    onNavSelected = Color(0xFF86EFAC),
    iconBadgeBg = Color(0xFF1D2C25),
    iconBadgeTint = Color(0xFFC5D7CE),
    amber = Color(0xFFFBBF24),
    amberContainer = Color(0xFF451A03),
    onAmberContainer = Color(0xFFFDE68A),
    danger = Color(0xFFF87171),
    dangerContainer = Color(0xFF450A0A),
    onDangerContainer = Color(0xFFFCA5A5),
    infoContainer = Color(0xFF0C4A6E),
    onInfoContainer = Color(0xFF7DD3FC),
    hairline = Color(0xFF21312A),
    waveformStroke = Color(0xFF6CDBAC),
    waveformFillTop = Color(0x4A34D399),
    waveformFillBottom = Color(0x0034D399),
)

val RustClashShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(26.dp),
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
