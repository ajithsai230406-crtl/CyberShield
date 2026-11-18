import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';

class AccentColorOption {
  final String name;
  final Color primary;
  final Color secondary;
  final Color glow;

  const AccentColorOption({
    required this.name,
    required this.primary,
    required this.secondary,
    required this.glow,
  });
}

class AppColors {
  // Preset Accent Color Options
  static const cyanAccent = AccentColorOption(
    name: 'Cyan',
    primary: Color(0xFF00E5FF),
    secondary: Color(0xFF00B0FF),
    glow: Color(0x3300E5FF),
  );

  static const greenAccent = AccentColorOption(
    name: 'Emerald',
    primary: Color(0xFF00E676),
    secondary: Color(0xFF00C853),
    glow: Color(0x3300E676),
  );

  static const purpleAccent = AccentColorOption(
    name: 'Violet',
    primary: Color(0xFF9D4EDD),
    secondary: Color(0xFF7209B7),
    glow: Color(0x339D4EDD),
  );

  static const redAccent = AccentColorOption(
    name: 'Crimson',
    primary: Color(0xFFFF3B30),
    secondary: Color(0xFFD90429),
    glow: Color(0x33FF3B30),
  );

  static const tealAccent = AccentColorOption(
    name: 'Aqua',
    primary: Color(0xFF00B4D8),
    secondary: Color(0xFF0077B6),
    glow: Color(0x3300B4D8),
  );

  static const List<AccentColorOption> accentPresets = [
    cyanAccent,
    greenAccent,
    purpleAccent,
    redAccent,
    tealAccent,
  ];

  // Dark Navy Base & Surfaces (Default)
  static const Color background = Color(0xFF0A0E1A);
  static const Color surface = Color(0xFF131B2E);
  static const Color surfaceLight = Color(0xFF1A233D);
  static const Color surfaceSubtle = Color(0xFF0F1526);
  static const Color cardBorder = Color(0xFF1E2C4F);
  static const Color cardBorderActive = Color(0xFF00E5FF);

  // Light Mode Surfaces
  static const Color lightBackground = Color(0xFFF8FAFC);
  static const Color lightSurface = Color(0xFFFFFFFF);
  static const Color lightSurfaceLight = Color(0xFFF1F5F9);
  static const Color lightSurfaceSubtle = Color(0xFFE2E8F0);
  static const Color lightCardBorder = Color(0xFFCBD5E1);

  // Default Primary Accents
  static const Color primary = Color(0xFF00E5FF);
  static const Color primaryDark = Color(0xFF00B0FF);
  static const Color secondary = Color(0xFF0077FE);
  static const Color accent = Color(0xFF7000FF);
  static const Color glow = Color(0x3300E5FF);

  // Threat & Security Status Colors
  static const Color safe = Color(0xFF00E676);
  static const Color danger = Color(0xFFFF3B30);
  static const Color warning = Color(0xFFFFB300);
  static const Color info = Color(0xFF00B0FF);
  static const Color success = safe;

  // Dark Text Colors
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textSecondary = Color(0xFF94A3B8);
  static const Color textMuted = Color(0xFF64748B);

  // Light Text Colors
  static const Color lightTextPrimary = Color(0xFF0F172A);
  static const Color lightTextSecondary = Color(0xFF475569);
  static const Color lightTextMuted = Color(0xFF94A3B8);
}

class ThemeController extends ChangeNotifier {
  static final ThemeController instance = ThemeController();

  ThemeMode _themeMode = ThemeMode.dark;
  AccentColorOption _accent = AppColors.cyanAccent;
  bool _highRiskAlertsEnabled = true;
  bool _hapticFeedbackEnabled = true;
  bool _cloudSyncEnabled = true;

  ThemeMode get themeMode => _themeMode;
  AccentColorOption get accent => _accent;
  Color get primaryColor => _accent.primary;
  Color get secondaryColor => _accent.secondary;
  Color get glowColor => _accent.glow;

  bool get highRiskAlertsEnabled => _highRiskAlertsEnabled;
  bool get hapticFeedbackEnabled => _hapticFeedbackEnabled;
  bool get cloudSyncEnabled => _cloudSyncEnabled;

  void setThemeMode(ThemeMode mode) {
    if (_themeMode == mode) return;
    _themeMode = mode;
    notifyListeners();
    _savePreferences();
  }

  void setAccentColor(AccentColorOption option) {
    if (_accent.name == option.name) return;
    _accent = option;
    notifyListeners();
    _savePreferences();
  }

  void setHighRiskAlerts(bool enabled) {
    _highRiskAlertsEnabled = enabled;
    notifyListeners();
    _savePreferences();
  }

  void setHapticFeedback(bool enabled) {
    _hapticFeedbackEnabled = enabled;
    notifyListeners();
    _savePreferences();
  }

  void setCloudSync(bool enabled) {
    _cloudSyncEnabled = enabled;
    notifyListeners();
    _savePreferences();
  }

  Future<void> _savePreferences() async {
    try {
      final user = FirebaseAuth.instance.currentUser;
      if (user != null) {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(user.uid)
            .collection('preferences')
            .doc('theme')
            .set({
          'themeMode': _themeMode.name,
          'accentName': _accent.name,
          'highRiskAlerts': _highRiskAlertsEnabled,
          'hapticFeedback': _hapticFeedbackEnabled,
          'cloudSync': _cloudSyncEnabled,
          'updatedAt': FieldValue.serverTimestamp(),
        }, SetOptions(merge: true));
      }
    } catch (_) {
      // Firebase may not be initialized in test environments or offline
    }
  }

  Future<void> loadPreferences() async {
    try {
      final user = FirebaseAuth.instance.currentUser;
      if (user != null) {
        final doc = await FirebaseFirestore.instance
            .collection('users')
            .doc(user.uid)
            .collection('preferences')
            .doc('theme')
            .get()
            .timeout(const Duration(seconds: 5));

        if (doc.exists && doc.data() != null) {
          final data = doc.data()!;
          final modeName = data['themeMode']?.toString();
          if (modeName == 'light') {
            _themeMode = ThemeMode.light;
          } else if (modeName == 'system') {
            _themeMode = ThemeMode.system;
          } else {
            _themeMode = ThemeMode.dark;
          }

          final accentName = data['accentName']?.toString();
          for (final preset in AppColors.accentPresets) {
            if (preset.name.toLowerCase() == accentName?.toLowerCase()) {
              _accent = preset;
              break;
            }
          }

          _highRiskAlertsEnabled = data['highRiskAlerts'] as bool? ?? true;
          _hapticFeedbackEnabled = data['hapticFeedback'] as bool? ?? true;
          _cloudSyncEnabled = data['cloudSync'] as bool? ?? true;

          notifyListeners();
        }
      }
    } catch (_) {
      // Firebase may not be initialized in test environments or offline
    }
  }
}

class AppTheme {
  static ThemeData darkTheme({Color? accentColor}) {
    final primary = accentColor ?? ThemeController.instance.primaryColor;
    final baseTheme = ThemeData.dark(useMaterial3: true);

    return baseTheme.copyWith(
      scaffoldBackgroundColor: AppColors.background,
      colorScheme: ColorScheme.dark(
        primary: primary,
        secondary: ThemeController.instance.secondaryColor,
        surface: AppColors.surface,
        error: AppColors.danger,
        onPrimary: AppColors.background,
        onSecondary: Colors.white,
        onSurface: AppColors.textPrimary,
        onError: Colors.white,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.background,
        elevation: 0,
        centerTitle: false,
        scrolledUnderElevation: 0,
        iconTheme: IconThemeData(color: AppColors.textPrimary),
        titleTextStyle: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w800,
          letterSpacing: -0.3,
        ),
      ),
      cardTheme: CardThemeData(
        color: AppColors.surface,
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.cardBorder, width: 1.2),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primary,
          foregroundColor: AppColors.background,
          elevation: 0,
          shadowColor: Colors.transparent,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 15),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 15,
            letterSpacing: 0.2,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: primary,
          side: BorderSide(color: primary, width: 1.5),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontWeight: FontWeight.w700,
            fontSize: 14,
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.surfaceLight,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.cardBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.cardBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: primary, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.danger, width: 1.5),
        ),
        hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 14),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
      ),
    );
  }

  static ThemeData lightTheme({Color? accentColor}) {
    final primary = accentColor ?? ThemeController.instance.primaryColor;
    final baseTheme = ThemeData.light(useMaterial3: true);

    return baseTheme.copyWith(
      scaffoldBackgroundColor: AppColors.lightBackground,
      colorScheme: ColorScheme.light(
        primary: primary,
        secondary: ThemeController.instance.secondaryColor,
        surface: AppColors.lightSurface,
        error: AppColors.danger,
        onPrimary: Colors.white,
        onSecondary: Colors.white,
        onSurface: AppColors.lightTextPrimary,
        onError: Colors.white,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.lightBackground,
        elevation: 0,
        centerTitle: false,
        scrolledUnderElevation: 0,
        iconTheme: IconThemeData(color: AppColors.lightTextPrimary),
        titleTextStyle: TextStyle(
          color: AppColors.lightTextPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w800,
          letterSpacing: -0.3,
        ),
      ),
      cardTheme: CardThemeData(
        color: AppColors.lightSurface,
        elevation: 1,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.lightCardBorder, width: 1.2),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primary,
          foregroundColor: Colors.white,
          elevation: 1,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 15),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontWeight: FontWeight.w800,
            fontSize: 15,
            letterSpacing: 0.2,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: primary,
          side: BorderSide(color: primary, width: 1.5),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontWeight: FontWeight.w700,
            fontSize: 14,
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.lightSurfaceLight,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.lightCardBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.lightCardBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: primary, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.danger, width: 1.5),
        ),
        hintStyle: const TextStyle(color: AppColors.lightTextMuted, fontSize: 14),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
      ),
    );
  }
}
