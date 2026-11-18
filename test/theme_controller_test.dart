import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/theme/app_theme.dart';

void main() {
  group('ThemeController & AppTheme Unit Tests', () {
    test('initial state defaults to Dark mode and Cyan accent', () {
      final ctrl = ThemeController.instance;
      expect(ctrl.themeMode, ThemeMode.dark);
      expect(ctrl.accent.name, 'Cyan');
      expect(ctrl.primaryColor, const Color(0xFF00E5FF));
    });

    test('setting theme mode updates state and triggers notification', () {
      final ctrl = ThemeController.instance;
      bool notified = false;
      ctrl.addListener(() => notified = true);

      ctrl.setThemeMode(ThemeMode.light);
      expect(ctrl.themeMode, ThemeMode.light);
      expect(notified, isTrue);

      // Revert to dark mode
      ctrl.setThemeMode(ThemeMode.dark);
      expect(ctrl.themeMode, ThemeMode.dark);
    });

    test('setting accent color updates primary and glow colors', () {
      final ctrl = ThemeController.instance;
      ctrl.setAccentColor(AppColors.greenAccent);

      expect(ctrl.accent.name, 'Emerald');
      expect(ctrl.primaryColor, const Color(0xFF00E676));

      // Reset to cyan
      ctrl.setAccentColor(AppColors.cyanAccent);
      expect(ctrl.accent.name, 'Cyan');
    });

    test('accent presets include 5 required cyber themes', () {
      final presets = AppColors.accentPresets;
      expect(presets.length, 5);
      final names = presets.map((p) => p.name).toList();
      expect(names, containsAll(['Cyan', 'Emerald', 'Violet', 'Crimson', 'Aqua']));
    });

    test('darkTheme and lightTheme produce valid ThemeData with custom accent', () {
      final dark = AppTheme.darkTheme(accentColor: const Color(0xFF9D4EDD));
      expect(dark.colorScheme.primary, const Color(0xFF9D4EDD));
      expect(dark.scaffoldBackgroundColor, AppColors.background);

      final light = AppTheme.lightTheme(accentColor: const Color(0xFF00E676));
      expect(light.colorScheme.primary, const Color(0xFF00E676));
      expect(light.scaffoldBackgroundColor, AppColors.lightBackground);
    });
  });
}

