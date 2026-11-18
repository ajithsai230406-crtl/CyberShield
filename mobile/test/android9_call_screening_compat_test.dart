import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/features/protection/screens/protection_dashboard_screen.dart';
import 'package:cybershield/features/settings/screens/settings_screen.dart';
import 'package:cybershield/features/settings/screens/permission_center_screen.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  group('Redmi Y2 Android 9 (API 28) vs Android 10+ Call Screening Compatibility', () {
    testWidgets('Android 9 (API 28): shows Unsupported notice, hides Set Role / ACTIVE, keeps Manual Check & other modules active',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(720, 2400);
      tester.view.devicePixelRatio = 2.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      ProtectionService.instance.statusNotifier.value = const ProtectionStatus(
        isMasterEnabled: true,
        isNotificationAccessGranted: true,
        isCallScreeningSupported: false,
        isCallScreeningRoleHeld: false,
        androidSdk: 28,
        androidRelease: '9',
        callScreeningUnavailableReason:
            'Native Call Screening Unsupported on This Device. Automatic CallScreeningService requires Android 10 (API 29) or higher; detected Android 9 (API 28).',
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: const ProtectionDashboardScreen(),
        ),
      );
      await tester.pump(const Duration(milliseconds: 200));

      expect(find.text('Native Call Screening Unsupported on This Device'), findsOneWidget);
      expect(find.text('Set Call Screening Role'), findsNothing);
      expect(find.text('ROLE ACTIVE'), findsNothing);
      expect(find.text('Manual Phone-Number Reputation Check'), findsOneWidget);
      // Other protection modules remain fully active!
      expect(find.text('Notification Guard'), findsOneWidget);
      await tester.drag(find.byType(ListView).first, const Offset(0, -500));
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.text('Installed Apps Inventory'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('Android 9 (API 28) SettingsScreen & PermissionCenterScreen hide Set Role and show Unsupported message',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(720, 3200);
      tester.view.devicePixelRatio = 2.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      ProtectionService.instance.statusNotifier.value = const ProtectionStatus(
        isMasterEnabled: true,
        isNotificationAccessGranted: true,
        isCallScreeningSupported: false,
        isCallScreeningRoleHeld: false,
        androidSdk: 28,
        androidRelease: '9',
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: const PermissionCenterScreen(),
        ),
      );
      await tester.pump(const Duration(milliseconds: 200));

      expect(find.text('Native Call Screening Unsupported on This Device'), findsOneWidget);
      expect(find.text('Set Role'), findsNothing);
      expect(find.text('Manual Number Check'), findsOneWidget);
      expect(tester.takeException(), isNull);

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: const SettingsScreen(),
        ),
      );
      await tester.pump(const Duration(milliseconds: 200));

      expect(find.text('Set Role'), findsNothing);
      expect(find.text('Unsupported'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('Android 10+ (API 29+): enables official CallScreeningService role request alongside Manual Check',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(720, 2400);
      tester.view.devicePixelRatio = 2.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      ProtectionService.instance.statusNotifier.value = const ProtectionStatus(
        isMasterEnabled: true,
        isNotificationAccessGranted: true,
        isCallScreeningSupported: true,
        isCallScreeningRoleHeld: false,
        androidSdk: 33,
        androidRelease: '13',
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: const ProtectionDashboardScreen(),
        ),
      );
      await tester.pump(const Duration(milliseconds: 200));

      expect(find.text('Automatic Incoming Call Screening (Android 10+)'), findsOneWidget);
      expect(find.text('Set Call Screening Role'), findsOneWidget);
      expect(find.text('Auto-Silence Verified Spam Callers'), findsOneWidget);
      expect(find.text('Manual Phone-Number Reputation Check'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  });
}
