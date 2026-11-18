import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/widgets/main_navigation_scaffold.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';
import 'package:cybershield/features/dashboard/screens/dashboard_screen.dart';
import 'package:cybershield/features/scan_hub/screens/scan_hub_screen.dart';
import 'package:cybershield/features/protection/screens/protection_dashboard_screen.dart';
import 'package:cybershield/features/history/screens/history_screen.dart';
import 'package:cybershield/features/settings/screens/settings_screen.dart';
import 'package:cybershield/features/settings/screens/permission_center_screen.dart';
import 'package:cybershield/features/communications/screens/communication_hub_screen.dart';
import 'package:cybershield/features/unified_events/screens/unified_security_hub_screen.dart';
import 'package:cybershield/features/alerts/screens/alerts_screen.dart';
import 'package:cybershield/features/community_reports/screens/community_reports_screen.dart';
import 'package:cybershield/features/ai_assistant/screens/ai_assistant_screen.dart';
import 'package:cybershield/features/url_scanner/screens/url_scanner_screen.dart';
import 'package:cybershield/features/sms_scanner/screens/sms_scanner_screen.dart';
import 'package:cybershield/features/qr_scanner/screens/qr_scanner_screen.dart';
import 'package:cybershield/features/screenshot_analysis/screens/screenshot_analysis_screen.dart';
import 'package:cybershield/features/apk_analysis/screens/apk_analysis_screen.dart';
import 'package:cybershield/features/permission_analyzer/screens/permission_analyzer_screen.dart';
import 'package:cybershield/features/email_scanner/screens/email_scanner_screen.dart';
import 'package:cybershield/features/file_scanner/screens/file_scanner_screen.dart';

/// Exact Redmi Y2 screen dimensions: 720x1440 @ 2.0x DPR = 360x720 logical pixels.
Future<void> _auditScreenOnRedmiY2(
  WidgetTester tester,
  String name,
  Widget screen, {
  int scrollSteps = 3,
}) async {
  tester.view.physicalSize = const Size(720, 1440);
  tester.view.devicePixelRatio = 2.0;
  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  final overflowErrors = <String>[];
  final prevOnError = FlutterError.onError;
  FlutterError.onError = (FlutterErrorDetails details) {
    final full = details.toString();
    final msg = details.exceptionAsString();
    if (msg.contains('overflowed') || msg.contains('RenderFlex')) {
      final locMatch = RegExp(r'lib/[^\s\)]+:\d+:\d+').firstMatch(full);
      final loc = locMatch?.group(0) ?? full.split('\n').take(6).join(' ');
      overflowErrors.add('[$name] $msg --> $loc');
    } else if (msg.contains('core/no-app') || msg.contains('Firebase')) {
      // Ignore Firebase uninitialized in isolated widget tests
    } else {
      prevOnError?.call(details);
    }
  };

  try {
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.darkTheme(),
        home: screen,
      ),
    );
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 300));

    // Scroll down to build lazy widgets and check off-screen items too
    final scrollable = find.byType(Scrollable);
    if (scrollable.evaluate().isNotEmpty) {
      for (int i = 0; i < scrollSteps; i++) {
        await tester.drag(scrollable.first, const Offset(0, -400), warnIfMissed: false);
        await tester.pump(const Duration(milliseconds: 150));
      }
    }
  } finally {
    FlutterError.onError = prevOnError;
  }

  expect(
    overflowErrors,
    isEmpty,
    reason: 'Overflow errors on Redmi Y2 (360x720) in $name:\n${overflowErrors.join('\n')}',
  );
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    SmartAlertEngine.instance.testUserIdOverride = 'redmi_y2_audit_uid';
    SmartAlertEngine.instance.testForceOffline = true;
    SmartAlertEngine.instance.testNotificationSink = (_) {};
  });

  tearDown(() {
    SmartAlertEngine.instance.testUserIdOverride = null;
    SmartAlertEngine.instance.testForceOffline = false;
    SmartAlertEngine.instance.testNotificationSink = null;
  });

  group('Redmi Y2 (360x720) Zero-Overflow UI Audit', () {
    testWidgets('MainNavigationScaffold + Draggable CYBOR AI', (t) async {
      await _auditScreenOnRedmiY2(t, 'MainNavigationScaffold', const MainNavigationScaffold(), scrollSteps: 2);
    });
    testWidgets('DashboardScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'DashboardScreen', const DashboardScreen(), scrollSteps: 8);
    });
    testWidgets('ScanHubScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'ScanHubScreen', const ScanHubScreen(), scrollSteps: 5);
    });
    testWidgets('ProtectionDashboardScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'ProtectionDashboardScreen', const ProtectionDashboardScreen(), scrollSteps: 6);
    });
    testWidgets('HistoryScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'HistoryScreen', const HistoryScreen(), scrollSteps: 3);
    });
    testWidgets('SettingsScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'SettingsScreen', const SettingsScreen(), scrollSteps: 6);
    });
    testWidgets('PermissionCenterScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'PermissionCenterScreen', const PermissionCenterScreen(), scrollSteps: 4);
    });
    testWidgets('CommunicationHubScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'CommunicationHubScreen', const CommunicationHubScreen(), scrollSteps: 4);
    });
    testWidgets('UnifiedSecurityHubScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'UnifiedSecurityHubScreen', const UnifiedSecurityHubScreen(), scrollSteps: 4);
    });
    testWidgets('AlertsScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'AlertsScreen', const AlertsScreen(), scrollSteps: 3);
    });
    testWidgets('CommunityReportsScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'CommunityReportsScreen', const CommunityReportsScreen(), scrollSteps: 3);
    });
    testWidgets('AiAssistantScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'AiAssistantScreen', const AiAssistantScreen(), scrollSteps: 2);
    });
    testWidgets('UrlScannerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'UrlScannerScreen', const UrlScannerScreen(), scrollSteps: 3);
    });
    testWidgets('SmsScannerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'SmsScannerScreen', const SmsScannerScreen(), scrollSteps: 3);
    });
    testWidgets('QrScannerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'QrScannerScreen', const QrScannerScreen(), scrollSteps: 3);
    });
    testWidgets('ScreenshotAnalysisScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'ScreenshotAnalysisScreen', const ScreenshotAnalysisScreen(), scrollSteps: 3);
    });
    testWidgets('ApkAnalysisScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'ApkAnalysisScreen', const ApkAnalysisScreen(), scrollSteps: 3);
    });
    testWidgets('PermissionAnalyzerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'PermissionAnalyzerScreen', const PermissionAnalyzerScreen(), scrollSteps: 3);
    });
    testWidgets('EmailScannerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'EmailScannerScreen', const EmailScannerScreen(), scrollSteps: 3);
    });
    testWidgets('FileScannerScreen', (t) async {
      await _auditScreenOnRedmiY2(t, 'FileScannerScreen', const FileScannerScreen(), scrollSteps: 3);
    });
    testWidgets('NavDrawer', (t) async {
      await _auditScreenOnRedmiY2(t, 'NavDrawer', const Scaffold(body: NavDrawer(currentRoute: '/')), scrollSteps: 4);
    });
  });
}
