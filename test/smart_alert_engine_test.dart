import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/models/security_event_model.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/features/unified_events/screens/unified_security_hub_screen.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    final engine = SmartAlertEngine.instance;
    engine.resetForAccountSwitch();
    engine.testUserIdOverride = 'unit_test_uid';
    engine.testForceOffline = true;
    engine.testNotificationSink = null;
    engine.prefsNotifier.value = const SmartNotificationPrefs();
  });

  tearDown(() {
    final engine = SmartAlertEngine.instance;
    engine.testUserIdOverride = null;
    engine.testForceOffline = false;
    engine.testNotificationSink = null;
  });

  test('All 18 CyberShield modules are registered and normalize properly', () {
    expect(kAll18Modules.length, 18);
    expect(SmartAlertEngine.normalizeModule('URL'), 'url_scanner');
    expect(SmartAlertEngine.normalizeModule('SMS'), 'sms_scanner');
    expect(SmartAlertEngine.normalizeModule('QR'), 'qr_scanner');
    expect(SmartAlertEngine.normalizeModule('SCREENSHOT'), 'screenshot_analyzer');
    expect(SmartAlertEngine.normalizeModule('APK'), 'apk_analyzer');
    expect(SmartAlertEngine.normalizeModule('FILE'), 'file_scanner');
    expect(SmartAlertEngine.normalizeModule('PERMISSIONS'), 'permission_analyzer');
    expect(SmartAlertEngine.normalizeModule('EMAIL'), 'email_scanner');
    expect(SmartAlertEngine.normalizeModule('GMAIL'), 'gmail_integration');
    expect(SmartAlertEngine.normalizeModule('call'), 'call_screening');
    expect(SmartAlertEngine.normalizeModule('notification'), 'notification_monitor');
    expect(SmartAlertEngine.normalizeModule('INSTALLED_APPS'), 'installed_app_audit');
    expect(SmartAlertEngine.normalizeModule('community'), 'community_threat_intel');
    expect(SmartAlertEngine.normalizeModule('assistant'), 'ai_security_assistant');
    expect(SmartAlertEngine.normalizeModule('analytics'), 'dashboard_analytics');
    expect(SmartAlertEngine.normalizeModule('alerts'), 'security_alerts');
    expect(SmartAlertEngine.normalizeModule('history'), 'audit_history');
    expect(SmartAlertEngine.normalizeModule('protection'), 'realtime_protection');
  });

  test('Smart notification rules: Critical/High immediate, Suspicious per pref, Safe suppressed, Lock-screen safe', () async {
    final delivered = <Map<String, dynamic>>[];
    final engine = SmartAlertEngine.instance;
    engine.testNotificationSink = delivered.add;

    // 1. Safe event: stored silently (not notified by default)
    final safeEvt = await engine.submitEvent(
      moduleName: 'url_scanner',
      targetIdentifier: 'https://www.wikipedia.org',
      riskScore: 5,
      explanation: 'Safe website.',
      idempotencyKey: 'safe-1',
    );
    expect(safeEvt, isNotNull);
    expect(safeEvt!.classification, 'Safe');
    expect(delivered.length, 0);

    // 2. High-risk event: delivered immediately with module label & hideOnLockScreen=true
    final highEvt = await engine.submitEvent(
      moduleName: 'sms_scanner',
      targetIdentifier: 'VM-SCAM',
      riskScore: 86,
      explanation: 'Urgent bank scam with OTP: 982341 and card 4111 2222 3333 4444',
      idempotencyKey: 'high-1',
    );
    expect(highEvt, isNotNull);
    expect(highEvt!.classification, 'Critical');
    expect(highEvt.explanation.contains('982341'), isFalse);
    expect(highEvt.explanation.contains('4111 2222'), isFalse);
    expect(delivered.length, 1);
    expect(delivered.last['moduleName'], 'SMS Scanner');
    expect(delivered.last['hideOnLockScreen'], isTrue);

    // 3. Suspicious event when disabled in preferences: NOT notified
    engine.prefsNotifier.value = const SmartNotificationPrefs(notifySuspicious: false);
    final suspEvt = await engine.submitEvent(
      moduleName: 'qr_scanner',
      targetIdentifier: 'http://bit.ly/promo-check',
      riskScore: 52,
      explanation: 'Shortened URL detected.',
      idempotencyKey: 'susp-1',
    );
    expect(suspEvt!.classification, 'Suspicious');
    expect(delivered.length, 1); // unchanged!

    // 4. Failed / Unavailable event is NEVER marked Safe and queues offline
    final failEvt = await engine.submitEvent(
      moduleName: 'call_screening',
      targetIdentifier: '+15550001234',
      riskScore: 0,
      analysisStatus: 'unavailable',
      explanation: 'Offline during call check.',
      idempotencyKey: 'fail-1',
    );
    expect(failEvt!.classification, 'Unavailable');
    expect(failEvt.isFailedOrUnavailable, isTrue);
    expect(failEvt.isSafe, isFalse);
    expect(engine.offlineQueueCountNotifier.value, 4);

    // 5. Analytics strictly separates Safe, Threats, and Failed/Unavailable
    final stats = engine.analyticsNotifier.value;
    expect(stats.totalAnalyzedEvents, 3);
    expect(stats.safeCount, 1);
    expect(stats.totalThreatsDetected, 2);
    expect(stats.failedOrUnavailableEvents, 1);
    expect(stats.totalRegisteredModules, 18);
  });

  testWidgets('UnifiedSecurityHubScreen renders all 3 tabs cleanly without ListTile assertions',
      (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2400);
    tester.view.devicePixelRatio = 2.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final engine = SmartAlertEngine.instance;
    engine.testNotificationSink = (_) {};
    await tester.runAsync(() async {
      await engine.initialize();
      await engine.submitEvent(
        moduleName: 'email_scanner',
        targetIdentifier: 'alerts@phish.test',
        riskScore: 78,
        explanation: 'Phishing link detected in email body.',
        idempotencyKey: 'ui-evt-1',
        skipBackendPost: true,
      );
    });

    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.darkTheme(),
        home: const UnifiedSecurityHubScreen(),
      ),
    );
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.takeException(), isNull);
    expect(find.text('Unified Event Center'), findsOneWidget);
    expect(find.text('alerts@phish.test'), findsOneWidget);

    // Switch to Analytics tab
    await tester.tap(find.text('Analytics'));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.takeException(), isNull);
    expect(find.text('Device Posture Score'), findsOneWidget);
    expect(find.text('Threat Detection %'), findsOneWidget);
    expect(find.text('All 18 Integrated Modules Breakdown'), findsOneWidget);

    // Switch to Smart Alerts tab (contains SwitchListTiles inside CyberShieldCard)
    await tester.tap(find.text('Smart Alerts'));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.takeException(), isNull);
    expect(find.text('Active Smart Alert Delivery Policy'), findsOneWidget);
    expect(find.text('Hide Sensitive Content on Lock Screen'), findsOneWidget);
  });
}
