// Unit & Widget tests for CyberShield Communication History & Threat Percentage Tracking

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/features/communications/screens/communication_detail_screen.dart';
import 'package:cybershield/features/communications/screens/communication_hub_screen.dart';

void main() {
  group('CommunicationRiskThresholds & Redaction Unit Tests', () {
    test('classifies 0-100 risk scores into exact configured tiers', () {
      const t = CommunicationRiskThresholds();
      expect(t.classify(0), 'Safe');
      expect(t.classify(20), 'Safe');
      expect(t.classify(21), 'Low Risk');
      expect(t.classify(40), 'Low Risk');
      expect(t.classify(41), 'Suspicious');
      expect(t.classify(60), 'Suspicious');
      expect(t.classify(61), 'High Risk');
      expect(t.classify(80), 'High Risk');
      expect(t.classify(81), 'Critical');
      expect(t.classify(100), 'Critical');
    });

    test('redacts OTPs, credit card numbers, CVVs, and passwords on-device', () {
      const raw =
          'Your OTP: 583920 for card 4532 1111 2222 3333 cvv: 742 password=TopSecret99';
      final clean = CommunicationService.redactSensitive(raw);
      expect(clean, isNot(contains('583920')));
      expect(clean, isNot(contains('4532 1111 2222 3333')));
      expect(clean, isNot(contains('742')));
      expect(clean, isNot(contains('TopSecret99')));
      expect(clean, contains('[REDACTED_OTP]'));
      expect(clean, contains('[REDACTED_CARD]'));
    });

    test('computes accurate local analytics separating analyzed vs unanalyzed and SMS vs Calls', () {
      final now = DateTime.now();
      final records = [
        CommunicationRecord(
          recordId: 'r1',
          userId: 'u1',
          communicationType: 'sms',
          sourceApp: 'SMS',
          senderIdentifier: '+919999999999',
          messagePreview: 'Hello friend',
          timestamp: now,
          riskScore: 5,
          classification: 'Safe',
          analysisStatus: 'analyzed',
        ),
        CommunicationRecord(
          recordId: 'r2',
          userId: 'u1',
          communicationType: 'sms',
          sourceApp: 'SMS',
          senderIdentifier: 'SCAM-BANK',
          messagePreview: 'Click http://evil.xyz',
          timestamp: now,
          riskScore: 85,
          classification: 'Critical',
          threatCategories: const ['phishing_url', 'financial_fraud'],
          analysisStatus: 'analyzed',
        ),
        CommunicationRecord(
          recordId: 'r3',
          userId: 'u1',
          communicationType: 'call',
          sourceApp: 'Phone Call',
          senderIdentifier: '+14155550199',
          timestamp: now,
          riskScore: 0,
          classification: 'Safe',
          isKnownContact: false,
          callStatus: 'missed',
          analysisStatus: 'analyzed',
        ),
        CommunicationRecord(
          recordId: 'r4',
          userId: 'u1',
          communicationType: 'notification',
          sourceApp: 'WhatsApp',
          senderIdentifier: 'OfflineMsg',
          timestamp: now,
          riskScore: 0,
          classification: 'Unavailable',
          analysisStatus: 'unanalyzed',
        ),
      ];

      final daily = CommunicationService.computeAnalyticsLocally(records, period: 'daily');
      expect(daily.overall.totalReceived, 4);
      expect(daily.overall.totalAnalyzed, 3);
      expect(daily.overall.totalUnanalyzed, 1);
      expect(daily.overall.safeCount, 2);
      expect(daily.overall.criticalCount, 1);
      expect(daily.overall.threatFlaggedCount, 1);
      expect(daily.overall.threatDetectionRate, closeTo(33.3, 0.1));
      expect(daily.messages.totalAnalyzed, 2);
      expect(daily.messages.threatDetectionRate, 50.0);
      expect(daily.calls.totalAnalyzed, 1);
      expect(daily.calls.unknownCallersCount, 1);
      expect(daily.calls.threatDetectionRate, 0.0);

      final monthly = CommunicationService.computeAnalyticsLocally(records, period: 'monthly');
      expect(monthly.trends.length, 6);
    });
  });

  group('Communication UI Widget Tests', () {
    testWidgets('CommunicationDetailScreen displays risk percentage and call audio privacy disclaimer',
        (WidgetTester tester) async {
      final callRec = CommunicationRecord(
        recordId: 'call-1',
        userId: 'u1',
        communicationType: 'call',
        sourceApp: 'Phone Call',
        senderIdentifier: '+19005559988',
        callerName: 'Suspected Robocaller',
        timestamp: DateTime(2026, 11, 18, 9, 30),
        riskScore: 78,
        classification: 'High Risk',
        threatCategories: const ['robocall', 'fraud'],
        findings: const ['Reported 5 times by community members.'],
        explanation: 'High spam caller reputation score.',
        recommendedAction: 'Silence or decline call.',
        analysisStatus: 'analyzed',
        isKnownContact: false,
        callStatus: 'silenced',
        spamReputation: 'reported_suspicious',
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: CommunicationDetailScreen(record: callRec),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('78%'), findsOneWidget);
      expect(find.text('Suspected Robocaller'), findsOneWidget);
      expect(find.textContaining('never records or analyzes call audio'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('CommunicationHubScreen renders first-activation privacy consent cleanly',
        (WidgetTester tester) async {
      CommunicationService.instance.settingsNotifier.value = const CommunicationSettings(
        consentAcknowledged: false,
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: const CommunicationHubScreen(),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Communication Security & Privacy Consent'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.text('Enable Communication Security'),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.text('Enable Communication Security'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  });
}
