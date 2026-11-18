import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:cybershield/core/models/security_alert.dart';
import 'package:cybershield/core/theme/app_theme.dart';

void main() {
  group('SecurityAlertModel Unit Tests', () {
    test('parses critical alert payload correctly', () {
      final json = {
        'id': 'alert-001',
        'user_id': 'user-123',
        'scan_id': 'scan-456',
        'event_key': 'key-789',
        'title': 'Critical Phishing Link Detected: badsite.com',
        'severity': 'critical',
        'category': 'URL',
        'target': 'https://badsite.com',
        'risk_score': 95,
        'explanation': 'Phishing domain impersonating financial bank.',
        'recommended_actions': [
          'Do not click or open URL',
          'Block sender domain',
          'Clear browser cache',
        ],
        'status': 'unread',
        'is_read': false,
        'is_resolved': false,
        'timestamp': '2026-11-10T00:00:00Z',
        'metadata': {'source': 'scanner_engine'},
      };

      final alert = SecurityAlertModel.fromJson(json);

      expect(alert.id, 'alert-001');
      expect(alert.userId, 'user-123');
      expect(alert.scanId, 'scan-456');
      expect(alert.severity, 'critical');
      expect(alert.category, 'URL');
      expect(alert.target, 'https://badsite.com');
      expect(alert.riskScore, 95);
      expect(alert.recommendedActions.length, 3);
      expect(alert.isRead, isFalse);
      expect(alert.isResolved, isFalse);
      expect(alert.severityColor, AppColors.danger);
      expect(alert.categoryIcon, Icons.link_rounded);

      // JSON roundtrip
      final serialized = alert.toJson();
      expect(serialized['id'], 'alert-001');
      expect(serialized['severity'], 'critical');
      expect(serialized['risk_score'], 95);
    });

    test('state transitions with copyWith work properly', () {
      final original = SecurityAlertModel(
        id: 'alert-002',
        title: 'SMS Scam Finding',
        severity: 'high',
        category: 'SMS',
        target: '+18885550199',
        riskScore: 70,
        explanation: 'Smishing alert',
        recommendedActions: const ['Block number'],
        status: 'unread',
        isRead: false,
        isResolved: false,
        timestamp: '2026-11-10T00:00:00Z',
      );

      // Mark read
      final readAlert = original.copyWith(isRead: true, status: 'read');
      expect(readAlert.isRead, isTrue);
      expect(readAlert.status, 'read');
      expect(readAlert.isResolved, isFalse);

      // Mark resolved
      final resolvedAlert = readAlert.copyWith(
        isResolved: true,
        status: 'resolved',
        resolvedAt: '2026-11-10T00:10:00Z',
      );
      expect(resolvedAlert.isResolved, isTrue);
      expect(resolvedAlert.status, 'resolved');
      expect(resolvedAlert.resolvedAt, isNotNull);
    });

    test('AlertStatsModel parses macro counts correctly', () {
      final json = {
        'total': 15,
        'unread': 4,
        'critical': 2,
        'high': 3,
        'medium': 5,
        'low': 5,
        'resolved': 11,
      };

      final stats = AlertStatsModel.fromJson(json);
      expect(stats.total, 15);
      expect(stats.unread, 4);
      expect(stats.critical, 2);
      expect(stats.high, 3);
      expect(stats.medium, 5);
      expect(stats.low, 5);
      expect(stats.resolved, 11);
    });
  });
}

