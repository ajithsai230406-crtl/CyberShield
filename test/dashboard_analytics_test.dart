import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/models/dashboard_analytics.dart';

void main() {
  group('DashboardAnalytics Model Tests', () {
    test('SecurityScoreModel parses correctly and retains disclaimer', () {
      final json = {
        'score': 88,
        'status': 'Strong Defense Posture',
        'tier': 'Optimal',
        'calculation_explanation': '100 base score minus threat penalties.',
        'disclaimer':
            'Advisory Notice: CyberShield Security Score reflects evaluated scan telemetry and cyber hygiene. No automated security system can guarantee 100% device immunity against emerging zero-day vulnerabilities.',
      };

      final model = SecurityScoreModel.fromJson(json);
      expect(model.score, 88);
      expect(model.status, 'Strong Defense Posture');
      expect(model.tier, 'Optimal');
      expect(model.disclaimer, contains('No automated security system can guarantee 100% device immunity'));
      expect(model.toJson()['score'], 88);
    });

    test('DashboardAnalytics parses complex payload with scanner breakdown and trends', () {
      final json = {
        'time_range_days': 30,
        'total_scans': 25,
        'safe_scans': 20,
        'suspicious_scans': 3,
        'high_risk_scans': 1,
        'critical_scans': 1,
        'threat_detection_rate': 20.0,
        'security_score': {
          'score': 74,
          'status': 'Moderate Protection',
          'tier': 'Guarded',
          'calculation_explanation': 'Formula breakdown',
          'disclaimer': 'Mandatory non-absolute notice',
        },
        'scanner_breakdown': {
          'URL': {'total': 10, 'safe': 8, 'threats': 2},
          'SMS': {'total': 5, 'safe': 5, 'threats': 0},
          'QR': {'total': 4, 'safe': 3, 'threats': 1},
          'FILE': {'total': 6, 'safe': 4, 'threats': 2},
        },
        'risk_distribution': {
          'safe': 20,
          'suspicious': 3,
          'high_risk': 1,
          'critical': 1,
        },
        'activity_trends': [
          {'date': '2026-11-08', 'total': 12, 'safe': 10, 'threats': 2},
          {'date': '2026-11-09', 'total': 13, 'safe': 10, 'threats': 3},
        ],
        'community_stats': {
          'total_reports': 50,
          'distinct_targets': 30,
          'active_reporters': 15,
          'verified_threats': 10,
        },
        'recent_scans': [
          {
            'id': 'scan_1',
            'scan_id': 'scan_1',
            'scan_type': 'URL',
            'target': 'https://evil.example.com',
            'risk_score': 85,
            'classification': 'Critical',
            'timestamp': '2026-11-09T18:00:00Z',
          }
        ],
        'timestamp': '2026-11-09T18:30:00Z',
      };

      final analytics = DashboardAnalytics.fromJson(json);

      expect(analytics.totalScans, 25);
      expect(analytics.safeScans, 20);
      expect(analytics.threatDetectionRate, 20.0);
      expect(analytics.securityScore.score, 74);
      expect(analytics.scannerBreakdown.containsKey('URL'), isTrue);
      expect(analytics.scannerBreakdown['URL']!.total, 10);
      expect(analytics.scannerBreakdown['URL']!.threats, 2);
      expect(analytics.activityTrends.length, 2);
      expect(analytics.communityStats.totalReports, 50);
      expect(analytics.recentScans.first.target, 'https://evil.example.com');
      expect(analytics.recentScans.first.classification, 'Critical');
    });

    test('DashboardAnalytics handles empty or fallback json gracefully', () {
      final analytics = DashboardAnalytics.fromJson({});
      expect(analytics.totalScans, 0);
      expect(analytics.safeScans, 0);
      expect(analytics.threatDetectionRate, 0.0);
      expect(analytics.securityScore.score, 70);
      expect(analytics.scannerBreakdown.isEmpty, isTrue);
      expect(analytics.activityTrends.isEmpty, isTrue);
      expect(analytics.recentScans.isEmpty, isTrue);
    });
  });
}

