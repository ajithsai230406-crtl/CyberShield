import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/models/community_report.dart';

void main() {
  group('Community Threat Models Unit Tests', () {
    test('CommunityReputation parses unverified reports correctly', () {
      final json = {
        'category': 'phone',
        'target': '+18005550199',
        'total_reports': 5,
        'distinct_reporters': 3,
        'suspicion_score': 45,
        'classification': 'Community Flagged',
        'confidence': 'Moderate',
        'threat_status': 'UNVERIFIED_COMMUNITY_FLAGGED',
        'is_verified_threat': false,
        'last_reported_at': '2026-11-09T18:00:00Z',
        'evidence_tags': [
          {'tag': 'robocall', 'count': 4},
          {'tag': 'irs_scam', 'count': 3},
        ],
        'disclaimer': 'Test disclaimer',
      };

      final rep = CommunityReputation.fromJson(json);
      expect(rep.category, 'phone');
      expect(rep.target, '+18005550199');
      expect(rep.totalReports, 5);
      expect(rep.distinctReporters, 3);
      expect(rep.suspicionScore, 45);
      expect(rep.confidence, 'Moderate');
      expect(rep.isVerifiedThreat, false);
      expect(rep.evidenceTags.length, 2);
      expect(rep.evidenceTags.first.tag, 'robocall');
      expect(rep.evidenceTags.first.count, 4);
    });

    test('CommunityReport parses report payload and nested reputation', () {
      final json = {
        'id': 'rep-abc123xyz',
        'category': 'url',
        'target': 'https://fake-login.xyz',
        'target_display': 'https://fake-login.xyz',
        'title': 'Phishing portal',
        'description': 'Captures user credentials',
        'tags': ['phishing', 'fake_bank'],
        'status': 'PENDING',
        'is_verified': false,
        'created_at': '2026-11-09T18:30:00Z',
        'reputation': {
          'category': 'url',
          'target': 'https://fake-login.xyz',
          'total_reports': 1,
          'distinct_reporters': 1,
          'suspicion_score': 25,
          'classification': 'Single Community Report',
          'confidence': 'Low',
          'threat_status': 'UNVERIFIED_COMMUNITY_FLAGGED',
          'is_verified_threat': false,
          'disclaimer': 'Test disclaimer',
        },
      };

      final report = CommunityReport.fromJson(json);
      expect(report.id, 'rep-abc123xyz');
      expect(report.category, 'url');
      expect(report.title, 'Phishing portal');
      expect(report.tags.length, 2);
      expect(report.reputation, isNotNull);
      expect(report.reputation!.suspicionScore, 25);
      expect(report.reputation!.confidence, 'Low');
    });

    test('CommunityStats parses macro counts', () {
      final json = {
        'total_reports': 42,
        'distinct_targets': 30,
        'active_reporters': 18,
        'verified_threats': 4,
        'categories': {
          'phone': 15,
          'url': 12,
          'sms': 10,
          'qr': 2,
          'email': 2,
          'app': 1,
        },
        'timestamp': '2026-11-09T18:45:00Z',
      };

      final stats = CommunityStats.fromJson(json);
      expect(stats.totalReports, 42);
      expect(stats.distinctTargets, 30);
      expect(stats.activeReporters, 18);
      expect(stats.verifiedThreats, 4);
      expect(stats.categories['phone'], 15);
      expect(stats.categories['app'], 1);
    });
  });
}

