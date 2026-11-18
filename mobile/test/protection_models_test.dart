// Unit tests for CyberShield Real-Time Android Protection Models & Call Screening Role Flow

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/services/protection_service.dart';

void main() {
  group('InstalledAppInfo Unit Tests', () {
    test('parses from native map correctly', () {
      final nativeMap = {
        'packageName': 'com.fraud.banktrojan',
        'appName': 'Flash Player Update',
        'versionName': '2.1.0',
        'versionCode': '21',
        'isSystemApp': false,
        'permissions': [
          'android.permission.RECEIVE_SMS',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
        'minSdk': 24,
        'targetSdk': 34,
      };

      final app = InstalledAppInfo.fromNativeMap(nativeMap);
      expect(app.packageName, 'com.fraud.banktrojan');
      expect(app.appName, 'Flash Player Update');
      expect(app.isSystemApp, isFalse);
      expect(app.permissions.length, 3);
      expect(app.minSdk, 24);
      expect(app.targetSdk, 34);
      expect(app.isRisky, isFalse); // default prior to backend analysis
    });

    test('parses from backend JSON response with risk classification', () {
      final json = {
        'package_name': 'com.fraud.banktrojan',
        'app_name': 'Flash Player Update',
        'version_name': '2.1.0',
        'version_code': '21',
        'is_system_app': false,
        'risk_score': 85,
        'classification': 'Critical',
        'dangerous_permissions_count': 3,
        'dangerous_permissions': [
          'android.permission.RECEIVE_SMS',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
        ],
        'combo_findings': ['Banking Trojan Profile (SMS + Accessibility)'],
        'explanation': 'Severe banking trojan risk detected.',
        'recommendations': ['Uninstall immediately.'],
      };

      final app = InstalledAppInfo.fromJson(json);
      expect(app.isRisky, isTrue);
      expect(app.isCritical, isTrue);
      expect(app.isHighRisk, isFalse);
      expect(app.riskScore, 85);
      expect(app.classification, 'Critical');
      expect(app.comboFindings.length, 1);
    });

    test('serializes to batch request json', () {
      const app = InstalledAppInfo(
        packageName: 'com.safe.calculator',
        appName: 'Calculator',
        versionName: '1.0',
        permissions: ['android.permission.VIBRATE'],
      );

      final json = app.toBatchRequestJson();
      expect(json['package_name'], 'com.safe.calculator');
      expect(json['permissions'], ['android.permission.VIBRATE']);
    });
  });

  group('BatchAppScanResult Unit Tests', () {
    test('parses batch summary and app lists', () {
      final json = {
        'total_apps_analyzed': 10,
        'safe_count': 8,
        'suspicious_count': 1,
        'high_risk_count': 0,
        'critical_count': 1,
        'overall_device_risk_score': 85,
        'overall_classification': 'Critical',
        'summary': 'Audited 10 apps: 1 critical, 8 safe.',
        'high_risk_apps': [
          {
            'package_name': 'com.trojan.app',
            'app_name': 'Trojan',
            'risk_score': 85,
            'classification': 'Critical',
          }
        ],
        'all_apps': [],
        'recommendations': ['Remove critical applications immediately.'],
        'timestamp': '2026-11-10T12:00:00Z',
      };

      final result = BatchAppScanResult.fromJson(json);
      expect(result.totalAppsAnalyzed, 10);
      expect(result.criticalCount, 1);
      expect(result.overallClassification, 'Critical');
      expect(result.highRiskApps.length, 1);
      expect(result.highRiskApps.first.packageName, 'com.trojan.app');
    });
  });

  group('CallScreenResult Unit Tests', () {
    test('parses clean caller result', () {
      final json = {
        'phone_number': '+14155552671',
        'normalized_number': '+14155552671',
        'is_known_spam': false,
        'spam_score': 0,
        'classification': 'Safe',
        'confidence': 'Low',
        'report_count': 0,
        'evidence_tags': [],
        'recommended_action': 'allow',
        'explanation': 'No threats reported.',
      };

      final result = CallScreenResult.fromJson(json);
      expect(result.isKnownSpam, isFalse);
      expect(result.recommendedAction, 'allow');
      expect(result.classification, 'Safe');
    });

    test('parses spam caller result', () {
      final json = {
        'phone_number': '+19005559876',
        'normalized_number': '+19005559876',
        'is_known_spam': true,
        'spam_score': 75,
        'classification': 'Critical',
        'confidence': 'High',
        'report_count': 14,
        'evidence_tags': ['robocall', 'fraud'],
        'recommended_action': 'silence',
        'explanation': 'Confirmed predatory robocall.',
      };

      final result = CallScreenResult.fromJson(json);
      expect(result.isKnownSpam, isTrue);
      expect(result.recommendedAction, 'silence');
      expect(result.evidenceTags, contains('robocall'));
    });
  });

  group('NotificationScanResult Unit Tests', () {
    test('parses notification analysis with phishing URL and redaction', () {
      final json = {
        'package_name': 'com.unknown.messenger',
        'sanitized_text': 'Your card [REDACTED_CARD] was charged. Click http://scam.xyz',
        'detected_urls': ['http://scam.xyz'],
        'sms_risk_score': 40,
        'overall_risk_score': 80,
        'classification': 'Critical',
        'threat_types': ['phishing_url', 'financial_fraud'],
        'has_phishing_url': true,
        'has_financial_urgency': true,
        'has_impersonation': false,
        'redacted_sensitive_data': true,
        'explanation': 'Phishing link detected.',
        'recommended_action': 'Do not tap link.',
      };

      final result = NotificationScanResult.fromJson(json);
      expect(result.hasPhishingUrl, isTrue);
      expect(result.redactedSensitiveData, isTrue);
      expect(result.overallRiskScore, 80);
      expect(result.classification, 'Critical');
    });
  });

  group('ProtectionStatus Unit Tests', () {
    test('parses native map correctly', () {
      final map = {
        'isMasterEnabled': true,
        'isNotificationAccessGranted': true,
        'isCallScreeningRoleHeld': true,
        'isCallScreeningSupported': true,
        'androidSdk': 34,
        'silenceSpamCalls': true,
      };

      final status = ProtectionStatus.fromMap(map);
      expect(status.isMasterEnabled, isTrue);
      expect(status.isNotificationAccessGranted, isTrue);
      expect(status.isCallScreeningRoleHeld, isTrue);
      expect(status.androidSdk, 34);
    });

    test('parses unsupported Android 9 device status accurately', () {
      final map = {
        'isMasterEnabled': true,
        'isNotificationAccessGranted': true,
        'isCallScreeningRoleHeld': false,
        'isCallScreeningSupported': false,
        'callScreeningUnavailableReason':
            'Android Call Screening Role requires Android 10 (API 29) or higher. This device is running Android 9 (API 28).',
        'androidSdk': 28,
        'androidRelease': '9',
        'silenceSpamCalls': false,
      };

      final status = ProtectionStatus.fromMap(map);
      expect(status.isCallScreeningSupported, isFalse);
      expect(status.isCallScreeningRoleHeld, isFalse);
      expect(status.androidSdk, 28);
      expect(status.androidRelease, '9');
      expect(status.callScreeningUnavailableReason, contains('API 29'));
    });
  });

  group('CallScreeningRoleResult & MethodChannel Flow Tests', () {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('com.example.mobile/protection');

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    test('parses all role result states accurately', () {
      final granted = CallScreeningRoleResult.fromMap({
        'status': 'granted',
        'granted': true,
        'supported': true,
        'androidSdk': 34,
        'message': 'Role granted.',
      });
      expect(granted.isGranted, isTrue);
      expect(granted.isDenied, isFalse);
      expect(granted.isUnsupported, isFalse);

      final denied = CallScreeningRoleResult.fromMap({
        'status': 'denied',
        'granted': false,
        'supported': true,
        'androidSdk': 34,
        'message': 'User declined role.',
      });
      expect(denied.isGranted, isFalse);
      expect(denied.isDenied, isTrue);
      expect(denied.isUnsupported, isFalse);

      final unsupported = CallScreeningRoleResult.fromMap({
        'status': 'unsupported',
        'granted': false,
        'supported': false,
        'androidSdk': 28,
        'message': 'Requires Android 10 (API 29)+.',
      });
      expect(unsupported.isGranted, isFalse);
      expect(unsupported.isUnsupported, isTrue);
    });

    test('requestCallScreeningRole grants, denies, and detects revocation via MethodChannel', () async {
      bool roleHeld = false;

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        switch (call.method) {
          case 'requestCallScreeningRole':
            roleHeld = true;
            return {
              'status': 'granted',
              'granted': true,
              'supported': true,
              'androidSdk': 33,
              'message': 'Call Screening role granted.',
            };
          case 'getProtectionStatus':
            return {
              'isMasterEnabled': true,
              'isNotificationAccessGranted': true,
              'isCallScreeningRoleHeld': roleHeld,
              'isCallScreeningSupported': true,
              'androidSdk': 33,
              'androidRelease': '13',
              'silenceSpamCalls': false,
            };
          case 'syncBackendConfig':
            return true;
          default:
            return null;
        }
      });

      final grantedRes = await ProtectionService.instance.requestCallScreeningRole();
      expect(grantedRes.isGranted, isTrue);
      expect(ProtectionService.instance.statusNotifier.value.isCallScreeningRoleHeld, isTrue);
      expect(ProtectionService.instance.isRequestingCallRoleNotifier.value, isFalse);

      // Simulate user revoking the role in Android System Settings
      roleHeld = false;
      final refreshed = await ProtectionService.instance.refreshStatus();
      expect(refreshed.isCallScreeningRoleHeld, isFalse);
    });

    test('requestCallScreeningRole handles unsupported device cleanly', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        switch (call.method) {
          case 'requestCallScreeningRole':
            return {
              'status': 'unsupported',
              'granted': false,
              'supported': false,
              'androidSdk': 28,
              'message': 'Requires Android 10 (API 29) or higher.',
            };
          case 'getProtectionStatus':
            return {
              'isMasterEnabled': true,
              'isNotificationAccessGranted': true,
              'isCallScreeningRoleHeld': false,
              'isCallScreeningSupported': false,
              'androidSdk': 28,
              'androidRelease': '9',
              'silenceSpamCalls': false,
            };
          default:
            return null;
        }
      });

      final res = await ProtectionService.instance.requestCallScreeningRole();
      expect(res.isUnsupported, isTrue);
      expect(res.isGranted, isFalse);
      expect(ProtectionService.instance.statusNotifier.value.isCallScreeningSupported, isFalse);
      expect(ProtectionService.instance.statusNotifier.value.isCallScreeningRoleHeld, isFalse);
    });
  });
}

