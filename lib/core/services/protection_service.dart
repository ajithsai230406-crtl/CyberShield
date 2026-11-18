// CyberShield Real-Time Android Protection Service
// Bridges Flutter UI with Android Kotlin Services (NotificationListenerService & CallScreeningService)
// and handles batch application audits, real-time alert streaming, and local notifications.

import 'dart:async';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/alert_service.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/app.dart';

class ProtectionService {
  static final ProtectionService instance = ProtectionService._internal();
  ProtectionService._internal();

  static const MethodChannel _methodChannel = MethodChannel('com.example.mobile/protection');
  static const EventChannel _eventChannel = EventChannel('com.example.mobile/protection_events');

  // Value notifiers for reactive UI binding
  final ValueNotifier<ProtectionStatus> statusNotifier =
      ValueNotifier<ProtectionStatus>(const ProtectionStatus());

  final ValueNotifier<bool> isRequestingCallRoleNotifier = ValueNotifier<bool>(false);

  final ValueNotifier<BatchAppScanResult?> lastBatchScanNotifier =
      ValueNotifier<BatchAppScanResult?>(null);

  final ValueNotifier<bool> isScanningAppsNotifier = ValueNotifier<bool>(false);

  final ValueNotifier<List<ProtectionEventLogItem>> recentEventsNotifier =
      ValueNotifier<List<ProtectionEventLogItem>>([]);

  final ValueNotifier<int> totalInterceptedNotifier = ValueNotifier<int>(0);
  final ValueNotifier<int> threatsBlockedNotifier = ValueNotifier<int>(0);
  final ValueNotifier<int> safePassedNotifier = ValueNotifier<int>(0);

  final ValueNotifier<String> alertSensitivityNotifier =
      ValueNotifier<String>('HIGH'); // 'STANDARD' (60+), 'HIGH' (40+), 'MAXIMUM' (25+)

  final ValueNotifier<List<String>> trustedAppsNotifier =
      ValueNotifier<List<String>>([
    'com.google.android.apps.messaging',
    'com.whatsapp',
    'com.android.dialer',
  ]);

  StreamSubscription? _eventSubscription;
  bool _isListening = false;
  bool _hasObservedInitialStatus = false;

  /// Masks sensitive numeric sequences like OTPs and card numbers
  static String maskSensitiveText(String text) {
    var result = text;
    // OTPs (4 to 8 digits)
    result = result.replaceAll(RegExp(r'\b\d{4,8}\b'), '******');
    // Credit card / debit card numbers
    result = result.replaceAll(RegExp(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'), '****-****-****-****');
    return result;
  }

  /// Appends an event to the Live Sentry buffer with automatic sensitive data masking
  void recordEventLog({
    required String type,
    required String source,
    required String title,
    required String rawContent,
    required int riskScore,
    required String classification,
    bool isSimulated = false,
    String? recommendedAction,
  }) {
    final masked = maskSensitiveText(rawContent);
    final isThreat = riskScore >= 35 || classification != 'Safe';

    totalInterceptedNotifier.value++;
    if (isThreat) {
      threatsBlockedNotifier.value++;
    } else {
      safePassedNotifier.value++;
    }

    final item = ProtectionEventLogItem(
      id: 'evt-${DateTime.now().millisecondsSinceEpoch}',
      type: type,
      source: source,
      title: title,
      maskedContent: masked,
      riskScore: riskScore,
      classification: classification,
      timestamp: DateTime.now(),
      isSimulated: isSimulated,
      recommendedAction: recommendedAction,
    );

    final current = List<ProtectionEventLogItem>.from(recentEventsNotifier.value);
    current.insert(0, item);
    if (current.length > 50) current.removeLast();
    recentEventsNotifier.value = current;
  }

  /// Initialize service, check status, sync native config, and start listening to real-time events
  Future<void> initialize() async {
    await refreshStatus();
    await syncNativeBackendConfig();
    await loadNativeScreenedCallHistory();
    startEventListener();
    await checkInitialNotificationLaunch();
  }

  /// Check if the application was launched from a CyberShield notification tap
  Future<void> checkInitialNotificationLaunch() async {
    try {
      final payload = await _methodChannel.invokeMethod<Map<dynamic, dynamic>>('getInitialNotificationPayload');
      if (payload != null && payload.isNotEmpty) {
        final map = Map<String, dynamic>.from(payload);
        await _methodChannel.invokeMethod('clearInitialNotificationPayload');
        handleThreatNavigation(map);
      }
    } on MissingPluginException {
      // Non-Android
    } catch (_) {}
  }

  /// Direct the user to the appropriate detection screen based on notification event
  void handleThreatNavigation(Map<String, dynamic> data) {
    final screen = data['screen']?.toString();
    final type = data['type']?.toString();
    final navigator = CyberShieldApp.navigatorKey.currentState;
    if (navigator == null) return;

    if (screen == 'sms_scanner' || type == 'sms') {
      navigator.pushNamed(
        AppRouter.smsScanner,
        arguments: {
          'content': data['content'] ?? data['text'] ?? '',
          'sender': data['sender'] ?? data['title'] ?? '',
          'sourceApp': data['sourceApp'] ?? 'SMS',
          'autoScan': true,
        },
      );
    } else if (screen == 'email_scanner' || type == 'email') {
      navigator.pushNamed(
        AppRouter.emailScanner,
        arguments: {
          'sender': data['sender'] ?? '',
          'title': data['title'] ?? '',
          'content': data['content'] ?? data['text'] ?? '',
          'autoScan': true,
        },
      );
    } else if (screen == 'call_screening' || type == 'call') {
      navigator.pushNamed(
        AppRouter.communications,
        arguments: 2, // Call History tab
      );
    } else if (screen == 'apk_analysis' || type == 'installed_apk' || type == 'apk') {
      navigator.pushNamed(
        AppRouter.permissionAnalyzer,
      );
    }
  }

  /// Process newly installed package broadcast event
  Future<void> handleInstalledApkEvent(Map<String, dynamic> data) async {
    final pkg = data['packageName']?.toString() ?? 'unknown.package';
    final appName = data['appName']?.toString() ?? pkg;
    final riskScore = data['riskScore'] is int ? data['riskScore'] as int : 0;
    final safetyScore = data['safetyScore'] is int ? data['safetyScore'] as int : (100 - riskScore);
    final classification = data['classification']?.toString() ?? 'Safe';
    final explanation = data['explanation']?.toString() ?? 'Application scanned upon installation.';
    final actions = (data['recommendedActions'] as List?)?.map((e) => e.toString()).toList() ?? <String>[];

    recordEventLog(
      type: 'apk',
      source: appName,
      title: 'Newly Installed APK: $appName',
      rawContent: '$appName ($pkg) - Risk Score: $riskScore/100, Safety: $safetyScore/100. $explanation',
      riskScore: riskScore,
      classification: classification,
      isSimulated: false,
      recommendedAction: actions.isNotEmpty ? actions.first : null,
    );

    if (classification != 'Safe' || riskScore >= 20) {
      await AlertService.instance.evaluateAndRecordScanAlert(
        scanType: 'APK',
        target: '$appName ($pkg)',
        riskScore: riskScore,
        classification: classification,
        summary: explanation,
        recommendedActions: actions.isNotEmpty
            ? actions
            : ['Review declared permissions.', 'Consider uninstalling if untrusted.'],
      );

      unawaited(
        SmartAlertEngine.instance.submitEvent(
          moduleName: 'apk_security_inspector',
          eventCategory: 'app_installed',
          source: 'package_manager',
          targetIdentifier: pkg,
          riskScore: riskScore,
          classification: classification,
          findings: [explanation],
          explanation: 'Newly installed package $appName ($pkg) was audited. Identified risk score: $riskScore/100.',
          recommendedActions: actions,
        ),
      );
    }
  }

  /// Sync active API base URL and Firebase ID token to native SharedPreferences
  /// so CyberShieldCallScreeningService can evaluate calls even when Flutter is closed.
  Future<void> syncNativeBackendConfig() async {
    try {
      String? idToken;
      try {
        idToken = await FirebaseAuth.instance.currentUser?.getIdToken();
      } catch (_) {
        // Firebase may not be initialized in unit tests
      }
      await _methodChannel.invokeMethod('syncBackendConfig', {
        'apiBaseUrl': ApiService.baseUrl,
        'authToken': idToken,
      });
    } on MissingPluginException {
      // Non-Android / unit tests
    } catch (_) {}
  }

  /// Load any incoming calls screened natively while Flutter was in the background/closed
  Future<void> loadNativeScreenedCallHistory() async {
    try {
      final rawList = await _methodChannel.invokeMethod<List<dynamic>>('getScreenedCallHistory');
      if (rawList == null || rawList.isEmpty) return;

      final existingIds = recentEventsNotifier.value.map((e) => e.id).toSet();
      final updated = List<ProtectionEventLogItem>.from(recentEventsNotifier.value);

      for (final item in rawList) {
        if (item is! Map) continue;
        final phone = item['phoneNumber']?.toString() ?? 'Unknown';
        final ts = item['timestamp'] is int
            ? item['timestamp'] as int
            : DateTime.now().millisecondsSinceEpoch;
        final id = 'call-native-$ts-$phone';
        if (existingIds.contains(id)) continue;

        final score = item['spamScore'] is int ? item['spamScore'] as int : 0;
        final classification = item['classification']?.toString() ?? 'Safe';
        final explanation = item['explanation']?.toString() ?? '';
        final action = item['recommendedAction']?.toString() ?? 'allow';
        final silenced = item['wasSilenced'] == true;

        updated.add(
          ProtectionEventLogItem(
            id: id,
            type: 'call',
            source: phone,
            title: silenced ? 'Silenced Spam Call' : 'Screened Incoming Call',
            maskedContent: explanation.isNotEmpty
                ? explanation
                : 'Call from $phone (risk score: $score/100)',
            riskScore: score,
            classification: classification,
            timestamp: DateTime.fromMillisecondsSinceEpoch(ts),
            isSimulated: false,
            recommendedAction: action,
          ),
        );
      }

      updated.sort((a, b) => b.timestamp.compareTo(a.timestamp));
      if (updated.length > 50) {
        recentEventsNotifier.value = updated.sublist(0, 50);
      } else {
        recentEventsNotifier.value = updated;
      }
    } on MissingPluginException {
      // Non-Android / unit tests
    } catch (_) {}
  }

  /// Query native Android for current protection and permission states
  Future<ProtectionStatus> refreshStatus() async {
    final prev = statusNotifier.value;
    try {
      final res = await _methodChannel.invokeMethod<Map<dynamic, dynamic>>('getProtectionStatus');
      if (res != null) {
        final status = ProtectionStatus.fromMap(res);
        statusNotifier.value = status;

        // Detect live permission revocations and emit Smart Alert Engine system events
        if (_hasObservedInitialStatus) {
          if (prev.isNotificationAccessGranted && !status.isNotificationAccessGranted) {
            unawaited(
              SmartAlertEngine.instance.submitEvent(
                moduleName: 'realtime_protection',
                eventCategory: 'permission_revoked',
                source: 'system_event',
                targetIdentifier: 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
                riskScore: 70,
                classification: 'High Risk',
                findings: const ['Notification Access was revoked in Android Settings.'],
                explanation:
                    'Real-Time Notification Guard lost Notification Access permission. Incoming phishing notifications cannot be screened until re-enabled.',
                recommendedActions: const ['Open Permission Center and re-grant Notification Access.'],
              ),
            );
          }
          if (prev.isCallScreeningRoleHeld && !status.isCallScreeningRoleHeld) {
            unawaited(
              SmartAlertEngine.instance.submitEvent(
                moduleName: 'call_screening',
                eventCategory: 'permission_revoked',
                source: 'system_event',
                targetIdentifier: 'android.app.role.CALL_SCREENING',
                riskScore: 65,
                classification: 'High Risk',
                findings: const ['Call Screening role was revoked by Android system.'],
                explanation:
                    'CyberShield is no longer the active Android Call Screening app. Automatic spam caller screening is paused.',
                recommendedActions: const ['Re-enable Spam Call Screening role in Settings.'],
              ),
            );
          }
        }
        _hasObservedInitialStatus = true;
        return status;
      }
    } on MissingPluginException {
      // In web, unit tests, or unsupported platforms
    } catch (_) {}

    return statusNotifier.value;
  }

  /// Toggle Master Protection Shield
  Future<bool> setProtectionMasterEnabled(bool enabled) async {
    try {
      final success = await _methodChannel.invokeMethod<bool>(
        'setProtectionMasterEnabled',
        {'enabled': enabled},
      );
      await refreshStatus();
      unawaited(
        SmartAlertEngine.instance.submitEvent(
          moduleName: 'realtime_protection',
          eventCategory: enabled ? 'protection_activated' : 'service_interruption',
          source: 'system_event',
          targetIdentifier: 'realtime_protection_master',
          riskScore: enabled ? 0 : 65,
          classification: enabled ? 'Safe' : 'High Risk',
          explanation: enabled
              ? 'CyberShield Real-Time Protection has been activated across monitoring modules.'
              : 'CyberShield Real-Time Protection was disabled by the user. Active monitoring is paused.',
          recommendedActions: enabled
              ? const ['All enabled protection monitors are active.']
              : const ['Re-enable Real-Time Protection when ready to resume live defense.'],
        ),
      );
      return success ?? false;
    } on MissingPluginException {
      statusNotifier.value = ProtectionStatus(
        isMasterEnabled: enabled,
        isNotificationAccessGranted: statusNotifier.value.isNotificationAccessGranted,
        isCallScreeningRoleHeld: statusNotifier.value.isCallScreeningRoleHeld,
        isCallScreeningSupported: statusNotifier.value.isCallScreeningSupported,
        androidSdk: statusNotifier.value.androidSdk,
        silenceSpamCalls: statusNotifier.value.silenceSpamCalls,
      );
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Toggle automatic silencing of confirmed spam callers
  Future<bool> setCallScreeningSilenceSpamEnabled(bool enabled) async {
    try {
      final success = await _methodChannel.invokeMethod<bool>(
        'setCallScreeningSilenceSpamEnabled',
        {'enabled': enabled},
      );
      await refreshStatus();
      return success ?? false;
    } on MissingPluginException {
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Open Android System Settings -> Notification Access
  Future<void> openNotificationListenerSettings() async {
    try {
      await _methodChannel.invokeMethod('openNotificationListenerSettings');
    } catch (_) {}
  }

  /// Request Android 10+ Call Screening Role and return the verified system outcome
  Future<CallScreeningRoleResult> requestCallScreeningRole() async {
    if (isRequestingCallRoleNotifier.value) {
      return const CallScreeningRoleResult(
        status: 'in_progress',
        granted: false,
        supported: true,
        message: 'Call screening role request is already in progress.',
      );
    }

    isRequestingCallRoleNotifier.value = true;
    try {
      final raw = await _methodChannel.invokeMethod<dynamic>('requestCallScreeningRole');
      await refreshStatus();

      if (raw is Map) {
        final parsed = CallScreeningRoleResult.fromMap(raw);
        if (parsed.isGranted) {
          await syncNativeBackendConfig();
        }
        return parsed;
      }

      final current = statusNotifier.value;
      if (!current.isCallScreeningSupported) {
        return CallScreeningRoleResult(
          status: 'unsupported',
          granted: false,
          supported: false,
          androidSdk: current.androidSdk,
          message: current.callScreeningUnavailableReason ??
              'Android Call Screening requires Android 10 (API 29) or higher.',
        );
      }

      return CallScreeningRoleResult(
        status: current.isCallScreeningRoleHeld ? 'granted' : 'denied',
        granted: current.isCallScreeningRoleHeld,
        supported: current.isCallScreeningSupported,
        androidSdk: current.androidSdk,
        message: current.isCallScreeningRoleHeld
            ? 'Call Screening role granted. CyberShield is now active.'
            : 'Call Screening permission was not granted.',
      );
    } on MissingPluginException {
      return const CallScreeningRoleResult(
        status: 'unsupported',
        granted: false,
        supported: false,
        message: 'Android Call Screening is only supported on Android 10 (API 29) or higher devices.',
      );
    } catch (e) {
      await refreshStatus();
      return CallScreeningRoleResult(
        status: 'error',
        granted: statusNotifier.value.isCallScreeningRoleHeld,
        supported: statusNotifier.value.isCallScreeningSupported,
        androidSdk: statusNotifier.value.androidSdk,
        message: 'Unable to request Call Screening role: $e',
      );
    } finally {
      isRequestingCallRoleNotifier.value = false;
    }
  }

  /// Check if local Android notification permission (POST_NOTIFICATIONS on Android 13+) is granted
  Future<bool> isNotificationPermissionGranted() async {
    try {
      final res = await _methodChannel.invokeMethod<bool>('isNotificationPermissionGranted');
      return res ?? true;
    } catch (_) {
      return true;
    }
  }

  /// Request local Android notification permission (Android 13+ runtime dialog)
  Future<void> requestNotificationPermission() async {
    try {
      await _methodChannel.invokeMethod('requestNotificationPermission');
    } catch (_) {}
  }

  /// Retrieve installed application inventory using Android package visibility
  Future<List<InstalledAppInfo>> getInstalledApplications({bool includeSystemApps = false}) async {
    try {
      final res = await _methodChannel.invokeMethod<List<dynamic>>(
        'getInstalledApplications',
        {'includeSystemApps': includeSystemApps},
      );
      if (res != null) {
        return res
            .map((e) => InstalledAppInfo.fromNativeMap(Map<dynamic, dynamic>.from(e as Map)))
            .toList();
      }
    } on MissingPluginException {
      // Provide fallback app profiles for testing or desktop/web environments
      return _getFallbackAppInventory(includeSystemApps);
    } catch (_) {
      return _getFallbackAppInventory(includeSystemApps);
    }
    return _getFallbackAppInventory(includeSystemApps);
  }

  /// Analyze apps locally using deterministic static permission heuristics
  static BatchAppScanResult analyzeAppsLocally(List<InstalledAppInfo> rawApps) {
    final List<InstalledAppInfo> analyzed = [];
    int safeCount = 0;
    int suspiciousCount = 0;
    int highRiskCount = 0;
    int criticalCount = 0;
    int maxDeviceScore = 0;

    for (final app in rawApps) {
      final perms = app.permissions.toSet();
      final dangerousFound = <String>[];
      final comboFindings = <String>[];
      int score = 0;

      // Check dangerous permissions
      if (perms.contains('android.permission.BIND_ACCESSIBILITY_SERVICE')) {
        dangerousFound.add('BIND_ACCESSIBILITY_SERVICE');
        score += 25;
      }
      if (perms.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
        dangerousFound.add('SYSTEM_ALERT_WINDOW');
        score += 20;
      }
      if (perms.contains('android.permission.RECEIVE_SMS')) {
        dangerousFound.add('RECEIVE_SMS');
        score += 20;
      }
      if (perms.contains('android.permission.READ_SMS')) {
        dangerousFound.add('READ_SMS');
        score += 20;
      }
      if (perms.contains('android.permission.SEND_SMS')) {
        dangerousFound.add('SEND_SMS');
        score += 20;
      }
      if (perms.contains('android.permission.REQUEST_INSTALL_PACKAGES')) {
        dangerousFound.add('REQUEST_INSTALL_PACKAGES');
        score += 20;
      }
      if (perms.contains('android.permission.RECORD_AUDIO')) {
        dangerousFound.add('RECORD_AUDIO');
        score += 15;
      }
      if (perms.contains('android.permission.CAMERA')) {
        dangerousFound.add('CAMERA');
        score += 15;
      }
      if (perms.contains('android.permission.ACCESS_FINE_LOCATION')) {
        dangerousFound.add('ACCESS_FINE_LOCATION');
        score += 15;
      }
      if (perms.contains('android.permission.READ_CONTACTS')) {
        dangerousFound.add('READ_CONTACTS');
        score += 15;
      }

      // Check dangerous combos
      if ((perms.contains('android.permission.READ_SMS') || perms.contains('android.permission.RECEIVE_SMS')) &&
          perms.contains('android.permission.BIND_ACCESSIBILITY_SERVICE')) {
        comboFindings.add('SMS + Accessibility (Banking Trojan Pattern)');
        score += 25;
      }
      if ((perms.contains('android.permission.READ_SMS') || perms.contains('android.permission.RECEIVE_SMS')) &&
          perms.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
        comboFindings.add('SMS + Overlay (Credential Harvesting Pattern)');
        score += 20;
      }
      if (perms.contains('android.permission.REQUEST_INSTALL_PACKAGES') &&
          perms.contains('android.permission.BIND_ACCESSIBILITY_SERVICE')) {
        comboFindings.add('Silent Dropper + Accessibility Combo');
        score += 20;
      }
      if (perms.contains('android.permission.RECORD_AUDIO') &&
          perms.contains('android.permission.ACCESS_FINE_LOCATION')) {
        comboFindings.add('Microphone + Location (Stalkerware Profile)');
        score += 15;
      }

      score = score.clamp(0, 100);
      if (score > maxDeviceScore) maxDeviceScore = score;

      String classification;
      if (score >= 75) {
        classification = 'Critical';
        criticalCount++;
      } else if (score >= 50) {
        classification = 'High Risk';
        highRiskCount++;
      } else if (score >= 25) {
        classification = 'Suspicious';
        suspiciousCount++;
      } else {
        classification = 'Safe';
        safeCount++;
      }

      final recommendations = <String>[];
      if (score >= 50) {
        recommendations.add('Review app permissions in Android Settings.');
        if (comboFindings.isNotEmpty) {
          recommendations.add('Disable Accessibility or Overlay permissions if not strictly necessary.');
        }
      } else {
        recommendations.add('No immediate threat action required.');
      }

      analyzed.add(app.copyWithAnalysis(
        riskScore: score,
        classification: classification,
        dangerousPermissionsCount: dangerousFound.length,
        dangerousPermissions: dangerousFound,
        comboFindings: comboFindings,
        explanation: comboFindings.isNotEmpty
            ? 'Flagged for dangerous permission combinations: ${comboFindings.join(", ")}'
            : (dangerousFound.isNotEmpty
                ? 'Contains ${dangerousFound.length} sensitive permissions: ${dangerousFound.join(", ")}'
                : 'Declared permissions within standard operational boundaries.'),
        recommendations: recommendations,
      ));
    }

    final highRiskApps = analyzed.where((a) => a.isRisky).toList();
    analyzed.sort((a, b) => b.riskScore.compareTo(a.riskScore));
    highRiskApps.sort((a, b) => b.riskScore.compareTo(a.riskScore));

    String overallClassification;
    if (criticalCount > 0 || maxDeviceScore >= 75) {
      overallClassification = 'Critical';
    } else if (highRiskCount > 0 || maxDeviceScore >= 50) {
      overallClassification = 'High Risk';
    } else if (suspiciousCount > 0 || maxDeviceScore >= 25) {
      overallClassification = 'Suspicious';
    } else {
      overallClassification = 'Safe';
    }

    return BatchAppScanResult(
      totalAppsAnalyzed: analyzed.length,
      safeCount: safeCount,
      suspiciousCount: suspiciousCount,
      highRiskCount: highRiskCount,
      criticalCount: criticalCount,
      overallDeviceRiskScore: maxDeviceScore,
      overallClassification: overallClassification,
      summary: 'Audited ${analyzed.length} installed packages: $criticalCount critical, $highRiskCount high-risk.',
      highRiskApps: highRiskApps,
      allApps: analyzed,
      recommendations: highRiskApps.isNotEmpty
          ? ['Review flagged applications and revoke sensitive accessibility and overlay permissions.']
          : ['All inspected application permissions appear within normal operational baselines.'],
      timestamp: DateTime.now().toUtc().toIso8601String(),
    );
  }

  /// Scan and analyze declared permissions for installed applications
  Future<BatchAppScanResult?> scanInstalledApplications({
    bool includeSystemApps = false,
  }) async {
    isScanningAppsNotifier.value = true;
    try {
      final apps = await getInstalledApplications(includeSystemApps: includeSystemApps);
      if (apps.isEmpty) {
        isScanningAppsNotifier.value = false;
        return null;
      }

      // Step 1: Immediately perform deterministic on-device analysis (guaranteed fast feedback)
      final localResult = analyzeAppsLocally(apps);
      lastBatchScanNotifier.value = localResult;
      isScanningAppsNotifier.value = false;

      // Step 2: Try to enrich via backend in the background
      try {
        final remoteResult = await ApiService.analyzeInstalledAppsBatch(apps);
        if (remoteResult != null) {
          lastBatchScanNotifier.value = remoteResult;
          for (final risky in remoteResult.highRiskApps) {
            if (risky.isCritical || risky.isHighRisk) {
              await AlertService.instance.evaluateAndRecordScanAlert(
                scanType: 'PERMISSIONS',
                target: risky.appName,
                riskScore: risky.riskScore,
                classification: risky.classification,
                summary:
                    '${risky.packageName}: Dangerous permissions detected (${risky.comboFindings.join(", ")}).',
                recommendedActions: risky.recommendations,
              );
            }
          }
          return remoteResult;
        }
      } catch (_) {}

      return localResult;
    } catch (_) {
      isScanningAppsNotifier.value = false;
      return null;
    }
  }

  /// Screen an incoming phone number against community threat intelligence
  Future<CallScreenResult?> screenIncomingCall(
    String phoneNumber, {
    String? callerName,
  }) async {
    final result = await ApiService.screenIncomingCall(phoneNumber, callerName: callerName);
    if (result != null) {
      recordEventLog(
        type: 'call',
        source: phoneNumber,
        title: (callerName != null && callerName.isNotEmpty) ? callerName : 'Incoming Call',
        rawContent: 'Call from $phoneNumber. Risk score: ${result.spamScore}/100.',
        riskScore: result.spamScore,
        classification: result.classification,
        isSimulated: false,
        recommendedAction: result.isKnownSpam
            ? 'Decline or silence call immediately.'
            : 'Number has low threat reputation.',
      );

      if (result.isKnownSpam) {
        try {
          await _methodChannel.invokeMethod('markSpamNumber', {
            'phoneNumber': result.phoneNumber,
            'isSpam': true,
          });
        } catch (_) {}

        await AlertService.instance.evaluateAndRecordScanAlert(
          scanType: 'SPAM_CALLER',
          target: result.normalizedNumber,
          riskScore: result.spamScore,
          classification: result.classification,
          summary: result.explanation,
          recommendedActions: [
            'Decline or silence call.',
            'Do not share financial or personal details.',
          ],
        );
      }
    }
    return result;
  }

  /// Process an incoming notification event
  Future<NotificationScanResult?> analyzeNotificationEvent(Map<String, dynamic> data) async {
    final pkg = data['packageName']?.toString() ?? 'unknown.app';
    final title = data['title']?.toString() ?? '';
    final text = data['text']?.toString() ?? '';
    final subText = data['subText']?.toString() ?? '';

    final result = await ApiService.analyzeNotification(
      packageName: pkg,
      title: title,
      text: text,
      subText: subText,
    );

    if (result != null) {
      recordEventLog(
        type: 'notification',
        source: pkg,
        title: title.isNotEmpty ? title : 'Android Notification',
        rawContent: '$title: $text ${subText.isNotEmpty ? "($subText)" : ""}',
        riskScore: result.overallRiskScore,
        classification: result.classification,
        isSimulated: false,
        recommendedAction: result.recommendedAction,
      );

      if (result.overallRiskScore >= 35 || result.hasPhishingUrl) {
        await AlertService.instance.evaluateAndRecordScanAlert(
          scanType: result.hasPhishingUrl ? 'PHISHING_URL' : 'NOTIFICATION',
          target: result.detectedUrls.isNotEmpty ? result.detectedUrls.first : '$pkg: $title',
          riskScore: result.overallRiskScore,
          classification: result.classification,
          summary: result.explanation,
          recommendedActions: [result.recommendedAction],
        );

        // Trigger high-priority lock-screen-safe local notification alert
        await showLocalNotification(
          title: '${result.classification} Notification',
          body: '${result.explanation} (${result.recommendedAction})',
          severity: result.classification.toLowerCase(),
          moduleName: 'Notification Monitor',
        );
      }
    }

    return result;
  }

  /// Display a lock-screen-safe local Android notification identifying its originating module
  Future<void> showLocalNotification({
    required String title,
    required String body,
    required String severity,
    String? moduleName,
    bool hideOnLockScreen = true,
  }) async {
    try {
      await _methodChannel.invokeMethod('showLocalNotification', {
        'title': title,
        'body': body,
        'severity': severity,
        if (moduleName != null) 'moduleName': moduleName,
        'hideOnLockScreen': hideOnLockScreen,
      });
    } catch (_) {}
  }

  /// Start listening to real-time events from Kotlin services
  void startEventListener() {
    if (_isListening) return;
    try {
      _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
        (event) {
          if (event is Map) {
            final type = event['type']?.toString();
            if (type == 'notification_tap') {
              final map = Map<String, dynamic>.from(event);
              handleThreatNavigation(map);
            } else if (type == 'installed_apk') {
              final map = Map<String, dynamic>.from(event);
              handleInstalledApkEvent(map);
            } else if (type == 'notification') {
              final map = Map<String, dynamic>.from(event);
              analyzeNotificationEvent(map);
              final tsMs = map['timestamp'] is int
                  ? map['timestamp'] as int
                  : (map['postTime'] is int ? map['postTime'] as int : DateTime.now().millisecondsSinceEpoch);
              CommunicationService.instance.ingestCommunication(
                communicationType: map['communicationType']?.toString() ?? 'notification',
                sourceApp: map['sourceApp']?.toString() ?? map['packageName']?.toString() ?? 'Notification',
                senderIdentifier: map['sender']?.toString() ?? map['title']?.toString() ?? 'Unknown',
                subject: map['title']?.toString(),
                content: map['content']?.toString() ?? map['text']?.toString(),
                timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
              );
            } else if (type == 'comm_sms') {
              final map = Map<String, dynamic>.from(event);
              final tsMs = map['timestamp'] is int ? map['timestamp'] as int : DateTime.now().millisecondsSinceEpoch;
              CommunicationService.instance.ingestCommunication(
                communicationType: 'sms',
                sourceApp: map['sourceApp']?.toString() ?? 'SMS',
                senderIdentifier: map['sender']?.toString() ?? 'Unknown Sender',
                content: map['content']?.toString() ?? '',
                timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
              );
            } else if (type == 'comm_call') {
              final map = Map<String, dynamic>.from(event);
              final phone = map['phoneNumber']?.toString() ?? map['sender']?.toString();
              if (phone != null && phone.isNotEmpty) {
                final tsMs = map['timestamp'] is int ? map['timestamp'] as int : DateTime.now().millisecondsSinceEpoch;
                CommunicationService.instance.ingestCommunication(
                  communicationType: 'call',
                  sourceApp: 'Phone Call',
                  senderIdentifier: phone,
                  callerName: map['callerName']?.toString(),
                  isKnownContact: map['isKnownContact'] is bool ? map['isKnownContact'] as bool : null,
                  callStatus: map['callStatus']?.toString() ?? 'incoming',
                  timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
                );
              }
            } else if (type == 'call') {
              final phone = event['phoneNumber']?.toString();
              if (phone != null && phone.isNotEmpty && phone != 'Unknown') {
                final tsMs = event['timestamp'] is int ? event['timestamp'] as int : DateTime.now().millisecondsSinceEpoch;
                CommunicationService.instance.ingestCommunication(
                  communicationType: 'call',
                  sourceApp: 'Phone Call',
                  senderIdentifier: phone,
                  callStatus: event['wasSilenced'] == true ? 'silenced' : 'incoming',
                  timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
                );
                final backendEvaluated = event['backendEvaluated'] == true;
                if (backendEvaluated) {
                  final score = event['spamScore'] is int ? event['spamScore'] as int : 0;
                  final classification = event['classification']?.toString() ?? 'Safe';
                  final explanation = event['explanation']?.toString() ?? '';
                  final action = event['recommendedAction']?.toString() ?? 'allow';
                  final silenced = event['wasSilenced'] == true;
                  final isKnownSpam = event['isKnownSpam'] == true;

                  recordEventLog(
                    type: 'call',
                    source: phone,
                    title: silenced ? 'Silenced Spam Call' : 'Screened Incoming Call',
                    rawContent: explanation.isNotEmpty
                        ? explanation
                        : 'Incoming call from $phone. Risk score: $score/100.',
                    riskScore: score,
                    classification: classification,
                    isSimulated: false,
                    recommendedAction: action,
                  );

                  if (isKnownSpam || score >= 25) {
                    AlertService.instance.evaluateAndRecordScanAlert(
                      scanType: 'SPAM_CALLER',
                      target: phone,
                      riskScore: score,
                      classification: classification,
                      summary: explanation.isNotEmpty
                          ? explanation
                          : 'Incoming caller $phone flagged as $classification ($score/100).',
                      recommendedActions: [
                        if (silenced) 'Call was automatically silenced by CyberShield.' else 'Exercise caution if answering.',
                        'Never share OTPs or banking details over incoming calls.',
                      ],
                    );
                  }
                } else {
                  screenIncomingCall(phone);
                }
              }
            }
          }
        },
        onError: (err) {
          if (kDebugMode) {
            debugPrint('CyberShield ProtectionEventChannel error: $err');
          }
        },
      );
      _isListening = true;
    } catch (_) {}
  }

  void stopEventListener() {
    _eventSubscription?.cancel();
    _eventSubscription = null;
    _isListening = false;
  }

  List<InstalledAppInfo> _getFallbackAppInventory(bool includeSystem) {
    final apps = [
      const InstalledAppInfo(
        packageName: 'com.fraud.banktrojan',
        appName: 'Flash Player Update',
        versionName: '2.4.1',
        isSystemApp: false,
        permissions: [
          'android.permission.RECEIVE_SMS',
          'android.permission.READ_SMS',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.SYSTEM_ALERT_WINDOW',
          'android.permission.INTERNET',
        ],
      ),
      const InstalledAppInfo(
        packageName: 'com.covert.tracker',
        appName: 'Smart Battery Saver',
        versionName: '1.2.0',
        isSystemApp: false,
        permissions: [
          'android.permission.RECORD_AUDIO',
          'android.permission.CAMERA',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.ACCESS_BACKGROUND_LOCATION',
          'android.permission.RECEIVE_BOOT_COMPLETED',
        ],
      ),
      const InstalledAppInfo(
        packageName: 'com.google.android.apps.messaging',
        appName: 'Messages',
        versionName: '2024.11',
        isSystemApp: true,
        permissions: [
          'android.permission.READ_SMS',
          'android.permission.SEND_SMS',
          'android.permission.RECEIVE_SMS',
          'android.permission.READ_CONTACTS',
        ],
      ),
      const InstalledAppInfo(
        packageName: 'com.android.calculator2',
        appName: 'Calculator',
        versionName: '14.0',
        isSystemApp: true,
        permissions: ['android.permission.VIBRATE'],
      ),
      const InstalledAppInfo(
        packageName: 'com.example.notes',
        appName: 'Secure Notepad',
        versionName: '3.1.0',
        isSystemApp: false,
        permissions: [
          'android.permission.INTERNET',
          'android.permission.ACCESS_NETWORK_STATE',
        ],
      ),
    ];

    if (!includeSystem) {
      return apps.where((a) => !a.isSystemApp).toList();
    }
    return apps;
  }
}

