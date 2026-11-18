// CyberShield Centralized Smart Alert & All-18-Module Security Event Engine (Flutter)
//
// Single centralized pipeline for every CyberShield module:
// Detection -> Analysis -> Risk Scoring -> Classification -> Event Storage ->
// Smart Alert Evaluation -> Lock-Screen-Safe Notification Delivery ->
// History Update -> Unified Analytics Update (with Offline Retry Queue).

import 'dart:async';
import 'dart:convert';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/models/security_event_model.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/communication_service.dart';

class SmartAlertEngine {
  static final SmartAlertEngine instance = SmartAlertEngine._internal();
  SmartAlertEngine._internal();

  static const MethodChannel _channel = MethodChannel('com.example.mobile/protection');
  static const String _prefEventsPrefix = 'cybershield_smart_events_';
  static const String _prefQueuePrefix = 'cybershield_smart_queue_';
  static const String _prefPrefsPrefix = 'cybershield_smart_prefs_';

  final ValueNotifier<List<SecurityEventModel>> eventsNotifier =
      ValueNotifier<List<SecurityEventModel>>([]);
  final ValueNotifier<UnifiedSecurityAnalytics> analyticsNotifier =
      ValueNotifier<UnifiedSecurityAnalytics>(const UnifiedSecurityAnalytics());
  final ValueNotifier<SmartNotificationPrefs> prefsNotifier =
      ValueNotifier<SmartNotificationPrefs>(const SmartNotificationPrefs());
  final ValueNotifier<int> offlineQueueCountNotifier = ValueNotifier<int>(0);
  final ValueNotifier<bool> isLoadingNotifier = ValueNotifier<bool>(false);
  final ValueNotifier<bool> isFlushingQueueNotifier = ValueNotifier<bool>(false);

  final Set<String> _sessionDedupKeys = {};
  String? _activeUid;
  bool _initialized = false;
  String _currentPeriod = 'daily';

  /// Optional override for unit tests to avoid FirebaseAuth singleton calls.
  @visibleForTesting
  String? testUserIdOverride;

  /// Optional override for unit tests to inspect delivered notifications without MethodChannel.
  @visibleForTesting
  void Function(Map<String, dynamic> notificationPayload)? testNotificationSink;

  /// Optional override for unit tests to simulate offline backend.
  @visibleForTesting
  bool testForceOffline = false;

  String get currentUserId {
    if (testUserIdOverride != null) return testUserIdOverride!;
    try {
      return FirebaseAuth.instance.currentUser?.uid ?? 'local_guest';
    } catch (_) {
      return 'local_guest';
    }
  }

  bool get isAuthenticated {
    if (testUserIdOverride != null) return false;
    try {
      return FirebaseAuth.instance.currentUser != null;
    } catch (_) {
      return false;
    }
  }

  /// Reset in-memory state (used when switching user accounts or in unit tests).
  void resetForAccountSwitch() {
    _initialized = false;
    _activeUid = null;
    _sessionDedupKeys.clear();
    eventsNotifier.value = [];
    analyticsNotifier.value = const UnifiedSecurityAnalytics();
    offlineQueueCountNotifier.value = 0;
  }

  /// Normalize any module key or legacy scanType into one of the 18 canonical module keys.
  static String normalizeModule(String moduleName) {
    final key = moduleName.trim().toLowerCase().replaceAll(' ', '_').replaceAll('-', '_');
    const aliases = {
      'url': 'url_scanner',
      'sms': 'sms_scanner',
      'qr': 'qr_scanner',
      'screenshot': 'screenshot_analyzer',
      'apk': 'apk_analyzer',
      'file': 'file_scanner',
      'permission': 'permission_analyzer',
      'permissions': 'permission_analyzer',
      'email': 'email_scanner',
      'gmail': 'gmail_integration',
      'call': 'call_screening',
      'calls': 'call_screening',
      'notification': 'notification_monitor',
      'notifications': 'notification_monitor',
      'installed_apps': 'installed_app_audit',
      'apps': 'installed_app_audit',
      'community': 'community_threat_intel',
      'assistant': 'ai_security_assistant',
      'analytics': 'dashboard_analytics',
      'alerts': 'security_alerts',
      'history': 'audit_history',
      'protection': 'realtime_protection',
    };
    final mapped = aliases[key] ?? key;
    for (final m in kAll18Modules) {
      if (m.key == mapped) return m.key;
    }
    return 'realtime_protection';
  }

  static CyberShieldModuleMeta moduleMeta(String moduleName) {
    final key = normalizeModule(moduleName);
    return kAll18Modules.firstWhere(
      (m) => m.key == key,
      orElse: () => kAll18Modules.last,
    );
  }

  /// Strict classification matching backend rules (NEVER classifies failed/unavailable as Safe).
  static String classifyRisk({
    required int? riskScore,
    required String analysisStatus,
    String? explicitClassification,
  }) {
    final status = analysisStatus.trim().toLowerCase();
    if (status == 'failed') return 'Failed';
    if (status == 'unavailable') return 'Unavailable';
    if (status == 'unverified') return 'Unverified';

    final score = (riskScore ?? 0).clamp(0, 100);
    String cls;
    if (score <= 20) {
      cls = 'Safe';
    } else if (score <= 40) {
      cls = 'Low Risk';
    } else if (score <= 60) {
      cls = 'Suspicious';
    } else if (score <= 80) {
      cls = 'High Risk';
    } else {
      cls = 'Critical';
    }

    if (explicitClassification != null) {
      final low = explicitClassification.trim().toLowerCase();
      if (low == 'critical' && score >= 70) return 'Critical';
      if ((low == 'high risk' || low == 'malicious') && score >= 55) return 'High Risk';
    }
    return cls;
  }

  static String severityFor({
    required String classification,
    required String eventCategory,
    required String analysisStatus,
  }) {
    final cat = eventCategory.trim().toLowerCase();
    if (cat == 'service_interruption' || cat == 'permission_revoked') return 'high';
    if (cat == 'protection_activated' || cat == 'daily_report') return 'info';
    if (analysisStatus == 'failed' || analysisStatus == 'unavailable') return 'medium';
    if (analysisStatus == 'unverified') return 'low';

    switch (classification) {
      case 'Critical':
        return 'critical';
      case 'High Risk':
        return 'high';
      case 'Suspicious':
        return 'medium';
      case 'Low Risk':
        return 'low';
      default:
        return 'info';
    }
  }

  /// Evaluates Smart Notification Delivery policy for any module or system event.
  static bool shouldDeliverNotification({
    required String severity,
    required String eventCategory,
    required String analysisStatus,
    required SmartNotificationPrefs prefs,
  }) {
    final cat = eventCategory.trim().toLowerCase();
    if (cat == 'service_interruption' || cat == 'permission_revoked') {
      return prefs.notifySystemEvents;
    }
    if (cat == 'protection_activated') {
      return prefs.notifySystemEvents;
    }
    if (cat == 'daily_report') {
      return prefs.dailyReportEnabled;
    }
    if (analysisStatus == 'failed' || analysisStatus == 'unavailable') {
      return prefs.notifySystemEvents;
    }
    if (severity == 'critical' || severity == 'high') {
      return true; // Immediate delivery mandatory for Critical & High Risk
    }
    if (severity == 'medium') {
      return prefs.notifySuspicious; // Per user preference
    }
    // Safe / Low Risk: stored silently unless user explicitly opted into safe summaries
    return prefs.notifySafeSummary;
  }

  Future<void> initialize({bool forceRefresh = false}) async {
    final uid = currentUserId;
    if (_activeUid != uid) {
      resetForAccountSwitch();
      _activeUid = uid;
    }
    if (_initialized && !forceRefresh) return;
    _initialized = true;

    await loadPreferences();
    await _loadLocalEvents();
    await _loadOfflineQueueCount();
    await flushOfflineQueue();
    await refreshAll(period: _currentPeriod);
  }

  Future<SmartNotificationPrefs> loadPreferences() async {
    final uid = currentUserId;
    try {
      final sp = await SharedPreferences.getInstance();
      final raw = sp.getString('$_prefPrefsPrefix$uid');
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          prefsNotifier.value = SmartNotificationPrefs.fromJson(decoded);
        }
      }

      if (isAuthenticated) {
        try {
          final doc = await FirebaseFirestore.instance
              .collection('users')
              .doc(uid)
              .collection('smart_notification_prefs')
              .doc('default')
              .get()
              .timeout(const Duration(seconds: 4));
          if (doc.exists && doc.data() != null) {
            prefsNotifier.value = SmartNotificationPrefs.fromJson(doc.data());
            await sp.setString('$_prefPrefsPrefix$uid', jsonEncode(prefsNotifier.value.toJson()));
          }
        } catch (_) {}
      }
    } catch (_) {}
    return prefsNotifier.value;
  }

  Future<void> updatePreferences(SmartNotificationPrefs updated) async {
    prefsNotifier.value = updated;
    final uid = currentUserId;
    try {
      final sp = await SharedPreferences.getInstance();
      await sp.setString('$_prefPrefsPrefix$uid', jsonEncode(updated.toJson()));
    } catch (_) {}

    if (isAuthenticated) {
      try {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(uid)
            .collection('smart_notification_prefs')
            .doc('default')
            .set(updated.toJson(), SetOptions(merge: true))
            .timeout(const Duration(seconds: 4));
      } catch (_) {}
    }
  }

  /// Centralized fault-isolated entry point for EVERY CyberShield module.
  ///
  /// Never throws; always redacts sensitive data, deduplicates, stores locally,
  /// syncs to backend + Firestore (or queues offline for retry), delivers
  /// lock-screen-safe Android notifications per rules, and updates unified analytics.
  Future<SecurityEventModel?> submitEvent({
    required String moduleName,
    required String targetIdentifier,
    int? riskScore = 0,
    String? classification,
    String? eventCategory,
    String? source,
    List<String> findings = const [],
    String explanation = '',
    List<String> recommendedActions = const [],
    String analysisStatus = 'analyzed',
    String? idempotencyKey,
    bool createBackendAlert = true,
    bool skipBackendPost = false,
    Map<String, dynamic> metadata = const {},
  }) async {
    try {
      final uid = currentUserId;
      _activeUid ??= uid;
      final meta = moduleMeta(moduleName);
      final modKey = meta.key;
      final cat = (eventCategory ?? meta.defaultCategory).trim().toLowerCase();
      final src = (source ?? meta.defaultSource).trim().toLowerCase();
      final now = DateTime.now();

      // 1. Privacy redaction
      final cleanTarget = CommunicationService.redactSensitive(targetIdentifier.trim().isEmpty ? 'N/A' : targetIdentifier.trim());
      final cleanExpl = CommunicationService.redactSensitive(explanation.trim());
      final cleanFindings = findings
          .take(15)
          .map((f) => CommunicationService.redactSensitive(f))
          .toList();
      final cleanActions = recommendedActions
          .take(6)
          .map((a) => CommunicationService.redactSensitive(a))
          .toList();

      // 2. Strict scoring & classification (never mark failed/unavailable as Safe)
      final statusNorm = ['analyzed', 'failed', 'unverified', 'unavailable']
              .contains(analysisStatus.trim().toLowerCase())
          ? analysisStatus.trim().toLowerCase()
          : 'analyzed';
      final effectiveCls = classifyRisk(
        riskScore: riskScore,
        analysisStatus: statusNorm,
        explicitClassification: classification,
      );
      final sev = severityFor(
        classification: effectiveCls,
        eventCategory: cat,
        analysisStatus: statusNorm,
      );

      // 3. Session deduplication
      final minuteBucket = now.toUtc().toIso8601String().substring(0, 16);
      final dedupKey = idempotencyKey?.trim().isNotEmpty == true
          ? '$uid|$modKey|idemp:${idempotencyKey!.trim()}'
          : '$uid|$modKey|$cat|${cleanTarget.toLowerCase()}|$effectiveCls|$statusNorm|$minuteBucket';
      if (_sessionDedupKeys.contains(dedupKey)) {
        return null;
      }
      _sessionDedupKeys.add(dedupKey);
      if (_sessionDedupKeys.length > 500) {
        _sessionDedupKeys.remove(_sessionDedupKeys.first);
      }

      // 4. Smart Notification evaluation & delivery
      final prefs = prefsNotifier.value;
      final willNotify = shouldDeliverNotification(
        severity: sev,
        eventCategory: cat,
        analysisStatus: statusNorm,
        prefs: prefs,
      );
      final notifStatus = willNotify
          ? ((sev == 'critical' || sev == 'high' || cat == 'protection_activated')
              ? 'delivered_immediate'
              : 'queued_preference')
          : 'suppressed_safe';

      if (willNotify) {
        final scoreTag = (statusNorm == 'analyzed' && riskScore != null) ? ' ($riskScore%)' : '';
        final notifTitle = '[${meta.label}] $effectiveCls$scoreTag';
        final notifBody = cleanExpl.isNotEmpty
            ? cleanExpl
            : '${meta.label} recorded a $effectiveCls event for $cleanTarget.';
        await _deliverLocalNotification(
          title: notifTitle,
          body: notifBody,
          severity: sev,
          moduleName: meta.label,
          hideOnLockScreen: prefs.hideSensitiveOnLockScreen,
          notificationId: dedupKey.hashCode & 0x7FFFFFFF,
        );
      }

      // 5. Submit to FastAPI backend (unless already recorded server-side by the endpoint)
      SecurityEventModel? serverEvent;
      if (!skipBackendPost && !testForceOffline) {
        serverEvent = await ApiService.processSecurityEvent(
          moduleName: modKey,
          targetIdentifier: cleanTarget,
          riskScore: statusNorm == 'analyzed' ? (riskScore ?? 0).clamp(0, 100) : riskScore,
          classification: effectiveCls,
          eventCategory: cat,
          source: src,
          findings: cleanFindings,
          explanation: cleanExpl,
          recommendedActions: cleanActions,
          analysisStatus: statusNorm,
          detectionTimestamp: now.toUtc().toIso8601String(),
          idempotencyKey: dedupKey,
          createAlert: createBackendAlert,
          metadata: metadata,
        );
      }

      final finalEvent = serverEvent ??
          SecurityEventModel(
            eventId: 'evt-local-${now.microsecondsSinceEpoch}',
            userId: uid,
            moduleName: modKey,
            moduleLabel: meta.label,
            eventCategory: cat,
            source: src,
            targetIdentifier: cleanTarget,
            riskScore: statusNorm == 'analyzed' ? (riskScore ?? 0).clamp(0, 100) : riskScore,
            classification: effectiveCls,
            severity: sev,
            findings: cleanFindings,
            explanation: cleanExpl,
            recommendedActions: cleanActions,
            detectionTimestamp: now,
            analysisStatus: statusNorm,
            notificationStatus: notifStatus,
            metadata: {
              ...metadata,
              'idempotency_key': dedupKey,
              'offline_queued': !skipBackendPost && serverEvent == null,
            },
            pendingSync: !skipBackendPost && serverEvent == null,
          );

      // 6. Queue for offline retry if backend was unreachable
      if (!skipBackendPost && serverEvent == null) {
        await _enqueueOfflineEvent(finalEvent, dedupKey: dedupKey, createAlert: createBackendAlert);
      }

      // 7. Store locally + mirror to user-isolated Firestore + recompute unified analytics
      await _upsertLocalEvent(finalEvent);
      unawaited(_mirrorToFirestore(finalEvent));
      _recomputeLocalAnalytics(period: _currentPeriod);

      return finalEvent;
    } catch (_) {
      // Fault isolation: Smart Alert Engine failure must NEVER crash the calling module!
      return null;
    }
  }

  /// Flush queued offline events back to FastAPI when connectivity returns.
  Future<int> flushOfflineQueue() async {
    if (testForceOffline || isFlushingQueueNotifier.value) return 0;
    isFlushingQueueNotifier.value = true;
    int synced = 0;
    try {
      final uid = currentUserId;
      final sp = await SharedPreferences.getInstance();
      final raw = sp.getString('$_prefQueuePrefix$uid');
      if (raw == null || raw.isEmpty) {
        offlineQueueCountNotifier.value = 0;
        return 0;
      }
      final list = jsonDecode(raw);
      if (list is! List || list.isEmpty) {
        offlineQueueCountNotifier.value = 0;
        return 0;
      }

      final remaining = <Map<String, dynamic>>[];
      for (final item in list) {
        if (item is! Map) continue;
        final map = Map<String, dynamic>.from(item);
        final res = await ApiService.processSecurityEvent(
          moduleName: map['module_name']?.toString() ?? 'realtime_protection',
          targetIdentifier: map['target_identifier']?.toString() ?? 'N/A',
          riskScore: map['risk_score'] is int ? map['risk_score'] as int : null,
          classification: map['classification']?.toString(),
          eventCategory: map['event_category']?.toString(),
          source: map['source']?.toString(),
          findings: (map['findings'] is List)
              ? (map['findings'] as List).map((e) => e.toString()).toList()
              : const [],
          explanation: map['explanation']?.toString() ?? '',
          recommendedActions: (map['recommended_actions'] is List)
              ? (map['recommended_actions'] as List).map((e) => e.toString()).toList()
              : const [],
          analysisStatus: map['analysis_status']?.toString() ?? 'analyzed',
          detectionTimestamp: map['detection_timestamp']?.toString(),
          idempotencyKey: map['idempotency_key']?.toString(),
          createAlert: map['create_alert'] != false,
        );
        if (res != null) {
          synced++;
          await _upsertLocalEvent(res.copyWith(pendingSync: false));
          unawaited(_mirrorToFirestore(res));
        } else {
          remaining.add(map);
        }
      }

      await sp.setString('$_prefQueuePrefix$uid', jsonEncode(remaining));
      offlineQueueCountNotifier.value = remaining.length;
    } catch (_) {
    } finally {
      isFlushingQueueNotifier.value = false;
    }
    return synced;
  }

  /// Trigger a real-data Daily Security Report event & notification.
  Future<SecurityEventModel?> generateDailySecurityReport() async {
    if (!testForceOffline) {
      final serverEvt = await ApiService.generateDailySecurityReport();
      if (serverEvt != null) {
        await _upsertLocalEvent(serverEvt);
        if (prefsNotifier.value.dailyReportEnabled) {
          await _deliverLocalNotification(
            title: '[Real-Time Protection] Daily Security Report',
            body: serverEvt.explanation,
            severity: 'info',
            moduleName: 'Real-Time Protection',
            hideOnLockScreen: prefsNotifier.value.hideSensitiveOnLockScreen,
          );
        }
        return serverEvt;
      }
    }

    // Offline local daily report derived purely from real stored local events
    final analytics = computeLocalAnalytics(eventsNotifier.value, period: 'daily');
    final today = DateTime.now().toUtc().toIso8601String().substring(0, 10);
    return submitEvent(
      moduleName: 'realtime_protection',
      eventCategory: 'daily_report',
      source: 'system_event',
      targetIdentifier: 'daily_report_$today',
      riskScore: (100 - analytics.deviceSecurityPostureScore).clamp(0, 100),
      findings: [
        'Analyzed Events: ${analytics.totalAnalyzedEvents}',
        'Threats Detected: ${analytics.totalThreatsDetected} (${analytics.threatDetectionRatePercent.toStringAsFixed(1)}%)',
        'Active Modules: ${analytics.activeModulesCount}/${analytics.totalRegisteredModules}',
      ],
      explanation:
          'Daily Security Report ($today): ${analytics.totalAnalyzedEvents} analyzed, '
          '${analytics.totalThreatsDetected} threat(s), '
          '${analytics.failedOrUnavailableEvents} failed/unavailable, '
          'Posture ${analytics.deviceSecurityPostureScore}/100.',
      recommendedActions: const [
        'Inspect flagged findings inside Unified Event Center.',
      ],
      idempotencyKey: 'daily_report:$today:${DateTime.now().hour}',
      createBackendAlert: false,
    );
  }

  /// Refresh unified history and analytics from FastAPI (falling back gracefully to local cache).
  Future<void> refreshAll({
    String period = 'daily',
    String? moduleName,
    String? source,
    String? classification,
    String? severity,
    String? search,
  }) async {
    _currentPeriod = period;
    isLoadingNotifier.value = true;
    try {
      if (!testForceOffline) {
        final historyResp = await ApiService.getUnifiedEventHistory(
          moduleName: moduleName,
          source: source,
          classification: classification,
          severity: severity,
          search: search,
          limit: 120,
        );
        if (historyResp != null && historyResp['events'] is List<SecurityEventModel>) {
          final remoteEvents = historyResp['events'] as List<SecurityEventModel>;
          // Merge pending offline events with server events without losing offline items
          final pendingLocal = eventsNotifier.value.where((e) => e.pendingSync).toList();
          final merged = <String, SecurityEventModel>{};
          for (final e in pendingLocal) {
            merged[e.eventId] = e;
          }
          for (final e in remoteEvents) {
            merged[e.eventId] = e;
          }
          final sorted = merged.values.toList()
            ..sort((a, b) => b.detectionTimestamp.compareTo(a.detectionTimestamp));
          eventsNotifier.value = sorted;
          await _persistLocalEvents(sorted);
        }

        final remoteAnalytics = await ApiService.getUnifiedEventAnalytics(period: period);
        if (remoteAnalytics != null) {
          analyticsNotifier.value = remoteAnalytics;
          return;
        }
      }
      _recomputeLocalAnalytics(period: period);
    } finally {
      isLoadingNotifier.value = false;
    }
  }

  Future<bool> deleteEvent(String eventId) async {
    final uid = currentUserId;
    if (!testForceOffline) {
      await ApiService.deleteSecurityEvent(eventId);
    }
    if (isAuthenticated) {
      try {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(uid)
            .collection('security_events')
            .doc(eventId)
            .delete()
            .timeout(const Duration(seconds: 4));
      } catch (_) {}
    }
    final remaining = eventsNotifier.value.where((e) => e.eventId != eventId).toList();
    eventsNotifier.value = remaining;
    await _persistLocalEvents(remaining);
    _recomputeLocalAnalytics(period: _currentPeriod);
    return true;
  }

  Future<int> purgeEvents({int? olderThanDays}) async {
    int deleted = 0;
    if (!testForceOffline) {
      final res = await ApiService.purgeSecurityEvents(olderThanDays: olderThanDays);
      if (res != null) deleted = res;
    }
    final current = eventsNotifier.value;
    List<SecurityEventModel> kept;
    if (olderThanDays == null) {
      deleted = deleted > 0 ? deleted : current.length;
      kept = [];
    } else {
      final cutoff = DateTime.now().subtract(Duration(days: olderThanDays));
      kept = current.where((e) => !e.detectionTimestamp.isBefore(cutoff)).toList();
      final localRemoved = current.length - kept.length;
      if (localRemoved > deleted) deleted = localRemoved;
    }
    eventsNotifier.value = kept;
    await _persistLocalEvents(kept);
    _recomputeLocalAnalytics(period: _currentPeriod);
    return deleted;
  }

  /// Pure local computation of UnifiedSecurityAnalytics from real stored events.
  /// Strictly separates failed/unavailable from safe, and keeps Posture Score separate from Threat %.
  static UnifiedSecurityAnalytics computeLocalAnalytics(
    List<SecurityEventModel> events, {
    String period = 'daily',
  }) {
    final now = DateTime.now();
    final days = period == 'monthly' ? 30 : (period == 'weekly' ? 7 : 1);
    final cutoff = now.subtract(Duration(days: days));

    final inWindow = events.where((e) => !e.detectionTimestamp.isBefore(cutoff)).toList();

    int totalAnalyzed = 0;
    int failedOrUnavail = 0;
    int safeCount = 0;
    int suspiciousCount = 0;
    int highRiskCount = 0;
    int criticalCount = 0;
    final sourceBreakdown = <String, int>{};

    final modStats = <String, Map<String, int>>{};
    for (final m in kAll18Modules) {
      modStats[m.key] = {
        'total': 0,
        'analyzed': 0,
        'threats': 0,
        'critical': 0,
        'high': 0,
        'suspicious': 0,
        'safe': 0,
        'failed': 0,
      };
    }

    for (final e in inWindow) {
      sourceBreakdown[e.source] = (sourceBreakdown[e.source] ?? 0) + 1;
      final ms = modStats[normalizeModule(e.moduleName)]!;
      ms['total'] = ms['total']! + 1;

      if (e.isFailedOrUnavailable) {
        failedOrUnavail++;
        ms['failed'] = ms['failed']! + 1;
        continue;
      }

      totalAnalyzed++;
      ms['analyzed'] = ms['analyzed']! + 1;
      if (e.classification == 'Critical') {
        criticalCount++;
        ms['critical'] = ms['critical']! + 1;
        ms['threats'] = ms['threats']! + 1;
      } else if (e.classification == 'High Risk') {
        highRiskCount++;
        ms['high'] = ms['high']! + 1;
        ms['threats'] = ms['threats']! + 1;
      } else if (e.classification == 'Suspicious') {
        suspiciousCount++;
        ms['suspicious'] = ms['suspicious']! + 1;
        ms['threats'] = ms['threats']! + 1;
      } else {
        safeCount++;
        ms['safe'] = ms['safe']! + 1;
      }
    }

    final totalThreats = criticalCount + highRiskCount + suspiciousCount;
    final threatRate = totalAnalyzed > 0 ? (totalThreats / totalAnalyzed) * 100.0 : 0.0;
    final coverage = inWindow.isNotEmpty ? (totalAnalyzed / inWindow.length) * 100.0 : 100.0;

    // Device Security Posture Score (distinct from Threat Detection Rate %)
    int penalty = (criticalCount * 18) + (highRiskCount * 10) + (suspiciousCount * 4) + (failedOrUnavail * 3);
    if (penalty > 95) penalty = 95;
    final posture = (100 - penalty).clamp(5, 100);
    final postureLabel = posture >= 85
        ? 'Strong'
        : (posture >= 65 ? 'Moderate' : (posture >= 40 ? 'Elevated Risk' : 'Critical Attention'));

    int activeModules = 0;
    final modDist = <ModuleDistributionItem>[];
    for (final m in kAll18Modules) {
      final st = modStats[m.key]!;
      if (st['total']! > 0) activeModules++;
      final an = st['analyzed']!;
      modDist.add(ModuleDistributionItem(
        moduleName: m.key,
        moduleLabel: m.label,
        totalEvents: st['total']!,
        analyzedEvents: an,
        threatCount: st['threats']!,
        criticalCount: st['critical']!,
        highRiskCount: st['high']!,
        suspiciousCount: st['suspicious']!,
        safeCount: st['safe']!,
        failedOrUnavailable: st['failed']!,
        threatRatePercent: an > 0 ? (st['threats']! / an) * 100.0 : 0.0,
      ));
    }

    return UnifiedSecurityAnalytics(
      period: period,
      totalEvents: inWindow.length,
      totalAnalyzedEvents: totalAnalyzed,
      failedOrUnavailableEvents: failedOrUnavail,
      totalThreatsDetected: totalThreats,
      safeCount: safeCount,
      suspiciousCount: suspiciousCount,
      highRiskCount: highRiskCount,
      criticalCount: criticalCount,
      threatDetectionRatePercent: double.parse(threatRate.toStringAsFixed(1)),
      monitoringCoveragePercent: double.parse(coverage.toStringAsFixed(1)),
      deviceSecurityPostureScore: posture,
      postureLabel: postureLabel,
      activeModulesCount: activeModules,
      totalRegisteredModules: kAll18Modules.length,
      sourceBreakdown: sourceBreakdown,
      moduleDistribution: modDist,
    );
  }

  void _recomputeLocalAnalytics({required String period}) {
    analyticsNotifier.value = computeLocalAnalytics(eventsNotifier.value, period: period);
  }

  Future<void> _deliverLocalNotification({
    required String title,
    required String body,
    required String severity,
    required String moduleName,
    required bool hideOnLockScreen,
    int? notificationId,
  }) async {
    final payload = {
      'title': title,
      'body': body,
      'severity': severity,
      'moduleName': moduleName,
      'hideOnLockScreen': hideOnLockScreen,
      if (notificationId != null) 'notificationId': notificationId,
    };
    if (testNotificationSink != null) {
      testNotificationSink!(payload);
      return;
    }
    try {
      await _channel.invokeMethod('showLocalNotification', payload);
    } on MissingPluginException {
      // Non-Android / unit tests
    } catch (_) {}
  }

  Future<void> _enqueueOfflineEvent(
    SecurityEventModel event, {
    required String dedupKey,
    required bool createAlert,
  }) async {
    try {
      final uid = currentUserId;
      final sp = await SharedPreferences.getInstance();
      final raw = sp.getString('$_prefQueuePrefix$uid');
      final list = (raw != null && raw.isNotEmpty)
          ? List<dynamic>.from(jsonDecode(raw) as List)
          : <dynamic>[];
      list.add({
        ...event.toJson(),
        'idempotency_key': dedupKey,
        'create_alert': createAlert,
      });
      if (list.length > 200) {
        list.removeRange(0, list.length - 200);
      }
      await sp.setString('$_prefQueuePrefix$uid', jsonEncode(list));
      offlineQueueCountNotifier.value = list.length;
    } catch (_) {}
  }

  Future<void> _loadOfflineQueueCount() async {
    try {
      final uid = currentUserId;
      final sp = await SharedPreferences.getInstance();
      final raw = sp.getString('$_prefQueuePrefix$uid');
      if (raw != null && raw.isNotEmpty) {
        final list = jsonDecode(raw);
        if (list is List) {
          offlineQueueCountNotifier.value = list.length;
          return;
        }
      }
      offlineQueueCountNotifier.value = 0;
    } catch (_) {
      offlineQueueCountNotifier.value = 0;
    }
  }

  Future<void> _upsertLocalEvent(SecurityEventModel event) async {
    final current = List<SecurityEventModel>.from(eventsNotifier.value);
    final idx = current.indexWhere((e) => e.eventId == event.eventId);
    if (idx >= 0) {
      current[idx] = event;
    } else {
      current.insert(0, event);
    }
    if (current.length > 250) {
      current.removeRange(250, current.length);
    }
    eventsNotifier.value = current;
    await _persistLocalEvents(current);
  }

  Future<void> _persistLocalEvents(List<SecurityEventModel> events) async {
    try {
      final uid = currentUserId;
      final sp = await SharedPreferences.getInstance();
      await sp.setString(
        '$_prefEventsPrefix$uid',
        jsonEncode(events.take(200).map((e) => e.toJson()).toList()),
      );
    } catch (_) {}
  }

  Future<void> _loadLocalEvents() async {
    try {
      final uid = currentUserId;
      final sp = await SharedPreferences.getInstance();
      final raw = sp.getString('$_prefEventsPrefix$uid');
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is List) {
          final loaded = decoded
              .whereType<Map<String, dynamic>>()
              .map(SecurityEventModel.fromJson)
              .toList();
          eventsNotifier.value = loaded;
          _recomputeLocalAnalytics(period: _currentPeriod);
        }
      }
    } catch (_) {}
  }

  Future<void> _mirrorToFirestore(SecurityEventModel event) async {
    if (!isAuthenticated) return;
    try {
      await FirebaseFirestore.instance
          .collection('users')
          .doc(currentUserId)
          .collection('security_events')
          .doc(event.eventId)
          .set(event.toJson(), SetOptions(merge: true))
          .timeout(const Duration(seconds: 4));
    } catch (_) {}
  }
}
