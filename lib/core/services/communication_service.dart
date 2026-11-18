// CyberShield Communication History & Threat Percentage Tracking Service
// Coordinates native Android SMS/Notification/Call readers, Gmail integration,
// FastAPI real-time analysis, user-isolated Firestore sync, offline fallback,
// privacy redaction, retention cleanup, and live threat analytics.

import 'dart:async';
import 'dart:convert';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/alert_service.dart';
import 'package:cybershield/core/services/gmail_service.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';

class CommunicationService {
  static final CommunicationService instance = CommunicationService._internal();
  CommunicationService._internal();

  static const MethodChannel _channel = MethodChannel('com.example.mobile/protection');
  static const String _prefSettingsPrefix = 'cybershield_comm_settings_';
  static const String _prefRecordsPrefix = 'cybershield_comm_records_';

  final ValueNotifier<List<CommunicationRecord>> recordsNotifier =
      ValueNotifier<List<CommunicationRecord>>([]);
  final ValueNotifier<CommunicationAnalytics> analyticsNotifier =
      ValueNotifier<CommunicationAnalytics>(const CommunicationAnalytics());
  final ValueNotifier<CommunicationSettings> settingsNotifier =
      ValueNotifier<CommunicationSettings>(const CommunicationSettings());
  final ValueNotifier<CommunicationPermissionsStatus> permissionsNotifier =
      ValueNotifier<CommunicationPermissionsStatus>(const CommunicationPermissionsStatus());
  final ValueNotifier<bool> isLoadingNotifier = ValueNotifier<bool>(false);
  final ValueNotifier<bool> isSyncingNotifier = ValueNotifier<bool>(false);
  final ValueNotifier<String?> errorNotifier = ValueNotifier<String?>(null);

  final Set<String> _recentDedupKeys = {};
  String _currentPeriod = 'daily';
  bool _initializedForUid = false;
  String? _activeUid;

  String get currentUserId {
    try {
      return FirebaseAuth.instance.currentUser?.uid ?? 'local_guest';
    } catch (_) {
      return 'local_guest';
    }
  }

  bool get isAuthenticated {
    try {
      return FirebaseAuth.instance.currentUser != null;
    } catch (_) {
      return false;
    }
  }

  /// Client-side sensitive data redaction (never leak OTPs, cards, CVVs, passwords, tokens)
  static String redactSensitive(String input) {
    var out = input;
    out = out.replaceAll(RegExp(r'\b(?:\d{4}[ -]?){3}\d{1,4}\b'), '[REDACTED_CARD]');
    out = out.replaceAllMapped(
      RegExp(
        r'\b(otp|code|pin|passcode|verification code|auth code|security code)\s*[:=\-#]?\s*(\d{4,8})\b',
        caseSensitive: false,
      ),
      (m) => '${m.group(1)}: [REDACTED_OTP]',
    );
    out = out.replaceAll(
      RegExp(r'\bcvv\s*[:=\-]?\s*\d{3,4}\b', caseSensitive: false),
      'cvv: [REDACTED]',
    );
    out = out.replaceAllMapped(
      RegExp(r'\b(password|passwd|pwd|secret|token|bearer)\s*[:=]\s*([^\s,;]+)', caseSensitive: false),
      (m) => '${m.group(1)}=[REDACTED]',
    );
    return out;
  }

  /// Initialize for the active authenticated user (resets cleanly if user switched accounts!)
  Future<void> initialize({bool forceRefresh = false}) async {
    final uid = currentUserId;
    if (_activeUid != uid) {
      _activeUid = uid;
      _initializedForUid = false;
      _recentDedupKeys.clear();
      recordsNotifier.value = [];
      analyticsNotifier.value = const CommunicationAnalytics();
    }

    if (_initializedForUid && !forceRefresh) return;
    _initializedForUid = true;

    await loadSettings();
    await refreshPermissions();
    await _loadLocalRecords();
    await refreshAll(period: _currentPeriod);
  }

  /// Load user-isolated settings from SharedPreferences + Firestore and sync to native Kotlin
  Future<CommunicationSettings> loadSettings() async {
    final uid = currentUserId;
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString('$_prefSettingsPrefix$uid');
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          settingsNotifier.value = CommunicationSettings.fromJson(decoded);
        }
      }

      if (isAuthenticated) {
        try {
          final doc = await FirebaseFirestore.instance
              .collection('users')
              .doc(uid)
              .collection('communication_settings')
              .doc('default')
              .get()
              .timeout(const Duration(seconds: 4));
          if (doc.exists && doc.data() != null) {
            settingsNotifier.value = CommunicationSettings.fromJson(doc.data());
            await prefs.setString('$_prefSettingsPrefix$uid', jsonEncode(settingsNotifier.value.toJson()));
          }
        } catch (_) {
          // Offline or Firestore unavailable; keep local settings
        }
      }
    } catch (_) {}

    await _syncPreferencesToNative(settingsNotifier.value);
    return settingsNotifier.value;
  }

  /// Save updated communication monitoring / privacy settings across local, Firestore, and native
  Future<void> updateSettings(CommunicationSettings updated) async {
    settingsNotifier.value = updated;
    final uid = currentUserId;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('$_prefSettingsPrefix$uid', jsonEncode(updated.toJson()));
    } catch (_) {}

    if (isAuthenticated) {
      try {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(uid)
            .collection('communication_settings')
            .doc('default')
            .set(updated.toJson(), SetOptions(merge: true))
            .timeout(const Duration(seconds: 4));
      } catch (_) {}
    }

    await _syncPreferencesToNative(updated);
  }

  Future<void> _syncPreferencesToNative(CommunicationSettings s) async {
    try {
      await _channel.invokeMethod('syncCommunicationPreferences', {
        'monitoringPaused': s.monitoringPaused || !s.consentAcknowledged,
        'monitorSms': s.monitorSms,
        'monitorNotifications': s.monitorNotifications,
        'monitorCalls': s.monitorCalls,
        'monitorEmail': s.monitorEmail,
        'monitorWhatsapp': s.monitorWhatsapp,
        'storeMessagePreview': s.storeMessagePreview,
      });
    } on MissingPluginException {
      // Non-Android / unit tests
    } catch (_) {}
  }

  /// Refresh actual Android permissions & Telecom Call Screening role state
  Future<CommunicationPermissionsStatus> refreshPermissions() async {
    try {
      final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>('getCommunicationPermissionsStatus');
      if (raw != null) {
        final st = CommunicationPermissionsStatus.fromMap(raw);
        permissionsNotifier.value = st;
        return st;
      }
    } on MissingPluginException {
      // Non-Android / unit tests
    } catch (_) {}
    return permissionsNotifier.value;
  }

  /// Request a specific runtime Android permission ('sms', 'call_log', 'contacts')
  Future<Map<String, dynamic>> requestNativePermission(String permissionType) async {
    try {
      final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'requestCommunicationPermission',
        {'permissionType': permissionType},
      );
      await refreshPermissions();
      if (raw != null) {
        return Map<String, dynamic>.from(raw);
      }
    } on MissingPluginException {
      return {
        'granted': false,
        'status': 'unsupported',
        'message': 'Android permissions are only available on Android devices.',
      };
    } catch (e) {
      return {'granted': false, 'status': 'error', 'message': e.toString()};
    }
    return {'granted': false, 'status': 'denied', 'message': 'Permission was not granted.'};
  }

  /// Ingest and analyze a single eligible communication (both normal and suspicious are recorded!)
  Future<CommunicationRecord?> ingestCommunication({
    required String communicationType,
    required String sourceApp,
    required String senderIdentifier,
    String? callerName,
    String? subject,
    String? content,
    DateTime? timestamp,
    bool? isKnownContact,
    String? callStatus,
    String? externalId,
    Map<String, dynamic>? metadata,
  }) async {
    final settings = settingsNotifier.value;
    if (settings.monitoringPaused) return null;

    final type = communicationType.trim().toLowerCase();
    if (type == 'sms' && !settings.monitorSms && !settings.monitorNotifications) return null;
    if (type == 'whatsapp' && !settings.monitorWhatsapp) return null;
    if (type == 'notification' && !settings.monitorNotifications) return null;
    if (type == 'call' && !settings.monitorCalls) return null;
    if (type == 'email' && !settings.monitorEmail) return null;

    final ts = timestamp ?? DateTime.now();
    final tsIso = ts.toUtc().toIso8601String();
    final sanitizedSender = redactSensitive(senderIdentifier.trim());
    final sanitizedContent = redactSensitive((content ?? '').trim());
    final sanitizedSubject = redactSensitive((subject ?? '').trim());

    // Local dedup guard (prevents duplicate processing of rapid re-posted notifications)
    final minuteKey = tsIso.length >= 16 ? tsIso.substring(0, 16) : tsIso;
    final dedupKey = externalId != null && externalId.isNotEmpty
        ? '$currentUserId|$type|ext:$externalId'
        : '$currentUserId|$type|${sourceApp.toLowerCase()}|${sanitizedSender.toLowerCase()}|${sanitizedContent.toLowerCase().hashCode}|$minuteKey';
    if (_recentDedupKeys.contains(dedupKey)) {
      return null;
    }
    _recentDedupKeys.add(dedupKey);
    if (_recentDedupKeys.length > 500) {
      _recentDedupKeys.remove(_recentDedupKeys.first);
    }

    // Try real CyberShield FastAPI backend analysis first
    CommunicationRecord? record = await ApiService.ingestCommunication(
      communicationType: type,
      sourceApp: sourceApp,
      senderIdentifier: sanitizedSender,
      callerName: callerName,
      subject: sanitizedSubject.isNotEmpty ? sanitizedSubject : null,
      content: sanitizedContent.isNotEmpty ? sanitizedContent : null,
      timestamp: tsIso,
      storePreview: settings.storeMessagePreview,
      isKnownContact: isKnownContact,
      callStatus: callStatus,
      externalId: externalId,
      metadata: metadata,
    );

    // Offline / backend unavailable safe fallback:
    // Record accurately as 'unanalyzed' (never fabricate a threat score or falsely mark as safe/spam!)
    if (record == null) {
      final preview = settings.storeMessagePreview
          ? (sanitizedContent.isNotEmpty
              ? sanitizedContent
              : (sanitizedSubject.isNotEmpty ? sanitizedSubject : ''))
          : '';
      record = CommunicationRecord(
        recordId: 'comm-local-${ts.millisecondsSinceEpoch}-${dedupKey.hashCode.abs()}',
        userId: currentUserId,
        communicationType: type,
        sourceApp: sourceApp,
        senderIdentifier: sanitizedSender,
        callerName: callerName,
        messagePreview: preview.length > 220 ? preview.substring(0, 220) : preview,
        timestamp: ts,
        riskScore: 0,
        classification: 'Unavailable',
        threatCategories: const [],
        findings: const ['Backend threat engine was unreachable at capture time.'],
        explanation: type == 'call'
            ? 'Backend unreachable; caller reputation could not be verified. Call allowed safely without blocking. Audio is never analyzed.'
            : 'Backend unreachable; message was recorded as unanalyzed without fabricating a risk score.',
        recommendedAction: 'Reconnect to CyberShield backend and tap Sync to analyze.',
        analysisStatus: 'unanalyzed',
        isKnownContact: isKnownContact,
        callStatus: callStatus,
        spamReputation: type == 'call' ? 'unknown' : null,
        metadata: {
          ...?metadata,
          'offline_capture': true,
          if (type == 'call') 'audio_analyzed': false,
        },
      );
    }

    if (!record.isDuplicate) {
      await _storeLocallyAndMirrorFirestore(record);
      _recomputeLocalAnalyticsIfNeeded();

      final commModule = record.isCall
          ? 'call_screening'
          : (record.communicationType == 'email' && record.sourceApp.toLowerCase().contains('gmail'))
              ? 'gmail_integration'
              : (record.communicationType == 'email')
                  ? 'email_scanner'
                  : (record.communicationType == 'sms' ? 'sms_scanner' : 'notification_monitor');
      final commModuleLabel = SmartAlertEngine.moduleMeta(commModule).label;

      // Mirror into Centralized Smart Event Engine (records unavailable honestly if backend was offline!)
      unawaited(
        SmartAlertEngine.instance.submitEvent(
          moduleName: commModule,
          eventCategory: record.isAnalyzed ? 'comm_${record.communicationType}' : 'service_interruption',
          source: 'communication',
          targetIdentifier: record.displayTitle,
          riskScore: record.isAnalyzed ? record.riskScore : null,
          classification: record.isAnalyzed ? record.classification : 'Unavailable',
          findings: record.findings,
          explanation: record.explanation,
          recommendedActions: [record.recommendedAction],
          analysisStatus: record.isAnalyzed ? 'analyzed' : 'unavailable',
          idempotencyKey: 'comm:${record.recordId}',
          createBackendAlert: false,
          skipBackendPost: record.isAnalyzed, // Online records were already mirrored server-side
          metadata: {'record_id': record.recordId, 'source_app': record.sourceApp},
        ),
      );

      // Generate alert/notification ONLY for meaningful threats (>= 41%), never for normal safe messages
      if (record.isAnalyzed && record.riskScore >= 41) {
        final shouldAlert = (record.riskScore >= 61 && settings.alertOnHighRisk) ||
            (record.riskScore >= 41 && record.riskScore <= 60 && settings.alertOnSuspicious);
        if (shouldAlert) {
          await AlertService.instance.evaluateAndRecordScanAlert(
            scanType: record.isCall ? 'SPAM_CALLER' : 'SMS_SCAM',
            target: record.displayTitle,
            riskScore: record.riskScore,
            classification: record.classification,
            summary: record.explanation,
            recommendedActions: [record.recommendedAction],
          );
          await ProtectionService.instance.showLocalNotification(
            title: '${record.classification} ${record.sourceApp} (${record.riskScore}%)',
            body: '${record.displayTitle}: ${record.recommendedAction}',
            severity: record.classification.toLowerCase(),
            moduleName: commModuleLabel,
            hideOnLockScreen: SmartAlertEngine.instance.prefsNotifier.value.hideSensitiveOnLockScreen,
          );
        }
      }
    }

    return record;
  }

  /// Sync all eligible device communications (pending native queue, SMS inbox if granted,
  /// Call log if granted, and authorized Gmail messages if connected).
  Future<Map<String, int>> syncDeviceCommunications({int maxPerSource = 25}) async {
    if (isSyncingNotifier.value) return {'synced': 0};
    final settings = settingsNotifier.value;
    if (settings.monitoringPaused || !settings.consentAcknowledged) {
      return {'synced': 0};
    }

    isSyncingNotifier.value = true;
    int syncedCount = 0;

    try {
      await refreshPermissions();
      final perms = permissionsNotifier.value;

      // 1. Drain notifications / real-time SMS / real-time calls captured while backgrounded
      try {
        final pending = await _channel.invokeMethod<List<dynamic>>('drainPendingCommunicationEvents');
        if (pending != null) {
          for (final raw in pending) {
            if (raw is! Map) continue;
            final ev = Map<String, dynamic>.from(raw);
            final commType = ev['communicationType']?.toString() ??
                (ev['type'] == 'comm_sms'
                    ? 'sms'
                    : (ev['type'] == 'comm_call' ? 'call' : 'notification'));
            final tsMs = ev['timestamp'] is int
                ? ev['timestamp'] as int
                : (ev['postTime'] is int ? ev['postTime'] as int : DateTime.now().millisecondsSinceEpoch);
            final rec = await ingestCommunication(
              communicationType: commType,
              sourceApp: ev['sourceApp']?.toString() ?? ev['packageName']?.toString() ?? 'Notification',
              senderIdentifier: ev['sender']?.toString() ?? ev['phoneNumber']?.toString() ?? 'Unknown',
              callerName: ev['callerName']?.toString(),
              subject: ev['title']?.toString(),
              content: ev['content']?.toString() ?? ev['text']?.toString(),
              timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
              isKnownContact: ev['isKnownContact'] is bool ? ev['isKnownContact'] as bool : null,
              callStatus: ev['callStatus']?.toString(),
            );
            if (rec != null && !rec.isDuplicate) syncedCount++;
          }
        }
      } catch (_) {}

      // 2. Read eligible recent SMS inbox messages ONLY if user consented & granted READ_SMS
      if (settings.monitorSms && perms.readSms) {
        try {
          final smsRes = await _channel.invokeMethod<Map<dynamic, dynamic>>(
            'readRecentSmsMessages',
            {'limit': maxPerSource},
          );
          final msgs = (smsRes?['messages'] as List?) ?? [];
          for (final raw in msgs) {
            if (raw is! Map) continue;
            final m = Map<String, dynamic>.from(raw);
            final tsMs = m['timestamp'] is int ? m['timestamp'] as int : DateTime.now().millisecondsSinceEpoch;
            final rec = await ingestCommunication(
              communicationType: 'sms',
              sourceApp: 'SMS',
              senderIdentifier: m['sender']?.toString() ?? 'Unknown Sender',
              content: m['content']?.toString() ?? '',
              timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
              externalId: m['externalId']?.toString(),
            );
            if (rec != null && !rec.isDuplicate) syncedCount++;
          }
        } catch (_) {}
      }

      // 3. Read eligible recent incoming calls ONLY if user consented & granted READ_CALL_LOG
      if (settings.monitorCalls && perms.readCallLog) {
        try {
          final callRes = await _channel.invokeMethod<Map<dynamic, dynamic>>(
            'readRecentIncomingCalls',
            {'limit': maxPerSource},
          );
          final calls = (callRes?['calls'] as List?) ?? [];
          for (final raw in calls) {
            if (raw is! Map) continue;
            final c = Map<String, dynamic>.from(raw);
            final tsMs = c['timestamp'] is int ? c['timestamp'] as int : DateTime.now().millisecondsSinceEpoch;
            final rec = await ingestCommunication(
              communicationType: 'call',
              sourceApp: 'Phone Call',
              senderIdentifier: c['phoneNumber']?.toString() ?? 'Unknown',
              callerName: c['callerName']?.toString(),
              isKnownContact: c['isKnownContact'] is bool ? c['isKnownContact'] as bool : null,
              callStatus: c['callStatus']?.toString() ?? 'incoming',
              timestamp: DateTime.fromMillisecondsSinceEpoch(tsMs),
              externalId: c['externalId']?.toString(),
              metadata: {
                if (c['durationSeconds'] != null) 'duration_seconds': c['durationSeconds'],
              },
            );
            if (rec != null && !rec.isDuplicate) syncedCount++;
          }
        } catch (_) {}
      }

      // 4. Ingest authorized Gmail messages ONLY if Gmail OAuth is explicitly connected & enabled
      if (settings.monitorEmail && GmailService.instance.isConnected) {
        final emails = GmailService.instance.messages;
        for (final mail in emails.take(maxPerSource)) {
          final rec = await ingestCommunication(
            communicationType: 'email',
            sourceApp: 'Gmail (Authorized)',
            senderIdentifier: mail.sender,
            subject: mail.subject,
            content: mail.bodyText.isNotEmpty ? mail.bodyText : mail.snippet,
            timestamp: DateTime.tryParse(mail.date) ?? DateTime.now(),
            externalId: 'gmail_${mail.id}',
          );
          if (rec != null && !rec.isDuplicate) syncedCount++;
        }
      }

      await refreshAll(period: _currentPeriod);
    } finally {
      isSyncingNotifier.value = false;
    }

    return {'synced': syncedCount};
  }

  /// Refresh history & analytics from FastAPI backend (merging Firestore & local offline cache)
  Future<void> refreshAll({String? period}) async {
    if (period != null) _currentPeriod = period;
    isLoadingNotifier.value = true;
    errorNotifier.value = null;

    try {
      final remoteHistory = await ApiService.getCommunicationHistory(limit: 200);
      final remoteAnalytics = await ApiService.getCommunicationAnalytics(period: _currentPeriod);

      if (remoteHistory != null) {
        final remoteRecords = remoteHistory['records'] as List<CommunicationRecord>;
        // Merge with any local offline-only records that haven't synced yet
        final merged = _mergeRecords(remoteRecords, recordsNotifier.value);
        recordsNotifier.value = merged;
        await _saveLocalRecords(merged);
      } else {
        // Fallback: load from Firestore if backend is offline
        final firestoreRecords = await _fetchFromFirestore();
        if (firestoreRecords.isNotEmpty) {
          final merged = _mergeRecords(firestoreRecords, recordsNotifier.value);
          recordsNotifier.value = merged;
          await _saveLocalRecords(merged);
        }
      }

      if (remoteAnalytics != null) {
        analyticsNotifier.value = remoteAnalytics;
      } else {
        analyticsNotifier.value = computeAnalyticsLocally(
          recordsNotifier.value,
          period: _currentPeriod,
        );
      }
    } catch (e) {
      errorNotifier.value = 'Unable to refresh remote communication telemetry; showing local records.';
      analyticsNotifier.value = computeAnalyticsLocally(
        recordsNotifier.value,
        period: _currentPeriod,
      );
    } finally {
      isLoadingNotifier.value = false;
    }
  }

  /// Delete a single communication record across backend, Firestore, and local cache
  Future<bool> deleteRecord(String recordId) async {
    await ApiService.deleteCommunicationRecord(recordId);
    if (isAuthenticated) {
      try {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(currentUserId)
            .collection('communication_history')
            .doc(recordId)
            .delete()
            .timeout(const Duration(seconds: 4));
      } catch (_) {}
    }

    final updated = recordsNotifier.value.where((r) => r.recordId != recordId).toList();
    recordsNotifier.value = updated;
    await _saveLocalRecords(updated);
    analyticsNotifier.value = computeAnalyticsLocally(updated, period: _currentPeriod);
    return true;
  }

  /// Apply configured retention days (delete records older than retentionDays)
  Future<int> applyRetentionCleanup({int? daysOverride}) async {
    final days = daysOverride ?? settingsNotifier.value.retentionDays;
    final cutoff = DateTime.now().subtract(Duration(days: days));

    await ApiService.purgeCommunicationHistory(olderThanDays: days);

    final toDelete = recordsNotifier.value.where((r) => r.timestamp.isBefore(cutoff)).toList();
    if (isAuthenticated) {
      for (final rec in toDelete) {
        try {
          await FirebaseFirestore.instance
              .collection('users')
              .doc(currentUserId)
              .collection('communication_history')
              .doc(rec.recordId)
              .delete();
        } catch (_) {}
      }
    }

    final remaining = recordsNotifier.value.where((r) => !r.timestamp.isBefore(cutoff)).toList();
    recordsNotifier.value = remaining;
    await _saveLocalRecords(remaining);
    analyticsNotifier.value = computeAnalyticsLocally(remaining, period: _currentPeriod);
    return toDelete.length;
  }

  /// Delete ALL communication history for the authenticated user
  Future<int> clearAllHistory() async {
    final prevCount = recordsNotifier.value.length;
    await ApiService.purgeCommunicationHistory();

    if (isAuthenticated) {
      try {
        final col = FirebaseFirestore.instance
            .collection('users')
            .doc(currentUserId)
            .collection('communication_history');
        final snap = await col.get().timeout(const Duration(seconds: 6));
        for (final doc in snap.docs) {
          await doc.reference.delete();
        }
      } catch (_) {}
    }

    recordsNotifier.value = [];
    _recentDedupKeys.clear();
    await _saveLocalRecords([]);
    analyticsNotifier.value = computeAnalyticsLocally([], period: _currentPeriod);
    return prevCount;
  }

  Future<void> _storeLocallyAndMirrorFirestore(CommunicationRecord record) async {
    final updated = _mergeRecords([record], recordsNotifier.value);
    recordsNotifier.value = updated;
    await _saveLocalRecords(updated);

    if (isAuthenticated) {
      try {
        await FirebaseFirestore.instance
            .collection('users')
            .doc(currentUserId)
            .collection('communication_history')
            .doc(record.recordId)
            .set(record.toJson(), SetOptions(merge: true))
            .timeout(const Duration(seconds: 4));
      } catch (_) {
        // Offline safe
      }
    }
  }

  Future<List<CommunicationRecord>> _fetchFromFirestore() async {
    if (!isAuthenticated) return [];
    try {
      final snap = await FirebaseFirestore.instance
          .collection('users')
          .doc(currentUserId)
          .collection('communication_history')
          .orderBy('timestamp', descending: true)
          .limit(200)
          .get()
          .timeout(const Duration(seconds: 5));
      return snap.docs.map((d) => CommunicationRecord.fromJson(d.data())).toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> _loadLocalRecords() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString('$_prefRecordsPrefix$currentUserId');
      if (raw == null || raw.isEmpty) return;
      final decoded = jsonDecode(raw);
      if (decoded is List) {
        final items = decoded
            .whereType<Map>()
            .map((e) => CommunicationRecord.fromJson(Map<String, dynamic>.from(e)))
            .toList();
        items.sort((a, b) => b.timestamp.compareTo(a.timestamp));
        recordsNotifier.value = items;
        analyticsNotifier.value = computeAnalyticsLocally(items, period: _currentPeriod);
      }
    } catch (_) {}
  }

  Future<void> _saveLocalRecords(List<CommunicationRecord> items) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final capped = items.take(300).map((e) => e.toJson()).toList();
      await prefs.setString('$_prefRecordsPrefix$currentUserId', jsonEncode(capped));
    } catch (_) {}
  }

  List<CommunicationRecord> _mergeRecords(
    List<CommunicationRecord> primary,
    List<CommunicationRecord> secondary,
  ) {
    final map = <String, CommunicationRecord>{};
    for (final r in secondary) {
      map[r.recordId] = r;
    }
    for (final r in primary) {
      map[r.recordId] = r;
    }
    final list = map.values.toList()..sort((a, b) => b.timestamp.compareTo(a.timestamp));
    return list;
  }

  void _recomputeLocalAnalyticsIfNeeded() {
    analyticsNotifier.value = computeAnalyticsLocally(
      recordsNotifier.value,
      period: _currentPeriod,
    );
  }

  /// Pure deterministic analytics calculation from real stored records (never fake data!)
  static CommunicationAnalytics computeAnalyticsLocally(
    List<CommunicationRecord> records, {
    String period = 'daily',
  }) {
    CommunicationBucketStats bucketStats(List<CommunicationRecord> list) {
      final received = list.length;
      int analyzed = 0;
      int unanalyzed = 0;
      int safe = 0;
      int low = 0;
      int susp = 0;
      int high = 0;
      int crit = 0;
      int unknownCallers = 0;

      for (final r in list) {
        if (!r.isAnalyzed) {
          unanalyzed++;
          continue;
        }
        analyzed++;
        final cls = r.classification.toLowerCase();
        if (cls == 'critical') {
          crit++;
        } else if (cls == 'high risk') {
          high++;
        } else if (cls == 'suspicious') {
          susp++;
        } else if (cls == 'low risk') {
          low++;
        } else {
          safe++;
        }
        if (r.isCall && r.isKnownContact == false) {
          unknownCallers++;
        }
      }

      final flagged = susp + high + crit;
      final rate = analyzed > 0 ? double.parse(((flagged / analyzed) * 100.0).toStringAsFixed(1)) : null;

      return CommunicationBucketStats(
        totalReceived: received,
        totalAnalyzed: analyzed,
        totalUnanalyzed: unanalyzed,
        safeCount: safe,
        lowRiskCount: low,
        suspiciousCount: susp,
        highRiskCount: high,
        criticalCount: crit,
        threatFlaggedCount: flagged,
        threatDetectionRate: rate,
        hasAnalyzedData: analyzed > 0,
        unknownCallersCount: unknownCallers,
      );
    }

    final msgs = records.where((r) => !r.isCall).toList();
    final calls = records.where((r) => r.isCall).toList();
    final overall = bucketStats(records);
    final msgStats = bucketStats(msgs);
    final callStats = bucketStats(calls);

    final now = DateTime.now();
    final p = (period == 'weekly' || period == 'monthly') ? period : 'daily';
    final trendMap = <String, List<int>>{}; // [total, analyzed, safe, threats]

    if (p == 'daily') {
      for (int d = 13; d >= 0; d--) {
        final dt = now.subtract(Duration(days: d));
        final key = '${dt.year.toString().padLeft(4, '0')}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';
        trendMap[key] = [0, 0, 0, 0];
      }
    } else if (p == 'weekly') {
      for (int w = 7; w >= 0; w--) {
        final dt = now.subtract(Duration(days: w * 7));
        final key = 'W${_weekOfYear(dt)}';
        trendMap[key] = [0, 0, 0, 0];
      }
    } else {
      for (int m = 5; m >= 0; m--) {
        int y = now.year;
        int mo = now.month - m;
        while (mo <= 0) {
          mo += 12;
          y -= 1;
        }
        final key = '${y.toString().padLeft(4, '0')}-${mo.toString().padLeft(2, '0')}';
        trendMap[key] = [0, 0, 0, 0];
      }
    }

    final catCounts = <String, int>{};
    for (final r in records) {
      final dt = r.timestamp;
      String key;
      if (p == 'daily') {
        key = '${dt.year.toString().padLeft(4, '0')}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';
      } else if (p == 'weekly') {
        key = 'W${_weekOfYear(dt)}';
      } else {
        key = '${dt.year.toString().padLeft(4, '0')}-${dt.month.toString().padLeft(2, '0')}';
      }

      if (trendMap.containsKey(key)) {
        trendMap[key]![0]++;
        if (r.isAnalyzed) {
          trendMap[key]![1]++;
          if (r.isThreatFlagged) {
            trendMap[key]![3]++;
          } else {
            trendMap[key]![2]++;
          }
        }
      }

      for (final c in r.threatCategories) {
        if (c.trim().isNotEmpty) {
          catCounts[c.trim()] = (catCounts[c.trim()] ?? 0) + 1;
        }
      }
    }

    final trends = trendMap.entries.map((e) {
      final analyzed = e.value[1];
      final threats = e.value[3];
      final pct = analyzed > 0 ? double.parse(((threats / analyzed) * 100.0).toStringAsFixed(1)) : 0.0;
      return CommunicationTrendPoint(
        label: e.key,
        total: e.value[0],
        analyzed: analyzed,
        safe: e.value[2],
        threats: threats,
        threatPercentage: pct,
      );
    }).toList();

    final topCats = catCounts.entries.toList()..sort((a, b) => b.value.compareTo(a.value));

    Map<String, int> distMap(CommunicationBucketStats s) => {
          'Safe': s.safeCount,
          'Low Risk': s.lowRiskCount,
          'Suspicious': s.suspiciousCount,
          'High Risk': s.highRiskCount,
          'Critical': s.criticalCount,
          'Unanalyzed': s.totalUnanalyzed,
        };

    return CommunicationAnalytics(
      period: p,
      overall: overall,
      messages: msgStats,
      calls: callStats,
      trends: trends,
      smsThreatDistribution: distMap(msgStats),
      callThreatDistribution: distMap(callStats),
      topThreatCategories: topCats.take(8).map((e) => {'category': e.key, 'count': e.value}).toList(),
    );
  }

  static int _weekOfYear(DateTime dt) {
    final startOfYear = DateTime(dt.year, 1, 1);
    final diff = dt.difference(startOfYear).inDays;
    return ((diff + startOfYear.weekday) / 7).ceil();
  }
}
