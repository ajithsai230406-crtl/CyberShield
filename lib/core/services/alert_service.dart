// CyberShield Security Alerts Service
// Handles user-isolated Cloud Firestore alerts, deduplication, state transitions,
// and in-app alert badges with SQLite backend fallback.

import 'dart:async';
import 'dart:developer' as developer;
import 'package:flutter/foundation.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/models/security_alert.dart';
import 'package:cybershield/core/services/api_service.dart';

class AlertService {
  final FirebaseFirestore? _customDb;
  final FirebaseAuth? _customAuth;

  AlertService({
    FirebaseFirestore? firestore,
    FirebaseAuth? auth,
  })  : _customDb = firestore,
        _customAuth = auth;

  static final AlertService instance = AlertService();

  FirebaseFirestore? get _db {
    if (_customDb != null) return _customDb;
    try {
      return FirebaseFirestore.instance;
    } catch (_) {
      return null;
    }
  }

  FirebaseAuth? get _auth {
    if (_customAuth != null) return _customAuth;
    try {
      return FirebaseAuth.instance;
    } catch (_) {
      return null;
    }
  }

  /// Real-time notifier for unread alerts count to power UI badges
  final ValueNotifier<int> unreadCountNotifier = ValueNotifier<int>(0);

  String? get currentUserId {
    try {
      return _auth?.currentUser?.uid;
    } catch (_) {
      return null;
    }
  }

  bool get isAuthenticated => currentUserId != null;

  CollectionReference<Map<String, dynamic>>? get _alertsCollection {
    final uid = currentUserId;
    final db = _db;
    if (uid == null || uid.isEmpty || db == null) return null;
    return db.collection('users').doc(uid).collection('alerts');
  }

  /// Automatically evaluate a scan finding and record a security alert if
  /// Critical, High Risk, or Suspicious, with deduplication.
  Future<SecurityAlertModel?> evaluateAndRecordScanAlert({
    required String scanType,
    required String target,
    required int riskScore,
    required String classification,
    String? scanId,
    String? summary,
    List<String>? recommendedActions,
  }) async {
    final clsLower = classification.toLowerCase();
    final isCritical = riskScore >= 70 || clsLower == 'critical' || clsLower == 'malicious';
    final isHigh = riskScore >= 50 || clsLower == 'high risk' || clsLower == 'danger';
    final isSuspicious = riskScore >= 35 || clsLower == 'suspicious' || clsLower == 'warning';

    if (!isCritical && !isHigh && !isSuspicious) {
      return null; // Safe finding, no alert needed
    }

    String severity = 'medium';
    if (isCritical) {
      severity = 'critical';
    } else if (isHigh) {
      severity = 'high';
    }

    final category = scanType.toUpperCase();
    final defaultTitle = _generateTitle(category, target, severity);
    final defaultExplanation = summary != null && summary.isNotEmpty
        ? summary
        : _generateExplanation(category, target, severity, riskScore);
    final actions = (recommendedActions != null && recommendedActions.isNotEmpty)
        ? recommendedActions
        : _generateRecommendations(category, target);

    final eventKey = '${currentUserId ?? "global"}:${scanId ?? target}:$category:$severity';

    // 1. If authenticated, store in user's isolated Cloud Firestore collection
    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        if (col != null) {
          // Check for existing alert with same scanId or eventKey to prevent duplicates
          if (scanId != null && scanId.isNotEmpty) {
            final existing = await col
                .where('scanId', isEqualTo: scanId)
                .limit(1)
                .get()
                .timeout(const Duration(seconds: 6));
            if (existing.docs.isNotEmpty) {
              final doc = existing.docs.first;
              return _docToModel(doc.id, doc.data());
            }
          }

          final existingKey = await col
              .where('eventKey', isEqualTo: eventKey)
              .limit(1)
              .get()
              .timeout(const Duration(seconds: 6));
          if (existingKey.docs.isNotEmpty) {
            final doc = existingKey.docs.first;
            return _docToModel(doc.id, doc.data());
          }

          final nowIso = DateTime.now().toUtc().toIso8601String();
          final docRef = await col.add({
            'userId': currentUserId,
            'scanId': scanId,
            'eventKey': eventKey,
            'title': defaultTitle,
            'severity': severity,
            'category': category,
            'target': target,
            'riskScore': riskScore,
            'explanation': defaultExplanation,
            'recommendedActions': actions,
            'status': 'unread',
            'isRead': false,
            'isResolved': false,
            'timestamp': FieldValue.serverTimestamp(),
            'timestampIso': nowIso,
            'resolvedAt': null,
            'metadata': {'source': 'scanner_engine', 'classification': classification},
          });

          await refreshUnreadCount();

          return SecurityAlertModel(
            id: docRef.id,
            userId: currentUserId,
            scanId: scanId,
            eventKey: eventKey,
            title: defaultTitle,
            severity: severity,
            category: category,
            target: target,
            riskScore: riskScore,
            explanation: defaultExplanation,
            recommendedActions: actions,
            status: 'unread',
            isRead: false,
            isResolved: false,
            timestamp: nowIso,
          );
        }
      } catch (e, st) {
        developer.log('Error creating alert in Firestore: $e', error: e, stackTrace: st, name: 'AlertService');
      }
    }

    // 2. Fallback / Sync with backend API
    try {
      final backendAlert = await ApiService.createAlert({
        'title': defaultTitle,
        'severity': severity,
        'category': category,
        'target': target,
        'risk_score': riskScore,
        'explanation': defaultExplanation,
        'recommended_actions': actions,
        'scan_id': scanId,
        'event_key': eventKey,
      });

      await refreshUnreadCount();
      return backendAlert;
    } catch (_) {
      return null;
    }
  }

  /// Fetch list of security alerts with optional filters
  Future<List<SecurityAlertModel>> getAlerts({
    String? severity,
    bool? isRead,
    bool? isResolved,
    int limit = 100,
  }) async {
    // 1. Prioritize Cloud Firestore for authenticated users
    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        if (col != null) {
          Query<Map<String, dynamic>> query = col;

          if (severity != null && severity.isNotEmpty && severity != 'all') {
            query = query.where('severity', isEqualTo: severity.toLowerCase());
          }
          if (isRead != null) {
            query = query.where('isRead', isEqualTo: isRead);
          }
          if (isResolved != null) {
            query = query.where('isResolved', isEqualTo: isResolved);
          }

          // Order by timestamp descending
          try {
            query = query.orderBy('timestamp', descending: true);
          } catch (_) {
            // In case index is building
          }

          final snapshot = await query
              .limit(limit)
              .get()
              .timeout(const Duration(seconds: 6));
          final alerts = snapshot.docs.map((doc) => _docToModel(doc.id, doc.data())).toList();

          // Sort in memory if index was omitted
          alerts.sort((a, b) => b.timestamp.compareTo(a.timestamp));

          // Update unread count
          unreadCountNotifier.value = alerts.where((a) => !a.isRead && !a.isResolved).length;

          return alerts;
        }
      } catch (e, st) {
        developer.log('Firestore getAlerts error: $e', error: e, stackTrace: st, name: 'AlertService');
      }
    }

    // 2. Fallback to backend API SQLite history
    final backendList = await ApiService.getAlerts(
      severity: (severity != null && severity != 'all') ? severity : null,
      isRead: isRead,
      isResolved: isResolved,
      limit: limit,
    );

    unreadCountNotifier.value = backendList.where((a) => !a.isRead && !a.isResolved).length;
    return backendList;
  }

  /// Mark an alert as read / unread
  Future<bool> markAsRead(String alertId, bool isRead) async {
    bool updatedInCloud = false;

    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        if (col != null) {
          await col.doc(alertId).update({
            'isRead': isRead,
            'status': isRead ? 'read' : 'unread',
          });
          updatedInCloud = true;
        }
      } catch (_) {}
    }

    final backendSuccess = await ApiService.markAlertRead(alertId, isRead);
    await refreshUnreadCount();
    return updatedInCloud || backendSuccess;
  }

  /// Mark an alert as resolved
  Future<bool> markAsResolved(String alertId, bool isResolved) async {
    bool updatedInCloud = false;

    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        if (col != null) {
          await col.doc(alertId).update({
            'isResolved': isResolved,
            'status': isResolved ? 'resolved' : 'unread',
            'resolvedAt': isResolved ? DateTime.now().toUtc().toIso8601String() : null,
          });
          updatedInCloud = true;
        }
      } catch (_) {}
    }

    final backendSuccess = await ApiService.markAlertResolved(alertId, isResolved);
    await refreshUnreadCount();
    return updatedInCloud || backendSuccess;
  }

  /// Mark all alerts as read
  Future<void> markAllAsRead() async {
    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        final db = _db;
        if (col != null && db != null) {
          final snapshot = await col
              .where('isRead', isEqualTo: false)
              .get()
              .timeout(const Duration(seconds: 6));
          final batch = db.batch();
          for (final doc in snapshot.docs) {
            batch.update(doc.reference, {'isRead': true, 'status': 'read'});
          }
          await batch.commit();
        }
      } catch (_) {}
    }

    unreadCountNotifier.value = 0;
  }

  /// Clear all alert documents for the authenticated user safely using batched writes
  Future<bool> clearAllAlerts() async {
    if (!isAuthenticated) return false;
    try {
      final col = _alertsCollection;
      final db = _db;
      if (col == null || db == null) return false;

      final snapshot = await col.get().timeout(const Duration(seconds: 6));
      if (snapshot.docs.isEmpty) {
        unreadCountNotifier.value = 0;
        return true;
      }

      const batchSize = 400;
      for (var i = 0; i < snapshot.docs.length; i += batchSize) {
        final batch = db.batch();
        final chunk = snapshot.docs.skip(i).take(batchSize);
        for (final doc in chunk) {
          batch.delete(doc.reference);
        }
        await batch.commit();
      }
      unreadCountNotifier.value = 0;
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Refresh unread count for badge indicators
  Future<int> refreshUnreadCount() async {
    int count = 0;

    if (isAuthenticated) {
      try {
        final col = _alertsCollection;
        if (col != null) {
          final snapshot = await col
              .where('isRead', isEqualTo: false)
              .get()
              .timeout(const Duration(seconds: 6));
          count = snapshot.docs.where((d) => d.data()['isResolved'] != true).length;
          unreadCountNotifier.value = count;
          return count;
        }
      } catch (_) {}
    }

    final stats = await ApiService.getAlertStats();
    if (stats != null) {
      count = stats.unread;
    }
    unreadCountNotifier.value = count;
    return count;
  }

  /// Request notification permission transparently explaining scope
  Future<bool> requestNotificationPermissions() async {
    developer.log(
      'Notification permission requested. Notice: CyberShield alerts are generated '
      'during active scans and user evaluations. Continuous background monitoring is not active.',
      name: 'AlertService',
    );
    return true;
  }

  SecurityAlertModel _docToModel(String docId, Map<String, dynamic> data) {
    String tsIso = DateTime.now().toUtc().toIso8601String();
    final rawTs = data['timestamp'];
    if (rawTs is Timestamp) {
      tsIso = rawTs.toDate().toUtc().toIso8601String();
    } else if (rawTs is String) {
      tsIso = rawTs;
    } else if (data['timestampIso'] != null) {
      tsIso = data['timestampIso'].toString();
    }

    List<String> actions = [];
    if (data['recommendedActions'] is List) {
      actions = (data['recommendedActions'] as List).map((e) => e.toString()).toList();
    } else if (data['recommended_actions'] is List) {
      actions = (data['recommended_actions'] as List).map((e) => e.toString()).toList();
    }

    return SecurityAlertModel(
      id: docId,
      userId: data['userId']?.toString() ?? data['user_id']?.toString(),
      scanId: data['scanId']?.toString() ?? data['scan_id']?.toString(),
      eventKey: data['eventKey']?.toString() ?? data['event_key']?.toString(),
      title: data['title']?.toString() ?? 'Security Alert',
      severity: (data['severity']?.toString() ?? 'medium').toLowerCase(),
      category: (data['category']?.toString() ?? 'SYSTEM').toUpperCase(),
      target: data['target']?.toString() ?? '',
      riskScore: data['riskScore'] as int? ?? data['risk_score'] as int? ?? 0,
      explanation: data['explanation']?.toString() ?? '',
      recommendedActions: actions,
      status: data['status']?.toString() ?? 'unread',
      isRead: data['isRead'] == true || data['is_read'] == true,
      isResolved: data['isResolved'] == true || data['is_resolved'] == true,
      timestamp: tsIso,
      resolvedAt: data['resolvedAt']?.toString() ?? data['resolved_at']?.toString(),
      metadata: Map<String, dynamic>.from(data['metadata'] as Map? ?? {}),
    );
  }

  String _generateTitle(String category, String target, String severity) {
    final sev = severity.capitalize();
    switch (category.toUpperCase()) {
      case 'URL':
        return '$sev Risk Phishing URL: $target';
      case 'SMS':
        return '$sev Threat Smishing Message: $target';
      case 'QR':
        return '$sev Malicious QR Code Redirection: $target';
      case 'APK':
        return '$sev Malware Risk in APK: $target';
      case 'PERMISSIONS':
        return '$sev Excessive App Permission: $target';
      case 'EMAIL':
        return '$sev Email Phishing Threat: $target';
      case 'FILE':
        return '$sev Suspicious File Artifact: $target';
      case 'COMMUNITY':
        return '$sev Community Threat Intel Alert: $target';
      case 'NOTIFICATION':
        return '$sev Suspicious Notification Detected: $target';
      case 'SPAM_CALLER':
        return '$sev Fraudulent Caller Blocked: $target';
      case 'PHISHING_URL':
        return '$sev Phishing URL in Notification: $target';
      case 'SCAM_SMS':
        return '$sev Scam Message Alert: $target';
      default:
        return '$sev Security Finding: $target';
    }
  }

  String _generateExplanation(String category, String target, String severity, int score) {
    return 'CyberShield detected $severity security risk for $target ($score/100). Review recommended remediation steps.';
  }

  List<String> _generateRecommendations(String category, String target) {
    switch (category.toUpperCase()) {
      case 'URL':
        return [
          'Do not open, click, or redirect to this URL.',
          'Never submit credentials, PINs, or card details.',
          'Block sender if received via SMS or email.',
        ];
      case 'SMS':
        return [
          'Do not reply or click embedded hyperlinks.',
          'Never disclose OTP or banking passwords.',
          'Mark message sender as spam in messaging app.',
        ];
      case 'QR':
        return [
          'Do not authorize payment or confirm redirections.',
          'Inspect the target website URL before proceeding.',
          'Report compromised QR stickers to venue security.',
        ];
      case 'APK':
        return [
          'Do not install or execute this APK package.',
          'If installed, uninstall immediately and revoke device admin.',
          'Obtain apps exclusively from Google Play Store.',
        ];
      case 'PERMISSIONS':
        return [
          'Revoke sensitive background permissions in Android Settings.',
          'Disable SMS, Contacts, and Accessibility rights.',
          'Evaluate whether a safer app alternative is available.',
        ];
      case 'EMAIL':
        return [
          'Mark as phishing in your mail provider and delete.',
          'Do not open file attachments or click links.',
          'Verify sender address authenticity through direct contact.',
        ];
      case 'FILE':
        return [
          'Do not execute or unpack this file.',
          'Quarantine or delete from storage immediately.',
          'Perform a comprehensive antivirus scan.',
        ];
      case 'NOTIFICATION':
        return [
          'Do not tap or follow instructions in this notification.',
          'Verify requests directly through the official app or portal.',
          'Dismiss and report notification source if persistent.',
        ];
      case 'SPAM_CALLER':
        return [
          'Decline or silence call from this number.',
          'Never reveal passwords, OTPs, or financial details over the phone.',
          'Block caller in phone settings.',
        ];
      default:
        return [
          'Exercise high caution with this digital item.',
          'Review associated scan telemetry and forensic risks.',
          'Ask the AI Security Assistant for guided mitigation.',
        ];
    }
  }
}

extension StringCapitalizeExtension on String {
  String capitalize() {
    if (isEmpty) return this;
    return '${this[0].toUpperCase()}${substring(1).toLowerCase()}';
  }
}

