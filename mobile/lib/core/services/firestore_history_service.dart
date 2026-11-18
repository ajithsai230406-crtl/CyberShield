import 'dart:async';
import 'dart:convert';
import 'dart:developer' as developer;
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cybershield/core/models/history_item.dart';
import 'package:cybershield/core/models/dashboard_analytics.dart';
import 'package:cybershield/core/services/alert_service.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';

/// Secure, user-isolated Firestore Cloud Scan History Service with persistent local fallback cache.
///
/// Firestore collection layout:
///   users/{userId}/scan_history/{scanId}
///
/// Guarantees that each authenticated user can only access their own scan records,
/// while maintaining immediate local offline persistence.
class FirestoreHistoryService {
  static const String _prefKeyLocalHistory = 'cybershield_local_scan_history';

  final FirebaseFirestore? _customDb;
  final FirebaseAuth? _customAuth;

  FirestoreHistoryService({
    FirebaseFirestore? firestore,
    FirebaseAuth? auth,
  })  : _customDb = firestore,
        _customAuth = auth;

  /// Singleton accessor
  static final FirestoreHistoryService instance = FirestoreHistoryService();

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

  /// Currently authenticated user
  User? get currentUser {
    try {
      return _auth?.currentUser;
    } catch (_) {
      return null;
    }
  }

  /// UID of authenticated user
  String? get currentUserId => currentUser?.uid;

  /// Whether a user is currently signed in
  bool get isAuthenticated => currentUser != null;

  /// Internal reference to current user's scan_history subcollection
  CollectionReference<Map<String, dynamic>>? get _historyCollection {
    final uid = currentUserId;
    final db = _db;
    if (uid == null || uid.isEmpty || db == null) return null;
    return db.collection('users').doc(uid).collection('scan_history');
  }

  /// Save scan result to the authenticated user's Firestore scan_history and persistent local storage.
  ///
  /// Safe against failure: never throws or crashes the calling scanner.
  Future<String?> recordScan({
    required String scanType,
    required String target,
    required int riskScore,
    required String classification,
    required Map<String, dynamic> result,
    String? status,
    String? summary,
    Map<String, dynamic>? metadata,
  }) async {
    final localId = 'scan-${DateTime.now().millisecondsSinceEpoch}';
    final nowIso = DateTime.now().toUtc().toIso8601String();

    // 1. Always save to local persistent cache
    final localMap = {
      'id': localId,
      'scan_id': localId,
      'scan_type': scanType.toUpperCase(),
      'target': target,
      'risk_score': riskScore,
      'classification': classification,
      'status': status ?? classification,
      'status_badge': classification.toLowerCase(),
      'summary': summary ?? '',
      'timestamp': nowIso,
      'details': result,
    };
    await _saveLocalScan(localMap);

    String? createdId = localId;

    // 2. Mirror to Firestore if authenticated
    try {
      final col = _historyCollection;
      if (col != null) {
        final docRef = await col.add({
          'scanType': scanType.toUpperCase(),
          'target': target,
          'scannedItem': target,
          'riskScore': riskScore,
          'risk_score': riskScore,
          'classification': classification,
          'status': status ?? classification,
          'summary': summary ?? '',
          'result': result,
          'metadata': metadata ?? {},
          'timestamp': FieldValue.serverTimestamp(),
        });
        createdId = docRef.id;
      }
    } catch (e, st) {
      developer.log(
        'Failed to save scan to Firestore: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
    }

    // 3. Automatically evaluate and record security alert
    try {
      AlertService.instance.evaluateAndRecordScanAlert(
        scanType: scanType,
        target: target,
        riskScore: riskScore,
        classification: classification,
        scanId: createdId,
        summary: summary,
      );
    } catch (_) {}

    // 4. Mirror into Centralized Smart Alert & All-18-Module Event Engine (fault-isolated)
    try {
      final rawFindings = result['findings'] ?? result['threat_categories'] ?? result['detected_indicators'];
      final findingsList = (rawFindings is List)
          ? rawFindings.map((e) => e.toString()).toList()
          : const <String>[];
      final rawRecs = result['recommendations'];
      final recList = (rawRecs is List)
          ? rawRecs.map((e) => e.toString()).toList()
          : (result['recommendation'] != null ? [result['recommendation'].toString()] : const <String>[]);
      final isGmail = (metadata?['gmail_message_id'] != null) ||
          (result['metadata'] is Map && (result['metadata'] as Map)['gmail_message_id'] != null);
      unawaited(
        SmartAlertEngine.instance.submitEvent(
          moduleName: isGmail ? 'gmail_integration' : scanType,
          targetIdentifier: target,
          riskScore: riskScore,
          classification: classification,
          findings: findingsList,
          explanation: (result['explanation']?.toString().isNotEmpty == true)
              ? result['explanation'].toString()
              : (summary ?? 'Scan completed ($classification, $riskScore/100)'),
          recommendedActions: recList,
          analysisStatus: 'analyzed',
          idempotencyKey: 'scan:$createdId',
          createBackendAlert: false,
          skipBackendPost: true, // Backend scanner endpoint already recorded the event
          metadata: {'scan_id': createdId, ...?metadata},
        ),
      );
    } catch (_) {}

    return createdId;
  }

  Future<void> _saveLocalScan(Map<String, dynamic> record) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final list = prefs.getStringList(_prefKeyLocalHistory) ?? [];
      final encoded = jsonEncode(record);
      final updated = [encoded, ...list.where((s) {
        try {
          final m = jsonDecode(s) as Map<String, dynamic>;
          return m['id'] != record['id'];
        } catch (_) {
          return true;
        }
      })];
      if (updated.length > 150) {
        updated.removeRange(150, updated.length);
      }
      await prefs.setStringList(_prefKeyLocalHistory, updated);
    } catch (_) {}
  }

  Future<List<HistoryItem>> _getLocalScans({
    String? scanType,
    String? classification,
  }) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final rawList = prefs.getStringList(_prefKeyLocalHistory) ?? [];
      final result = <HistoryItem>[];
      for (final s in rawList) {
        try {
          final m = jsonDecode(s) as Map<String, dynamic>;
          final item = HistoryItem.fromJson(m);
          if (scanType != null && scanType.isNotEmpty && scanType.toUpperCase() != 'ALL') {
            if (item.scanType.toUpperCase() != scanType.toUpperCase()) continue;
          }
          if (classification != null && classification.isNotEmpty && classification.toUpperCase() != 'ALL') {
            if (item.classification.toLowerCase() != classification.toLowerCase()) continue;
          }
          result.add(item);
        } catch (_) {}
      }
      return result;
    } catch (_) {
      return [];
    }
  }

  /// Save community report to the authenticated user's Firestore community_reports collection.
  Future<String?> recordCommunityReport({
    required String reportId,
    required String category,
    required String target,
    required String title,
    String? description,
    List<String>? tags,
  }) async {
    try {
      final uid = currentUserId;
      final db = _db;
      if (uid == null || uid.isEmpty || db == null) return null;
      final docRef = db
          .collection('users')
          .doc(uid)
          .collection('community_reports')
          .doc(reportId);

      await docRef.set({
        'reportId': reportId,
        'category': category.toLowerCase(),
        'target': target,
        'title': title,
        'description': description ?? '',
        'tags': tags ?? [],
        'timestamp': FieldValue.serverTimestamp(),
      });

      return docRef.id;
    } catch (e, st) {
      developer.log(
        'Failed to save community report to Firestore: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
      return null;
    }
  }

  /// Save an AI assistant chat message to the authenticated user's Firestore assistant_chats subcollection.
  Future<String?> recordAssistantChat({
    required String messageId,
    required String role,
    required String content,
    String? sessionId,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final uid = currentUserId;
      final db = _db;
      if (uid == null || uid.isEmpty || db == null) return null;
      final docRef = db
          .collection('users')
          .doc(uid)
          .collection('assistant_chats')
          .doc(messageId);

      await docRef.set({
        'messageId': messageId,
        'role': role,
        'content': content,
        'sessionId': sessionId ?? 'default-session',
        'metadata': metadata ?? {},
        'timestamp': FieldValue.serverTimestamp(),
      });

      return messageId;
    } catch (e, st) {
      developer.log(
        'Failed to save assistant chat to Firestore: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
      return null;
    }
  }

  /// Legacy stub compatibility: saveScan
  Future<void> saveScan({
    required String scanType,
    required Map<String, dynamic> result,
  }) async {
    final target = (result['target'] ??
            result['scanned_url'] ??
            result['scanned_message'] ??
            result['decoded_payload'] ??
            result['filename'] ??
            'Unknown')
        .toString();
    final riskScore = result['risk_score'] as int? ?? 0;
    final classification = (result['classification'] ?? 'Safe').toString();
    final explanation = (result['explanation'] ?? '').toString();

    await recordScan(
      scanType: scanType,
      target: target,
      riskScore: riskScore,
      classification: classification,
      summary: explanation,
      result: result,
    );
  }

  /// Stream scan history for the current user, ordered by timestamp descending.
  Stream<List<HistoryItem>> streamHistory({
    String? scanType,
    String? classification,
  }) {
    final col = _historyCollection;
    if (col == null) {
      return Stream.value(<HistoryItem>[]);
    }

    Query<Map<String, dynamic>> query =
        col.orderBy('timestamp', descending: true);

    if (scanType != null &&
        scanType.isNotEmpty &&
        scanType.toUpperCase() != 'ALL') {
      query = query.where('scanType', isEqualTo: scanType.toUpperCase());
    }

    if (classification != null &&
        classification.isNotEmpty &&
        classification.toUpperCase() != 'ALL') {
      query = query.where('classification', isEqualTo: classification);
    }

    return query.snapshots().map((snapshot) {
      return snapshot.docs.map((doc) => _mapDocToHistoryItem(doc)).toList();
    });
  }

  /// Fetch history list once (for pull-to-refresh or direct queries), with seamless local fallback
  Future<List<HistoryItem>> fetchHistory({
    String? scanType,
    String? classification,
  }) async {
    try {
      final col = _historyCollection;
      if (col != null) {
        Query<Map<String, dynamic>> query =
            col.orderBy('timestamp', descending: true);

        if (scanType != null &&
            scanType.isNotEmpty &&
            scanType.toUpperCase() != 'ALL') {
          query = query.where('scanType', isEqualTo: scanType.toUpperCase());
        }

        if (classification != null &&
            classification.isNotEmpty &&
            classification.toUpperCase() != 'ALL') {
          query = query.where('classification', isEqualTo: classification);
        }

        final snapshot = await query.get().timeout(const Duration(seconds: 6));
        final cloudItems = snapshot.docs.map((doc) => _mapDocToHistoryItem(doc)).toList();
        if (cloudItems.isNotEmpty) {
          return cloudItems;
        }
      }
    } catch (e, st) {
      developer.log(
        'Failed to fetch cloud history: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
    }
    // Seamless fallback to persistent local cache
    return await _getLocalScans(scanType: scanType, classification: classification);
  }

  /// Delete a single scan document from the user's scan_history and local cache
  Future<bool> deleteScan(String scanId) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final list = prefs.getStringList(_prefKeyLocalHistory) ?? [];
      final updated = list.where((s) {
        try {
          final m = jsonDecode(s) as Map<String, dynamic>;
          return m['id'] != scanId && m['scan_id'] != scanId;
        } catch (_) {
          return true;
        }
      }).toList();
      await prefs.setStringList(_prefKeyLocalHistory, updated);
    } catch (_) {}

    try {
      final col = _historyCollection;
      if (col == null) return true;
      await col.doc(scanId).delete();
      return true;
    } catch (e, st) {
      developer.log(
        'Error deleting scan $scanId: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
      return false;
    }
  }

  /// Clear all scan history documents safely across both cloud and local cache
  Future<bool> clearAllHistory() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(_prefKeyLocalHistory);
    } catch (_) {}

    try {
      final col = _historyCollection;
      final db = _db;
      if (col == null || db == null) return true;

      final snapshot = await col.get().timeout(const Duration(seconds: 6));
      if (snapshot.docs.isEmpty) return true;

      // Firestore batches support up to 500 operations
      const batchSize = 400;
      for (var i = 0; i < snapshot.docs.length; i += batchSize) {
        final batch = db.batch();
        final chunk = snapshot.docs.skip(i).take(batchSize);
        for (final doc in chunk) {
          batch.delete(doc.reference);
        }
        await batch.commit();
      }
      return true;
    } catch (e, st) {
      developer.log(
        'Error clearing all scan history: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
      return false;
    }
  }

  /// Aggregates scan stats (total, safe, suspicious, malicious, top 3 recent)
  Future<Map<String, dynamic>> getCloudScanStats() async {
    try {
      final col = _historyCollection;
      if (col == null) {
        return {'status': 'unauthenticated', 'message': 'User not signed in'};
      }

      final snapshot = await col
          .orderBy('timestamp', descending: true)
          .get()
          .timeout(const Duration(seconds: 6));
      final docs = snapshot.docs;

      int total = docs.length;
      int safe = 0;
      int suspicious = 0;
      int malicious = 0;
      final List<Map<String, dynamic>> recentScans = [];

      for (var i = 0; i < docs.length; i++) {
        final doc = docs[i];
        final data = doc.data();
        final cls =
            (data['classification']?.toString() ?? 'Safe').toLowerCase();
        final score =
            data['riskScore'] as int? ?? data['risk_score'] as int? ?? 0;

        if (cls == 'safe' && score < 30) {
          safe++;
        } else if (cls == 'suspicious' || (score >= 30 && score < 60)) {
          suspicious++;
        } else {
          malicious++;
        }

        if (i < 3) {
          DateTime dt = DateTime.now();
          final rawTs = data['timestamp'];
          if (rawTs is Timestamp) {
            dt = rawTs.toDate();
          } else if (rawTs is String) {
            dt = DateTime.tryParse(rawTs) ?? DateTime.now();
          }

          final rawResult = data['result'];
          Map<String, dynamic> details = const {};
          if (rawResult is Map) {
            details = Map<String, dynamic>.from(rawResult);
          }

          recentScans.add({
            'scan_id': doc.id,
            'id': doc.id,
            'scan_type':
                (data['scanType'] as String? ?? 'SCAN').toUpperCase(),
            'target': data['target'] as String? ??
                data['scannedItem'] as String? ??
                'Unknown',
            'risk_score': score,
            'classification': data['classification'] as String? ?? 'Safe',
            'timestamp': dt.toIso8601String(),
            'details': details,
          });
        }
      }

      return {
        'status': 'success',
        'total_count': total,
        'safe_count': safe,
        'suspicious_count': suspicious,
        'malicious_count': malicious,
        'recent_scans': recentScans,
      };
    } catch (e, st) {
      developer.log(
        'Error retrieving cloud scan stats: $e',
        error: e,
        stackTrace: st,
        name: 'FirestoreHistoryService',
      );
      return {'status': 'error', 'message': e.toString()};
    }
  }

  /// Compute full user-isolated DashboardAnalytics from Cloud Firestore scan history
  Future<DashboardAnalytics?> getCloudDashboardAnalytics({int days = 30}) async {
    try {
      final col = _historyCollection;
      if (col == null) return null;

      final now = DateTime.now();
      Query<Map<String, dynamic>> query = col.orderBy('timestamp', descending: true);

      if (days > 0) {
        final cutoff = now.subtract(Duration(days: days));
        query = query.where('timestamp', isGreaterThanOrEqualTo: Timestamp.fromDate(cutoff));
      }

      final snapshot = await query.get().timeout(const Duration(seconds: 6));
      final docs = snapshot.docs;

      int total = docs.length;
      int safe = 0;
      int suspicious = 0;
      int highRisk = 0;
      int critical = 0;

      final knownScanners = ['URL', 'SMS', 'QR', 'SCREENSHOT', 'APK', 'PERMISSIONS', 'EMAIL', 'FILE'];
      final scannerMap = <String, ScannerStatsItemModel>{
        for (var s in knownScanners) s: const ScannerStatsItemModel(total: 0, safe: 0, threats: 0),
      };

      final trendsMap = <String, Map<String, int>>{};
      final trendDays = days > 0 ? (days > 14 ? 14 : days) : 14;
      for (var d = trendDays - 1; d >= 0; d--) {
        final dayStr = now.subtract(Duration(days: d)).toIso8601String().substring(0, 10);
        trendsMap[dayStr] = {'total': 0, 'safe': 0, 'threats': 0};
      }

      final recentList = <RecentScanItemModel>[];

      for (var i = 0; i < docs.length; i++) {
        final doc = docs[i];
        final data = doc.data();
        final cls = (data['classification']?.toString() ?? 'Safe').toLowerCase();
        final score = data['riskScore'] as int? ?? data['risk_score'] as int? ?? 0;
        final scanType = (data['scanType'] as String? ?? 'URL').toUpperCase();

        final isCrit = score >= 80 || cls == 'critical';
        final isHigh = !isCrit && (score >= 60 || cls == 'high risk' || cls == 'malicious');
        final isSusp = !isCrit && !isHigh && (score >= 30 || cls == 'suspicious');
        final isSafe = !isCrit && !isHigh && !isSusp;

        if (isCrit) {
          critical++;
        } else if (isHigh) {
          highRisk++;
        } else if (isSusp) {
          suspicious++;
        } else {
          safe++;
        }

        // Scanner breakdown
        final currentStats = scannerMap[scanType] ?? const ScannerStatsItemModel(total: 0, safe: 0, threats: 0);
        scannerMap[scanType] = ScannerStatsItemModel(
          total: currentStats.total + 1,
          safe: currentStats.safe + (isSafe ? 1 : 0),
          threats: currentStats.threats + (isSafe ? 0 : 1),
        );

        // Date timestamp
        DateTime dt = now;
        final rawTs = data['timestamp'];
        if (rawTs is Timestamp) {
          dt = rawTs.toDate();
        } else if (rawTs is String) {
          dt = DateTime.tryParse(rawTs) ?? now;
        }

        final dateKey = dt.toIso8601String().substring(0, 10);
        if (trendsMap.containsKey(dateKey)) {
          trendsMap[dateKey]!['total'] = (trendsMap[dateKey]!['total'] ?? 0) + 1;
          if (isSafe) {
            trendsMap[dateKey]!['safe'] = (trendsMap[dateKey]!['safe'] ?? 0) + 1;
          } else {
            trendsMap[dateKey]!['threats'] = (trendsMap[dateKey]!['threats'] ?? 0) + 1;
          }
        }

        if (i < 5) {
          recentList.add(
            RecentScanItemModel(
              id: doc.id,
              scanId: doc.id,
              scanType: scanType,
              target: data['target']?.toString() ?? data['scannedItem']?.toString() ?? 'Item',
              riskScore: score,
              classification: data['classification']?.toString() ?? 'Safe',
              timestamp: dt.toIso8601String(),
            ),
          );
        }
      }

      final threatsTotal = suspicious + highRisk + critical;
      final threatRate = total > 0 ? ((threatsTotal / total) * 100).toDouble() : 0.0;

      // Score calculation
      int score;
      String status;
      String tier;
      if (total == 0) {
        score = 70;
        status = 'Baseline Exposure';
        tier = 'Neutral';
      } else {
        final penalty = (critical * 20) + (highRisk * 10) + (suspicious * 4);
        final raw = 100 - penalty + (safe * 2);
        score = raw.clamp(10, 98);
        if (score >= 85) {
          status = 'Strong Defense Posture';
          tier = 'Optimal';
        } else if (score >= 65) {
          status = 'Moderate Protection';
          tier = 'Guarded';
        } else if (score >= 40) {
          status = 'Elevated Threat Exposure';
          tier = 'Warning';
        } else {
          status = 'Critical Exposure Detected';
          tier = 'Danger';
        }
      }

      final securityScore = SecurityScoreModel(
        score: score,
        status: status,
        tier: tier,
        calculationExplanation:
            'Calculated from $total user cloud scans. Baseline 100 minus threat penalties plus verified safe interactions.',
        disclaimer:
            'Advisory Notice: CyberShield Security Score reflects evaluated scan telemetry and cyber hygiene. No automated security system can guarantee 100% device immunity against emerging zero-day vulnerabilities.',
      );

      final trendsList = trendsMap.entries.map((e) {
        return ActivityTrendPointModel(
          date: e.key,
          total: e.value['total'] ?? 0,
          safe: e.value['safe'] ?? 0,
          threats: e.value['threats'] ?? 0,
        );
      }).toList();

      return DashboardAnalytics(
        timeRangeDays: days,
        totalScans: total,
        safeScans: safe,
        suspiciousScans: suspicious,
        highRiskScans: highRisk,
        criticalScans: critical,
        threatDetectionRate: threatRate,
        securityScore: securityScore,
        scannerBreakdown: scannerMap,
        riskDistribution: {
          'safe': safe,
          'suspicious': suspicious,
          'high_risk': highRisk,
          'critical': critical,
        },
        activityTrends: trendsList,
        communityStats: const CommunityOverviewStatsModel(
          totalReports: 0,
          distinctTargets: 0,
          activeReporters: 0,
          verifiedThreats: 0,
        ),
        recentScans: recentList,
        timestamp: now.toIso8601String(),
      );
    } catch (e, st) {
      developer.log('Failed to build cloud analytics: $e', error: e, stackTrace: st, name: 'FirestoreHistoryService');
      return null;
    }
  }

  /// Helper to convert a Firestore DocumentSnapshot into a HistoryItem
  HistoryItem _mapDocToHistoryItem(
      DocumentSnapshot<Map<String, dynamic>> doc) {
    final data = doc.data() ?? {};

    DateTime parsedDate = DateTime.now();
    final rawTs = data['timestamp'];
    if (rawTs is Timestamp) {
      parsedDate = rawTs.toDate();
    } else if (rawTs is String) {
      parsedDate = DateTime.tryParse(rawTs) ?? DateTime.now();
    }

    final rawResult = data['result'];
    Map<String, dynamic> detailsMap = const {};
    if (rawResult is Map) {
      detailsMap = Map<String, dynamic>.from(rawResult);
    } else {
      final rawDetails = data['details'];
      if (rawDetails is Map) {
        detailsMap = Map<String, dynamic>.from(rawDetails);
      }
    }

    return HistoryItem(
      id: doc.id,
      scanId: doc.id,
      scanType: (data['scanType'] as String? ?? 'SCAN').toUpperCase(),
      target: data['target'] as String? ??
          data['scannedItem'] as String? ??
          'Unknown target',
      riskScore:
          data['riskScore'] as int? ?? data['risk_score'] as int? ?? 0,
      classification: data['classification'] as String? ?? 'Safe',
      summary: data['summary'] as String? ??
          data['explanation'] as String? ??
          '',
      statusBadge: data['status'] as String? ?? 'safe',
      timestamp: parsedDate.toIso8601String(),
      details: detailsMap,
    );
  }
}
