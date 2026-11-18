// CyberShield Communication History & Threat Percentage Models

class CommunicationRiskThresholds {
  final int safeMax;
  final int lowRiskMax;
  final int suspiciousMax;
  final int highRiskMax;

  const CommunicationRiskThresholds({
    this.safeMax = 20,
    this.lowRiskMax = 40,
    this.suspiciousMax = 60,
    this.highRiskMax = 80,
  });

  String classify(int score) {
    final s = score.clamp(0, 100);
    if (s <= safeMax) return 'Safe';
    if (s <= lowRiskMax) return 'Low Risk';
    if (s <= suspiciousMax) return 'Suspicious';
    if (s <= highRiskMax) return 'High Risk';
    return 'Critical';
  }

  bool isThreatFlagged(int score, String classification) {
    final c = classification.trim().toLowerCase();
    return score > lowRiskMax || c == 'suspicious' || c == 'high risk' || c == 'critical';
  }

  factory CommunicationRiskThresholds.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const CommunicationRiskThresholds();
    return CommunicationRiskThresholds(
      safeMax: json['safe_max'] is int ? json['safe_max'] as int : 20,
      lowRiskMax: json['low_risk_max'] is int ? json['low_risk_max'] as int : 40,
      suspiciousMax: json['suspicious_max'] is int ? json['suspicious_max'] as int : 60,
      highRiskMax: json['high_risk_max'] is int ? json['high_risk_max'] as int : 80,
    );
  }
}

class CommunicationRecord {
  final String recordId;
  final String userId;
  final String communicationType; // sms, notification, call, email, whatsapp, other
  final String sourceApp;
  final String senderIdentifier;
  final String? callerName;
  final String messagePreview;
  final DateTime timestamp;
  final int riskScore; // 0-100
  final String classification; // Safe, Low Risk, Suspicious, High Risk, Critical, Unavailable
  final List<String> threatCategories;
  final List<String> findings;
  final String explanation;
  final String recommendedAction;
  final String analysisStatus; // analyzed, unanalyzed, offline_fallback, received_pending
  final bool? isKnownContact;
  final String? callStatus;
  final String? spamReputation;
  final Map<String, dynamic> metadata;
  final bool isDuplicate;

  const CommunicationRecord({
    required this.recordId,
    required this.userId,
    required this.communicationType,
    required this.sourceApp,
    required this.senderIdentifier,
    this.callerName,
    this.messagePreview = '',
    required this.timestamp,
    required this.riskScore,
    required this.classification,
    this.threatCategories = const [],
    this.findings = const [],
    this.explanation = '',
    this.recommendedAction = '',
    this.analysisStatus = 'analyzed',
    this.isKnownContact,
    this.callStatus,
    this.spamReputation,
    this.metadata = const {},
    this.isDuplicate = false,
  });

  bool get isCall => communicationType.toLowerCase() == 'call';
  bool get isAnalyzed => analysisStatus.toLowerCase() == 'analyzed';
  bool get isThreatFlagged =>
      isAnalyzed && const CommunicationRiskThresholds().isThreatFlagged(riskScore, classification);

  String get displayTitle {
    if (isCall && callerName != null && callerName!.trim().isNotEmpty) {
      return callerName!.trim();
    }
    return senderIdentifier;
  }

  factory CommunicationRecord.fromJson(Map<String, dynamic> json) {
    DateTime parsedTs;
    final rawTs = json['timestamp'];
    if (rawTs is String && rawTs.isNotEmpty) {
      parsedTs = DateTime.tryParse(rawTs)?.toLocal() ?? DateTime.now();
    } else if (rawTs is int) {
      parsedTs = DateTime.fromMillisecondsSinceEpoch(rawTs);
    } else {
      parsedTs = DateTime.now();
    }

    return CommunicationRecord(
      recordId: json['record_id']?.toString() ?? json['id']?.toString() ?? '',
      userId: json['user_id']?.toString() ?? '',
      communicationType: json['communication_type']?.toString() ?? 'notification',
      sourceApp: json['source_app']?.toString() ?? 'Unknown',
      senderIdentifier: json['sender_identifier']?.toString() ?? 'Unknown',
      callerName: json['caller_name']?.toString(),
      messagePreview: json['message_preview']?.toString() ?? '',
      timestamp: parsedTs,
      riskScore: json['risk_score'] is int
          ? (json['risk_score'] as int).clamp(0, 100)
          : int.tryParse(json['risk_score']?.toString() ?? '0') ?? 0,
      classification: json['classification']?.toString() ?? 'Safe',
      threatCategories: (json['threat_categories'] as List?)
              ?.map((e) => e.toString())
              .toList() ??
          const [],
      findings: (json['findings'] as List?)?.map((e) => e.toString()).toList() ?? const [],
      explanation: json['explanation']?.toString() ?? '',
      recommendedAction: json['recommended_action']?.toString() ?? '',
      analysisStatus: json['analysis_status']?.toString() ?? 'analyzed',
      isKnownContact: json['is_known_contact'] is bool ? json['is_known_contact'] as bool : null,
      callStatus: json['call_status']?.toString(),
      spamReputation: json['spam_reputation']?.toString(),
      metadata: json['metadata'] is Map
          ? Map<String, dynamic>.from(json['metadata'] as Map)
          : const {},
      isDuplicate: json['is_duplicate'] == true,
    );
  }

  Map<String, dynamic> toJson() => {
        'record_id': recordId,
        'user_id': userId,
        'communication_type': communicationType,
        'source_app': sourceApp,
        'sender_identifier': senderIdentifier,
        'caller_name': callerName,
        'message_preview': messagePreview,
        'timestamp': timestamp.toUtc().toIso8601String(),
        'risk_score': riskScore,
        'classification': classification,
        'threat_categories': threatCategories,
        'findings': findings,
        'explanation': explanation,
        'recommended_action': recommendedAction,
        'analysis_status': analysisStatus,
        'is_known_contact': isKnownContact,
        'call_status': callStatus,
        'spam_reputation': spamReputation,
        'metadata': metadata,
      };
}

class CommunicationBucketStats {
  final int totalReceived;
  final int totalAnalyzed;
  final int totalUnanalyzed;
  final int safeCount;
  final int lowRiskCount;
  final int suspiciousCount;
  final int highRiskCount;
  final int criticalCount;
  final int threatFlaggedCount;
  final double? threatDetectionRate; // null when totalAnalyzed == 0
  final bool hasAnalyzedData;
  final int unknownCallersCount;

  const CommunicationBucketStats({
    this.totalReceived = 0,
    this.totalAnalyzed = 0,
    this.totalUnanalyzed = 0,
    this.safeCount = 0,
    this.lowRiskCount = 0,
    this.suspiciousCount = 0,
    this.highRiskCount = 0,
    this.criticalCount = 0,
    this.threatFlaggedCount = 0,
    this.threatDetectionRate,
    this.hasAnalyzedData = false,
    this.unknownCallersCount = 0,
  });

  factory CommunicationBucketStats.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const CommunicationBucketStats();
    final rawRate = json['threat_detection_rate'];
    return CommunicationBucketStats(
      totalReceived: json['total_received'] is int ? json['total_received'] as int : 0,
      totalAnalyzed: json['total_analyzed'] is int ? json['total_analyzed'] as int : 0,
      totalUnanalyzed: json['total_unanalyzed'] is int ? json['total_unanalyzed'] as int : 0,
      safeCount: json['safe_count'] is int ? json['safe_count'] as int : 0,
      lowRiskCount: json['low_risk_count'] is int ? json['low_risk_count'] as int : 0,
      suspiciousCount: json['suspicious_count'] is int ? json['suspicious_count'] as int : 0,
      highRiskCount: json['high_risk_count'] is int ? json['high_risk_count'] as int : 0,
      criticalCount: json['critical_count'] is int ? json['critical_count'] as int : 0,
      threatFlaggedCount: json['threat_flagged_count'] is int ? json['threat_flagged_count'] as int : 0,
      threatDetectionRate: rawRate is num ? rawRate.toDouble() : null,
      hasAnalyzedData: json['has_analyzed_data'] == true,
      unknownCallersCount: json['unknown_callers_count'] is int ? json['unknown_callers_count'] as int : 0,
    );
  }
}

class CommunicationTrendPoint {
  final String label;
  final int total;
  final int analyzed;
  final int safe;
  final int threats;
  final double threatPercentage;

  const CommunicationTrendPoint({
    required this.label,
    required this.total,
    required this.analyzed,
    required this.safe,
    required this.threats,
    required this.threatPercentage,
  });

  factory CommunicationTrendPoint.fromJson(Map<String, dynamic> json) {
    return CommunicationTrendPoint(
      label: json['label']?.toString() ?? '',
      total: json['total'] is int ? json['total'] as int : 0,
      analyzed: json['analyzed'] is int ? json['analyzed'] as int : 0,
      safe: json['safe'] is int ? json['safe'] as int : 0,
      threats: json['threats'] is int ? json['threats'] as int : 0,
      threatPercentage: json['threat_percentage'] is num
          ? (json['threat_percentage'] as num).toDouble()
          : 0.0,
    );
  }
}

class CommunicationAnalytics {
  final String period; // daily, weekly, monthly
  final CommunicationBucketStats overall;
  final CommunicationBucketStats messages;
  final CommunicationBucketStats calls;
  final List<CommunicationTrendPoint> trends;
  final Map<String, int> smsThreatDistribution;
  final Map<String, int> callThreatDistribution;
  final List<Map<String, dynamic>> topThreatCategories;
  final String formula;
  final CommunicationRiskThresholds thresholds;

  const CommunicationAnalytics({
    this.period = 'daily',
    this.overall = const CommunicationBucketStats(),
    this.messages = const CommunicationBucketStats(),
    this.calls = const CommunicationBucketStats(),
    this.trends = const [],
    this.smsThreatDistribution = const {},
    this.callThreatDistribution = const {},
    this.topThreatCategories = const [],
    this.formula =
        'Threat Rate = (Threat-flagged analyzed communications / Total analyzed communications) × 100',
    this.thresholds = const CommunicationRiskThresholds(),
  });

  factory CommunicationAnalytics.fromJson(Map<String, dynamic> json) {
    Map<String, int> parseDist(dynamic raw) {
      if (raw is! Map) return const {};
      return raw.map((k, v) => MapEntry(k.toString(), v is int ? v : int.tryParse('$v') ?? 0));
    }

    return CommunicationAnalytics(
      period: json['period']?.toString() ?? 'daily',
      overall: CommunicationBucketStats.fromJson(
        json['overall'] is Map ? Map<String, dynamic>.from(json['overall'] as Map) : null,
      ),
      messages: CommunicationBucketStats.fromJson(
        json['messages'] is Map ? Map<String, dynamic>.from(json['messages'] as Map) : null,
      ),
      calls: CommunicationBucketStats.fromJson(
        json['calls'] is Map ? Map<String, dynamic>.from(json['calls'] as Map) : null,
      ),
      trends: (json['trends'] as List?)
              ?.whereType<Map>()
              .map((e) => CommunicationTrendPoint.fromJson(Map<String, dynamic>.from(e)))
              .toList() ??
          const [],
      smsThreatDistribution: parseDist(json['sms_threat_distribution']),
      callThreatDistribution: parseDist(json['call_threat_distribution']),
      topThreatCategories: (json['top_threat_categories'] as List?)
              ?.whereType<Map>()
              .map((e) => Map<String, dynamic>.from(e))
              .toList() ??
          const [],
      formula: json['formula']?.toString() ??
          'Threat Rate = (Threat-flagged analyzed communications / Total analyzed communications) × 100',
      thresholds: CommunicationRiskThresholds.fromJson(
        json['thresholds'] is Map ? Map<String, dynamic>.from(json['thresholds'] as Map) : null,
      ),
    );
  }
}

class CommunicationSettings {
  final bool consentAcknowledged;
  final bool monitoringPaused;
  final bool monitorSms;
  final bool monitorNotifications;
  final bool monitorCalls;
  final bool monitorEmail;
  final bool monitorWhatsapp;
  final bool storeMessagePreview;
  final bool alertOnSuspicious;
  final bool alertOnHighRisk;
  final int retentionDays; // 7, 30, 90, 365

  const CommunicationSettings({
    this.consentAcknowledged = false,
    this.monitoringPaused = false,
    this.monitorSms = false,
    this.monitorNotifications = true,
    this.monitorCalls = false,
    this.monitorEmail = false,
    this.monitorWhatsapp = true,
    this.storeMessagePreview = true,
    this.alertOnSuspicious = true,
    this.alertOnHighRisk = true,
    this.retentionDays = 30,
  });

  CommunicationSettings copyWith({
    bool? consentAcknowledged,
    bool? monitoringPaused,
    bool? monitorSms,
    bool? monitorNotifications,
    bool? monitorCalls,
    bool? monitorEmail,
    bool? monitorWhatsapp,
    bool? storeMessagePreview,
    bool? alertOnSuspicious,
    bool? alertOnHighRisk,
    int? retentionDays,
  }) {
    return CommunicationSettings(
      consentAcknowledged: consentAcknowledged ?? this.consentAcknowledged,
      monitoringPaused: monitoringPaused ?? this.monitoringPaused,
      monitorSms: monitorSms ?? this.monitorSms,
      monitorNotifications: monitorNotifications ?? this.monitorNotifications,
      monitorCalls: monitorCalls ?? this.monitorCalls,
      monitorEmail: monitorEmail ?? this.monitorEmail,
      monitorWhatsapp: monitorWhatsapp ?? this.monitorWhatsapp,
      storeMessagePreview: storeMessagePreview ?? this.storeMessagePreview,
      alertOnSuspicious: alertOnSuspicious ?? this.alertOnSuspicious,
      alertOnHighRisk: alertOnHighRisk ?? this.alertOnHighRisk,
      retentionDays: retentionDays ?? this.retentionDays,
    );
  }

  Map<String, dynamic> toJson() => {
        'consentAcknowledged': consentAcknowledged,
        'monitoringPaused': monitoringPaused,
        'monitorSms': monitorSms,
        'monitorNotifications': monitorNotifications,
        'monitorCalls': monitorCalls,
        'monitorEmail': monitorEmail,
        'monitorWhatsapp': monitorWhatsapp,
        'storeMessagePreview': storeMessagePreview,
        'alertOnSuspicious': alertOnSuspicious,
        'alertOnHighRisk': alertOnHighRisk,
        'retentionDays': retentionDays,
      };

  factory CommunicationSettings.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const CommunicationSettings();
    return CommunicationSettings(
      consentAcknowledged: json['consentAcknowledged'] == true,
      monitoringPaused: json['monitoringPaused'] == true,
      monitorSms: json['monitorSms'] == true,
      monitorNotifications: json['monitorNotifications'] != false,
      monitorCalls: json['monitorCalls'] == true,
      monitorEmail: json['monitorEmail'] == true,
      monitorWhatsapp: json['monitorWhatsapp'] != false,
      storeMessagePreview: json['storeMessagePreview'] != false,
      alertOnSuspicious: json['alertOnSuspicious'] != false,
      alertOnHighRisk: json['alertOnHighRisk'] != false,
      retentionDays: json['retentionDays'] is int ? json['retentionDays'] as int : 30,
    );
  }
}

class CommunicationPermissionsStatus {
  final bool notificationAccess;
  final bool callScreeningSupported;
  final bool callScreeningRole;
  final String? callScreeningUnavailableReason;
  final bool readSms;
  final bool receiveSms;
  final bool readCallLog;
  final bool readPhoneState;
  final bool readContacts;
  final int androidSdk;
  final String? androidRelease;

  const CommunicationPermissionsStatus({
    this.notificationAccess = false,
    this.callScreeningSupported = false,
    this.callScreeningRole = false,
    this.callScreeningUnavailableReason,
    this.readSms = false,
    this.receiveSms = false,
    this.readCallLog = false,
    this.readPhoneState = false,
    this.readContacts = false,
    this.androidSdk = 0,
    this.androidRelease,
  });

  bool get hasSmsPermission => readSms || receiveSms;
  bool get hasCallMetadataPermission => readCallLog && readPhoneState;

  factory CommunicationPermissionsStatus.fromMap(Map<dynamic, dynamic> map) {
    return CommunicationPermissionsStatus(
      notificationAccess: map['notificationAccess'] == true,
      callScreeningSupported: map['callScreeningSupported'] == true,
      callScreeningRole: map['callScreeningRole'] == true,
      callScreeningUnavailableReason: map['callScreeningUnavailableReason']?.toString(),
      readSms: map['readSms'] == true,
      receiveSms: map['receiveSms'] == true,
      readCallLog: map['readCallLog'] == true,
      readPhoneState: map['readPhoneState'] == true,
      readContacts: map['readContacts'] == true,
      androidSdk: map['androidSdk'] is int ? map['androidSdk'] as int : 0,
      androidRelease: map['androidRelease']?.toString(),
    );
  }
}
