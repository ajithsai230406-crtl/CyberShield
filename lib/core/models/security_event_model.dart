// CyberShield Centralized Smart Alert & All-18-Module Security Event Models

import 'package:flutter/foundation.dart';

class CyberShieldModuleMeta {
  final String key;
  final String label;
  final String defaultSource;
  final String defaultCategory;

  const CyberShieldModuleMeta({
    required this.key,
    required this.label,
    required this.defaultSource,
    required this.defaultCategory,
  });
}

/// Canonical registry of all 18 integrated CyberShield modules.
const List<CyberShieldModuleMeta> kAll18Modules = [
  CyberShieldModuleMeta(key: 'url_scanner', label: 'URL Scanner', defaultSource: 'manual_scan', defaultCategory: 'phishing_url'),
  CyberShieldModuleMeta(key: 'sms_scanner', label: 'SMS Scanner', defaultSource: 'manual_scan', defaultCategory: 'smishing'),
  CyberShieldModuleMeta(key: 'qr_scanner', label: 'QR Scanner', defaultSource: 'manual_scan', defaultCategory: 'qr_threat'),
  CyberShieldModuleMeta(key: 'screenshot_analyzer', label: 'Screenshot Analyzer', defaultSource: 'manual_scan', defaultCategory: 'screenshot_ocr'),
  CyberShieldModuleMeta(key: 'apk_analyzer', label: 'APK Analyzer', defaultSource: 'manual_scan', defaultCategory: 'apk_malware'),
  CyberShieldModuleMeta(key: 'file_scanner', label: 'File Scanner', defaultSource: 'manual_scan', defaultCategory: 'file_malware'),
  CyberShieldModuleMeta(key: 'permission_analyzer', label: 'Permission Analyzer', defaultSource: 'device_audit', defaultCategory: 'permission_risk'),
  CyberShieldModuleMeta(key: 'email_scanner', label: 'Email Scanner', defaultSource: 'manual_scan', defaultCategory: 'phishing_email'),
  CyberShieldModuleMeta(key: 'gmail_integration', label: 'Gmail Integration', defaultSource: 'communication', defaultCategory: 'gmail_message'),
  CyberShieldModuleMeta(key: 'call_screening', label: 'Call Screening', defaultSource: 'communication', defaultCategory: 'spam_call'),
  CyberShieldModuleMeta(key: 'notification_monitor', label: 'Notification Monitor', defaultSource: 'communication', defaultCategory: 'notification_threat'),
  CyberShieldModuleMeta(key: 'installed_app_audit', label: 'Installed Application Audit', defaultSource: 'device_audit', defaultCategory: 'installed_app_audit'),
  CyberShieldModuleMeta(key: 'community_threat_intel', label: 'Community Threat Intelligence', defaultSource: 'community', defaultCategory: 'community_report'),
  CyberShieldModuleMeta(key: 'ai_security_assistant', label: 'AI Security Assistant', defaultSource: 'assistant', defaultCategory: 'ai_advisory'),
  CyberShieldModuleMeta(key: 'dashboard_analytics', label: 'Security Dashboard Analytics', defaultSource: 'system_event', defaultCategory: 'analytics_telemetry'),
  CyberShieldModuleMeta(key: 'security_alerts', label: 'Security Alerts', defaultSource: 'system_event', defaultCategory: 'alert_lifecycle'),
  CyberShieldModuleMeta(key: 'audit_history', label: 'Audit History', defaultSource: 'system_event', defaultCategory: 'audit_record'),
  CyberShieldModuleMeta(key: 'realtime_protection', label: 'Real-Time Protection', defaultSource: 'realtime_monitor', defaultCategory: 'protection_status'),
];

String moduleLabelFor(String moduleKey) {
  final norm = moduleKey.trim().toLowerCase();
  for (final m in kAll18Modules) {
    if (m.key == norm) return m.label;
  }
  return moduleKey.replaceAll('_', ' ');
}

/// Standardized 15-field security event produced by every CyberShield module.
@immutable
class SecurityEventModel {
  final String eventId;
  final String userId;
  final String moduleName;
  final String moduleLabel;
  final String eventCategory;
  final String source;
  final String targetIdentifier;
  final int? riskScore;
  final String classification;
  final String severity;
  final List<String> findings;
  final String explanation;
  final List<String> recommendedActions;
  final DateTime detectionTimestamp;
  final String analysisStatus; // analyzed | failed | unverified | unavailable
  final String notificationStatus; // delivered_immediate | queued_preference | suppressed_safe | dismissed | acknowledged
  final Map<String, dynamic> metadata;
  final bool isDuplicate;
  final bool pendingSync;

  const SecurityEventModel({
    required this.eventId,
    required this.userId,
    required this.moduleName,
    required this.moduleLabel,
    required this.eventCategory,
    required this.source,
    required this.targetIdentifier,
    required this.riskScore,
    required this.classification,
    required this.severity,
    required this.findings,
    required this.explanation,
    required this.recommendedActions,
    required this.detectionTimestamp,
    required this.analysisStatus,
    required this.notificationStatus,
    this.metadata = const {},
    this.isDuplicate = false,
    this.pendingSync = false,
  });

  bool get isFailedOrUnavailable =>
      analysisStatus == 'failed' ||
      analysisStatus == 'unavailable' ||
      analysisStatus == 'unverified';

  bool get isThreat =>
      !isFailedOrUnavailable &&
      ((riskScore ?? 0) >= 41 ||
          classification == 'Suspicious' ||
          classification == 'High Risk' ||
          classification == 'Critical');

  bool get isSafe => !isFailedOrUnavailable && !isThreat;

  String get sourceGroup {
    switch (source.toLowerCase()) {
      case 'manual_scan':
        return 'Manual Scans';
      case 'communication':
        return 'Communications';
      case 'device_audit':
        return 'Device Audits';
      case 'realtime_monitor':
      case 'system_event':
        return 'System & Protection';
      case 'community':
        return 'Community Intel';
      case 'assistant':
        return 'AI Assistant';
      default:
        return 'System & Protection';
    }
  }

  factory SecurityEventModel.fromJson(Map<String, dynamic> json) {
    final modName = json['module_name']?.toString() ?? 'realtime_protection';
    final rawScore = json['risk_score'];
    int? parsedScore;
    if (rawScore is int) {
      parsedScore = rawScore;
    } else if (rawScore is num) {
      parsedScore = rawScore.toInt();
    } else if (rawScore != null) {
      parsedScore = int.tryParse(rawScore.toString());
    }

    DateTime ts;
    try {
      ts = DateTime.parse(json['detection_timestamp']?.toString() ?? '').toLocal();
    } catch (_) {
      ts = DateTime.now();
    }

    return SecurityEventModel(
      eventId: json['event_id']?.toString() ?? 'evt-local',
      userId: json['user_id']?.toString() ?? 'local_guest',
      moduleName: modName,
      moduleLabel: json['module_label']?.toString() ?? moduleLabelFor(modName),
      eventCategory: json['event_category']?.toString() ?? 'general',
      source: json['source']?.toString() ?? 'system_event',
      targetIdentifier: json['target_identifier']?.toString() ?? 'N/A',
      riskScore: parsedScore,
      classification: json['classification']?.toString() ?? 'Unverified',
      severity: json['severity']?.toString() ?? 'info',
      findings: (json['findings'] is List)
          ? (json['findings'] as List).map((e) => e.toString()).toList()
          : const [],
      explanation: json['explanation']?.toString() ?? '',
      recommendedActions: (json['recommended_actions'] is List)
          ? (json['recommended_actions'] as List).map((e) => e.toString()).toList()
          : const [],
      detectionTimestamp: ts,
      analysisStatus: json['analysis_status']?.toString() ?? 'analyzed',
      notificationStatus: json['notification_status']?.toString() ?? 'suppressed_safe',
      metadata: (json['metadata'] is Map)
          ? Map<String, dynamic>.from(json['metadata'] as Map)
          : const {},
      isDuplicate: json['is_duplicate'] == true,
      pendingSync: json['pending_sync'] == true,
    );
  }

  Map<String, dynamic> toJson() => {
        'event_id': eventId,
        'user_id': userId,
        'module_name': moduleName,
        'module_label': moduleLabel,
        'event_category': eventCategory,
        'source': source,
        'target_identifier': targetIdentifier,
        'risk_score': riskScore,
        'classification': classification,
        'severity': severity,
        'findings': findings,
        'explanation': explanation,
        'recommended_actions': recommendedActions,
        'detection_timestamp': detectionTimestamp.toUtc().toIso8601String(),
        'analysis_status': analysisStatus,
        'notification_status': notificationStatus,
        'metadata': metadata,
        'is_duplicate': isDuplicate,
        'pending_sync': pendingSync,
      };

  SecurityEventModel copyWith({
    String? notificationStatus,
    bool? pendingSync,
  }) {
    return SecurityEventModel(
      eventId: eventId,
      userId: userId,
      moduleName: moduleName,
      moduleLabel: moduleLabel,
      eventCategory: eventCategory,
      source: source,
      targetIdentifier: targetIdentifier,
      riskScore: riskScore,
      classification: classification,
      severity: severity,
      findings: findings,
      explanation: explanation,
      recommendedActions: recommendedActions,
      detectionTimestamp: detectionTimestamp,
      analysisStatus: analysisStatus,
      notificationStatus: notificationStatus ?? this.notificationStatus,
      metadata: metadata,
      isDuplicate: isDuplicate,
      pendingSync: pendingSync ?? this.pendingSync,
    );
  }
}

@immutable
class ModuleDistributionItem {
  final String moduleName;
  final String moduleLabel;
  final int totalEvents;
  final int analyzedEvents;
  final int threatCount;
  final int criticalCount;
  final int highRiskCount;
  final int suspiciousCount;
  final int safeCount;
  final int failedOrUnavailable;
  final double threatRatePercent;

  const ModuleDistributionItem({
    required this.moduleName,
    required this.moduleLabel,
    required this.totalEvents,
    required this.analyzedEvents,
    required this.threatCount,
    required this.criticalCount,
    required this.highRiskCount,
    required this.suspiciousCount,
    required this.safeCount,
    required this.failedOrUnavailable,
    required this.threatRatePercent,
  });

  factory ModuleDistributionItem.fromJson(Map<String, dynamic> json) {
    return ModuleDistributionItem(
      moduleName: json['module_name']?.toString() ?? '',
      moduleLabel: json['module_label']?.toString() ?? '',
      totalEvents: (json['total_events'] as num?)?.toInt() ?? 0,
      analyzedEvents: (json['analyzed_events'] as num?)?.toInt() ?? 0,
      threatCount: (json['threat_count'] as num?)?.toInt() ?? 0,
      criticalCount: (json['critical_count'] as num?)?.toInt() ?? 0,
      highRiskCount: (json['high_risk_count'] as num?)?.toInt() ?? 0,
      suspiciousCount: (json['suspicious_count'] as num?)?.toInt() ?? 0,
      safeCount: (json['safe_count'] as num?)?.toInt() ?? 0,
      failedOrUnavailable: (json['failed_or_unavailable'] as num?)?.toInt() ?? 0,
      threatRatePercent: (json['threat_rate_percent'] as num?)?.toDouble() ?? 0.0,
    );
  }
}

@immutable
class UnifiedTrendPoint {
  final String label;
  final int analyzed;
  final int threats;
  final int failedOrUnavailable;

  const UnifiedTrendPoint({
    required this.label,
    required this.analyzed,
    required this.threats,
    required this.failedOrUnavailable,
  });

  factory UnifiedTrendPoint.fromJson(Map<String, dynamic> json) {
    return UnifiedTrendPoint(
      label: json['label']?.toString() ?? '',
      analyzed: (json['analyzed'] as num?)?.toInt() ?? 0,
      threats: (json['threats'] as num?)?.toInt() ?? 0,
      failedOrUnavailable: (json['failed_or_unavailable'] as num?)?.toInt() ?? 0,
    );
  }
}

@immutable
class UnifiedSecurityAnalytics {
  final String period;
  final int totalEvents;
  final int totalAnalyzedEvents;
  final int failedOrUnavailableEvents;
  final int totalThreatsDetected;
  final int safeCount;
  final int suspiciousCount;
  final int highRiskCount;
  final int criticalCount;
  final double threatDetectionRatePercent;
  final double monitoringCoveragePercent;
  final int deviceSecurityPostureScore;
  final String postureLabel;
  final int activeModulesCount;
  final int totalRegisteredModules;
  final Map<String, int> sourceBreakdown;
  final List<ModuleDistributionItem> moduleDistribution;
  final List<UnifiedTrendPoint> trendSeries;

  const UnifiedSecurityAnalytics({
    this.period = 'daily',
    this.totalEvents = 0,
    this.totalAnalyzedEvents = 0,
    this.failedOrUnavailableEvents = 0,
    this.totalThreatsDetected = 0,
    this.safeCount = 0,
    this.suspiciousCount = 0,
    this.highRiskCount = 0,
    this.criticalCount = 0,
    this.threatDetectionRatePercent = 0.0,
    this.monitoringCoveragePercent = 100.0,
    this.deviceSecurityPostureScore = 100,
    this.postureLabel = 'Strong',
    this.activeModulesCount = 0,
    this.totalRegisteredModules = 18,
    this.sourceBreakdown = const {},
    this.moduleDistribution = const [],
    this.trendSeries = const [],
  });

  factory UnifiedSecurityAnalytics.fromJson(Map<String, dynamic> json) {
    final rawSources = json['source_breakdown'];
    final sourceMap = <String, int>{};
    if (rawSources is Map) {
      rawSources.forEach((k, v) {
        sourceMap[k.toString()] = (v as num?)?.toInt() ?? 0;
      });
    }

    return UnifiedSecurityAnalytics(
      period: json['period']?.toString() ?? 'daily',
      totalEvents: (json['total_events'] as num?)?.toInt() ?? 0,
      totalAnalyzedEvents: (json['total_analyzed_events'] as num?)?.toInt() ?? 0,
      failedOrUnavailableEvents: (json['failed_or_unavailable_events'] as num?)?.toInt() ?? 0,
      totalThreatsDetected: (json['total_threats_detected'] as num?)?.toInt() ?? 0,
      safeCount: (json['safe_count'] as num?)?.toInt() ?? 0,
      suspiciousCount: (json['suspicious_count'] as num?)?.toInt() ?? 0,
      highRiskCount: (json['high_risk_count'] as num?)?.toInt() ?? 0,
      criticalCount: (json['critical_count'] as num?)?.toInt() ?? 0,
      threatDetectionRatePercent: (json['threat_detection_rate_percent'] as num?)?.toDouble() ?? 0.0,
      monitoringCoveragePercent: (json['monitoring_coverage_percent'] as num?)?.toDouble() ?? 100.0,
      deviceSecurityPostureScore: (json['device_security_posture_score'] as num?)?.toInt() ?? 100,
      postureLabel: json['posture_label']?.toString() ?? 'Strong',
      activeModulesCount: (json['active_modules_count'] as num?)?.toInt() ?? 0,
      totalRegisteredModules: (json['total_registered_modules'] as num?)?.toInt() ?? 18,
      sourceBreakdown: sourceMap,
      moduleDistribution: (json['module_distribution'] is List)
          ? (json['module_distribution'] as List)
              .whereType<Map<String, dynamic>>()
              .map(ModuleDistributionItem.fromJson)
              .toList()
          : const [],
      trendSeries: (json['trend_series'] is List)
          ? (json['trend_series'] as List)
              .whereType<Map<String, dynamic>>()
              .map(UnifiedTrendPoint.fromJson)
              .toList()
          : const [],
    );
  }
}

@immutable
class SmartNotificationPrefs {
  final bool notifySuspicious;
  final bool notifySafeSummary;
  final bool dailyReportEnabled;
  final bool notifySystemEvents;
  final bool hideSensitiveOnLockScreen;
  final int retentionDays;

  const SmartNotificationPrefs({
    this.notifySuspicious = true,
    this.notifySafeSummary = false,
    this.dailyReportEnabled = true,
    this.notifySystemEvents = true,
    this.hideSensitiveOnLockScreen = true,
    this.retentionDays = 90,
  });

  factory SmartNotificationPrefs.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const SmartNotificationPrefs();
    return SmartNotificationPrefs(
      notifySuspicious: json['notify_suspicious'] != false,
      notifySafeSummary: json['notify_safe_summary'] == true,
      dailyReportEnabled: json['daily_report_enabled'] != false,
      notifySystemEvents: json['notify_system_events'] != false,
      hideSensitiveOnLockScreen: json['hide_sensitive_on_lock_screen'] != false,
      retentionDays: (json['retention_days'] as num?)?.toInt() ?? 90,
    );
  }

  Map<String, dynamic> toJson() => {
        'notify_suspicious': notifySuspicious,
        'notify_safe_summary': notifySafeSummary,
        'daily_report_enabled': dailyReportEnabled,
        'notify_system_events': notifySystemEvents,
        'hide_sensitive_on_lock_screen': hideSensitiveOnLockScreen,
        'retention_days': retentionDays,
      };

  SmartNotificationPrefs copyWith({
    bool? notifySuspicious,
    bool? notifySafeSummary,
    bool? dailyReportEnabled,
    bool? notifySystemEvents,
    bool? hideSensitiveOnLockScreen,
    int? retentionDays,
  }) {
    return SmartNotificationPrefs(
      notifySuspicious: notifySuspicious ?? this.notifySuspicious,
      notifySafeSummary: notifySafeSummary ?? this.notifySafeSummary,
      dailyReportEnabled: dailyReportEnabled ?? this.dailyReportEnabled,
      notifySystemEvents: notifySystemEvents ?? this.notifySystemEvents,
      hideSensitiveOnLockScreen: hideSensitiveOnLockScreen ?? this.hideSensitiveOnLockScreen,
      retentionDays: retentionDays ?? this.retentionDays,
    );
  }
}
