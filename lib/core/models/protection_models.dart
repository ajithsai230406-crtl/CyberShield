// CyberShield Real-Time Android Protection Models

class InstalledAppInfo {
  final String packageName;
  final String appName;
  final String versionName;
  final String versionCode;
  final bool isSystemApp;
  final List<String> permissions;
  final int minSdk;
  final int targetSdk;
  final int firstInstallTime;
  final int lastUpdateTime;

  // Analysis result fields (populated after backend or local scan)
  final int riskScore;
  final String classification;
  final int dangerousPermissionsCount;
  final List<String> dangerousPermissions;
  final List<String> comboFindings;
  final List<Map<String, dynamic>> findingExplanations;
  final String explanation;
  final List<String> recommendations;

  const InstalledAppInfo({
    required this.packageName,
    required this.appName,
    this.versionName = '1.0',
    this.versionCode = '1',
    this.isSystemApp = false,
    this.permissions = const [],
    this.minSdk = 0,
    this.targetSdk = 0,
    this.firstInstallTime = 0,
    this.lastUpdateTime = 0,
    this.riskScore = 0,
    this.classification = 'Safe',
    this.dangerousPermissionsCount = 0,
    this.dangerousPermissions = const [],
    this.comboFindings = const [],
    this.findingExplanations = const [],
    this.explanation = '',
    this.recommendations = const [],
  });

  bool get isRisky => riskScore >= 35 || classification != 'Safe';
  bool get isCritical => riskScore >= 70 || classification == 'Critical';
  bool get isHighRisk => (riskScore >= 50 && riskScore < 70) || classification == 'High Risk';
  bool get isSuspicious => (riskScore >= 35 && riskScore < 50) || classification == 'Suspicious';

  factory InstalledAppInfo.fromNativeMap(Map<dynamic, dynamic> map) {
    final rawPerms = map['permissions'] as List?;
    final perms = rawPerms?.map((e) => e.toString()).toList() ?? <String>[];

    return InstalledAppInfo(
      packageName: map['packageName']?.toString() ?? 'unknown.package',
      appName: map['appName']?.toString() ?? 'Android App',
      versionName: map['versionName']?.toString() ?? '1.0',
      versionCode: map['versionCode']?.toString() ?? '1',
      isSystemApp: map['isSystemApp'] == true,
      permissions: perms,
      minSdk: map['minSdk'] is int ? map['minSdk'] as int : 0,
      targetSdk: map['targetSdk'] is int ? map['targetSdk'] as int : 0,
      firstInstallTime: map['firstInstallTime'] is int ? map['firstInstallTime'] as int : 0,
      lastUpdateTime: map['lastUpdateTime'] is int ? map['lastUpdateTime'] as int : 0,
    );
  }

  factory InstalledAppInfo.fromJson(Map<String, dynamic> json) {
    return InstalledAppInfo(
      packageName: json['package_name']?.toString() ?? '',
      appName: json['app_name']?.toString() ?? 'Android Application',
      versionName: json['version_name']?.toString() ?? '1.0',
      versionCode: json['version_code']?.toString() ?? '1',
      isSystemApp: json['is_system_app'] == true,
      permissions: (json['permissions'] as List?)?.map((e) => e.toString()).toList() ?? [],
      minSdk: json['min_sdk'] is int ? json['min_sdk'] as int : 0,
      targetSdk: json['target_sdk'] is int ? json['target_sdk'] as int : 0,
      riskScore: json['risk_score'] is int ? json['risk_score'] as int : 0,
      classification: json['classification']?.toString() ?? 'Safe',
      dangerousPermissionsCount: json['dangerous_permissions_count'] is int
          ? json['dangerous_permissions_count'] as int
          : 0,
      dangerousPermissions: (json['dangerous_permissions'] as List?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
      comboFindings: (json['combo_findings'] as List?)?.map((e) => e.toString()).toList() ?? [],
      findingExplanations: (json['finding_explanations'] as List?)
              ?.map((e) => Map<String, dynamic>.from(e as Map))
              .toList() ??
          [],
      explanation: json['explanation']?.toString() ?? '',
      recommendations: (json['recommendations'] as List?)?.map((e) => e.toString()).toList() ?? [],
    );
  }

  Map<String, dynamic> toBatchRequestJson() {
    return {
      'package_name': packageName,
      'app_name': appName,
      'permissions': permissions,
      'version_name': versionName,
      'version_code': versionCode,
      'min_sdk': minSdk,
      'target_sdk': targetSdk,
      'is_system_app': isSystemApp,
    };
  }

  InstalledAppInfo copyWithAnalysis({
    int? riskScore,
    String? classification,
    int? dangerousPermissionsCount,
    List<String>? dangerousPermissions,
    List<String>? comboFindings,
    List<Map<String, dynamic>>? findingExplanations,
    String? explanation,
    List<String>? recommendations,
  }) {
    return InstalledAppInfo(
      packageName: packageName,
      appName: appName,
      versionName: versionName,
      versionCode: versionCode,
      isSystemApp: isSystemApp,
      permissions: permissions,
      minSdk: minSdk,
      targetSdk: targetSdk,
      firstInstallTime: firstInstallTime,
      lastUpdateTime: lastUpdateTime,
      riskScore: riskScore ?? this.riskScore,
      classification: classification ?? this.classification,
      dangerousPermissionsCount: dangerousPermissionsCount ?? this.dangerousPermissionsCount,
      dangerousPermissions: dangerousPermissions ?? this.dangerousPermissions,
      comboFindings: comboFindings ?? this.comboFindings,
      findingExplanations: findingExplanations ?? this.findingExplanations,
      explanation: explanation ?? this.explanation,
      recommendations: recommendations ?? this.recommendations,
    );
  }
}

class BatchAppScanResult {
  final int totalAppsAnalyzed;
  final int safeCount;
  final int suspiciousCount;
  final int highRiskCount;
  final int criticalCount;
  final int overallDeviceRiskScore;
  final String overallClassification;
  final String summary;
  final List<InstalledAppInfo> highRiskApps;
  final List<InstalledAppInfo> allApps;
  final List<String> recommendations;
  final String timestamp;

  const BatchAppScanResult({
    required this.totalAppsAnalyzed,
    required this.safeCount,
    required this.suspiciousCount,
    required this.highRiskCount,
    required this.criticalCount,
    required this.overallDeviceRiskScore,
    required this.overallClassification,
    required this.summary,
    required this.highRiskApps,
    required this.allApps,
    required this.recommendations,
    required this.timestamp,
  });

  factory BatchAppScanResult.fromJson(Map<String, dynamic> json) {
    final highRiskList = (json['high_risk_apps'] as List?)
            ?.map((e) => InstalledAppInfo.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList() ??
        [];
    final allList = (json['all_apps'] as List?)
            ?.map((e) => InstalledAppInfo.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList() ??
        [];

    return BatchAppScanResult(
      totalAppsAnalyzed: json['total_apps_analyzed'] is int ? json['total_apps_analyzed'] as int : 0,
      safeCount: json['safe_count'] is int ? json['safe_count'] as int : 0,
      suspiciousCount: json['suspicious_count'] is int ? json['suspicious_count'] as int : 0,
      highRiskCount: json['high_risk_count'] is int ? json['high_risk_count'] as int : 0,
      criticalCount: json['critical_count'] is int ? json['critical_count'] as int : 0,
      overallDeviceRiskScore: json['overall_device_risk_score'] is int
          ? json['overall_device_risk_score'] as int
          : 0,
      overallClassification: json['overall_classification']?.toString() ?? 'Safe',
      summary: json['summary']?.toString() ?? '',
      highRiskApps: highRiskList,
      allApps: allList,
      recommendations: (json['recommendations'] as List?)?.map((e) => e.toString()).toList() ?? [],
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
    );
  }
}

class CallScreenResult {
  final String phoneNumber;
  final String normalizedNumber;
  final String? callerName;
  final bool isKnownSpam;
  final int spamScore;
  final String classification;
  final String confidence;
  final int reportCount;
  final List<String> evidenceTags;
  final String recommendedAction; // allow, warn, silence, block
  final String explanation;
  final String timestamp;

  const CallScreenResult({
    required this.phoneNumber,
    required this.normalizedNumber,
    this.callerName,
    required this.isKnownSpam,
    required this.spamScore,
    required this.classification,
    required this.confidence,
    required this.reportCount,
    required this.evidenceTags,
    required this.recommendedAction,
    required this.explanation,
    required this.timestamp,
  });

  factory CallScreenResult.fromJson(Map<String, dynamic> json) {
    return CallScreenResult(
      phoneNumber: json['phone_number']?.toString() ?? '',
      normalizedNumber: json['normalized_number']?.toString() ?? '',
      callerName: json['caller_name']?.toString(),
      isKnownSpam: json['is_known_spam'] == true,
      spamScore: json['spam_score'] is int ? json['spam_score'] as int : 0,
      classification: json['classification']?.toString() ?? 'Safe',
      confidence: json['confidence']?.toString() ?? 'Low',
      reportCount: json['report_count'] is int ? json['report_count'] as int : 0,
      evidenceTags: (json['evidence_tags'] as List?)?.map((e) => e.toString()).toList() ?? [],
      recommendedAction: json['recommended_action']?.toString() ?? 'allow',
      explanation: json['explanation']?.toString() ?? '',
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
    );
  }
}

class NotificationScanResult {
  final String packageName;
  final String sanitizedText;
  final List<String> detectedUrls;
  final int smsRiskScore;
  final int overallRiskScore;
  final String classification;
  final List<String> threatTypes;
  final bool hasPhishingUrl;
  final bool hasFinancialUrgency;
  final bool hasImpersonation;
  final bool redactedSensitiveData;
  final String explanation;
  final String recommendedAction;
  final String timestamp;

  const NotificationScanResult({
    required this.packageName,
    required this.sanitizedText,
    required this.detectedUrls,
    required this.smsRiskScore,
    required this.overallRiskScore,
    required this.classification,
    required this.threatTypes,
    required this.hasPhishingUrl,
    required this.hasFinancialUrgency,
    required this.hasImpersonation,
    required this.redactedSensitiveData,
    required this.explanation,
    required this.recommendedAction,
    required this.timestamp,
  });

  factory NotificationScanResult.fromJson(Map<String, dynamic> json) {
    return NotificationScanResult(
      packageName: json['package_name']?.toString() ?? '',
      sanitizedText: json['sanitized_text']?.toString() ?? '',
      detectedUrls: (json['detected_urls'] as List?)?.map((e) => e.toString()).toList() ?? [],
      smsRiskScore: json['sms_risk_score'] is int ? json['sms_risk_score'] as int : 0,
      overallRiskScore: json['overall_risk_score'] is int ? json['overall_risk_score'] as int : 0,
      classification: json['classification']?.toString() ?? 'Safe',
      threatTypes: (json['threat_types'] as List?)?.map((e) => e.toString()).toList() ?? [],
      hasPhishingUrl: json['has_phishing_url'] == true,
      hasFinancialUrgency: json['has_financial_urgency'] == true,
      hasImpersonation: json['has_impersonation'] == true,
      redactedSensitiveData: json['redacted_sensitive_data'] == true,
      explanation: json['explanation']?.toString() ?? '',
      recommendedAction: json['recommended_action']?.toString() ?? '',
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
    );
  }
}

class CallScreeningRoleResult {
  final String status; // granted, already_granted, denied, unsupported, in_progress, error
  final bool granted;
  final bool supported;
  final String message;
  final int androidSdk;

  const CallScreeningRoleResult({
    required this.status,
    required this.granted,
    required this.supported,
    required this.message,
    this.androidSdk = 0,
  });

  bool get isGranted => granted || status == 'granted' || status == 'already_granted';
  bool get isDenied => status == 'denied';
  bool get isUnsupported => !supported || status == 'unsupported';
  bool get isInProgress => status == 'in_progress';

  factory CallScreeningRoleResult.fromMap(Map<dynamic, dynamic> map) {
    final status = map['status']?.toString() ?? 'error';
    final granted = map['granted'] == true || status == 'granted' || status == 'already_granted';
    final supported = map['supported'] != false && status != 'unsupported';
    return CallScreeningRoleResult(
      status: status,
      granted: granted,
      supported: supported,
      message: map['message']?.toString() ??
          (granted
              ? 'Call Screening role is active.'
              : 'Call Screening role was not granted.'),
      androidSdk: map['androidSdk'] is int ? map['androidSdk'] as int : 0,
    );
  }
}

class ProtectionStatus {
  final bool isMasterEnabled;
  final bool isNotificationAccessGranted;
  final bool isCallScreeningRoleHeld;
  final bool isCallScreeningSupported;
  final String? callScreeningUnavailableReason;
  final int androidSdk;
  final String? androidRelease;
  final bool silenceSpamCalls;

  const ProtectionStatus({
    this.isMasterEnabled = true,
    this.isNotificationAccessGranted = false,
    this.isCallScreeningRoleHeld = false,
    this.isCallScreeningSupported = false,
    this.callScreeningUnavailableReason,
    this.androidSdk = 0,
    this.androidRelease,
    this.silenceSpamCalls = false,
  });

  factory ProtectionStatus.fromMap(Map<dynamic, dynamic> map) {
    return ProtectionStatus(
      isMasterEnabled: map['isMasterEnabled'] == true,
      isNotificationAccessGranted: map['isNotificationAccessGranted'] == true,
      isCallScreeningRoleHeld: map['isCallScreeningRoleHeld'] == true,
      isCallScreeningSupported: map['isCallScreeningSupported'] == true,
      callScreeningUnavailableReason: map['callScreeningUnavailableReason']?.toString(),
      androidSdk: map['androidSdk'] is int ? map['androidSdk'] as int : 0,
      androidRelease: map['androidRelease']?.toString(),
      silenceSpamCalls: map['silenceSpamCalls'] == true,
    );
  }
}

class ProtectionEventLogItem {
  final String id;
  final String type; // 'notification', 'call', 'demo'
  final String source;
  final String title;
  final String maskedContent;
  final int riskScore;
  final String classification;
  final DateTime timestamp;
  final bool isSimulated;
  final String? recommendedAction;

  const ProtectionEventLogItem({
    required this.id,
    required this.type,
    required this.source,
    required this.title,
    required this.maskedContent,
    required this.riskScore,
    required this.classification,
    required this.timestamp,
    this.isSimulated = false,
    this.recommendedAction,
  });

  bool get isRisky => riskScore >= 35 || classification != 'Safe';
}

