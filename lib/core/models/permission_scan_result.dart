// Strongly typed model for CyberShield Permission Analyzer scan results

class PermissionExplanation {
  final String indicator;
  final String permission;
  final String category;
  final String dangerLevel;
  final int riskPoints;
  final String explanation;

  const PermissionExplanation({
    required this.indicator,
    required this.permission,
    required this.category,
    required this.dangerLevel,
    required this.riskPoints,
    required this.explanation,
  });

  factory PermissionExplanation.fromJson(Map<String, dynamic> json) {
    return PermissionExplanation(
      indicator: json['indicator']?.toString() ?? '',
      permission: json['permission']?.toString() ?? '',
      category: json['category']?.toString() ?? 'General',
      dangerLevel: json['danger_level']?.toString() ?? 'Dangerous',
      riskPoints: json['risk_points'] as int? ?? 0,
      explanation: json['explanation']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'indicator': indicator,
    'permission': permission,
    'category': category,
    'danger_level': dangerLevel,
    'risk_points': riskPoints,
    'explanation': explanation,
  };
}

class PermissionScanResult {
  final String status;
  final String scanType;
  final String packageName;
  final String appName;
  final String versionName;
  final String versionCode;
  final int minSdk;
  final int targetSdk;
  final int totalPermissionsCount;
  final int dangerousPermissionsCount;
  final List<String> permissions;
  final List<String> dangerousPermissions;
  final int riskScore;
  final String classification;
  final List<String> findings;
  final List<String> detectedIndicators;
  final List<String> comboFindings;
  final List<PermissionExplanation> findingExplanations;
  final String explanation;
  final String recommendation;
  final List<String> recommendations;
  final Map<String, dynamic> metadata;
  final String engineStatus;
  final String timestamp;
  final bool isError;
  final String? errorMessage;

  const PermissionScanResult({
    required this.status,
    required this.scanType,
    required this.packageName,
    required this.appName,
    required this.versionName,
    required this.versionCode,
    required this.minSdk,
    required this.targetSdk,
    required this.totalPermissionsCount,
    required this.dangerousPermissionsCount,
    required this.permissions,
    required this.dangerousPermissions,
    required this.riskScore,
    required this.classification,
    required this.findings,
    required this.detectedIndicators,
    required this.comboFindings,
    required this.findingExplanations,
    required this.explanation,
    required this.recommendation,
    required this.recommendations,
    required this.metadata,
    required this.engineStatus,
    required this.timestamp,
    this.isError = false,
    this.errorMessage,
  });

  factory PermissionScanResult.fromJson(Map<String, dynamic> json) {
    final rawExplanations = json['finding_explanations'] as List? ?? [];
    final explanations = rawExplanations
        .map((e) => PermissionExplanation.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();

    final rawRecs = json['recommendations'] as List? ?? [];
    final recs = rawRecs.map((e) => e.toString()).toList();

    return PermissionScanResult(
      status: json['status']?.toString() ?? 'analyzed',
      scanType: json['scan_type']?.toString() ?? 'permissions',
      packageName: json['package_name']?.toString() ?? 'unknown.package',
      appName: json['app_name']?.toString() ?? 'Android Application',
      versionName: json['version_name']?.toString() ?? '1.0',
      versionCode: json['version_code']?.toString() ?? '1',
      minSdk: json['min_sdk'] as int? ?? 0,
      targetSdk: json['target_sdk'] as int? ?? 0,
      totalPermissionsCount: json['total_permissions_count'] as int? ??
          (json['permissions'] as List? ?? []).length,
      dangerousPermissionsCount: json['dangerous_permissions_count'] as int? ??
          (json['dangerous_permissions'] as List? ?? []).length,
      permissions: List<String>.from(json['permissions'] as List? ?? []),
      dangerousPermissions:
          List<String>.from(json['dangerous_permissions'] as List? ?? []),
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification']?.toString() ?? 'Safe',
      findings: List<String>.from(json['findings'] as List? ?? []),
      detectedIndicators:
          List<String>.from(json['detected_indicators'] as List? ?? []),
      comboFindings: List<String>.from(json['combo_findings'] as List? ?? []),
      findingExplanations: explanations,
      explanation: json['explanation']?.toString() ?? '',
      recommendation: json['recommendation']?.toString() ?? '',
      recommendations: recs.isNotEmpty
          ? recs
          : [json['recommendation']?.toString() ?? 'Review application permissions.'],
      metadata: Map<String, dynamic>.from(json['metadata'] as Map? ?? {}),
      engineStatus: json['engine_status']?.toString() ?? 'permission_analyzer_active',
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
      isError: false,
    );
  }

  factory PermissionScanResult.error(String message) {
    return PermissionScanResult(
      status: 'error',
      scanType: 'permissions',
      packageName: 'unknown',
      appName: 'Error',
      versionName: '',
      versionCode: '',
      minSdk: 0,
      targetSdk: 0,
      totalPermissionsCount: 0,
      dangerousPermissionsCount: 0,
      permissions: const [],
      dangerousPermissions: const [],
      riskScore: 0,
      classification: 'Error',
      findings: const [],
      detectedIndicators: const [],
      comboFindings: const [],
      findingExplanations: const [],
      explanation: message,
      recommendation: 'Check connection or inspect your input.',
      recommendations: const ['Check network connection and backend service.'],
      metadata: const {},
      engineStatus: 'error',
      timestamp: DateTime.now().toIso8601String(),
      isError: true,
      errorMessage: message,
    );
  }

  Map<String, dynamic> toJson() => {
    'status': status,
    'scan_type': scanType,
    'package_name': packageName,
    'app_name': appName,
    'version_name': versionName,
    'version_code': versionCode,
    'min_sdk': minSdk,
    'target_sdk': targetSdk,
    'total_permissions_count': totalPermissionsCount,
    'dangerous_permissions_count': dangerousPermissionsCount,
    'permissions': permissions,
    'dangerous_permissions': dangerousPermissions,
    'risk_score': riskScore,
    'classification': classification,
    'findings': findings,
    'detected_indicators': detectedIndicators,
    'combo_findings': comboFindings,
    'finding_explanations': findingExplanations.map((e) => e.toJson()).toList(),
    'explanation': explanation,
    'recommendation': recommendation,
    'recommendations': recommendations,
    'metadata': metadata,
    'engine_status': engineStatus,
    'timestamp': timestamp,
    'is_error': isError,
    'error_message': errorMessage,
  };
}

