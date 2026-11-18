// Strongly-typed model for APK Security Analysis from POST /api/v1/apk/analyze

class ApkFindingDetail {
  final String indicator;
  final String category;
  final String explanation;

  const ApkFindingDetail({
    required this.indicator,
    required this.category,
    required this.explanation,
  });

  factory ApkFindingDetail.fromJson(Map<String, dynamic> json) {
    return ApkFindingDetail(
      indicator: json['indicator'] as String? ?? '',
      category: json['category'] as String? ?? 'General Risk',
      explanation: json['explanation'] as String? ?? '',
    );
  }
}

class ApkScanResult {
  final String status;
  final String scanType;
  final String filename;
  final String packageName;
  final String appName;
  final String versionName;
  final String versionCode;
  final int minSdk;
  final int targetSdk;
  final List<String> permissions;
  final List<String> dangerousPermissions;
  final List<String> comboFindings;
  final int riskScore;
  final String classification;
  final List<String> findings;
  final List<String> detectedIndicators;
  final String explanation;
  final List<ApkFindingDetail> findingExplanations;
  final String recommendation;
  final Map<String, dynamic>? metadata;
  final String? timestamp;
  final String? engineStatus;
  final String? errorMessage;

  const ApkScanResult({
    required this.status,
    required this.scanType,
    required this.filename,
    required this.packageName,
    required this.appName,
    required this.versionName,
    required this.versionCode,
    required this.minSdk,
    required this.targetSdk,
    required this.permissions,
    required this.dangerousPermissions,
    required this.comboFindings,
    required this.riskScore,
    required this.classification,
    required this.findings,
    required this.detectedIndicators,
    required this.explanation,
    required this.findingExplanations,
    required this.recommendation,
    this.metadata,
    this.timestamp,
    this.engineStatus,
    this.errorMessage,
  });

  bool get isSafe =>
      classification.toLowerCase() == 'safe' && riskScore < 30;

  bool get isSuspicious =>
      classification.toLowerCase() == 'suspicious' ||
      (riskScore >= 30 && riskScore < 60);

  bool get isHighRisk =>
      classification.toLowerCase() == 'high risk' ||
      classification.toLowerCase() == 'malicious' ||
      riskScore >= 60;

  bool get hasError => errorMessage != null || status == 'error';

  factory ApkScanResult.fromJson(Map<String, dynamic> json) {
    final rawPerms = json['permissions'] as List? ?? [];
    final rawDanger = json['dangerous_permissions'] as List? ?? [];
    final rawCombos = json['combo_findings'] as List? ?? [];
    final rawFindings = json['findings'] as List? ?? [];
    final rawIndicators = json['detected_indicators'] as List? ?? [];
    final rawExplanations = json['finding_explanations'] as List? ?? [];

    return ApkScanResult(
      status: json['status'] as String? ?? 'inspected',
      scanType: json['scan_type'] as String? ?? 'apk',
      filename: json['filename'] as String? ?? 'package.apk',
      packageName: json['package_name'] as String? ?? 'unknown',
      appName: json['app_name'] as String? ?? 'Unknown Application',
      versionName: json['version_name'] as String? ?? 'unknown',
      versionCode: json['version_code'] as String? ?? 'unknown',
      minSdk: json['min_sdk'] as int? ?? 0,
      targetSdk: json['target_sdk'] as int? ?? 0,
      permissions: rawPerms.map((e) => e.toString()).toList(),
      dangerousPermissions: rawDanger.map((e) => e.toString()).toList(),
      comboFindings: rawCombos.map((e) => e.toString()).toList(),
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      findings: rawFindings.map((e) => e.toString()).toList(),
      detectedIndicators: rawIndicators.map((e) => e.toString()).toList(),
      explanation: json['explanation'] as String? ?? '',
      findingExplanations: rawExplanations
          .map((e) => ApkFindingDetail.fromJson(
              Map<String, dynamic>.from(e as Map)))
          .toList(),
      recommendation: json['recommendation'] as String? ?? '',
      metadata: json['metadata'] as Map<String, dynamic>?,
      timestamp: json['timestamp'] as String?,
      engineStatus: json['engine_status'] as String?,
    );
  }

  factory ApkScanResult.error(String message) {
    return ApkScanResult(
      status: 'error',
      scanType: 'apk',
      filename: '',
      packageName: '',
      appName: '',
      versionName: '',
      versionCode: '',
      minSdk: 0,
      targetSdk: 0,
      permissions: const [],
      dangerousPermissions: const [],
      comboFindings: const [],
      riskScore: 0,
      classification: 'Error',
      findings: const [],
      detectedIndicators: const [],
      explanation: message,
      findingExplanations: const [],
      recommendation:
          'Please ensure the APK is a valid Android package file and try again.',
      errorMessage: message,
    );
  }
}

