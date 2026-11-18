class SmsFindingDetail {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const SmsFindingDetail({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory SmsFindingDetail.fromJson(Map<String, dynamic> json) {
    return SmsFindingDetail(
      indicator: json['indicator'] as String? ?? '',
      title: json['title'] as String? ?? '',
      riskLevel: json['risk_level'] as String? ?? 'Medium',
      explanation: json['explanation'] as String? ?? '',
    );
  }
}

class SmsScanResult {
  final String status;
  final String scanType;
  final String target;
  final String scannedMessage;
  final int riskScore;
  final String classification;
  final List<String> threatCategories;
  final List<String> findings;
  final List<String> detectedIndicators;
  final String explanation;
  final List<SmsFindingDetail> findingExplanations;
  final String recommendation;
  final List<String> embeddedUrls;
  final Map<String, dynamic>? metadata;
  final String? timestamp;
  final String? engineStatus;
  final String? errorMessage;

  const SmsScanResult({
    required this.status,
    required this.scanType,
    required this.target,
    required this.scannedMessage,
    required this.riskScore,
    required this.classification,
    required this.threatCategories,
    required this.findings,
    required this.detectedIndicators,
    required this.explanation,
    required this.findingExplanations,
    required this.recommendation,
    required this.embeddedUrls,
    this.metadata,
    this.timestamp,
    this.engineStatus,
    this.errorMessage,
  });

  bool get isSafe => classification.toLowerCase() == 'safe' && riskScore < 30;
  bool get isSuspicious =>
      classification.toLowerCase() == 'suspicious' ||
      (riskScore >= 30 && riskScore < 70);
  bool get isMalicious =>
      classification.toLowerCase() == 'malicious' || riskScore >= 70;

  bool get hasError => errorMessage != null || status == 'error';

  factory SmsScanResult.fromJson(Map<String, dynamic> json) {
    final rawIndicators = json['detected_indicators'] as List? ?? [];
    final rawFindings = json['findings'] as List? ?? [];
    final rawCategories = json['threat_categories'] as List? ?? [];
    final rawExplanations = json['finding_explanations'] as List? ?? [];
    final rawUrls = json['embedded_urls'] as List? ?? [];

    return SmsScanResult(
      status: json['status'] as String? ?? 'inspected',
      scanType: json['scan_type'] as String? ?? 'sms',
      target: json['target'] as String? ?? '',
      scannedMessage:
          json['scanned_message'] as String? ?? json['target'] as String? ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      threatCategories: rawCategories.map((e) => e.toString()).toList(),
      findings: rawFindings.map((e) => e.toString()).toList(),
      detectedIndicators: rawIndicators.map((e) => e.toString()).toList(),
      explanation: json['explanation'] as String? ?? '',
      findingExplanations: rawExplanations
          .map((e) => SmsFindingDetail.fromJson(
              Map<String, dynamic>.from(e as Map)))
          .toList(),
      recommendation: json['recommendation'] as String? ?? '',
      embeddedUrls: rawUrls.map((e) => e.toString()).toList(),
      metadata: json['metadata'] as Map<String, dynamic>?,
      timestamp: json['timestamp'] as String?,
      engineStatus: json['engine_status'] as String?,
    );
  }

  factory SmsScanResult.error(String message) {
    return SmsScanResult(
      status: 'error',
      scanType: 'sms',
      target: '',
      scannedMessage: '',
      riskScore: 0,
      classification: 'Error',
      threatCategories: const [],
      findings: const [],
      detectedIndicators: const [],
      explanation: '',
      findingExplanations: const [],
      recommendation: '',
      embeddedUrls: const [],
      errorMessage: message,
    );
  }
}

