class FindingExplanation {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const FindingExplanation({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory FindingExplanation.fromJson(Map<String, dynamic> json) {
    return FindingExplanation(
      indicator: json['indicator'] as String? ?? '',
      title: json['title'] as String? ?? '',
      riskLevel: json['risk_level'] as String? ?? 'Medium',
      explanation: json['explanation'] as String? ?? '',
    );
  }
}

class UrlScanResult {
  final String status;
  final String scanType;
  final String target;
  final String scannedUrl;
  final int riskScore;
  final String classification;
  final List<String> detectedIndicators;
  final List<String> findings;
  final String explanation;
  final List<FindingExplanation> findingExplanations;
  final String recommendation;
  final Map<String, dynamic>? metadata;
  final String? timestamp;
  final String? engineStatus;
  final String? errorMessage;

  const UrlScanResult({
    required this.status,
    required this.scanType,
    required this.target,
    required this.scannedUrl,
    required this.riskScore,
    required this.classification,
    required this.detectedIndicators,
    required this.findings,
    required this.explanation,
    required this.findingExplanations,
    required this.recommendation,
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

  factory UrlScanResult.fromJson(Map<String, dynamic> json) {
    final rawIndicators = json['detected_indicators'] as List? ?? [];
    final rawFindings = json['findings'] as List? ?? [];
    final rawExplanations = json['finding_explanations'] as List? ?? [];

    return UrlScanResult(
      status: json['status'] as String? ?? 'inspected',
      scanType: json['scan_type'] as String? ?? 'url',
      target: json['target'] as String? ?? '',
      scannedUrl:
          json['scanned_url'] as String? ?? json['target'] as String? ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      detectedIndicators: rawIndicators.map((e) => e.toString()).toList(),
      findings: rawFindings.map((e) => e.toString()).toList(),
      explanation: json['explanation'] as String? ?? '',
      findingExplanations: rawExplanations
          .map((e) => FindingExplanation.fromJson(
              Map<String, dynamic>.from(e as Map)))
          .toList(),
      recommendation: json['recommendation'] as String? ?? '',
      metadata: json['metadata'] as Map<String, dynamic>?,
      timestamp: json['timestamp'] as String?,
      engineStatus: json['engine_status'] as String?,
    );
  }

  factory UrlScanResult.error(String message) {
    return UrlScanResult(
      status: 'error',
      scanType: 'url',
      target: '',
      scannedUrl: '',
      riskScore: 0,
      classification: 'Error',
      detectedIndicators: const [],
      findings: const [],
      explanation: '',
      findingExplanations: const [],
      recommendation: '',
      errorMessage: message,
    );
  }
}

