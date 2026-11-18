// Strongly-typed model for Screenshot threat analysis from POST /api/v1/screenshot/analyze

class ScreenshotFindingDetail {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const ScreenshotFindingDetail({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory ScreenshotFindingDetail.fromJson(Map<String, dynamic> json) {
    return ScreenshotFindingDetail(
      indicator: json['indicator'] as String? ?? '',
      title: json['title'] as String? ?? '',
      riskLevel: json['risk_level'] as String? ?? 'Medium',
      explanation: json['explanation'] as String? ?? '',
    );
  }
}

class ScreenshotScanResult {
  final String status;
  final String scanType;
  final String filename;
  final String ocrText;
  final int riskScore;
  final String classification;
  final List<String> findings;
  final List<String> detectedIndicators;
  final String explanation;
  final List<ScreenshotFindingDetail> findingExplanations;
  final String recommendation;
  final List<String> extractedUrls;
  final List<String> threatCategories;
  final Map<String, dynamic>? metadata;
  final String? timestamp;
  final String? engineStatus;
  final String? errorMessage;

  const ScreenshotScanResult({
    required this.status,
    required this.scanType,
    required this.filename,
    required this.ocrText,
    required this.riskScore,
    required this.classification,
    required this.findings,
    required this.detectedIndicators,
    required this.explanation,
    required this.findingExplanations,
    required this.recommendation,
    required this.extractedUrls,
    required this.threatCategories,
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

  factory ScreenshotScanResult.fromJson(Map<String, dynamic> json) {
    final rawFindings = json['findings'] as List? ?? [];
    final rawIndicators = json['detected_indicators'] as List? ?? [];
    final rawExplanations = json['finding_explanations'] as List? ?? [];
    final rawUrls = json['extracted_urls'] as List? ?? [];
    final rawCats = json['threat_categories'] as List? ?? [];

    return ScreenshotScanResult(
      status: json['status'] as String? ?? 'inspected',
      scanType: json['scan_type'] as String? ?? 'screenshot',
      filename: json['filename'] as String? ?? 'screenshot.png',
      ocrText: json['ocr_text'] as String? ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      findings: rawFindings.map((e) => e.toString()).toList(),
      detectedIndicators: rawIndicators.map((e) => e.toString()).toList(),
      explanation: json['explanation'] as String? ?? '',
      findingExplanations: rawExplanations
          .map((e) => ScreenshotFindingDetail.fromJson(
              Map<String, dynamic>.from(e as Map)))
          .toList(),
      recommendation: json['recommendation'] as String? ?? '',
      extractedUrls: rawUrls.map((e) => e.toString()).toList(),
      threatCategories: rawCats.map((e) => e.toString()).toList(),
      metadata: json['metadata'] as Map<String, dynamic>?,
      timestamp: json['timestamp'] as String?,
      engineStatus: json['engine_status'] as String?,
    );
  }

  factory ScreenshotScanResult.error(String message) {
    return ScreenshotScanResult(
      status: 'error',
      scanType: 'screenshot',
      filename: 'unknown',
      ocrText: '',
      riskScore: 0,
      classification: 'Error',
      findings: const [],
      detectedIndicators: const [],
      explanation: '',
      findingExplanations: const [],
      recommendation: '',
      extractedUrls: const [],
      threatCategories: const [],
      errorMessage: message,
    );
  }
}
