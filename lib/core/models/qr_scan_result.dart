// Strongly-typed model for QR Code scan results from POST /api/v1/qr/scan

class QrFindingDetail {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const QrFindingDetail({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory QrFindingDetail.fromJson(Map<String, dynamic> json) {
    return QrFindingDetail(
      indicator: json['indicator'] as String? ?? '',
      title: json['title'] as String? ?? '',
      riskLevel: json['risk_level'] as String? ?? 'Medium',
      explanation: json['explanation'] as String? ?? '',
    );
  }
}

class QrScanResult {
  final String status;
  final String scanType;
  final String contentType;
  final String decodedPayload;
  final int riskScore;
  final String classification;
  final List<String> findings;
  final List<String> detectedIndicators;
  final String explanation;
  final List<QrFindingDetail> findingExplanations;
  final String recommendation;
  final Map<String, dynamic>? metadata;
  final String? timestamp;
  final String? engineStatus;
  final String? errorMessage;

  const QrScanResult({
    required this.status,
    required this.scanType,
    required this.contentType,
    required this.decodedPayload,
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

  bool get isSafe => classification.toLowerCase() == 'safe' && riskScore < 30;
  bool get isSuspicious =>
      classification.toLowerCase() == 'suspicious' ||
      (riskScore >= 30 && riskScore < 70);
  bool get isMalicious =>
      classification.toLowerCase() == 'malicious' || riskScore >= 70;

  bool get hasError => errorMessage != null || status == 'error';

  /// Human-readable label for the QR content type
  String get contentTypeLabel {
    switch (contentType.toLowerCase()) {
      case 'url':
        return 'URL / Web Link';
      case 'upi':
        return 'UPI Payment Link';
      case 'contact':
        return 'Contact (vCard)';
      case 'wifi':
        return 'WiFi Network';
      case 'text':
        return 'Plain Text';
      default:
        return contentType;
    }
  }

  factory QrScanResult.fromJson(Map<String, dynamic> json) {
    final rawFindings = json['findings'] as List? ?? [];
    final rawIndicators = json['detected_indicators'] as List? ?? [];
    final rawExplanations = json['finding_explanations'] as List? ?? [];

    return QrScanResult(
      status: json['status'] as String? ?? 'inspected',
      scanType: json['scan_type'] as String? ?? 'qr',
      contentType: json['content_type'] as String? ?? 'text',
      decodedPayload: json['decoded_payload'] as String? ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      findings: rawFindings.map((e) => e.toString()).toList(),
      detectedIndicators: rawIndicators.map((e) => e.toString()).toList(),
      explanation: json['explanation'] as String? ?? '',
      findingExplanations: rawExplanations
          .map((e) =>
              QrFindingDetail.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      recommendation: json['recommendation'] as String? ?? '',
      metadata: json['metadata'] as Map<String, dynamic>?,
      timestamp: json['timestamp'] as String?,
      engineStatus: json['engine_status'] as String?,
    );
  }

  factory QrScanResult.error(String message) {
    return QrScanResult(
      status: 'error',
      scanType: 'qr',
      contentType: 'unknown',
      decodedPayload: '',
      riskScore: 0,
      classification: 'Error',
      findings: const [],
      detectedIndicators: const [],
      explanation: '',
      findingExplanations: const [],
      recommendation: '',
      errorMessage: message,
    );
  }
}

