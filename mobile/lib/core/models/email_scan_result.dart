// Strongly typed model for CyberShield Email Threat Scanner results

class EmailFindingExplanation {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const EmailFindingExplanation({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory EmailFindingExplanation.fromJson(Map<String, dynamic> json) {
    return EmailFindingExplanation(
      indicator: json['indicator']?.toString() ?? '',
      title: json['title']?.toString() ?? '',
      riskLevel: json['risk_level']?.toString() ?? 'Medium',
      explanation: json['explanation']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'indicator': indicator,
    'title': title,
    'risk_level': riskLevel,
    'explanation': explanation,
  };
}

class EmailScanResult {
  final String status;
  final String scanType;
  final String sender;
  final String subject;
  final String body;
  final int riskScore;
  final String classification;
  final List<String> threatCategories;
  final List<String> detectedIndicators;
  final List<String> findings;
  final List<EmailFindingExplanation> findingExplanations;
  final String explanation;
  final String recommendation;
  final List<String> recommendations;
  final List<String> embeddedUrls;
  final List<Map<String, dynamic>> urlScanResults;
  final Map<String, dynamic> metadata;
  final String engineStatus;
  final String timestamp;
  final bool isError;
  final String? errorMessage;

  const EmailScanResult({
    required this.status,
    required this.scanType,
    required this.sender,
    required this.subject,
    required this.body,
    required this.riskScore,
    required this.classification,
    required this.threatCategories,
    required this.detectedIndicators,
    required this.findings,
    required this.findingExplanations,
    required this.explanation,
    required this.recommendation,
    required this.recommendations,
    required this.embeddedUrls,
    required this.urlScanResults,
    required this.metadata,
    required this.engineStatus,
    required this.timestamp,
    this.isError = false,
    this.errorMessage,
  });

  factory EmailScanResult.fromJson(Map<String, dynamic> json) {
    final rawDetails = json['finding_explanations'] as List? ?? [];
    final explanations = rawDetails
        .map((e) => EmailFindingExplanation.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();

    final rawRecs = json['recommendations'] as List? ?? [];
    final recs = rawRecs.map((e) => e.toString()).toList();

    final rawUrlResults = json['url_scan_results'] as List? ?? [];
    final urlResults = rawUrlResults
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList();

    return EmailScanResult(
      status: json['status']?.toString() ?? 'inspected',
      scanType: json['scan_type']?.toString() ?? 'email',
      sender: json['sender']?.toString() ?? '',
      subject: json['subject']?.toString() ?? '',
      body: json['body']?.toString() ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification']?.toString() ?? 'Safe',
      threatCategories: List<String>.from(json['threat_categories'] as List? ?? []),
      detectedIndicators: List<String>.from(json['detected_indicators'] as List? ?? []),
      findings: List<String>.from(json['findings'] as List? ?? []),
      findingExplanations: explanations,
      explanation: json['explanation']?.toString() ?? '',
      recommendation: json['recommendation']?.toString() ?? '',
      recommendations: recs.isNotEmpty
          ? recs
          : [json['recommendation']?.toString() ?? 'Review email carefully before proceeding.'],
      embeddedUrls: List<String>.from(json['embedded_urls'] as List? ?? []),
      urlScanResults: urlResults,
      metadata: Map<String, dynamic>.from(json['metadata'] as Map? ?? {}),
      engineStatus: json['engine_status']?.toString() ?? 'email_threat_detector_active',
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
      isError: false,
    );
  }

  factory EmailScanResult.error(String message) {
    return EmailScanResult(
      status: 'error',
      scanType: 'email',
      sender: '',
      subject: '',
      body: '',
      riskScore: 0,
      classification: 'Error',
      threatCategories: const [],
      detectedIndicators: const [],
      findings: const [],
      findingExplanations: const [],
      explanation: message,
      recommendation: 'Check connection or inspect your input.',
      recommendations: const ['Check network connection and try again.'],
      embeddedUrls: const [],
      urlScanResults: const [],
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
    'sender': sender,
    'subject': subject,
    'body': body,
    'risk_score': riskScore,
    'classification': classification,
    'threat_categories': threatCategories,
    'detected_indicators': detectedIndicators,
    'findings': findings,
    'finding_explanations': findingExplanations.map((e) => e.toJson()).toList(),
    'explanation': explanation,
    'recommendation': recommendation,
    'recommendations': recommendations,
    'embedded_urls': embeddedUrls,
    'url_scan_results': urlScanResults,
    'metadata': metadata,
    'engine_status': engineStatus,
    'timestamp': timestamp,
    'is_error': isError,
    'error_message': errorMessage,
  };
}

