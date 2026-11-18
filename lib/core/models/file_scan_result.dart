// Strongly typed model for CyberShield File Threat Scanner results

class FileFindingExplanation {
  final String indicator;
  final String title;
  final String riskLevel;
  final String explanation;

  const FileFindingExplanation({
    required this.indicator,
    required this.title,
    required this.riskLevel,
    required this.explanation,
  });

  factory FileFindingExplanation.fromJson(Map<String, dynamic> json) {
    return FileFindingExplanation(
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

class FileScanResult {
  final String status;
  final String scanType;
  final String filename;
  final int fileSizeBytes;
  final String detectedMime;
  final String fileExtension;
  final bool isArchive;
  final int riskScore;
  final String classification;
  final List<String> threatCategories;
  final List<String> detectedIndicators;
  final List<String> findings;
  final List<FileFindingExplanation> findingExplanations;
  final String explanation;
  final String recommendation;
  final List<String> recommendations;
  final List<String> archiveContents;
  final String? md5;
  final String? sha1;
  final String? sha256;
  final Map<String, dynamic> metadata;
  final String engineStatus;
  final String timestamp;
  final bool isError;
  final String? errorMessage;

  const FileScanResult({
    required this.status,
    required this.scanType,
    required this.filename,
    required this.fileSizeBytes,
    required this.detectedMime,
    required this.fileExtension,
    required this.isArchive,
    required this.riskScore,
    required this.classification,
    required this.threatCategories,
    required this.detectedIndicators,
    required this.findings,
    required this.findingExplanations,
    required this.explanation,
    required this.recommendation,
    required this.recommendations,
    required this.archiveContents,
    this.md5,
    this.sha1,
    this.sha256,
    required this.metadata,
    required this.engineStatus,
    required this.timestamp,
    this.isError = false,
    this.errorMessage,
  });

  factory FileScanResult.fromJson(Map<String, dynamic> json) {
    final rawDetails = json['finding_explanations'] as List? ?? [];
    final explanations = rawDetails
        .map((e) => FileFindingExplanation.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();

    final rawRecs = json['recommendations'] as List? ?? [];
    final recs = rawRecs.map((e) => e.toString()).toList();
    final meta = Map<String, dynamic>.from(json['metadata'] as Map? ?? {});

    final md5Val = json['md5']?.toString() ?? meta['md5']?.toString();
    final sha1Val = json['sha1']?.toString() ?? meta['sha1']?.toString();
    final sha256Val = json['sha256']?.toString() ?? meta['sha256']?.toString();

    return FileScanResult(
      status: json['status']?.toString() ?? 'inspected',
      scanType: json['scan_type']?.toString() ?? 'file',
      filename: json['filename']?.toString() ?? 'file',
      fileSizeBytes: json['file_size_bytes'] as int? ?? 0,
      detectedMime: json['detected_mime']?.toString() ?? 'Unknown',
      fileExtension: json['file_extension']?.toString() ?? '',
      isArchive: json['is_archive'] as bool? ?? false,
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
          : [json['recommendation']?.toString() ?? 'Handle file with standard caution.'],
      archiveContents: List<String>.from(json['archive_contents'] as List? ?? []),
      md5: md5Val,
      sha1: sha1Val,
      sha256: sha256Val,
      metadata: meta,
      engineStatus: json['engine_status']?.toString() ?? 'file_threat_detector_active',
      timestamp: json['timestamp']?.toString() ?? DateTime.now().toIso8601String(),
      isError: false,
    );
  }

  factory FileScanResult.error(String message) {
    return FileScanResult(
      status: 'error',
      scanType: 'file',
      filename: 'unknown',
      fileSizeBytes: 0,
      detectedMime: 'error',
      fileExtension: '',
      isArchive: false,
      riskScore: 0,
      classification: 'Error',
      threatCategories: const [],
      detectedIndicators: const [],
      findings: const [],
      findingExplanations: const [],
      explanation: message,
      recommendation: 'Check connection or inspect your input.',
      recommendations: const ['Check network connection and try again.'],
      archiveContents: const [],
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
    'filename': filename,
    'file_size_bytes': fileSizeBytes,
    'detected_mime': detectedMime,
    'file_extension': fileExtension,
    'is_archive': isArchive,
    'risk_score': riskScore,
    'classification': classification,
    'threat_categories': threatCategories,
    'detected_indicators': detectedIndicators,
    'findings': findings,
    'finding_explanations': findingExplanations.map((e) => e.toJson()).toList(),
    'explanation': explanation,
    'recommendation': recommendation,
    'recommendations': recommendations,
    'archive_contents': archiveContents,
    'metadata': metadata,
    'engine_status': engineStatus,
    'timestamp': timestamp,
    'is_error': isError,
    'error_message': errorMessage,
  };
}

