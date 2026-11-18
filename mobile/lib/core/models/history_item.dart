// Audit History Item Model for CyberShield

class HistoryItem {
  final String id;
  final String scanId;
  final String scanType;
  final String target;
  final int riskScore;
  final String classification;
  final String summary;
  final String statusBadge;
  final String timestamp;
  final Map<String, dynamic> details;

  const HistoryItem({
    required this.id,
    required this.scanId,
    required this.scanType,
    required this.target,
    required this.riskScore,
    required this.classification,
    required this.summary,
    required this.statusBadge,
    required this.timestamp,
    this.details = const {},
  });

  bool get isSafe =>
      classification.toLowerCase() == 'safe' && riskScore < 30;

  bool get isSuspicious =>
      classification.toLowerCase() == 'suspicious' ||
      (riskScore >= 30 && riskScore < 60);

  bool get isMalicious =>
      classification.toLowerCase() == 'malicious' ||
      classification.toLowerCase() == 'high risk' ||
      riskScore >= 60;

  factory HistoryItem.fromJson(Map<String, dynamic> json) {
    final rawId = json['id'] as String? ?? json['scan_id'] as String? ?? '';
    final rawDetails = json['details'];
    Map<String, dynamic> detailsMap = const {};
    if (rawDetails is Map) {
      detailsMap = Map<String, dynamic>.from(rawDetails);
    }

    return HistoryItem(
      id: rawId,
      scanId: json['scan_id'] as String? ?? rawId,
      scanType: (json['scan_type'] as String? ?? 'SCAN').toUpperCase(),
      target: json['target'] as String? ?? 'Unknown target',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification'] as String? ?? 'Safe',
      summary: json['summary'] as String? ?? '',
      statusBadge: json['status_badge'] as String? ?? 'safe',
      timestamp: json['timestamp'] as String? ?? '',
      details: detailsMap,
    );
  }
}

