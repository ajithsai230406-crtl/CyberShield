// Community Threat Report and Reputation Models for CyberShield

class EvidenceTag {
  final String tag;
  final int count;

  const EvidenceTag({
    required this.tag,
    required this.count,
  });

  factory EvidenceTag.fromJson(Map<String, dynamic> json) {
    return EvidenceTag(
      tag: json['tag']?.toString() ?? '',
      count: json['count'] as int? ?? 1,
    );
  }

  Map<String, dynamic> toJson() => {
    'tag': tag,
    'count': count,
  };
}

class CommunityReputation {
  final String category;
  final String target;
  final int totalReports;
  final int distinctReporters;
  final int suspicionScore;
  final String classification;
  final String confidence;
  final String threatStatus;
  final bool isVerifiedThreat;
  final String? lastReportedAt;
  final List<EvidenceTag> evidenceTags;
  final String disclaimer;

  const CommunityReputation({
    required this.category,
    required this.target,
    required this.totalReports,
    required this.distinctReporters,
    required this.suspicionScore,
    required this.classification,
    required this.confidence,
    required this.threatStatus,
    required this.isVerifiedThreat,
    this.lastReportedAt,
    this.evidenceTags = const [],
    required this.disclaimer,
  });

  factory CommunityReputation.fromJson(Map<String, dynamic> json) {
    final rawTags = json['evidence_tags'] as List? ?? [];
    return CommunityReputation(
      category: json['category']?.toString() ?? '',
      target: json['target']?.toString() ?? '',
      totalReports: json['total_reports'] as int? ?? 0,
      distinctReporters: json['distinct_reporters'] as int? ?? 0,
      suspicionScore: json['suspicion_score'] as int? ?? 0,
      classification: json['classification']?.toString() ?? 'Unreported / Unknown',
      confidence: json['confidence']?.toString() ?? 'None',
      threatStatus: json['threat_status']?.toString() ?? 'UNKNOWN',
      isVerifiedThreat: json['is_verified_threat'] as bool? ?? false,
      lastReportedAt: json['last_reported_at']?.toString(),
      evidenceTags: rawTags
          .whereType<Map<String, dynamic>>()
          .map((t) => EvidenceTag.fromJson(t))
          .toList(),
      disclaimer: json['disclaimer']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'category': category,
    'target': target,
    'total_reports': totalReports,
    'distinct_reporters': distinctReporters,
    'suspicion_score': suspicionScore,
    'classification': classification,
    'confidence': confidence,
    'threat_status': threatStatus,
    'is_verified_threat': isVerifiedThreat,
    'last_reported_at': lastReportedAt,
    'evidence_tags': evidenceTags.map((t) => t.toJson()).toList(),
    'disclaimer': disclaimer,
  };
}

class CommunityReport {
  final String id;
  final String category;
  final String target;
  final String targetDisplay;
  final String title;
  final String description;
  final List<String> tags;
  final String status;
  final bool isVerified;
  final String createdAt;
  final CommunityReputation? reputation;

  const CommunityReport({
    required this.id,
    required this.category,
    required this.target,
    required this.targetDisplay,
    required this.title,
    required this.description,
    this.tags = const [],
    required this.status,
    required this.isVerified,
    required this.createdAt,
    this.reputation,
  });

  factory CommunityReport.fromJson(Map<String, dynamic> json) {
    final rawTags = json['tags'] as List? ?? [];
    final repJson = json['reputation'] as Map<String, dynamic>?;

    return CommunityReport(
      id: json['id']?.toString() ?? '',
      category: (json['category']?.toString() ?? 'phone').toLowerCase(),
      target: json['target']?.toString() ?? '',
      targetDisplay: json['target_display']?.toString() ?? json['target']?.toString() ?? '',
      title: json['title']?.toString() ?? 'Community Threat Report',
      description: json['description']?.toString() ?? '',
      tags: rawTags.map((t) => t.toString()).toList(),
      status: json['status']?.toString() ?? 'PENDING',
      isVerified: json['is_verified'] as bool? ?? false,
      createdAt: json['created_at']?.toString() ?? '',
      reputation: repJson != null ? CommunityReputation.fromJson(repJson) : null,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'category': category,
    'target': target,
    'target_display': targetDisplay,
    'title': title,
    'description': description,
    'tags': tags,
    'status': status,
    'is_verified': isVerified,
    'created_at': createdAt,
    'reputation': reputation?.toJson(),
  };
}

class CommunityStats {
  final int totalReports;
  final int distinctTargets;
  final int activeReporters;
  final int verifiedThreats;
  final Map<String, int> categories;
  final String timestamp;

  const CommunityStats({
    required this.totalReports,
    required this.distinctTargets,
    required this.activeReporters,
    required this.verifiedThreats,
    this.categories = const {},
    required this.timestamp,
  });

  factory CommunityStats.fromJson(Map<String, dynamic> json) {
    final rawCats = json['categories'] as Map? ?? {};
    final catMap = <String, int>{};
    rawCats.forEach((k, v) {
      catMap[k.toString()] = (v as num?)?.toInt() ?? 0;
    });

    return CommunityStats(
      totalReports: json['total_reports'] as int? ?? 0,
      distinctTargets: json['distinct_targets'] as int? ?? 0,
      activeReporters: json['active_reporters'] as int? ?? 0,
      verifiedThreats: json['verified_threats'] as int? ?? 0,
      categories: catMap,
      timestamp: json['timestamp']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'total_reports': totalReports,
    'distinct_targets': distinctTargets,
    'active_reporters': activeReporters,
    'verified_threats': verifiedThreats,
    'categories': categories,
    'timestamp': timestamp,
  };
}

