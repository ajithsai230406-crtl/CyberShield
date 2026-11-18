// Dashboard & Analytics Data Models for CyberShield

class SecurityScoreModel {
  final int score;
  final String status;
  final String tier;
  final String calculationExplanation;
  final String disclaimer;

  const SecurityScoreModel({
    required this.score,
    required this.status,
    required this.tier,
    required this.calculationExplanation,
    required this.disclaimer,
  });

  factory SecurityScoreModel.fromJson(Map<String, dynamic> json) {
    return SecurityScoreModel(
      score: json['score'] as int? ?? 70,
      status: json['status']?.toString() ?? 'Baseline Exposure',
      tier: json['tier']?.toString() ?? 'Neutral',
      calculationExplanation: json['calculation_explanation']?.toString() ?? '',
      disclaimer: json['disclaimer']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'score': score,
    'status': status,
    'tier': tier,
    'calculation_explanation': calculationExplanation,
    'disclaimer': disclaimer,
  };
}

class ScannerStatsItemModel {
  final int total;
  final int safe;
  final int threats;

  const ScannerStatsItemModel({
    required this.total,
    required this.safe,
    required this.threats,
  });

  factory ScannerStatsItemModel.fromJson(Map<String, dynamic> json) {
    return ScannerStatsItemModel(
      total: json['total'] as int? ?? 0,
      safe: json['safe'] as int? ?? 0,
      threats: json['threats'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'total': total,
    'safe': safe,
    'threats': threats,
  };
}

class ActivityTrendPointModel {
  final String date;
  final int total;
  final int safe;
  final int threats;

  const ActivityTrendPointModel({
    required this.date,
    required this.total,
    required this.safe,
    required this.threats,
  });

  factory ActivityTrendPointModel.fromJson(Map<String, dynamic> json) {
    return ActivityTrendPointModel(
      date: json['date']?.toString() ?? '',
      total: json['total'] as int? ?? 0,
      safe: json['safe'] as int? ?? 0,
      threats: json['threats'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'date': date,
    'total': total,
    'safe': safe,
    'threats': threats,
  };
}

class CommunityOverviewStatsModel {
  final int totalReports;
  final int distinctTargets;
  final int activeReporters;
  final int verifiedThreats;

  const CommunityOverviewStatsModel({
    required this.totalReports,
    required this.distinctTargets,
    required this.activeReporters,
    required this.verifiedThreats,
  });

  factory CommunityOverviewStatsModel.fromJson(Map<String, dynamic> json) {
    return CommunityOverviewStatsModel(
      totalReports: json['total_reports'] as int? ?? 0,
      distinctTargets: json['distinct_targets'] as int? ?? 0,
      activeReporters: json['active_reporters'] as int? ?? 0,
      verifiedThreats: json['verified_threats'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'total_reports': totalReports,
    'distinct_targets': distinctTargets,
    'active_reporters': activeReporters,
    'verified_threats': verifiedThreats,
  };
}

class RecentScanItemModel {
  final String id;
  final String scanId;
  final String scanType;
  final String target;
  final int riskScore;
  final String classification;
  final String timestamp;

  const RecentScanItemModel({
    required this.id,
    required this.scanId,
    required this.scanType,
    required this.target,
    required this.riskScore,
    required this.classification,
    required this.timestamp,
  });

  factory RecentScanItemModel.fromJson(Map<String, dynamic> json) {
    return RecentScanItemModel(
      id: json['id']?.toString() ?? '',
      scanId: json['scan_id']?.toString() ?? json['id']?.toString() ?? '',
      scanType: (json['scan_type']?.toString() ?? 'URL').toUpperCase(),
      target: json['target']?.toString() ?? '',
      riskScore: json['risk_score'] as int? ?? 0,
      classification: json['classification']?.toString() ?? 'Safe',
      timestamp: json['timestamp']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'scan_id': scanId,
    'scan_type': scanType,
    'target': target,
    'risk_score': riskScore,
    'classification': classification,
    'timestamp': timestamp,
  };
}

class DashboardAnalytics {
  final int timeRangeDays;
  final int totalScans;
  final int safeScans;
  final int suspiciousScans;
  final int highRiskScans;
  final int criticalScans;
  final double threatDetectionRate;
  final SecurityScoreModel securityScore;
  final Map<String, ScannerStatsItemModel> scannerBreakdown;
  final Map<String, int> riskDistribution;
  final List<ActivityTrendPointModel> activityTrends;
  final CommunityOverviewStatsModel communityStats;
  final List<RecentScanItemModel> recentScans;
  final String timestamp;

  const DashboardAnalytics({
    required this.timeRangeDays,
    required this.totalScans,
    required this.safeScans,
    required this.suspiciousScans,
    required this.highRiskScans,
    required this.criticalScans,
    required this.threatDetectionRate,
    required this.securityScore,
    required this.scannerBreakdown,
    required this.riskDistribution,
    required this.activityTrends,
    required this.communityStats,
    required this.recentScans,
    required this.timestamp,
  });

  factory DashboardAnalytics.fromJson(Map<String, dynamic> json) {
    // Scanner breakdown map parsing
    final rawBreakdown = json['scanner_breakdown'] as Map? ?? {};
    final breakdownMap = <String, ScannerStatsItemModel>{};
    rawBreakdown.forEach((k, v) {
      if (v is Map) {
        breakdownMap[k.toString().toUpperCase()] =
            ScannerStatsItemModel.fromJson(Map<String, dynamic>.from(v));
      }
    });

    // Risk distribution map parsing
    final rawDist = json['risk_distribution'] as Map? ?? {};
    final distMap = <String, int>{};
    rawDist.forEach((k, v) {
      distMap[k.toString()] = (v as num?)?.toInt() ?? 0;
    });

    // Trends list parsing
    final rawTrends = json['activity_trends'] as List? ?? [];
    final trendsList = rawTrends
        .whereType<Map<String, dynamic>>()
        .map((e) => ActivityTrendPointModel.fromJson(e))
        .toList();

    // Recent scans parsing
    final rawRecent = json['recent_scans'] as List? ?? [];
    final recentList = rawRecent
        .whereType<Map<String, dynamic>>()
        .map((e) => RecentScanItemModel.fromJson(e))
        .toList();

    return DashboardAnalytics(
      timeRangeDays: json['time_range_days'] as int? ?? 30,
      totalScans: json['total_scans'] as int? ?? 0,
      safeScans: json['safe_scans'] as int? ?? 0,
      suspiciousScans: json['suspicious_scans'] as int? ?? 0,
      highRiskScans: json['high_risk_scans'] as int? ?? 0,
      criticalScans: json['critical_scans'] as int? ?? 0,
      threatDetectionRate: (json['threat_detection_rate'] as num?)?.toDouble() ?? 0.0,
      securityScore: SecurityScoreModel.fromJson(
        Map<String, dynamic>.from(json['security_score'] as Map? ?? {}),
      ),
      scannerBreakdown: breakdownMap,
      riskDistribution: distMap,
      activityTrends: trendsList,
      communityStats: CommunityOverviewStatsModel.fromJson(
        Map<String, dynamic>.from(json['community_stats'] as Map? ?? {}),
      ),
      recentScans: recentList,
      timestamp: json['timestamp']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'time_range_days': timeRangeDays,
    'total_scans': totalScans,
    'safe_scans': safeScans,
    'suspicious_scans': suspiciousScans,
    'high_risk_scans': highRiskScans,
    'critical_scans': criticalScans,
    'threat_detection_rate': threatDetectionRate,
    'security_score': securityScore.toJson(),
    'scanner_breakdown': scannerBreakdown.map((k, v) => MapEntry(k, v.toJson())),
    'risk_distribution': riskDistribution,
    'activity_trends': activityTrends.map((t) => t.toJson()).toList(),
    'community_stats': communityStats.toJson(),
    'recent_scans': recentScans.map((r) => r.toJson()).toList(),
    'timestamp': timestamp,
  };
}

