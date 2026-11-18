// Security Alert Data Models for CyberShield

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class SecurityAlertModel {
  final String id;
  final String? userId;
  final String? scanId;
  final String? eventKey;
  final String title;
  final String severity; // critical, high, medium, low, info
  final String category; // URL, SMS, QR, APK, PERMISSIONS, EMAIL, FILE, COMMUNITY, SYSTEM
  final String target;
  final int riskScore;
  final String explanation;
  final List<String> recommendedActions;
  final String status; // unread, read, resolved
  final bool isRead;
  final bool isResolved;
  final String timestamp;
  final String? resolvedAt;
  final Map<String, dynamic> metadata;

  const SecurityAlertModel({
    required this.id,
    this.userId,
    this.scanId,
    this.eventKey,
    required this.title,
    required this.severity,
    required this.category,
    required this.target,
    required this.riskScore,
    required this.explanation,
    required this.recommendedActions,
    required this.status,
    required this.isRead,
    required this.isResolved,
    required this.timestamp,
    this.resolvedAt,
    this.metadata = const {},
  });

  factory SecurityAlertModel.fromJson(Map<String, dynamic> json) {
    // Parse recommended actions list
    List<String> actions = [];
    if (json['recommended_actions'] is List) {
      actions = (json['recommended_actions'] as List)
          .map((e) => e.toString())
          .toList();
    } else if (json['recommendedActions'] is List) {
      actions = (json['recommendedActions'] as List)
          .map((e) => e.toString())
          .toList();
    }

    // Parse metadata map
    Map<String, dynamic> meta = {};
    if (json['metadata'] is Map) {
      meta = Map<String, dynamic>.from(json['metadata'] as Map);
    }

    final bool readState = json['is_read'] == true ||
        json['isRead'] == true ||
        json['status'] == 'read' ||
        json['status'] == 'resolved';

    final bool resolvedState = json['is_resolved'] == true ||
        json['isResolved'] == true ||
        json['status'] == 'resolved';

    return SecurityAlertModel(
      id: json['id']?.toString() ?? json['alert_id']?.toString() ?? '',
      userId: json['user_id']?.toString() ?? json['userId']?.toString(),
      scanId: json['scan_id']?.toString() ?? json['scanId']?.toString(),
      eventKey: json['event_key']?.toString() ?? json['eventKey']?.toString(),
      title: json['title']?.toString() ?? 'Security Finding',
      severity: (json['severity']?.toString() ?? 'medium').toLowerCase(),
      category: (json['category']?.toString() ?? 'SYSTEM').toUpperCase(),
      target: json['target']?.toString() ?? '',
      riskScore: json['risk_score'] as int? ?? json['riskScore'] as int? ?? 0,
      explanation: json['explanation']?.toString() ?? '',
      recommendedActions: actions,
      status: json['status']?.toString() ?? (resolvedState ? 'resolved' : (readState ? 'read' : 'unread')),
      isRead: readState,
      isResolved: resolvedState,
      timestamp: json['timestamp']?.toString() ?? '',
      resolvedAt: json['resolved_at']?.toString() ?? json['resolvedAt']?.toString(),
      metadata: meta,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'user_id': userId,
    'scan_id': scanId,
    'event_key': eventKey,
    'title': title,
    'severity': severity,
    'category': category,
    'target': target,
    'risk_score': riskScore,
    'explanation': explanation,
    'recommended_actions': recommendedActions,
    'status': status,
    'is_read': isRead,
    'is_resolved': isResolved,
    'timestamp': timestamp,
    'resolved_at': resolvedAt,
    'metadata': metadata,
  };

  SecurityAlertModel copyWith({
    String? id,
    String? userId,
    String? scanId,
    String? eventKey,
    String? title,
    String? severity,
    String? category,
    String? target,
    int? riskScore,
    String? explanation,
    List<String>? recommendedActions,
    String? status,
    bool? isRead,
    bool? isResolved,
    String? timestamp,
    String? resolvedAt,
    Map<String, dynamic>? metadata,
  }) {
    return SecurityAlertModel(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      scanId: scanId ?? this.scanId,
      eventKey: eventKey ?? this.eventKey,
      title: title ?? this.title,
      severity: severity ?? this.severity,
      category: category ?? this.category,
      target: target ?? this.target,
      riskScore: riskScore ?? this.riskScore,
      explanation: explanation ?? this.explanation,
      recommendedActions: recommendedActions ?? this.recommendedActions,
      status: status ?? this.status,
      isRead: isRead ?? this.isRead,
      isResolved: isResolved ?? this.isResolved,
      timestamp: timestamp ?? this.timestamp,
      resolvedAt: resolvedAt ?? this.resolvedAt,
      metadata: metadata ?? this.metadata,
    );
  }

  Color get severityColor {
    switch (severity.toLowerCase()) {
      case 'critical':
        return AppColors.danger;
      case 'high':
        return const Color(0xFFFF6B22);
      case 'medium':
        return AppColors.warning;
      case 'low':
        return AppColors.info;
      default:
        return AppColors.textMuted;
    }
  }

  IconData get categoryIcon {
    switch (category.toUpperCase()) {
      case 'URL':
        return Icons.link_rounded;
      case 'SMS':
        return Icons.sms_rounded;
      case 'QR':
        return Icons.qr_code_2_rounded;
      case 'APK':
        return Icons.android_rounded;
      case 'PERMISSIONS':
        return Icons.security_rounded;
      case 'EMAIL':
        return Icons.mark_email_read_rounded;
      case 'FILE':
        return Icons.folder_zip_rounded;
      case 'COMMUNITY':
        return Icons.public_rounded;
      default:
        return Icons.shield_rounded;
    }
  }
}

class AlertStatsModel {
  final int total;
  final int unread;
  final int critical;
  final int high;
  final int medium;
  final int low;
  final int resolved;

  const AlertStatsModel({
    required this.total,
    required this.unread,
    required this.critical,
    required this.high,
    required this.medium,
    required this.low,
    required this.resolved,
  });

  factory AlertStatsModel.fromJson(Map<String, dynamic> json) {
    return AlertStatsModel(
      total: json['total'] as int? ?? 0,
      unread: json['unread'] as int? ?? 0,
      critical: json['critical'] as int? ?? 0,
      high: json['high'] as int? ?? 0,
      medium: json['medium'] as int? ?? 0,
      low: json['low'] as int? ?? 0,
      resolved: json['resolved'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'total': total,
    'unread': unread,
    'critical': critical,
    'high': high,
    'medium': medium,
    'low': low,
    'resolved': resolved,
  };
}

