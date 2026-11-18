// CyberShield Security Suite Dashboard & Analytics System

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/widgets/status_indicator.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/models/dashboard_analytics.dart';
import 'package:cybershield/core/services/alert_service.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';
import 'package:cybershield/core/models/security_event_model.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with WidgetsBindingObserver {
  // Backend health status
  String _serverStatus = 'checking';
  String _connectionStatusLabel = 'CHECKING';
  String _serverMessage = 'Connecting to backend...';
  int _latencyMs = 0;

  // Analytics & History state
  bool _isLoadingAnalytics = true;
  String? _analyticsErrorMessage;
  int _selectedDays = 30; // 7, 30, or 0 (All-time)
  DashboardAnalytics? _analytics;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refreshAll();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && mounted) {
      _checkServerHealth();
    }
  }

  Future<void> _refreshAll() async {
    // Verify and recover the active backend endpoint FIRST (Wi-Fi LAN <-> ADB reverse)
    // so all subsequent analytics/alert/history requests hit the live host.
    await _checkServerHealth();
    await Future.wait([
      _loadAnalyticsData(),
      AlertService.instance.refreshUnreadCount(),
      ProtectionService.instance.refreshStatus(),
      CommunicationService.instance.initialize(forceRefresh: true),
      SmartAlertEngine.instance.initialize(forceRefresh: true),
    ]);
  }

  Future<void> _checkServerHealth() async {
    setState(() {
      _serverStatus = 'checking';
      _connectionStatusLabel = 'CHECKING';
      _serverMessage = 'Querying /health endpoint...';
    });

    final stopwatch = Stopwatch()..start();
    final result = await ApiService.healthCheck();
    stopwatch.stop();

    if (mounted) {
      setState(() {
        _latencyMs = stopwatch.elapsedMilliseconds;
        _serverStatus = result['status'] ?? 'offline';
        _connectionStatusLabel = result['connection_status']?.toString() ??
            (_serverStatus == 'healthy'
                ? ApiService.statusOnline
                : ApiService.statusOffline);
        if (_serverStatus == 'healthy') {
          _serverMessage =
              '${result['service'] ?? 'FastAPI'} (v${result['version'] ?? '1.0.0'})';
        } else {
          _serverMessage = result['message'] ?? 'Service unavailable';
        }
      });
    }
  }

  Future<void> _loadAnalyticsData() async {
    setState(() {
      _isLoadingAnalytics = true;
      _analyticsErrorMessage = null;
    });

    try {
      // 1. If user is authenticated in Firebase, attempt user-isolated Cloud Firestore analytics first
      if (FirestoreHistoryService.instance.isAuthenticated) {
        final cloudAnalytics = await FirestoreHistoryService.instance
            .getCloudDashboardAnalytics(days: _selectedDays);

        if (cloudAnalytics != null) {
          // If Firestore returns analytics, also grab live community stats from backend if possible
          DashboardAnalytics finalData = cloudAnalytics;
          final backendAnalytics =
              await ApiService.getDashboardAnalytics(days: _selectedDays);
          if (backendAnalytics != null) {
            finalData = DashboardAnalytics(
              timeRangeDays: cloudAnalytics.timeRangeDays,
              totalScans: cloudAnalytics.totalScans,
              safeScans: cloudAnalytics.safeScans,
              suspiciousScans: cloudAnalytics.suspiciousScans,
              highRiskScans: cloudAnalytics.highRiskScans,
              criticalScans: cloudAnalytics.criticalScans,
              threatDetectionRate: cloudAnalytics.threatDetectionRate,
              securityScore: cloudAnalytics.securityScore,
              scannerBreakdown: cloudAnalytics.scannerBreakdown.isNotEmpty
                  ? cloudAnalytics.scannerBreakdown
                  : backendAnalytics.scannerBreakdown,
              riskDistribution: cloudAnalytics.riskDistribution,
              activityTrends: cloudAnalytics.activityTrends,
              communityStats: backendAnalytics.communityStats,
              recentScans: cloudAnalytics.recentScans.isNotEmpty
                  ? cloudAnalytics.recentScans
                  : backendAnalytics.recentScans,
              timestamp: cloudAnalytics.timestamp,
            );
          }

          if (mounted) {
            setState(() {
              _isLoadingAnalytics = false;
              _analytics = finalData;
            });
            return;
          }
        }
      }

      // 2. Fallback to FastAPI backend analytics (SQLite audit logs & community db)
      final backendData =
          await ApiService.getDashboardAnalytics(days: _selectedDays);

      if (mounted) {
        setState(() {
          _isLoadingAnalytics = false;
          if (backendData != null) {
            _analytics = backendData;
          } else {
            _analyticsErrorMessage =
                'Unable to retrieve analytics telemetry. Connect backend or scan items.';
          }
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoadingAnalytics = false;
          _analyticsErrorMessage = 'Error loading analytics: $e';
        });
      }
    }
  }

  void _onTimeRangeChanged(int days) {
    if (_selectedDays == days) return;
    setState(() {
      _selectedDays = days;
    });
    _loadAnalyticsData();
  }

  void _showCalculationFormulaDialog() {
    final score = _analytics?.securityScore;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.calculate_rounded,
                  color: AppColors.primary, size: 20),
            ),
            const SizedBox(width: 10),
            const Expanded(
              child: Text(
                'Security Score Formula',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                score?.calculationExplanation.isNotEmpty == true
                    ? score!.calculationExplanation
                    : 'The CyberShield Security Posture Score starts from a baseline of 100 with deductions: -20 per Critical threat, -10 per High Risk threat, and -4 per Suspicious item, alongside +2 bonus per verified safe item. If zero scans are recorded, a baseline exposure of 70 is assumed.',
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  height: 1.45,
                ),
              ),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.warning.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: AppColors.warning.withValues(alpha: 0.35),
                  ),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.info_outline_rounded,
                        color: AppColors.warning, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        score?.disclaimer.isNotEmpty == true
                            ? score!.disclaimer
                            : 'Advisory Notice: CyberShield Security Score reflects evaluated scan telemetry and cyber hygiene. No automated security system can guarantee 100% device immunity against emerging zero-day vulnerabilities.',
                        style: const TextStyle(
                          color: AppColors.warning,
                          fontSize: 11,
                          height: 1.35,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Understood',
                style: TextStyle(color: AppColors.primary)),
          ),
        ],
      ),
    );
  }

  BadgeType _getBadgeType(String? classification) {
    switch (classification?.toLowerCase()) {
      case 'safe':
        return BadgeType.safe;
      case 'suspicious':
        return BadgeType.warning;
      case 'high risk':
      case 'critical':
      case 'malicious':
      case 'danger':
        return BadgeType.danger;
      default:
        return BadgeType.info;
    }
  }

  Color _getRiskColor(int score) {
    if (score >= 70) return AppColors.danger;
    if (score >= 40) return AppColors.warning;
    return AppColors.safe;
  }

  IconData _getScanTypeIcon(String? type) {
    switch (type?.toUpperCase()) {
      case 'URL':
        return Icons.link_rounded;
      case 'SMS':
        return Icons.sms_rounded;
      case 'QR':
        return Icons.qr_code_2_rounded;
      case 'SCREENSHOT':
        return Icons.image_search_rounded;
      case 'APK':
        return Icons.android_rounded;
      case 'PERMISSIONS':
        return Icons.security_rounded;
      case 'EMAIL':
        return Icons.mark_email_read_rounded;
      case 'FILE':
        return Icons.folder_zip_rounded;
      default:
        return Icons.shield_rounded;
    }
  }

  Color _getScanTypeColor(String? type) {
    switch (type?.toUpperCase()) {
      case 'URL':
        return const Color(0xFF0A84FF);
      case 'SMS':
        return const Color(0xFF5E5CE6);
      case 'QR':
        return const Color(0xFF30D158);
      case 'SCREENSHOT':
        return const Color(0xFFFF9F0A);
      case 'APK':
        return const Color(0xFFFF453A);
      case 'PERMISSIONS':
        return const Color(0xFFFF2D55);
      case 'EMAIL':
        return const Color(0xFFBF5AF2);
      case 'FILE':
        return const Color(0xFF64D2FF);
      default:
        return AppColors.primary;
    }
  }

  String _formatTimestamp(String? isoString) {
    if (isoString == null || isoString.isEmpty) return 'Recent';
    try {
      final dt = DateTime.parse(isoString).toLocal();
      const months = [
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
      ];
      final month = months[dt.month - 1];
      final day = dt.day;
      final hour = dt.hour > 12 ? dt.hour - 12 : (dt.hour == 0 ? 12 : dt.hour);
      final minute = dt.minute.toString().padLeft(2, '0');
      final period = dt.hour >= 12 ? 'PM' : 'AM';
      return '$month $day • $hour:$minute $period';
    } catch (_) {
      return isoString;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: AppColors.primary.withValues(alpha: 0.35),
                  width: 1,
                ),
              ),
              child: const Icon(
                Icons.shield_rounded,
                color: AppColors.primary,
                size: 20,
              ),
            ),
            const SizedBox(width: 10),
            const Flexible(
              child: Text(
                'CyberShield',
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
        actions: [
          ValueListenableBuilder<int>(
            valueListenable: AlertService.instance.unreadCountNotifier,
            builder: (context, unread, _) {
              return Stack(
                alignment: Alignment.center,
                children: [
                  IconButton(
                    icon: Icon(
                      unread > 0
                          ? Icons.notifications_active_rounded
                          : Icons.notifications_none_rounded,
                      color: unread > 0 ? AppColors.danger : AppColors.textSecondary,
                    ),
                    onPressed: () => Navigator.pushNamed(context, AppRouter.alerts),
                    tooltip: 'Security Alerts & Notifications',
                  ),
                  if (unread > 0)
                    Positioned(
                      top: 8,
                      right: 8,
                      child: Container(
                        padding: const EdgeInsets.all(4),
                        decoration: const BoxDecoration(
                          color: AppColors.danger,
                          shape: BoxShape.circle,
                        ),
                        constraints: const BoxConstraints(
                          minWidth: 16,
                          minHeight: 16,
                        ),
                        child: Text(
                          unread > 99 ? '99+' : '$unread',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 9,
                            fontWeight: FontWeight.w900,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                ],
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.sync_rounded, color: AppColors.primary),
            onPressed: _refreshAll,
            tooltip: 'Sync Dashboard & Health',
          ),
          const SizedBox(width: 8),
        ],
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.dashboard),
      body: RefreshIndicator(
        onRefresh: _refreshAll,
        color: AppColors.primary,
        backgroundColor: AppColors.surface,
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildSecurityPostureBanner(),
              const SizedBox(height: 16),
              _buildRealtimeProtectionBanner(context),
              const SizedBox(height: 16),
              _buildCommunicationSecuritySection(context),
              const SizedBox(height: 16),
              _buildUnifiedEventsSection(context),
              const SizedBox(height: 16),
              _buildBackendLiveStatus(),
              const SizedBox(height: 18),
              _buildTimeRangeSelector(),
              const SizedBox(height: 16),
              _buildOverviewMetrics(),
              const SizedBox(height: 20),
              _buildRiskDistributionSection(),
              const SizedBox(height: 20),
              _buildActivityTrendsSection(),
              const SizedBox(height: 20),
              _buildScannerBreakdownSection(),
              const SizedBox(height: 20),
              _buildCommunityThreatCard(),
              const SizedBox(height: 20),
              _buildQuickActions(context),
              const SizedBox(height: 24),
              _buildSecurityModulesGrid(context),
              const SizedBox(height: 24),
              _buildRecentScanHistorySection(context),
              const SizedBox(height: 80),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildCommunicationSecuritySection(BuildContext context) {
    return ValueListenableBuilder<CommunicationAnalytics>(
      valueListenable: CommunicationService.instance.analyticsNotifier,
      builder: (context, analytics, _) {
        final overall = analytics.overall;
        final msgs = analytics.messages;
        final calls = analytics.calls;
        final rateLabel = overall.hasAnalyzedData
            ? '${overall.threatDetectionRate?.toStringAsFixed(1)}% THREAT RATE'
            : 'NOT YET ANALYZED';
        final rateBadgeType = !overall.hasAnalyzedData
            ? BadgeType.neutral
            : ((overall.threatDetectionRate ?? 0) >= 30
                ? BadgeType.danger
                : ((overall.threatDetectionRate ?? 0) > 0 ? BadgeType.warning : BadgeType.safe));

        return CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.35),
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(7),
                    decoration: BoxDecoration(
                      color: AppColors.primary.withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Icon(Icons.forum_rounded, color: AppColors.primary, size: 18),
                  ),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'Communication Security',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  CyberBadge(label: rateLabel, type: rateBadgeType),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    child: _commStatBox(
                      'Messages',
                      '${msgs.totalAnalyzed}/${msgs.totalReceived}',
                      'analyzed / recv',
                      AppColors.primary,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: _commStatBox(
                      'Calls',
                      '${calls.totalAnalyzed}/${calls.totalReceived}',
                      'analyzed / recv',
                      AppColors.secondary,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: _commStatBox(
                      'Unanalyzed',
                      '${overall.totalUnanalyzed}',
                      'pending/offline',
                      AppColors.warning,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 6,
                children: [
                  _commMiniPill('Safe: ${overall.safeCount}', AppColors.safe),
                  _commMiniPill('Suspicious: ${overall.suspiciousCount}', AppColors.warning),
                  _commMiniPill('High Risk: ${overall.highRiskCount}', const Color(0xFFFF6D00)),
                  _commMiniPill('Critical: ${overall.criticalCount}', AppColors.danger),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.primary,
                        side: const BorderSide(color: AppColors.cardBorder),
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.communications, arguments: 1),
                      child: const Text('Messages', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700)),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.secondary,
                        side: const BorderSide(color: AppColors.cardBorder),
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.communications, arguments: 2),
                      child: const Text('Calls', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700)),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.primary,
                        foregroundColor: Colors.black,
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.communications, arguments: 3),
                      child: const Text('Analytics', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800)),
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildUnifiedEventsSection(BuildContext context) {
    return ValueListenableBuilder<UnifiedSecurityAnalytics>(
      valueListenable: SmartAlertEngine.instance.analyticsNotifier,
      builder: (context, stats, _) {
        final badgeType = stats.totalThreatsDetected > 0
            ? (stats.criticalCount > 0 || stats.highRiskCount > 0
                ? BadgeType.danger
                : BadgeType.warning)
            : BadgeType.safe;

        return CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.35),
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(7),
                    decoration: BoxDecoration(
                      color: AppColors.primary.withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(Icons.hub_rounded, color: AppColors.primary, size: 18),
                  ),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'Unified Event Engine (18 Modules)',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(width: 6),
                  CyberBadge(
                    label: '${stats.activeModulesCount}/${stats.totalRegisteredModules} ACTIVE',
                    type: badgeType,
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    child: _commStatBox(
                      'Posture',
                      '${stats.deviceSecurityPostureScore}/100',
                      stats.postureLabel,
                      stats.deviceSecurityPostureScore >= 75 ? AppColors.safe : AppColors.warning,
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: _commStatBox(
                      'Threat Rate',
                      '${stats.threatDetectionRatePercent.toStringAsFixed(1)}%',
                      '${stats.totalThreatsDetected}/${stats.totalAnalyzedEvents} analyzed',
                      stats.totalThreatsDetected > 0 ? AppColors.danger : AppColors.primary,
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: _commStatBox(
                      'Unavail/Err',
                      '${stats.failedOrUnavailableEvents}',
                      'Never marked safe',
                      stats.failedOrUnavailableEvents > 0 ? AppColors.warning : AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.textPrimary,
                        side: const BorderSide(color: AppColors.cardBorder),
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.unifiedEvents, arguments: 0),
                      child: const Text('History', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700)),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.textPrimary,
                        side: const BorderSide(color: AppColors.cardBorder),
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.unifiedEvents, arguments: 1),
                      child: const Text('Analytics', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700)),
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.primary,
                        foregroundColor: Colors.black,
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                      onPressed: () => Navigator.pushNamed(context, AppRouter.unifiedEvents, arguments: 2),
                      child: const Text('Smart Alerts', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800)),
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _commStatBox(String title, String value, String sub, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      decoration: BoxDecoration(
        color: AppColors.surfaceSubtle,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: const TextStyle(color: AppColors.textMuted, fontSize: 10)),
          const SizedBox(height: 2),
          Text(value, style: TextStyle(color: color, fontSize: 14, fontWeight: FontWeight.w800)),
          Text(
            sub,
            style: const TextStyle(color: AppColors.textMuted, fontSize: 9),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _commMiniPill(String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        text,
        style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w700),
      ),
    );
  }

  Widget _buildRealtimeProtectionBanner(BuildContext context) {
    return ValueListenableBuilder<ProtectionStatus>(
      valueListenable: ProtectionService.instance.statusNotifier,
      builder: (context, status, _) {
        final isEnabled = status.isMasterEnabled;
        final notifGranted = status.isNotificationAccessGranted;

        return CyberCard(
          borderColor: isEnabled ? AppColors.primary.withValues(alpha: 0.4) : AppColors.cardBorder,
          child: InkWell(
            onTap: () => Navigator.pushNamed(context, AppRouter.protection),
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              child: Row(
                children: [
                  Container(
                    width: 42,
                    height: 42,
                    decoration: BoxDecoration(
                      color: (isEnabled ? AppColors.primary : AppColors.textMuted)
                          .withValues(alpha: 0.12),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isEnabled ? Icons.shield_rounded : Icons.shield_outlined,
                      color: isEnabled ? AppColors.primary : AppColors.textMuted,
                      size: 22,
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Flexible(
                              child: Text(
                                'Real-Time Defense',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 14,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            CyberBadge(
                              label: isEnabled
                                  ? (notifGranted ? 'ACTIVE' : 'ATTENTION')
                                  : 'DISABLED',
                              type: isEnabled
                                  ? (notifGranted ? BadgeType.safe : BadgeType.warning)
                                  : BadgeType.danger,
                            ),
                          ],
                        ),
                        const SizedBox(height: 3),
                        Text(
                          isEnabled
                              ? (notifGranted
                                  ? (status.isCallScreeningSupported && status.isCallScreeningRoleHeld
                                      ? 'Notification guard and automatic call screening armed'
                                      : (!status.isCallScreeningSupported
                                          ? 'Notification guard armed • Native call screening unsupported on this device'
                                          : 'Notification guard armed • Call screening role optional'))
                                  : 'Notification access setup recommended')
                              : 'Real-time defense monitoring is paused',
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Icon(
                    Icons.arrow_forward_ios_rounded,
                    color: AppColors.textSecondary,
                    size: 14,
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildSecurityPostureBanner() {
    final score = _analytics?.securityScore.score ?? 70;
    final status = _analytics?.securityScore.status ?? 'Baseline Exposure';
    final tier = _analytics?.securityScore.tier ?? 'Neutral';

    Color tierColor;
    if (score >= 85) {
      tierColor = AppColors.safe;
    } else if (score >= 65) {
      tierColor = AppColors.primary;
    } else if (score >= 40) {
      tierColor = AppColors.warning;
    } else {
      tierColor = AppColors.danger;
    }

    return CyberShieldCard(
      gradientColors: const [
        Color(0xFF131F3B),
        Color(0xFF0C1326),
      ],
      borderColor: tierColor.withValues(alpha: 0.35),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Radial / Circular score badge
              Container(
                width: 68,
                height: 68,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppColors.background,
                  border: Border.all(
                    color: tierColor.withValues(alpha: 0.5),
                    width: 3,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: tierColor.withValues(alpha: 0.25),
                      blurRadius: 10,
                      spreadRadius: 1,
                    ),
                  ],
                ),
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        _isLoadingAnalytics ? '-' : '$score',
                        style: TextStyle(
                          color: tierColor,
                          fontSize: 22,
                          fontWeight: FontWeight.w900,
                          height: 1.0,
                        ),
                      ),
                      const Text(
                        '/100',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 9,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            status,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 16,
                              fontWeight: FontWeight.w800,
                              letterSpacing: -0.3,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: tierColor.withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(
                              color: tierColor.withValues(alpha: 0.4),
                              width: 1,
                            ),
                          ),
                          child: Text(
                            tier.toUpperCase(),
                            style: TextStyle(
                              color: tierColor,
                              fontSize: 9,
                              fontWeight: FontWeight.w800,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Aggregated cyber hygiene and evaluated scan posture.',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                        height: 1.3,
                      ),
                    ),
                    const SizedBox(height: 6),
                    InkWell(
                      onTap: _showCalculationFormulaDialog,
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.help_outline_rounded,
                              size: 13,
                              color: AppColors.primary.withValues(alpha: 0.9)),
                          const SizedBox(width: 4),
                          const Flexible(
                            child: Text(
                              'Score Formula & Disclaimers',
                              style: TextStyle(
                                color: AppColors.primary,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                                decoration: TextDecoration.underline,
                              ),
                              overflow: TextOverflow.ellipsis,
                              maxLines: 1,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          const Divider(color: AppColors.cardBorder, height: 1),
          const SizedBox(height: 12),
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              StatusIndicator(
                label: _serverStatus == 'healthy'
                    ? 'Protection Engine Online'
                    : 'Protection Engine Offline',
                color: _serverStatus == 'healthy' ? AppColors.safe : AppColors.danger,
                isActive: _serverStatus == 'healthy',
              ),
              StatusIndicator(
                label: _serverStatus == 'healthy'
                    ? '18 Modules Connected'
                    : 'Backend Disconnected',
                color: _serverStatus == 'healthy' ? AppColors.primary : AppColors.warning,
                isActive: _serverStatus == 'healthy',
              ),
              StatusIndicator(
                label: FirestoreHistoryService.instance.isAuthenticated
                    ? 'Cloud Isolated History'
                    : 'Local SQLite History',
                color: FirestoreHistoryService.instance.isAuthenticated
                    ? AppColors.info
                    : AppColors.warning,
                isActive: true,
              ),
            ],
          ),
          ValueListenableBuilder<int>(
            valueListenable: AlertService.instance.unreadCountNotifier,
            builder: (context, unread, _) {
              if (unread == 0) return const SizedBox.shrink();
              return Padding(
                padding: const EdgeInsets.only(top: 14),
                child: InkWell(
                  onTap: () => Navigator.pushNamed(context, AppRouter.alerts),
                  borderRadius: BorderRadius.circular(10),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                    decoration: BoxDecoration(
                      color: AppColors.danger.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.warning_amber_rounded, color: AppColors.danger, size: 20),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            '$unread Active Security Alert${unread > 1 ? "s" : ""} Require Attention',
                            style: const TextStyle(
                              color: AppColors.danger,
                              fontSize: 12,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                        const Text(
                          'Resolve',
                          style: TextStyle(
                            color: AppColors.danger,
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                            decoration: TextDecoration.underline,
                          ),
                        ),
                        const SizedBox(width: 4),
                        const Icon(Icons.arrow_forward_ios_rounded, size: 10, color: AppColors.danger),
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  Future<void> _showQuickFixIpModal() async {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        bool isDetecting = false;
        String? detectStatus;

        return StatefulBuilder(
          builder: (modalCtx, setModalState) {
            return Container(
              decoration: const BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
                border: Border(
                  top: BorderSide(color: AppColors.cardBorder, width: 1.5),
                ),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 18),
              child: SafeArea(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Center(
                      child: Container(
                        width: 36,
                        height: 4,
                        decoration: BoxDecoration(
                          color: AppColors.cardBorder,
                          borderRadius: BorderRadius.circular(2),
                        ),
                      ),
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: AppColors.primary.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: const Icon(Icons.dns_rounded, color: AppColors.primary, size: 20),
                        ),
                        const SizedBox(width: 10),
                        const Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'FastAPI Server Connectivity',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 16,
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                              Text(
                                'Select connection method for physical device or emulator',
                                style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
                              ),
                            ],
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.close_rounded, color: AppColors.textMuted),
                          onPressed: () => Navigator.pop(modalCtx),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.surfaceSubtle,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: AppColors.cardBorder),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.link_rounded, size: 16, color: AppColors.textMuted),
                          const SizedBox(width: 8),
                          const Text('Active URL: ', style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                          Expanded(
                            child: Text(
                              ApiService.baseUrl,
                              style: const TextStyle(
                                color: AppColors.primary,
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                                fontFamily: 'monospace',
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    // Auto-Detect Button
                    SizedBox(
                      width: double.infinity,
                      height: 46,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.black,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        ),
                        onPressed: isDetecting
                            ? null
                            : () async {
                                setModalState(() {
                                  isDetecting = true;
                                  detectStatus = 'Probing candidate servers...';
                                });
                                final res = await ApiService.autoDiscoverAndConnect();
                                setModalState(() {
                                  isDetecting = false;
                                  detectStatus = res['message']?.toString();
                                });
                                if (res['success'] == true) {
                                  if (ctx.mounted) Navigator.pop(ctx);
                                  _refreshAll();
                                  if (mounted) {
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text(res['message']?.toString() ?? 'Connected!'),
                                        backgroundColor: AppColors.safe,
                                      ),
                                    );
                                  }
                                }
                              },
                        icon: isDetecting
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                              )
                            : const Icon(Icons.radar_rounded, size: 18),
                        label: Text(
                          isDetecting ? 'Probing Candidates...' : 'Auto-Detect & Connect Server',
                          style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 13),
                        ),
                      ),
                    ),
                    if (detectStatus != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        detectStatus!,
                        style: TextStyle(
                          color: detectStatus!.contains('Connected') ? AppColors.safe : AppColors.danger,
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                    const SizedBox(height: 16),
                    const Text(
                      'Quick Presets:',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 11, fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 8),
                    _buildPresetTile(
                      modalCtx,
                      title: 'ADB Reverse (USB Cable - Recommended)',
                      url: ApiService.presetAdbReverse,
                      desc: 'Instant connection via USB cable (127.0.0.1:8000)',
                      icon: Icons.usb_rounded,
                    ),
                    _buildPresetTile(
                      modalCtx,
                      title: 'Current Wi-Fi LAN',
                      url: ApiService.presetCurrentWifi,
                      desc: 'For physical phone on same Wi-Fi (${ApiService.presetCurrentWifi.replaceFirst('http://', '')})',
                      icon: Icons.wifi_rounded,
                    ),
                    _buildPresetTile(
                      modalCtx,
                      title: 'Android Studio Emulator',
                      url: ApiService.presetEmulator,
                      desc: 'Only for PC Android emulator (10.0.2.2:8000)',
                      icon: Icons.phone_android_rounded,
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: TextButton.icon(
                        onPressed: () {
                          Navigator.pop(ctx);
                          Navigator.pushNamed(context, AppRouter.settings);
                        },
                        icon: const Icon(Icons.settings_outlined, size: 16),
                        label: const Text('Open Full Settings / Diagnostics'),
                        style: TextButton.styleFrom(foregroundColor: AppColors.textSecondary),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildPresetTile(
    BuildContext modalCtx, {
    required String title,
    required String url,
    required String desc,
    required IconData icon,
  }) {
    final isCurrent = ApiService.baseUrl == url;
    return InkWell(
      onTap: () async {
        Navigator.pop(modalCtx);
        await ApiService.saveCustomBaseUrl(url);
        _refreshAll();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('API URL set to $url. Reconnecting...'),
              backgroundColor: AppColors.primary,
              duration: const Duration(seconds: 2),
            ),
          );
        }
      },
      borderRadius: BorderRadius.circular(10),
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: isCurrent ? AppColors.primary.withValues(alpha: 0.1) : AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: isCurrent ? AppColors.primary : AppColors.cardBorder,
          ),
        ),
        child: Row(
          children: [
            Icon(icon, size: 18, color: isCurrent ? AppColors.primary : AppColors.textSecondary),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        title,
                        style: TextStyle(
                          color: isCurrent ? AppColors.primary : AppColors.textPrimary,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      if (isCurrent) ...[
                        const SizedBox(width: 6),
                        const Icon(Icons.check_circle_rounded, size: 12, color: AppColors.primary),
                      ],
                    ],
                  ),
                  Text(
                    '$url — $desc',
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right_rounded, size: 16, color: AppColors.textMuted),
          ],
        ),
      ),
    );
  }

  Widget _buildBackendLiveStatus() {
    Color statusColor;
    IconData statusIcon;
    BadgeType badgeType;

    switch (_serverStatus) {
      case 'healthy':
        statusColor = AppColors.safe;
        statusIcon = Icons.check_circle_rounded;
        badgeType = BadgeType.safe;
        break;
      case 'checking':
        statusColor = AppColors.warning;
        statusIcon = Icons.hourglass_top_rounded;
        badgeType = BadgeType.warning;
        break;
      default:
        statusColor = AppColors.danger;
        statusIcon = Icons.cloud_off_rounded;
        badgeType = BadgeType.danger;
    }

    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(7),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(statusIcon, color: statusColor, size: 18),
              ),
              const SizedBox(width: 10),
              const Expanded(
                child: Text(
                  'FastAPI Security Engine',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w700,
                    fontSize: 13,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 120),
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  child: CyberBadge(
                    label: _serverStatus == 'healthy' ? 'ONLINE' : _connectionStatusLabel,
                    type: badgeType,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              IconButton(
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
                icon: const Icon(Icons.refresh_rounded, size: 18),
                color: AppColors.textMuted,
                onPressed: _checkServerHealth,
                tooltip: 'Ping backend',
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            _serverStatus == 'healthy'
                ? '$_serverMessage • ${_latencyMs}ms latency'
                : _serverMessage,
            style: TextStyle(
              color: _serverStatus == 'healthy'
                  ? AppColors.textSecondary
                  : AppColors.danger,
              fontSize: 11,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          if (_serverStatus != 'healthy') ...[
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              height: 34,
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  side: const BorderSide(color: AppColors.primary, width: 1),
                  foregroundColor: AppColors.primary,
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                onPressed: _showQuickFixIpModal,
                icon: const Icon(Icons.tune_rounded, size: 14),
                label: const Text(
                  'Auto-Detect Server / Fix IP',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildTimeRangeSelector() {
    return Wrap(
      alignment: WrapAlignment.spaceBetween,
      crossAxisAlignment: WrapCrossAlignment.center,
      spacing: 8,
      runSpacing: 8,
      children: [
        const Text(
          'Security Telemetry',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            _buildFilterChip('7 Days', 7),
            const SizedBox(width: 6),
            _buildFilterChip('30 Days', 30),
            const SizedBox(width: 6),
            _buildFilterChip('All Time', 0),
          ],
        ),
      ],
    );
  }

  Widget _buildFilterChip(String label, int days) {
    final isSelected = _selectedDays == days;
    return InkWell(
      onTap: () => _onTimeRangeChanged(days),
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: isSelected
              ? AppColors.primary.withValues(alpha: 0.2)
              : AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected
                ? AppColors.primary
                : AppColors.cardBorder,
            width: 1,
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected ? AppColors.primary : AppColors.textSecondary,
            fontSize: 11,
            fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  Widget _buildOverviewMetrics() {
    final total = _analytics?.totalScans ?? 0;
    final safe = _analytics?.safeScans ?? 0;
    final suspicious = _analytics?.suspiciousScans ?? 0;
    final threats = (_analytics?.highRiskScans ?? 0) + (_analytics?.criticalScans ?? 0);
    final threatRate = _analytics?.threatDetectionRate ?? 0.0;

    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _buildMetricTile(
                title: 'Total Scans',
                value: _isLoadingAnalytics ? '-' : '$total',
                icon: Icons.analytics_rounded,
                color: AppColors.primary,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildMetricTile(
                title: 'Safe Scans',
                value: _isLoadingAnalytics ? '-' : '$safe',
                icon: Icons.verified_user_rounded,
                color: AppColors.safe,
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: _buildMetricTile(
                title: 'Suspicious',
                value: _isLoadingAnalytics ? '-' : '$suspicious',
                icon: Icons.warning_amber_rounded,
                color: AppColors.warning,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildMetricTile(
                title: 'High/Critical',
                value: _isLoadingAnalytics ? '-' : '$threats',
                icon: Icons.gpp_bad_rounded,
                color: AppColors.danger,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildMetricTile(
                title: 'Threat Rate',
                value: _isLoadingAnalytics
                    ? '-'
                    : '${threatRate.toStringAsFixed(1)}%',
                icon: Icons.radar_rounded,
                color: threatRate > 20
                    ? AppColors.danger
                    : (threatRate > 5 ? AppColors.warning : AppColors.safe),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMetricTile({
    required String title,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
      borderColor: color.withValues(alpha: 0.25),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Icon(icon, color: color, size: 16),
              Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(
                  color: color,
                  shape: BoxShape.circle,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 17,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            title,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _buildRiskDistributionSection() {
    final dist = _analytics?.riskDistribution ?? {};
    final safe = dist['safe'] ?? 0;
    final suspicious = dist['suspicious'] ?? 0;
    final highRisk = dist['high_risk'] ?? 0;
    final critical = dist['critical'] ?? 0;
    final sum = safe + suspicious + highRisk + critical;

    final safePct = sum > 0 ? (safe / sum) : 1.0;
    final suspPct = sum > 0 ? (suspicious / sum) : 0.0;
    final highPct = sum > 0 ? (highRisk / sum) : 0.0;
    final critPct = sum > 0 ? (critical / sum) : 0.0;

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Expanded(
                child: Text(
                  'Risk Distribution',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  '$sum scans evaluated',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          // Multi-segment horizontal bar
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: SizedBox(
              height: 12,
              child: sum == 0
                  ? Container(color: AppColors.cardBorder)
                  : Row(
                      children: [
                        if (safePct > 0)
                          Expanded(
                            flex: (safePct * 1000).toInt(),
                            child: Container(color: AppColors.safe),
                          ),
                        if (suspPct > 0)
                          Expanded(
                            flex: (suspPct * 1000).toInt(),
                            child: Container(color: AppColors.warning),
                          ),
                        if (highPct > 0)
                          Expanded(
                            flex: (highPct * 1000).toInt(),
                            child: Container(color: const Color(0xFFFF6B22)),
                          ),
                        if (critPct > 0)
                          Expanded(
                            flex: (critPct * 1000).toInt(),
                            child: Container(color: AppColors.danger),
                          ),
                      ],
                    ),
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 14,
            runSpacing: 8,
            children: [
              _buildDistributionLegendItem('Safe', safe, AppColors.safe),
              _buildDistributionLegendItem('Suspicious', suspicious, AppColors.warning),
              _buildDistributionLegendItem('High Risk', highRisk, const Color(0xFFFF6B22)),
              _buildDistributionLegendItem('Critical', critical, AppColors.danger),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildDistributionLegendItem(String label, int count, Color color) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 5),
        Text(
          '$label: $count',
          style: const TextStyle(
            color: AppColors.textSecondary,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildActivityTrendsSection() {
    final trends = _analytics?.activityTrends ?? [];

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Expanded(
                child: Text(
                  'Scan Activity Trends',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Text(
                _selectedDays == 0 ? 'All-Time' : 'Last $_selectedDays Days',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (trends.isEmpty)
            const SizedBox(
              height: 100,
              child: Center(
                child: Text(
                  'No scan timestamps recorded in this window.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
              ),
            )
          else
            SizedBox(
              height: 132,
              child: LayoutBuilder(
                builder: (context, constraints) {
                  // Find max total for proportional bar heights
                  int maxVal = 1;
                  for (final t in trends) {
                    if (t.total > maxVal) maxVal = t.total;
                  }

                  // Display at most the last 8 trend points on narrow phones (< 380dp) or 10 on wider screens
                  final maxBars = constraints.maxWidth < 340 ? 7 : 10;
                  final displayTrends =
                      trends.length > maxBars ? trends.sublist(trends.length - maxBars) : trends;
                  final maxBarHeight = (constraints.maxHeight - 46).clamp(16.0, 96.0);

                  return Row(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: displayTrends.map((pt) {
                      final double heightRatio =
                          (pt.total / maxVal).clamp(0.08, 1.0);
                      final bool hasThreat = pt.threats > 0;
                      final barColor =
                          hasThreat ? AppColors.danger : AppColors.safe;

                      String label = pt.date;
                      if (label.length >= 10) {
                        label = label.substring(5); // 'MM-DD'
                      }

                      return Expanded(
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 2),
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.end,
                            children: [
                              FittedBox(
                                fit: BoxFit.scaleDown,
                                child: Text(
                                  '${pt.total}',
                                  style: TextStyle(
                                    color: pt.total > 0
                                        ? AppColors.textPrimary
                                        : AppColors.textMuted,
                                    fontSize: 9,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                              ),
                              const SizedBox(height: 4),
                              Container(
                                width: 14,
                                height: maxBarHeight * heightRatio,
                                decoration: BoxDecoration(
                                  color: pt.total == 0
                                      ? AppColors.cardBorder
                                      : barColor.withValues(alpha: 0.8),
                                  borderRadius: BorderRadius.circular(4),
                                  border: Border.all(
                                    color: pt.total == 0
                                        ? Colors.transparent
                                        : barColor,
                                    width: 1,
                                  ),
                                ),
                              ),
                              const SizedBox(height: 6),
                              FittedBox(
                                fit: BoxFit.scaleDown,
                                child: Text(
                                  label,
                                  maxLines: 1,
                                  style: const TextStyle(
                                    color: AppColors.textMuted,
                                    fontSize: 9,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      );
                    }).toList(),
                  );
                },
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildScannerBreakdownSection() {
    final breakdown = _analytics?.scannerBreakdown ?? {};

    final scannerKeys = [
      'URL',
      'SMS',
      'QR',
      'SCREENSHOT',
      'APK',
      'PERMISSIONS',
      'EMAIL',
      'FILE',
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Scanner Breakdown & Telemetry',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        const SizedBox(height: 10),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
            mainAxisExtent: 64,
          ),
          itemCount: scannerKeys.length,
          itemBuilder: (context, index) {
            final key = scannerKeys[index];
            final stats = breakdown[key] ??
                const ScannerStatsItemModel(total: 0, safe: 0, threats: 0);
            final color = _getScanTypeColor(key);

            return CyberShieldCard(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              borderColor: color.withValues(alpha: 0.25),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: color.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Icon(_getScanTypeIcon(key), color: color, size: 16),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          key,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        Text(
                          '${stats.total} scans • ${stats.threats} alerts',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: stats.threats > 0
                                ? AppColors.danger
                                : AppColors.textMuted,
                            fontSize: 9,
                            fontWeight: stats.threats > 0
                                ? FontWeight.w700
                                : FontWeight.normal,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildCommunityThreatCard() {
    final comm = _analytics?.communityStats ??
        const CommunityOverviewStatsModel(
          totalReports: 0,
          distinctTargets: 0,
          activeReporters: 0,
          verifiedThreats: 0,
        );

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      borderColor: const Color(0xFF32D74B).withValues(alpha: 0.35),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: const Color(0xFF32D74B).withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: const Icon(Icons.public_rounded,
                          color: Color(0xFF32D74B), size: 18),
                    ),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        'Crowd Threat Intel Network',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              TextButton(
                onPressed: () =>
                    Navigator.pushNamed(context, AppRouter.communityReports),
                style: TextButton.styleFrom(
                  padding: EdgeInsets.zero,
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: const Text('View All',
                    style: TextStyle(fontSize: 11, color: AppColors.primary)),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Flexible(child: _buildCommunityMetric('Reports', '${comm.totalReports}')),
              Flexible(child: _buildCommunityMetric('Targets', '${comm.distinctTargets}')),
              Flexible(child: _buildCommunityMetric('Reporters', '${comm.activeReporters}')),
              Flexible(child: _buildCommunityMetric('Verified', '${comm.verifiedThreats}')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCommunityMetric(String title, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          value,
          style: const TextStyle(
            color: Color(0xFF32D74B),
            fontSize: 16,
            fontWeight: FontWeight.w800,
          ),
        ),
        Text(
          title,
          style: const TextStyle(
            color: AppColors.textMuted,
            fontSize: 10,
          ),
        ),
      ],
    );
  }

  Widget _buildQuickActions(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Quick Security Check',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: _buildQuickActionButton(
                context,
                icon: Icons.link_rounded,
                label: 'Inspect URL',
                color: AppColors.primary,
                route: AppRouter.urlScanner,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildQuickActionButton(
                context,
                icon: Icons.sms_rounded,
                label: 'Inspect SMS',
                color: const Color(0xFF5E5CE6),
                route: AppRouter.smsScanner,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildQuickActionButton(
                context,
                icon: Icons.qr_code_scanner_rounded,
                label: 'Scan QR',
                color: const Color(0xFF30D158),
                route: AppRouter.qrScanner,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildQuickActionButton(
    BuildContext context, {
    required IconData icon,
    required String label,
    required Color color,
    required String route,
  }) {
    return CyberShieldCard(
      onTap: () => Navigator.pushNamed(context, route),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(7),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: color, size: 16),
          ),
          const SizedBox(height: 6),
          Text(
            label,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontWeight: FontWeight.w600,
              fontSize: 11,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityModulesGrid(BuildContext context) {
    final modules = [
      _ScannerCardItem(
        icon: Icons.shield_rounded,
        title: 'Real-Time Protection',
        badge: 'Android Sentry',
        description:
            'Permission-based notification listener, call screening, and installed apps inventory',
        accentColor: const Color(0xFF00E5FF),
        route: AppRouter.protection,
      ),
      _ScannerCardItem(
        icon: Icons.link_rounded,
        title: 'URL Scanner',
        badge: 'Web Links',
        description:
            'Inspect domains, IPv4 hosts, and phishing patterns with real-time risk scores',
        accentColor: const Color(0xFF0A84FF),
        route: AppRouter.urlScanner,
      ),
      _ScannerCardItem(
        icon: Icons.sms_rounded,
        title: 'SMS Scam Scanner',
        badge: 'Smishing',
        description:
            'Detect urgent psychological coercion, bank KYC alerts, and scam links',
        accentColor: const Color(0xFF5E5CE6),
        route: AppRouter.smsScanner,
      ),
      _ScannerCardItem(
        icon: Icons.qr_code_scanner_rounded,
        title: 'QR Code Scanner',
        badge: 'Barcode',
        description:
            'Scan camera barcodes, analyze UPI payment links and malicious redirects',
        accentColor: const Color(0xFF30D158),
        route: AppRouter.qrScanner,
      ),
      _ScannerCardItem(
        icon: Icons.screenshot_monitor_rounded,
        title: 'Screenshot Analyzer',
        badge: 'Visual OCR',
        description:
            'Extract text via OCR to uncover deceptive payment alerts and fake logins',
        accentColor: const Color(0xFFFF9F0A),
        route: AppRouter.screenshotAnalysis,
      ),
      _ScannerCardItem(
        icon: Icons.android_rounded,
        title: 'APK Analyzer',
        badge: 'Android Package',
        description:
            'Static bytecode & manifest audit of permissions and dangerous trojan combos',
        accentColor: const Color(0xFFFF453A),
        route: AppRouter.apkAnalysis,
      ),
      _ScannerCardItem(
        icon: Icons.security_rounded,
        title: 'Permission Analyzer',
        badge: 'Permissions & Combos',
        description:
            'Inspect installed app profiles or APK manifests for dangerous permission combinations',
        accentColor: const Color(0xFFFF2D55),
        route: AppRouter.permissionAnalyzer,
      ),
      _ScannerCardItem(
        icon: Icons.mark_email_read_rounded,
        title: 'Email Scanner',
        badge: 'Phishing & Links',
        description:
            'Detect sender spoofing, urgency traps, and embedded malicious links in emails',
        accentColor: const Color(0xFFBF5AF2),
        route: AppRouter.emailScanner,
      ),
      _ScannerCardItem(
        icon: Icons.folder_zip_rounded,
        title: 'File Scanner',
        badge: 'Static Inspection',
        description:
            'Inspect magic bytes, disguised binaries, stealth scripts, and archive safety',
        accentColor: const Color(0xFF64D2FF),
        route: AppRouter.fileScanner,
      ),
      _ScannerCardItem(
        icon: Icons.history_rounded,
        title: 'Audit History',
        badge: 'Persistent Trail',
        description:
            'Review persistent SQLite logs, filter by threat level and manage records',
        accentColor: AppColors.textSecondary,
        route: AppRouter.history,
      ),
      _ScannerCardItem(
        icon: Icons.public_rounded,
        title: 'Community Intel',
        badge: 'Crowd Defense',
        description:
            'Report scams, check target reputation, and view decentralized threat intelligence',
        accentColor: const Color(0xFF32D74B),
        route: AppRouter.communityReports,
      ),
      _ScannerCardItem(
        icon: Icons.notifications_active_rounded,
        title: 'Security Alerts',
        badge: 'Threat Center',
        description:
            'Review critical findings, smishing, and phishing alerts with guided remediation steps',
        accentColor: AppColors.danger,
        route: AppRouter.alerts,
      ),
      _ScannerCardItem(
        icon: Icons.auto_awesome_rounded,
        title: 'AI Security Assistant',
        badge: 'Advisory Defense',
        description:
            'Interactive conversational AI to explain scan telemetry, forensic risks, and defense steps',
        accentColor: const Color(0xFFFFD60A),
        route: AppRouter.aiAssistant,
      ),
      _ScannerCardItem(
        icon: Icons.health_and_safety_rounded,
        title: 'Safety Center & Hygiene',
        badge: 'Cyber Awareness',
        description:
            'Interactive cyber hygiene guides, phishing indicators, passkey tips, and incident response',
        accentColor: const Color(0xFF32D74B),
        route: AppRouter.safetyCenter,
      ),
      _ScannerCardItem(
        icon: Icons.settings_suggest_rounded,
        title: 'Settings & Profile',
        badge: 'Customization',
        description:
            'Select themes, cyber accent colors, alert preferences, and account security',
        accentColor: const Color(0xFF00B0FF),
        route: AppRouter.settings,
      ),
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Security Modules & Controls (${modules.length} Available)',
          style: const TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        const SizedBox(height: 10),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            crossAxisSpacing: 10,
            mainAxisSpacing: 10,
            mainAxisExtent: 162,
          ),
          itemCount: modules.length,
          itemBuilder: (context, index) {
            final item = modules[index];
            return CyberShieldCard(
              onTap: () => Navigator.pushNamed(context, item.route),
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: item.accentColor.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: item.accentColor.withValues(alpha: 0.3),
                            width: 1,
                          ),
                        ),
                        child:
                            Icon(item.icon, color: item.accentColor, size: 19),
                      ),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 3),
                          decoration: BoxDecoration(
                            color: AppColors.surfaceLight,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            item.badge,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 9.5,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text(
                    item.title,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 13,
                      height: 1.2,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Expanded(
                    child: Text(
                      item.description,
                      style: const TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 11,
                        height: 1.3,
                      ),
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildRecentScanHistorySection(BuildContext context) {
    final recentScans = _analytics?.recentScans ?? [];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Expanded(
              child: Text(
                'Recent Scan History',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  letterSpacing: -0.2,
                ),
              ),
            ),
            const SizedBox(width: 8),
            TextButton(
              onPressed: () => Navigator.pushNamed(context, AppRouter.history),
              style: TextButton.styleFrom(
                foregroundColor: AppColors.primary,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              ),
              child: Row(
                children: [
                  Text(
                    'View All (${_analytics?.totalScans ?? 0})',
                    style: const TextStyle(
                        fontSize: 12, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(width: 4),
                  const Icon(Icons.arrow_forward_ios_rounded, size: 10),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        if (_isLoadingAnalytics)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 20),
            child: Center(
              child: SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ),
          )
        else if (_analyticsErrorMessage != null)
          CyberShieldCard(
            borderColor: AppColors.danger.withValues(alpha: 0.3),
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                const Icon(Icons.cloud_off_rounded,
                    color: AppColors.danger, size: 20),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    _analyticsErrorMessage!,
                    style: const TextStyle(
                        color: AppColors.danger, fontSize: 12),
                  ),
                ),
                TextButton(
                  onPressed: _loadAnalyticsData,
                  child: const Text('Retry'),
                ),
              ],
            ),
          )
        else if (recentScans.isEmpty)
          CyberShieldCard(
            padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
            child: Center(
              child: Column(
                children: [
                  Icon(Icons.history_rounded,
                      color: AppColors.textMuted.withValues(alpha: 0.6),
                      size: 32),
                  const SizedBox(height: 8),
                  const Text(
                    'No Inspections Recorded Yet',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Run any scanner above to start auditing threats.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                  ),
                ],
              ),
            ),
          )
        else
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: recentScans.length,
            separatorBuilder: (context, index) => const SizedBox(height: 8),
            itemBuilder: (context, index) {
              final scan = recentScans[index];
              final scanType = scan.scanType.toUpperCase();
              final target = scan.target.isNotEmpty ? scan.target : 'Item';
              final classification = scan.classification;
              final riskScore = scan.riskScore;
              final timestamp = _formatTimestamp(scan.timestamp);
              final typeColor = _getScanTypeColor(scanType);
              final riskColor = _getRiskColor(riskScore);
              final badgeType = _getBadgeType(classification);

              return CyberShieldCard(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(7),
                      decoration: BoxDecoration(
                        color: typeColor.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(_getScanTypeIcon(scanType),
                          color: typeColor, size: 16),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            target,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 2),
                          Text(
                            '$scanType • $timestamp',
                            style: const TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 10,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 6),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        CyberBadge(
                          label: classification.toUpperCase(),
                          type: badgeType,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          'Risk: $riskScore',
                          style: TextStyle(
                            color: riskColor,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(width: 6),
                    // Quick "Explain with AI" button
                    IconButton(
                      icon: const Icon(Icons.auto_awesome_rounded,
                          size: 16, color: Color(0xFFFFD60A)),
                      tooltip: 'Ask AI to analyze this scan',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                      onPressed: () {
                        Navigator.pushNamed(
                          context,
                          AppRouter.aiAssistant,
                          arguments: {
                            'scan_id': scan.scanId,
                            'scan_type': scan.scanType,
                            'target': scan.target,
                            'risk_score': scan.riskScore,
                            'classification': scan.classification,
                            'timestamp': scan.timestamp,
                          },
                        );
                      },
                    ),
                  ],
                ),
              );
            },
          ),
      ],
    );
  }
}

class _ScannerCardItem {
  final IconData icon;
  final String title;
  final String badge;
  final String description;
  final Color accentColor;
  final String route;

  const _ScannerCardItem({
    required this.icon,
    required this.title,
    required this.badge,
    required this.description,
    required this.accentColor,
    required this.route,
  });
}
