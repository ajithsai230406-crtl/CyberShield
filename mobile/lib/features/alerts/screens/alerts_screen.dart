// CyberShield Security Alerts & In-App Notification Center

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/models/security_alert.dart';
import 'package:cybershield/core/services/alert_service.dart';

class AlertsScreen extends StatefulWidget {
  const AlertsScreen({super.key});

  @override
  State<AlertsScreen> createState() => _AlertsScreenState();
}

class _AlertsScreenState extends State<AlertsScreen> {
  bool _isLoading = true;
  String? _errorMessage;
  List<SecurityAlertModel> _allAlerts = [];
  String _selectedFilter = 'all'; // all, unread, critical, high, medium, resolved
  String _searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadAlerts();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadAlerts() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final alerts = await AlertService.instance.getAlerts();
      if (mounted) {
        setState(() {
          _isLoading = false;
          _allAlerts = alerts;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _errorMessage = 'Could not load security alerts: $e';
        });
      }
    }
  }

  List<SecurityAlertModel> get _filteredAlerts {
    return _allAlerts.where((alert) {
      // 1. Category / State filter
      if (_selectedFilter == 'unread' && (alert.isRead || alert.isResolved)) {
        return false;
      } else if (_selectedFilter == 'resolved' && !alert.isResolved) {
        return false;
      } else if (_selectedFilter == 'critical' && alert.severity != 'critical') {
        return false;
      } else if (_selectedFilter == 'high' && alert.severity != 'high') {
        return false;
      } else if (_selectedFilter == 'medium' && alert.severity != 'medium') {
        return false;
      }

      // 2. Text Search Query
      if (_searchQuery.isNotEmpty) {
        final q = _searchQuery.toLowerCase();
        final matchTitle = alert.title.toLowerCase().contains(q);
        final matchTarget = alert.target.toLowerCase().contains(q);
        final matchCategory = alert.category.toLowerCase().contains(q);
        final matchExpl = alert.explanation.toLowerCase().contains(q);
        if (!matchTitle && !matchTarget && !matchCategory && !matchExpl) {
          return false;
        }
      }

      return true;
    }).toList();
  }

  Future<void> _toggleReadState(SecurityAlertModel alert) async {
    final newRead = !alert.isRead;
    final success = await AlertService.instance.markAsRead(alert.id, newRead);
    if (success && mounted) {
      setState(() {
        final index = _allAlerts.indexWhere((a) => a.id == alert.id);
        if (index != -1) {
          _allAlerts[index] = _allAlerts[index].copyWith(
            isRead: newRead,
            status: newRead ? 'read' : 'unread',
          );
        }
      });
    }
  }

  Future<void> _toggleResolvedState(SecurityAlertModel alert) async {
    final newResolved = !alert.isResolved;
    final success = await AlertService.instance.markAsResolved(alert.id, newResolved);
    if (success && mounted) {
      setState(() {
        final index = _allAlerts.indexWhere((a) => a.id == alert.id);
        if (index != -1) {
          _allAlerts[index] = _allAlerts[index].copyWith(
            isResolved: newResolved,
            status: newResolved ? 'resolved' : (_allAlerts[index].isRead ? 'read' : 'unread'),
            resolvedAt: newResolved ? DateTime.now().toUtc().toIso8601String() : null,
          );
        }
      });
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(newResolved ? 'Threat marked as resolved.' : 'Alert reopened.'),
          backgroundColor: newResolved ? AppColors.safe : AppColors.surfaceLight,
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  Future<void> _markAllAsRead() async {
    await AlertService.instance.markAllAsRead();
    if (mounted) {
      setState(() {
        _allAlerts = _allAlerts.map((a) => a.copyWith(isRead: true, status: a.isResolved ? 'resolved' : 'read')).toList();
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('All alerts marked as read.'),
          backgroundColor: AppColors.safe,
          duration: Duration(seconds: 2),
        ),
      );
    }
  }

  void _showAlertDetailSheet(SecurityAlertModel alert) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: AppColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return DraggableScrollableSheet(
              initialChildSize: 0.75,
              minChildSize: 0.5,
              maxChildSize: 0.95,
              expand: false,
              builder: (context, scrollController) {
                return SingleChildScrollView(
                  controller: scrollController,
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Center(
                        child: Container(
                          width: 40,
                          height: 4,
                          decoration: BoxDecoration(
                            color: AppColors.cardBorder,
                            borderRadius: BorderRadius.circular(2),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: alert.severityColor.withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: alert.severityColor.withValues(alpha: 0.4),
                              ),
                            ),
                            child: Icon(alert.categoryIcon, color: alert.severityColor, size: 24),
                          ),
                          const SizedBox(width: 14),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  children: [
                                    CyberBadge(
                                      label: alert.severity.toUpperCase(),
                                      type: _getBadgeType(alert.severity),
                                    ),
                                    const SizedBox(width: 8),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: AppColors.surfaceLight,
                                        borderRadius: BorderRadius.circular(6),
                                      ),
                                      child: Text(
                                        alert.category,
                                        style: const TextStyle(
                                          color: AppColors.textMuted,
                                          fontSize: 10,
                                          fontWeight: FontWeight.w700,
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  alert.title,
                                  style: const TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 16,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      const Divider(color: AppColors.cardBorder),
                      const SizedBox(height: 12),
                      const Text(
                        'TARGET ARTIFACT',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: AppColors.background,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppColors.cardBorder),
                        ),
                        child: Text(
                          alert.target,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 12,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                      const SizedBox(height: 14),
                      const Text(
                        'FORENSIC EXPLANATION',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        alert.explanation,
                        style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 13,
                          height: 1.45,
                        ),
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'RECOMMENDED REMEDIATION ACTIONS',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                        ),
                      ),
                      const SizedBox(height: 8),
                      if (alert.recommendedActions.isEmpty)
                        const Text(
                          'No specific remediation steps provided.',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                        )
                      else
                        ...alert.recommendedActions.asMap().entries.map((entry) {
                          final idx = entry.key + 1;
                          final action = entry.value;
                          return Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Container(
                                  width: 20,
                                  height: 20,
                                  decoration: BoxDecoration(
                                    color: AppColors.primary.withValues(alpha: 0.15),
                                    shape: BoxShape.circle,
                                    border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
                                  ),
                                  child: Center(
                                    child: Text(
                                      '$idx',
                                      style: const TextStyle(
                                        color: AppColors.primary,
                                        fontSize: 10,
                                        fontWeight: FontWeight.w800,
                                      ),
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 10),
                                Expanded(
                                  child: Text(
                                    action,
                                    style: const TextStyle(
                                      color: AppColors.textPrimary,
                                      fontSize: 12,
                                      height: 1.35,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          );
                        }),
                      const SizedBox(height: 20),
                      Row(
                        children: [
                          Expanded(
                            child: OutlinedButton.icon(
                              onPressed: () {
                                _toggleReadState(alert);
                                Navigator.pop(ctx);
                              },
                              icon: Icon(
                                alert.isRead ? Icons.mark_email_unread_rounded : Icons.mark_email_read_rounded,
                                size: 16,
                              ),
                              label: Text(alert.isRead ? 'Mark Unread' : 'Mark Read'),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.textPrimary,
                                side: const BorderSide(color: AppColors.cardBorder),
                                padding: const EdgeInsets.symmetric(vertical: 12),
                              ),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () {
                                _toggleResolvedState(alert);
                                Navigator.pop(ctx);
                              },
                              icon: Icon(
                                alert.isResolved ? Icons.restart_alt_rounded : Icons.check_circle_rounded,
                                size: 16,
                              ),
                              label: Text(alert.isResolved ? 'Reopen Alert' : 'Mark Resolved'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: alert.isResolved ? AppColors.surfaceLight : AppColors.safe,
                                foregroundColor: alert.isResolved ? AppColors.textPrimary : Colors.white,
                                padding: const EdgeInsets.symmetric(vertical: 12),
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      SizedBox(
                        width: double.infinity,
                        child: OutlinedButton.icon(
                          onPressed: () {
                            Navigator.pop(ctx);
                            Navigator.pushNamed(
                              context,
                              AppRouter.aiAssistant,
                              arguments: {
                                'scan_id': alert.scanId,
                                'scan_type': alert.category,
                                'target': alert.target,
                                'risk_score': alert.riskScore,
                                'classification': alert.severity,
                                'title': alert.title,
                                'explanation': alert.explanation,
                              },
                            );
                          },
                          icon: const Icon(Icons.auto_awesome_rounded, color: Color(0xFFFFD60A), size: 16),
                          label: const Text(
                            'Ask AI Assistant to Analyze & Remediate',
                            style: TextStyle(color: Color(0xFFFFD60A)),
                          ),
                          style: OutlinedButton.styleFrom(
                            side: const BorderSide(color: Color(0xFFFFD60A)),
                            padding: const EdgeInsets.symmetric(vertical: 12),
                          ),
                        ),
                      ),
                    ],
                  ),
                );
              },
            );
          },
        );
      },
    );
  }

  BadgeType _getBadgeType(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical':
        return BadgeType.danger;
      case 'high':
        return BadgeType.danger;
      case 'medium':
        return BadgeType.warning;
      case 'low':
        return BadgeType.info;
      default:
        return BadgeType.info;
    }
  }

  String _formatTimestamp(String isoString) {
    if (isoString.isEmpty) return 'Recent';
    try {
      final dt = DateTime.parse(isoString).toLocal();
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
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
    final unreadCount = _allAlerts.where((a) => !a.isRead && !a.isResolved).length;
    final filtered = _filteredAlerts;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                color: AppColors.danger.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: AppColors.danger.withValues(alpha: 0.35),
                  width: 1,
                ),
              ),
              child: const Icon(
                Icons.notifications_active_rounded,
                color: AppColors.danger,
                size: 20,
              ),
            ),
            const SizedBox(width: 10),
            const Flexible(
              child: Text(
                'Security Alerts',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            if (unreadCount > 0) ...[
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.danger,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '$unreadCount',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 11,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
            ],
          ],
        ),
        actions: [
          if (unreadCount > 0)
            IconButton(
              icon: const Icon(Icons.done_all_rounded, color: AppColors.primary),
              tooltip: 'Mark All as Read',
              onPressed: _markAllAsRead,
            ),
          IconButton(
            icon: const Icon(Icons.sync_rounded, color: AppColors.primary),
            tooltip: 'Refresh Alerts',
            onPressed: _loadAlerts,
          ),
          const SizedBox(width: 6),
        ],
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.alerts),
      body: RefreshIndicator(
        onRefresh: _loadAlerts,
        color: AppColors.primary,
        backgroundColor: AppColors.surface,
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildAdvisoryNoticeBanner(),
              const SizedBox(height: 14),
              _buildSearchBar(),
              const SizedBox(height: 12),
              _buildFilterChips(),
              const SizedBox(height: 16),
              if (_isLoading)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 40),
                  child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
                )
              else if (_errorMessage != null)
                _buildErrorCard()
              else if (filtered.isEmpty)
                _buildEmptyState()
              else
                _buildAlertsList(filtered),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAdvisoryNoticeBanner() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.primary.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.primary.withValues(alpha: 0.25)),
      ),
      child: const Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.shield_outlined, color: AppColors.primary, size: 18),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'Security alerts are generated from active scan evaluations and verified community intelligence. Continuous background device monitoring is not active.',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 11,
                height: 1.35,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchBar() {
    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
      child: TextField(
        controller: _searchController,
        style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
        decoration: InputDecoration(
          hintText: 'Search alerts by keyword, domain, or threat...',
          hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
          border: InputBorder.none,
          icon: const Icon(Icons.search_rounded, color: AppColors.textMuted, size: 18),
          suffixIcon: _searchQuery.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.clear_rounded, size: 16, color: AppColors.textMuted),
                  onPressed: () {
                    _searchController.clear();
                    setState(() {
                      _searchQuery = '';
                    });
                  },
                )
              : null,
        ),
        onChanged: (val) {
          setState(() {
            _searchQuery = val.trim();
          });
        },
      ),
    );
  }

  Widget _buildFilterChips() {
    final filters = [
      {'key': 'all', 'label': 'All (${_allAlerts.length})'},
      {'key': 'unread', 'label': 'Unread'},
      {'key': 'critical', 'label': 'Critical'},
      {'key': 'high', 'label': 'High'},
      {'key': 'medium', 'label': 'Medium'},
      {'key': 'resolved', 'label': 'Resolved'},
    ];

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: filters.map((f) {
          final isSelected = _selectedFilter == f['key'];
          return Padding(
            padding: const EdgeInsets.only(right: 6),
            child: InkWell(
              onTap: () {
                setState(() {
                  _selectedFilter = f['key']!;
                });
              },
              borderRadius: BorderRadius.circular(8),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: isSelected ? AppColors.primary.withValues(alpha: 0.2) : AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: isSelected ? AppColors.primary : AppColors.cardBorder,
                  ),
                ),
                child: Text(
                  f['label']!,
                  style: TextStyle(
                    color: isSelected ? AppColors.primary : AppColors.textSecondary,
                    fontSize: 11,
                    fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                  ),
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildErrorCard() {
    return CyberShieldCard(
      borderColor: AppColors.danger.withValues(alpha: 0.3),
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          const Icon(Icons.cloud_off_rounded, color: AppColors.danger, size: 24),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _errorMessage!,
              style: const TextStyle(color: AppColors.danger, fontSize: 12),
            ),
          ),
          TextButton(
            onPressed: _loadAlerts,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(vertical: 40, horizontal: 20),
      child: Center(
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.safe.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.verified_user_rounded, color: AppColors.safe, size: 36),
            ),
            const SizedBox(height: 12),
            const Text(
              'No Security Alerts',
              style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 15,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              _selectedFilter != 'all'
                  ? 'No alerts match the current filter: "$_selectedFilter".'
                  : 'All evaluated scans and telemetry are clear of high-severity risks.',
              textAlign: TextAlign.center,
              style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAlertsList(List<SecurityAlertModel> alerts) {
    return ListView.separated(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: alerts.length,
      separatorBuilder: (context, index) => const SizedBox(height: 10),
      itemBuilder: (context, index) {
        final alert = alerts[index];
        final isUnread = !alert.isRead && !alert.isResolved;

        return CyberShieldCard(
          onTap: () => _showAlertDetailSheet(alert),
          borderRadius: 12,
          borderColor: isUnread
              ? alert.severityColor.withValues(alpha: 0.45)
              : AppColors.cardBorder,
          padding: const EdgeInsets.all(14),
          child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: alert.severityColor.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(alert.categoryIcon, color: alert.severityColor, size: 18),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              CyberBadge(
                                label: alert.severity.toUpperCase(),
                                type: _getBadgeType(alert.severity),
                              ),
                              const SizedBox(width: 6),
                              Text(
                                alert.category,
                                style: const TextStyle(
                                  color: AppColors.textMuted,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              const Spacer(),
                              if (isUnread)
                                Container(
                                  width: 8,
                                  height: 8,
                                  decoration: BoxDecoration(
                                    color: alert.severityColor,
                                    shape: BoxShape.circle,
                                  ),
                                ),
                              if (alert.isResolved)
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: AppColors.safe.withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(4),
                                  ),
                                  child: const Text(
                                    'RESOLVED',
                                    style: TextStyle(
                                      color: AppColors.safe,
                                      fontSize: 9,
                                      fontWeight: FontWeight.w800,
                                    ),
                                  ),
                                ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(
                            alert.title,
                            style: TextStyle(
                              color: isUnread ? AppColors.textPrimary : AppColors.textSecondary,
                              fontSize: 13,
                              fontWeight: isUnread ? FontWeight.w800 : FontWeight.w600,
                            ),
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  alert.target,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 8),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      _formatTimestamp(alert.timestamp),
                      style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                    ),
                    Row(
                      children: [
                        Text(
                          'Risk Score: ${alert.riskScore}',
                          style: TextStyle(
                            color: alert.severityColor,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(width: 6),
                        const Icon(Icons.arrow_forward_ios_rounded, size: 10, color: AppColors.textMuted),
                      ],
                    ),
                  ],
                ),
              ],
            ),
        );
      },
    );
  }
}
