// CyberShield Unified 18-Module Security Event Center, Analytics & Smart Notification Hub

import 'package:flutter/material.dart';
import 'package:cybershield/core/models/security_event_model.dart';
import 'package:cybershield/core/services/smart_alert_engine.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_empty_state.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';

class UnifiedSecurityHubScreen extends StatefulWidget {
  final int initialTab;

  const UnifiedSecurityHubScreen({super.key, this.initialTab = 0});

  @override
  State<UnifiedSecurityHubScreen> createState() => _UnifiedSecurityHubScreenState();
}

class _UnifiedSecurityHubScreenState extends State<UnifiedSecurityHubScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final SmartAlertEngine _engine = SmartAlertEngine.instance;
  final TextEditingController _searchController = TextEditingController();

  String _selectedPeriod = 'daily';
  String _selectedSource = 'all';
  String _selectedModule = 'all';
  String _selectedClassification = 'all';
  String _searchQuery = '';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(
      length: 3,
      vsync: this,
      initialIndex: widget.initialTab.clamp(0, 2),
    );
    _engine.initialize();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  Color _classificationColor(SecurityEventModel event) {
    if (event.isFailedOrUnavailable) return Colors.blueGrey.shade300;
    switch (event.classification) {
      case 'Critical':
        return AppColors.danger;
      case 'High Risk':
        return Colors.deepOrangeAccent;
      case 'Suspicious':
        return AppColors.warning;
      case 'Low Risk':
        return AppColors.primary;
      default:
        return AppColors.safe;
    }
  }

  List<SecurityEventModel> _applyFilters(List<SecurityEventModel> sourceList) {
    final q = _searchQuery.trim().toLowerCase();
    return sourceList.where((e) {
      if (_selectedSource != 'all') {
        if (_selectedSource == 'system') {
          if (e.source != 'system_event' && e.source != 'realtime_monitor') {
            return false;
          }
        } else if (e.source != _selectedSource) {
          return false;
        }
      }
      if (_selectedModule != 'all' && e.moduleName != _selectedModule) {
        return false;
      }
      if (_selectedClassification != 'all') {
        if (_selectedClassification == 'failed_unavail') {
          if (!e.isFailedOrUnavailable) return false;
        } else if (e.classification.toLowerCase() != _selectedClassification.toLowerCase()) {
          return false;
        }
      }
      if (q.isNotEmpty) {
        final haystack =
            '${e.moduleLabel} ${e.moduleName} ${e.targetIdentifier} ${e.eventCategory} ${e.explanation} ${e.classification}'
                .toLowerCase();
        if (!haystack.contains(q)) return false;
      }
      return true;
    }).toList();
  }

  Future<void> _refresh() async {
    await _engine.flushOfflineQueue();
    await _engine.refreshAll(period: _selectedPeriod);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        title: const Text(
          'Unified Event Center',
          style: TextStyle(fontWeight: FontWeight.w700, fontSize: 18),
        ),
        actions: [
          IconButton(
            tooltip: 'Refresh & Sync Queue',
            icon: Icon(Icons.sync_rounded, color: AppColors.primary),
            onPressed: _refresh,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppColors.primary,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textMuted,
          tabs: const [
            Tab(icon: Icon(Icons.timeline_rounded, size: 18), text: 'History'),
            Tab(icon: Icon(Icons.analytics_rounded, size: 18), text: 'Analytics'),
            Tab(icon: Icon(Icons.notifications_active_rounded, size: 18), text: 'Smart Alerts'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildHistoryTab(),
          _buildAnalyticsTab(),
          _buildSmartNotificationsTab(),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // TAB 1: UNIFIED SECURITY HISTORY (ALL 18 MODULES)
  // ---------------------------------------------------------------------------

  Widget _buildHistoryTab() {
    return RefreshIndicator(
      onRefresh: _refresh,
      color: AppColors.primary,
      child: ValueListenableBuilder<bool>(
        valueListenable: _engine.isLoadingNotifier,
        builder: (context, isLoading, _) {
          return ValueListenableBuilder<List<SecurityEventModel>>(
            valueListenable: _engine.eventsNotifier,
            builder: (context, allEvents, _) {
              final filtered = _applyFilters(allEvents);
              return ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _buildFilterPanel(),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Text(
                          'Showing ${filtered.length} of ${allEvents.length} security event(s)',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                        ),
                      ),
                      const SizedBox(width: 8),
                      ValueListenableBuilder<int>(
                        valueListenable: _engine.offlineQueueCountNotifier,
                        builder: (context, qCount, _) {
                          if (qCount <= 0) return const SizedBox.shrink();
                          return Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: AppColors.warning.withValues(alpha: 0.16),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: AppColors.warning.withValues(alpha: 0.5)),
                            ),
                            child: Text(
                              '$qCount queued offline',
                              style: const TextStyle(
                                color: AppColors.warning,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  if (isLoading && allEvents.isEmpty)
                    const CyberLoadingState(
                      title: 'Loading Unified Security Events',
                      subtitle: 'Aggregating telemetry across all 18 CyberShield modules...',
                    )
                  else if (filtered.isEmpty)
                    CyberEmptyState(
                      icon: Icons.verified_user_outlined,
                      title: 'No Matching Security Events',
                      description: allEvents.isEmpty
                          ? 'Run any scanner, communication check, or protection audit to see real unified events here.'
                          : 'Try clearing one of your active module, source, or classification filters.',
                    )
                  else
                    ...filtered.map(_buildEventCard),
                ],
              );
            },
          );
        },
      ),
    );
  }

  Widget _buildFilterPanel() {
    return CyberShieldCard(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: _searchController,
            onChanged: (v) => setState(() => _searchQuery = v),
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Search target, module, category, or explanation...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
              prefixIcon: Icon(Icons.search_rounded, color: AppColors.primary, size: 18),
              suffixIcon: _searchQuery.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded, color: AppColors.textMuted, size: 18),
                      onPressed: () {
                        _searchController.clear();
                        setState(() => _searchQuery = '');
                      },
                    )
                  : null,
              filled: true,
              fillColor: AppColors.background,
              contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
          ),
          const SizedBox(height: 10),
          // Source scope selector
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                _buildFilterChip('All Sources', _selectedSource == 'all', () => setState(() => _selectedSource = 'all')),
                _buildFilterChip('Manual Scans', _selectedSource == 'manual_scan', () => setState(() => _selectedSource = 'manual_scan')),
                _buildFilterChip('Communications', _selectedSource == 'communication', () => setState(() => _selectedSource = 'communication')),
                _buildFilterChip('Device Audits', _selectedSource == 'device_audit', () => setState(() => _selectedSource = 'device_audit')),
                _buildFilterChip('System', _selectedSource == 'system', () => setState(() => _selectedSource = 'system')),
              ],
            ),
          ),
          const SizedBox(height: 8),
          // Module dropdown (all 18 modules)
          DropdownButtonFormField<String>(
            initialValue: _selectedModule,
            isExpanded: true,
            dropdownColor: AppColors.surface,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              labelText: 'Module Filter (18 Integrated Modules)',
              labelStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              filled: true,
              fillColor: AppColors.background,
              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
            items: [
              const DropdownMenuItem(value: 'all', child: Text('All 18 Modules')),
              ...kAll18Modules.map(
                (m) => DropdownMenuItem(value: m.key, child: Text(m.label)),
              ),
            ],
            onChanged: (v) => setState(() => _selectedModule = v ?? 'all'),
          ),
          const SizedBox(height: 8),
          // Classification filter chips
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                _buildFilterChip('All Status', _selectedClassification == 'all', () => setState(() => _selectedClassification = 'all')),
                _buildFilterChip('Critical', _selectedClassification == 'Critical', () => setState(() => _selectedClassification = 'Critical')),
                _buildFilterChip('High Risk', _selectedClassification == 'High Risk', () => setState(() => _selectedClassification = 'High Risk')),
                _buildFilterChip('Suspicious', _selectedClassification == 'Suspicious', () => setState(() => _selectedClassification = 'Suspicious')),
                _buildFilterChip('Safe', _selectedClassification == 'Safe', () => setState(() => _selectedClassification = 'Safe')),
                _buildFilterChip('Failed / Unavail', _selectedClassification == 'failed_unavail', () => setState(() => _selectedClassification = 'failed_unavail')),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChip(String label, bool selected, VoidCallback onTap) {
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: ChoiceChip(
        label: Text(
          label,
          style: TextStyle(
            color: selected ? Colors.black : AppColors.textSecondary,
            fontSize: 11.5,
            fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
          ),
        ),
        selected: selected,
        selectedColor: AppColors.primary,
        backgroundColor: AppColors.background,
        side: BorderSide(color: selected ? AppColors.primary : AppColors.cardBorder),
        onSelected: (_) => onTap(),
      ),
    );
  }

  Widget _buildEventCard(SecurityEventModel event) {
    final badgeColor = _classificationColor(event);
    final scoreLabel = event.isFailedOrUnavailable
        ? event.analysisStatus.toUpperCase()
        : '${event.riskScore ?? 0}%';
    final tsText =
        '${event.detectionTimestamp.year}-${event.detectionTimestamp.month.toString().padLeft(2, '0')}-${event.detectionTimestamp.day.toString().padLeft(2, '0')} '
        '${event.detectionTimestamp.hour.toString().padLeft(2, '0')}:${event.detectionTimestamp.minute.toString().padLeft(2, '0')}';

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: CyberShieldCard(
        padding: EdgeInsets.zero,
        onTap: () => _showEventDetailSheet(event),
        child: ListTile(
          contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          leading: CircleAvatar(
            backgroundColor: badgeColor.withValues(alpha: 0.16),
            child: Text(
              event.isFailedOrUnavailable ? '!' : '${event.riskScore ?? 0}',
              style: TextStyle(
                color: badgeColor,
                fontWeight: FontWeight.w800,
                fontSize: 12,
              ),
            ),
          ),
          title: Row(
            children: [
              Expanded(
                child: Text(
                  event.targetIdentifier,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: badgeColor.withValues(alpha: 0.16),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: badgeColor.withValues(alpha: 0.5)),
                ),
                child: Text(
                  '${event.classification} • $scoreLabel',
                  style: TextStyle(
                    color: badgeColor,
                    fontSize: 10.5,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          subtitle: Padding(
            padding: const EdgeInsets.only(top: 5),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '${event.moduleLabel} • ${event.sourceGroup} • $tsText',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: AppColors.primary, fontSize: 11.5, fontWeight: FontWeight.w500),
                ),
                if (event.explanation.isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(
                    event.explanation,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: AppColors.textSecondary, fontSize: 12),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showEventDetailSheet(SecurityEventModel event) {
    final color = _classificationColor(event);
    showModalBottomSheet(
      context: context,
      backgroundColor: AppColors.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.7,
        maxChildSize: 0.92,
        builder: (_, scrollController) => ListView(
          controller: scrollController,
          padding: const EdgeInsets.all(20),
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    event.moduleLabel,
                    style: TextStyle(
                      color: AppColors.primary,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: color),
                  ),
                  child: Text(
                    event.isFailedOrUnavailable
                        ? event.classification
                        : '${event.classification} (${event.riskScore ?? 0}%)',
                    style: TextStyle(color: color, fontWeight: FontWeight.w700, fontSize: 12),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              event.targetIdentifier,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 17,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 12),
            _detailRow('Event ID', event.eventId),
            _detailRow('Category', event.eventCategory),
            _detailRow('Source', '${event.sourceGroup} (${event.source})'),
            _detailRow('Analysis Status', event.analysisStatus.toUpperCase()),
            _detailRow('Severity', event.severity.toUpperCase()),
            _detailRow('Notification Status', event.notificationStatus),
            _detailRow('Detected At', event.detectionTimestamp.toIso8601String()),
            if (event.explanation.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text(
                'Explanation',
                style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              Text(event.explanation, style: const TextStyle(color: AppColors.textSecondary)),
            ],
            if (event.findings.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text(
                'Findings',
                style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              ...event.findings.map(
                (f) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text('• $f', style: const TextStyle(color: AppColors.textSecondary)),
                ),
              ),
            ],
            if (event.recommendedActions.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text(
                'Recommended Actions',
                style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              ...event.recommendedActions.map(
                (a) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text('→ $a', style: TextStyle(color: AppColors.primary)),
                ),
              ),
            ],
            const SizedBox(height: 18),
            OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                foregroundColor: AppColors.danger,
                side: const BorderSide(color: AppColors.danger),
              ),
              icon: const Icon(Icons.delete_outline_rounded),
              label: const Text('Delete This Security Event'),
              onPressed: () async {
                Navigator.of(ctx).pop();
                await _engine.deleteEvent(event.eventId);
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _detailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 135,
            child: Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 12)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 12, fontWeight: FontWeight.w500),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // TAB 2: UNIFIED ANALYTICS (STRICTLY SEPARATED POSTURE VS THREAT % VS FAILED)
  // ---------------------------------------------------------------------------

  Widget _buildAnalyticsTab() {
    return RefreshIndicator(
      onRefresh: _refresh,
      color: AppColors.primary,
      child: ValueListenableBuilder<UnifiedSecurityAnalytics>(
        valueListenable: _engine.analyticsNotifier,
        builder: (context, stats, _) {
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              // Period selector
              Row(
                children: [
                  _buildPeriodButton('Daily', 'daily'),
                  const SizedBox(width: 8),
                  _buildPeriodButton('Weekly', 'weekly'),
                  const SizedBox(width: 8),
                  _buildPeriodButton('Monthly', 'monthly'),
                ],
              ),
              const SizedBox(height: 14),
              // Strictly separated core KPI grid
              GridView.count(
                crossAxisCount: 2,
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                mainAxisSpacing: 10,
                crossAxisSpacing: 10,
                childAspectRatio: 1.48,
                children: [
                  _kpiCard(
                    title: 'Device Posture Score',
                    value: '${stats.deviceSecurityPostureScore}/100',
                    subtitle: '${stats.postureLabel} (distinct from threat %)',
                    color: stats.deviceSecurityPostureScore >= 75
                        ? AppColors.safe
                        : (stats.deviceSecurityPostureScore >= 45 ? AppColors.warning : AppColors.danger),
                    icon: Icons.shield_rounded,
                  ),
                  _kpiCard(
                    title: 'Threat Detection %',
                    value: '${stats.threatDetectionRatePercent.toStringAsFixed(1)}%',
                    subtitle: '${stats.totalThreatsDetected} of ${stats.totalAnalyzedEvents} analyzed',
                    color: stats.threatDetectionRatePercent > 25 ? AppColors.danger : AppColors.primary,
                    icon: Icons.radar_rounded,
                  ),
                  _kpiCard(
                    title: 'Failed / Unavailable',
                    value: '${stats.failedOrUnavailableEvents}',
                    subtitle: 'Coverage: ${stats.monitoringCoveragePercent.toStringAsFixed(1)}% (never safe)',
                    color: Colors.blueGrey.shade300,
                    icon: Icons.cloud_off_rounded,
                  ),
                  _kpiCard(
                    title: 'Active Modules',
                    value: '${stats.activeModulesCount} / ${stats.totalRegisteredModules}',
                    subtitle: '${stats.totalEvents} total events recorded',
                    color: AppColors.primary,
                    icon: Icons.hub_rounded,
                  ),
                ],
              ),
              const SizedBox(height: 14),
              // Severity breakdown card
              CyberShieldCard(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Analyzed Severity Breakdown',
                      style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: [
                        _miniCounter('Safe', stats.safeCount, AppColors.safe),
                        _miniCounter('Suspicious', stats.suspiciousCount, AppColors.warning),
                        _miniCounter('High Risk', stats.highRiskCount, Colors.deepOrangeAccent),
                        _miniCounter('Critical', stats.criticalCount, AppColors.danger),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              // All 18 modules distribution
              CyberShieldCard(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'All 18 Integrated Modules Breakdown',
                      style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Real stored telemetry per module. Zero fabricated metrics.',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 11.5),
                    ),
                    const SizedBox(height: 12),
                    ...stats.moduleDistribution.map(_buildModuleDistributionRow),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _buildPeriodButton(String label, String period) {
    final active = _selectedPeriod == period;
    return Expanded(
      child: OutlinedButton(
        style: OutlinedButton.styleFrom(
          backgroundColor: active ? AppColors.primary.withValues(alpha: 0.16) : AppColors.surface,
          foregroundColor: active ? AppColors.primary : AppColors.textSecondary,
          side: BorderSide(color: active ? AppColors.primary : AppColors.cardBorder),
        ),
        onPressed: () {
          setState(() => _selectedPeriod = period);
          _engine.refreshAll(period: period);
        },
        child: Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
      ),
    );
  }

  Widget _kpiCard({
    required String title,
    required String value,
    required String subtitle,
    required Color color,
    required IconData icon,
  }) {
    return CyberShieldCard(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 16),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11.5, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          Text(
            value,
            style: TextStyle(color: color, fontSize: 22, fontWeight: FontWeight.w800),
          ),
          Text(
            subtitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(color: AppColors.textSecondary, fontSize: 10.5),
          ),
        ],
      ),
    );
  }

  Widget _miniCounter(String label, int count, Color color) {
    return Column(
      children: [
        Text(
          '$count',
          style: TextStyle(color: color, fontSize: 18, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 2),
        Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
      ],
    );
  }

  Widget _buildModuleDistributionRow(ModuleDistributionItem item) {
    final rateFraction = (item.threatRatePercent / 100.0).clamp(0.0, 1.0);
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  item.moduleLabel,
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 12.5, fontWeight: FontWeight.w600),
                ),
              ),
              Text(
                '${item.totalEvents} evt • ${item.threatCount} threat${item.failedOrUnavailable > 0 ? ' • ${item.failedOrUnavailable} err' : ''}',
                style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
              ),
            ],
          ),
          const SizedBox(height: 4),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: item.totalEvents == 0 ? 0.0 : rateFraction,
              minHeight: 5,
              backgroundColor: AppColors.background,
              valueColor: AlwaysStoppedAnimation<Color>(
                item.threatCount > 0 ? AppColors.danger : AppColors.safe,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // TAB 3: SMART NOTIFICATION RULES, DAILY REPORT, QUEUE & RETENTION
  // ---------------------------------------------------------------------------

  Widget _buildSmartNotificationsTab() {
    return ValueListenableBuilder<SmartNotificationPrefs>(
      valueListenable: _engine.prefsNotifier,
      builder: (context, prefs, _) {
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            CyberShieldCard(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Active Smart Alert Delivery Policy',
                    style: TextStyle(color: AppColors.primary, fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    '• Critical & High Risk: Delivered immediately with originating module tag.\n'
                    '• Suspicious (41-60%): Delivered per preference below.\n'
                    '• Safe / Low Risk: Stored silently with optional summary.\n'
                    '• Lock-Screen Privacy: Sensitive message text, OTPs & credentials are always hidden on lock screens.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.45),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            CyberShieldCard(
              padding: EdgeInsets.zero,
              child: Column(
                children: [
                  SwitchListTile(
                    title: const Text('Suspicious Threat Alerts', style: TextStyle(color: AppColors.textPrimary, fontSize: 14)),
                    subtitle: const Text('Notify when any of the 18 modules flags a 41-60% suspicious event', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
                    activeThumbColor: AppColors.primary,
                    value: prefs.notifySuspicious,
                    onChanged: (v) => _engine.updatePreferences(prefs.copyWith(notifySuspicious: v)),
                  ),
                  const Divider(height: 1, color: AppColors.cardBorder),
                  SwitchListTile(
                    title: const Text('Safe Event Summary Notifications', style: TextStyle(color: AppColors.textPrimary, fontSize: 14)),
                    subtitle: const Text('Optional notification for safe scans (off by default to prevent noise)', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
                    activeThumbColor: AppColors.primary,
                    value: prefs.notifySafeSummary,
                    onChanged: (v) => _engine.updatePreferences(prefs.copyWith(notifySafeSummary: v)),
                  ),
                  const Divider(height: 1, color: AppColors.cardBorder),
                  SwitchListTile(
                    title: const Text('System & Protection Status Alerts', style: TextStyle(color: AppColors.textPrimary, fontSize: 14)),
                    subtitle: const Text('Notify on Permission Revoked, Service Interruption & Protection Activated', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
                    activeThumbColor: AppColors.primary,
                    value: prefs.notifySystemEvents,
                    onChanged: (v) => _engine.updatePreferences(prefs.copyWith(notifySystemEvents: v)),
                  ),
                  const Divider(height: 1, color: AppColors.cardBorder),
                  SwitchListTile(
                    title: const Text('Daily Security Report Digest', style: TextStyle(color: AppColors.textPrimary, fontSize: 14)),
                    subtitle: const Text('Real-data summary of analyzed events, threats & posture score', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
                    activeThumbColor: AppColors.primary,
                    value: prefs.dailyReportEnabled,
                    onChanged: (v) => _engine.updatePreferences(prefs.copyWith(dailyReportEnabled: v)),
                  ),
                  const Divider(height: 1, color: AppColors.cardBorder),
                  SwitchListTile(
                    title: const Text('Hide Sensitive Content on Lock Screen', style: TextStyle(color: AppColors.textPrimary, fontSize: 14)),
                    subtitle: const Text('Uses Android VISIBILITY_PRIVATE so only module title shows when locked', style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
                    activeThumbColor: AppColors.primary,
                    value: prefs.hideSensitiveOnLockScreen,
                    onChanged: (v) => _engine.updatePreferences(prefs.copyWith(hideSensitiveOnLockScreen: v)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
            ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.black,
                padding: const EdgeInsets.symmetric(vertical: 13),
              ),
              icon: const Icon(Icons.summarize_rounded),
              label: const Text('Generate Daily Security Report Now', style: TextStyle(fontWeight: FontWeight.w700)),
              onPressed: () async {
                final messenger = ScaffoldMessenger.of(context);
                final report = await _engine.generateDailySecurityReport();
                if (!mounted) return;
                messenger.showSnackBar(
                  SnackBar(
                    content: Text(
                      report != null
                          ? 'Daily Security Report generated and recorded.'
                          : 'Daily report already generated for this interval.',
                    ),
                  ),
                );
              },
            ),
            const SizedBox(height: 10),
            ValueListenableBuilder<int>(
              valueListenable: _engine.offlineQueueCountNotifier,
              builder: (context, qCount, _) {
                return OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.primary,
                    side: BorderSide(color: AppColors.primary),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                  icon: const Icon(Icons.cloud_upload_rounded),
                  label: Text('Retry Offline Sync Queue ($qCount pending)'),
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    final synced = await _engine.flushOfflineQueue();
                    if (!mounted) return;
                    messenger.showSnackBar(
                      SnackBar(content: Text('Synced $synced queued security event(s) to backend.')),
                    );
                  },
                );
              },
            ),
            const SizedBox(height: 14),
            CyberShieldCard(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Event Data Retention & Privacy Controls',
                    style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [30, 90, 365].map((days) {
                      final active = prefs.retentionDays == days;
                      return Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: ChoiceChip(
                          label: Text('$days Days'),
                          selected: active,
                          selectedColor: AppColors.primary,
                          labelStyle: TextStyle(color: active ? Colors.black : AppColors.textSecondary),
                          onSelected: (_) => _engine.updatePreferences(prefs.copyWith(retentionDays: days)),
                        ),
                      );
                    }).toList(),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: () async {
                            final messenger = ScaffoldMessenger.of(context);
                            final count = await _engine.purgeEvents(olderThanDays: prefs.retentionDays);
                            if (!mounted) return;
                            messenger.showSnackBar(
                              SnackBar(content: Text('Cleaned $count event(s) older than ${prefs.retentionDays} days.')),
                            );
                          },
                          child: const Text('Apply Retention'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: OutlinedButton(
                          style: OutlinedButton.styleFrom(
                            foregroundColor: AppColors.danger,
                            side: const BorderSide(color: AppColors.danger),
                          ),
                          onPressed: () async {
                            final messenger = ScaffoldMessenger.of(context);
                            final count = await _engine.purgeEvents();
                            if (!mounted) return;
                            messenger.showSnackBar(
                              SnackBar(content: Text('Cleared $count security event(s).')),
                            );
                          },
                          child: const Text('Clear All Events'),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }
}
