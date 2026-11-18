// CyberShield Communication Security Hub
// Unified Communication Security Dashboard, Message History, Call History,
// Threat Percentage Analytics, and First-Activation Privacy Transparency Consent.

import 'package:flutter/material.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_empty_state.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/features/communications/screens/communication_detail_screen.dart';
import 'package:cybershield/features/communications/screens/communication_settings_screen.dart';

class CommunicationHubScreen extends StatefulWidget {
  final int initialTab;

  const CommunicationHubScreen({super.key, this.initialTab = 0});

  @override
  State<CommunicationHubScreen> createState() => _CommunicationHubScreenState();
}

class _CommunicationHubScreenState extends State<CommunicationHubScreen>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  late TabController _tabController;
  final TextEditingController _msgSearchController = TextEditingController();
  final TextEditingController _callSearchController = TextEditingController();

  String _msgFilter = 'All'; // All, Safe, Low Risk, Suspicious, High Risk, Critical
  String _callFilter = 'All'; // All, Safe, Unknown, Suspicious, High Risk, Critical
  String _analyticsPeriod = 'daily'; // daily, weekly, monthly

  // Local consent selection before user clicks "Enable Selected Channels"
  bool _consentSms = true;
  bool _consentNotif = true;
  bool _consentCalls = true;
  bool _consentEmail = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _tabController = TabController(
      length: 4,
      vsync: this,
      initialIndex: widget.initialTab.clamp(0, 3),
    );
    CommunicationService.instance.initialize();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _tabController.dispose();
    _msgSearchController.dispose();
    _callSearchController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      CommunicationService.instance.refreshPermissions();
      CommunicationService.instance.refreshAll(period: _analyticsPeriod);
    }
  }

  Future<void> _triggerSync() async {
    final res = await CommunicationService.instance.syncDeviceCommunications();
    if (!mounted) return;
    final count = res['synced'] ?? 0;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          count > 0
              ? 'Synced & analyzed $count new communication record(s).'
              : 'Communication history is up to date.',
        ),
        backgroundColor: AppColors.primary,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  Future<void> _acceptConsentAndActivate() async {
    final service = CommunicationService.instance;
    final current = service.settingsNotifier.value;
    await service.updateSettings(
      current.copyWith(
        consentAcknowledged: true,
        monitoringPaused: false,
        monitorSms: _consentSms,
        monitorNotifications: _consentNotif,
        monitorWhatsapp: _consentNotif,
        monitorCalls: _consentCalls,
        monitorEmail: _consentEmail,
      ),
    );

    if (_consentSms) {
      await service.requestNativePermission('sms');
    }
    if (_consentCalls) {
      await service.requestNativePermission('call_log');
    }
    await service.syncDeviceCommunications();
  }

  Color _colorForRisk(CommunicationRecord r) {
    if (!r.isAnalyzed) return AppColors.textMuted;
    if (r.riskScore >= 81) return AppColors.danger;
    if (r.riskScore >= 61) return const Color(0xFFFF6D00);
    if (r.riskScore >= 41) return AppColors.warning;
    if (r.riskScore >= 21) return AppColors.info;
    return AppColors.safe;
  }

  BadgeType _badgeForRisk(CommunicationRecord r) {
    if (!r.isAnalyzed) return BadgeType.neutral;
    if (r.riskScore >= 61) return BadgeType.danger;
    if (r.riskScore >= 41) return BadgeType.warning;
    if (r.riskScore >= 21) return BadgeType.info;
    return BadgeType.safe;
  }

  String _formatDateShort(DateTime dt) {
    final m = dt.month.toString().padLeft(2, '0');
    final d = dt.day.toString().padLeft(2, '0');
    final h = dt.hour.toString().padLeft(2, '0');
    final mi = dt.minute.toString().padLeft(2, '0');
    return '${dt.year}-$m-$d $h:$mi';
  }

  @override
  Widget build(BuildContext context) {
    final service = CommunicationService.instance;

    return Scaffold(
      drawer: const NavDrawer(currentRoute: AppRouter.communications),
      appBar: AppBar(
        title: const Text('Communication Security'),
        actions: [
          ValueListenableBuilder<bool>(
            valueListenable: service.isSyncingNotifier,
            builder: (context, syncing, _) {
              return IconButton(
                icon: syncing
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                      )
                    : const Icon(Icons.sync_rounded, color: AppColors.primary),
                tooltip: 'Sync & analyze device communications',
                onPressed: syncing ? null : _triggerSync,
              );
            },
          ),
          IconButton(
            icon: const Icon(Icons.tune_rounded),
            tooltip: 'Monitoring & Privacy Settings',
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const CommunicationSettingsScreen()),
              ).then((_) => service.refreshAll(period: _analyticsPeriod));
            },
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          isScrollable: true,
          tabAlignment: TabAlignment.start,
          indicatorColor: AppColors.primary,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textSecondary,
          tabs: const [
            Tab(icon: Icon(Icons.dashboard_outlined, size: 16), text: 'Overview'),
            Tab(icon: Icon(Icons.sms_outlined, size: 16), text: 'Messages'),
            Tab(icon: Icon(Icons.call_outlined, size: 16), text: 'Calls'),
            Tab(icon: Icon(Icons.analytics_outlined, size: 16), text: 'Analytics'),
          ],
        ),
      ),
      body: ValueListenableBuilder<CommunicationSettings>(
        valueListenable: service.settingsNotifier,
        builder: (context, settings, _) {
          if (!settings.consentAcknowledged) {
            return _buildFirstActivationConsentView();
          }
          return TabBarView(
            controller: _tabController,
            children: [
              _buildOverviewTab(settings),
              _buildMessageHistoryTab(),
              _buildCallHistoryTab(),
              _buildAnalyticsTab(),
            ],
          );
        },
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // First-Activation Privacy & Transparency Consent Screen
  // ---------------------------------------------------------------------------
  Widget _buildFirstActivationConsentView() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.45),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.verified_user_rounded, color: AppColors.primary, size: 24),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Communication Security & Privacy Consent',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              _consentBullet(
                'What is accessed',
                'Only eligible incoming SMS, approved app notifications (e.g., WhatsApp), incoming call metadata, and authorized Gmail messages that you explicitly enable below.',
              ),
              _consentBullet(
                'Why it is accessed',
                'To evaluate every accessible communication (both safe and suspicious) on a 0–100% risk scale and build accurate threat intelligence.',
              ),
              _consentBullet(
                'What is stored & sent',
                'Redacted message previews (optional), sender IDs, timestamps, and risk scores. OTPs, card digits, CVVs, and passwords are redacted on-device. Call audio is NEVER accessed or analyzed.',
              ),
              _consentBullet(
                'Retention & full control',
                'Default 30-day retention (configurable 7–365 days). You can pause monitoring or permanently delete any/all records at any time.',
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        CyberShieldCard(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 6),
                child: Text(
                  'Choose Channels to Monitor',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                activeColor: AppColors.primary,
                title: const Text('Incoming SMS Messages',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                subtitle: const Text('Requires optional Android SMS permission',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: _consentSms,
                onChanged: (v) => setState(() => _consentSms = v ?? false),
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                activeColor: AppColors.primary,
                title: const Text('App & WhatsApp Notifications',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                subtitle: const Text('Uses Android Notification Access (never reads private databases)',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: _consentNotif,
                onChanged: (v) => setState(() => _consentNotif = v ?? false),
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                activeColor: AppColors.primary,
                title: const Text('Incoming Phone Calls (Metadata Only)',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                subtitle: const Text('Caller reputation only — call audio is never monitored',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: _consentCalls,
                onChanged: (v) => setState(() => _consentCalls = v ?? false),
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                activeColor: AppColors.primary,
                title: const Text('Authorized Gmail Messages',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                subtitle: const Text('Requires separate OAuth authorization in Email Scanner',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: _consentEmail,
                onChanged: (v) => setState(() => _consentEmail = v ?? false),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          height: 48,
          child: ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              foregroundColor: Colors.black,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            onPressed: _acceptConsentAndActivate,
            icon: const Icon(Icons.shield_rounded, size: 18),
            label: const Text(
              'Enable Communication Security',
              style: TextStyle(fontWeight: FontWeight.w800, fontSize: 14),
            ),
          ),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () {
            CommunicationService.instance.updateSettings(
              CommunicationService.instance.settingsNotifier.value.copyWith(
                consentAcknowledged: true,
                monitoringPaused: true,
              ),
            );
          },
          child: const Text(
            'Continue with Monitoring Paused',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
          ),
        ),
      ],
    );
  }

  Widget _consentBullet(String title, String body) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.check_circle_outline_rounded, color: AppColors.primary, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: RichText(
              text: TextSpan(
                style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
                children: [
                  TextSpan(
                    text: '$title: ',
                    style: const TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700),
                  ),
                  TextSpan(text: body),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 1: Communication Security Dashboard Overview
  // ---------------------------------------------------------------------------
  Widget _buildOverviewTab(CommunicationSettings settings) {
    final service = CommunicationService.instance;

    return RefreshIndicator(
      onRefresh: () => service.refreshAll(period: _analyticsPeriod),
      child: ValueListenableBuilder<CommunicationAnalytics>(
        valueListenable: service.analyticsNotifier,
        builder: (context, analytics, _) {
          final overall = analytics.overall;
          final msgs = analytics.messages;
          final calls = analytics.calls;

          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (settings.monitoringPaused) ...[
                CyberShieldCard(
                  borderColor: AppColors.warning.withValues(alpha: 0.5),
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      const Icon(Icons.pause_circle_outline_rounded, color: AppColors.warning, size: 22),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Text(
                          'Communication monitoring is paused. Resume to record new messages & calls.',
                          style: TextStyle(color: AppColors.textPrimary, fontSize: 12),
                        ),
                      ),
                      TextButton(
                        onPressed: () =>
                            service.updateSettings(settings.copyWith(monitoringPaused: false)),
                        child: const Text('Resume', style: TextStyle(color: AppColors.primary)),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],

              // Overall Threat Rate & Coverage Card
              CyberShieldCard(
                gradientColors: const [Color(0xFF131F3B), Color(0xFF0C1326)],
                borderColor: AppColors.primary.withValues(alpha: 0.4),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Expanded(
                          child: Text(
                            'Overall Threat Detection Rate',
                            style: TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 15,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                        ),
                        CyberBadge(
                          label: overall.hasAnalyzedData
                              ? '${overall.threatDetectionRate?.toStringAsFixed(1)}%'
                              : 'NO DATA',
                          type: !overall.hasAnalyzedData
                              ? BadgeType.neutral
                              : ((overall.threatDetectionRate ?? 0) >= 30
                                  ? BadgeType.danger
                                  : ((overall.threatDetectionRate ?? 0) > 0
                                      ? BadgeType.warning
                                      : BadgeType.safe)),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      overall.hasAnalyzedData
                          ? '${overall.threatFlaggedCount} threat-flagged out of ${overall.totalAnalyzed} analyzed communications.'
                          : 'No communications have been analyzed yet. Tap Sync above to inspect eligible SMS, calls, or notifications.',
                      style: const TextStyle(color: AppColors.textSecondary, fontSize: 12),
                    ),
                    const SizedBox(height: 12),
                    const Divider(color: AppColors.cardBorder, height: 1),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        _kpiMini('Received', '${overall.totalReceived}', AppColors.textPrimary),
                        _kpiMini('Analyzed', '${overall.totalAnalyzed}', AppColors.primary),
                        _kpiMini('Unanalyzed', '${overall.totalUnanalyzed}', AppColors.warning),
                      ],
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 14),

              // Classification Breakdown Grid
              CyberShieldCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Risk Tier Distribution (0–100%)',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        _tierChip('Safe (0–20%)', overall.safeCount, AppColors.safe),
                        _tierChip('Low Risk (21–40%)', overall.lowRiskCount, AppColors.info),
                        _tierChip('Suspicious (41–60%)', overall.suspiciousCount, AppColors.warning),
                        _tierChip('High Risk (61–80%)', overall.highRiskCount, const Color(0xFFFF6D00)),
                        _tierChip('Critical (81–100%)', overall.criticalCount, AppColors.danger),
                      ],
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 14),

              // Separate SMS & Messages vs Incoming Calls Stats
              Row(
                children: [
                  Expanded(
                    child: CyberShieldCard(
                      onTap: () => _tabController.animateTo(1),
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.sms_rounded, color: AppColors.primary, size: 18),
                              SizedBox(width: 6),
                              Flexible(
                                child: Text(
                                  'Messages & SMS',
                                  style: TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 10),
                          Text(
                            '${msgs.totalAnalyzed} analyzed',
                            style: const TextStyle(
                              color: AppColors.primary,
                              fontSize: 18,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '${msgs.totalReceived} received • ${msgs.totalUnanalyzed} unanalyzed',
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            msgs.hasAnalyzedData
                                ? 'Threat rate: ${msgs.threatDetectionRate?.toStringAsFixed(1)}%'
                                : 'Threat rate: N/A',
                            style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: CyberShieldCard(
                      onTap: () => _tabController.animateTo(2),
                      padding: const EdgeInsets.all(14),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.phone_in_talk_rounded, color: AppColors.secondary, size: 18),
                              SizedBox(width: 6),
                              Flexible(
                                child: Text(
                                  'Incoming Calls',
                                  style: TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 10),
                          Text(
                            '${calls.totalAnalyzed} analyzed',
                            style: const TextStyle(
                              color: AppColors.secondary,
                              fontSize: 18,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '${calls.totalReceived} received • ${calls.unknownCallersCount} unknown',
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            calls.hasAnalyzedData
                                ? 'Threat rate: ${calls.threatDetectionRate?.toStringAsFixed(1)}%'
                                : 'Threat rate: N/A',
                            style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 14),

              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 13),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                  ),
                  onPressed: _triggerSync,
                  icon: const Icon(Icons.sync_rounded, size: 18),
                  label: const Text(
                    'Sync Eligible Device Messages & Calls Now',
                    style: TextStyle(fontWeight: FontWeight.w800, fontSize: 13),
                  ),
                ),
              ),
              const SizedBox(height: 24),
            ],
          );
        },
      ),
    );
  }

  Widget _kpiMini(String label, String value, Color color) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: TextStyle(color: color, fontSize: 20, fontWeight: FontWeight.w900),
          ),
          const SizedBox(height: 2),
          Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _tierChip(String label, int count, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Text(
        '$label: $count',
        style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w700),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 2: Message History (SMS, WhatsApp, Gmail, Notifications)
  // ---------------------------------------------------------------------------
  Widget _buildMessageHistoryTab() {
    final service = CommunicationService.instance;
    const filters = ['All', 'Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical'];

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: TextField(
            controller: _msgSearchController,
            onChanged: (_) => setState(() {}),
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Search by sender, date (YYYY-MM-DD), app, or threat...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              prefixIcon: const Icon(Icons.search_rounded, color: AppColors.textMuted, size: 18),
              suffixIcon: _msgSearchController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded, size: 16),
                      onPressed: () {
                        _msgSearchController.clear();
                        setState(() {});
                      },
                    )
                  : null,
              filled: true,
              fillColor: AppColors.surface,
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
        ),
        SizedBox(
          height: 38,
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            itemCount: filters.length,
            separatorBuilder: (_, __) => const SizedBox(width: 6),
            itemBuilder: (_, idx) {
              final f = filters[idx];
              return ChoiceChip(
                label: Text(f, style: const TextStyle(fontSize: 11)),
                selected: _msgFilter == f,
                selectedColor: AppColors.primary.withValues(alpha: 0.25),
                onSelected: (_) => setState(() => _msgFilter = f),
              );
            },
          ),
        ),
        const SizedBox(height: 8),
        Expanded(
          child: ValueListenableBuilder<bool>(
            valueListenable: service.isLoadingNotifier,
            builder: (context, loading, _) {
              return ValueListenableBuilder<List<CommunicationRecord>>(
                valueListenable: service.recordsNotifier,
                builder: (context, allRecords, _) {
                  if (loading && allRecords.isEmpty) {
                    return const CyberLoadingState(title: 'Loading message history...');
                  }

                  final query = _msgSearchController.text.trim().toLowerCase();
                  final filtered = allRecords.where((r) {
                    if (r.isCall) return false;
                    if (_msgFilter != 'All' &&
                        r.classification.toLowerCase() != _msgFilter.toLowerCase()) {
                      return false;
                    }
                    if (query.isNotEmpty) {
                      final hay = '${r.senderIdentifier} ${r.sourceApp} ${_formatDateShort(r.timestamp)} '
                          '${r.threatCategories.join(' ')} ${r.messagePreview}'.toLowerCase();
                      if (!hay.contains(query)) return false;
                    }
                    return true;
                  }).toList();

                  if (filtered.isEmpty) {
                    return CyberEmptyState(
                      icon: Icons.mark_chat_read_outlined,
                      title: 'No Messages Recorded',
                      description:
                          'Eligible SMS, WhatsApp, Gmail, and app notifications will appear here with individual 0–100% risk scores once synced or received.',
                      actionLabel: 'Sync Device Messages',
                      onAction: _triggerSync,
                    );
                  }

                  return RefreshIndicator(
                    onRefresh: () => service.refreshAll(period: _analyticsPeriod),
                    child: ListView.separated(
                      padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
                      itemCount: filtered.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 10),
                      itemBuilder: (_, idx) => _buildMessageCard(filtered[idx]),
                    ),
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildMessageCard(CommunicationRecord rec) {
    final riskColor = _colorForRisk(rec);

    return CyberShieldCard(
      onTap: () {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => CommunicationDetailScreen(record: rec)),
        );
      },
      borderRadius: 12,
      borderColor: rec.isThreatFlagged ? riskColor.withValues(alpha: 0.45) : AppColors.cardBorder,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  rec.senderIdentifier,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: riskColor.withValues(alpha: 0.16),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: riskColor.withValues(alpha: 0.5)),
                ),
                child: Text(
                  rec.isAnalyzed ? '${rec.riskScore}%' : 'N/A',
                  style: TextStyle(
                    color: riskColor,
                    fontSize: 12,
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              CyberBadge(label: rec.sourceApp.toUpperCase(), type: BadgeType.info),
              CyberBadge(label: rec.classification.toUpperCase(), type: _badgeForRisk(rec)),
              if (!rec.isAnalyzed)
                const CyberBadge(label: 'UNANALYZED', type: BadgeType.neutral),
            ],
          ),
          if (rec.messagePreview.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              rec.messagePreview,
              style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.35),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                _formatDateShort(rec.timestamp),
                style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
              ),
              if (rec.threatCategories.isNotEmpty)
                Flexible(
                  child: Text(
                    rec.threatCategories.take(2).join(' • '),
                    style: TextStyle(color: riskColor, fontSize: 10, fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 3: Call History (Incoming Calls — Reputation Only)
  // ---------------------------------------------------------------------------
  Widget _buildCallHistoryTab() {
    final service = CommunicationService.instance;
    const filters = ['All', 'Safe', 'Unknown', 'Suspicious', 'High Risk', 'Critical'];

    return Column(
      children: [
        ValueListenableBuilder<CommunicationPermissionsStatus>(
          valueListenable: service.permissionsNotifier,
          builder: (context, perms, _) {
            return Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
              child: CyberShieldCard(
                padding: const EdgeInsets.all(10),
                borderColor: perms.callScreeningSupported
                    ? AppColors.cardBorder
                    : AppColors.warning.withValues(alpha: 0.4),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          perms.callScreeningSupported
                              ? Icons.phone_callback_rounded
                              : Icons.info_outline_rounded,
                          size: 15,
                          color: perms.callScreeningSupported ? AppColors.secondary : AppColors.warning,
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            perms.callScreeningSupported
                                ? 'Automatic Screening (Android 10+) & Call History'
                                : 'Native Call Screening Unsupported on This Device',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              color: perms.callScreeningSupported ? AppColors.textPrimary : AppColors.warning,
                              fontSize: 11.5,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      perms.callScreeningSupported
                          ? 'Automatic incoming call screening uses Android 10+ CallScreeningService; Call History analysis requires Call Log permission.'
                          : 'Calls are not automatically blocked or screened on Android 9. Call History analysis requires Call Log permission; manual number checks are available in Protection -> Call Security.',
                      style: const TextStyle(color: AppColors.textMuted, fontSize: 10.5, height: 1.3),
                    ),
                  ],
                ),
              ),
            );
          },
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 6, 16, 8),
          child: TextField(
            controller: _callSearchController,
            onChanged: (_) => setState(() {}),
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              hintText: 'Search by caller name, phone number, or date...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              prefixIcon: const Icon(Icons.search_rounded, color: AppColors.textMuted, size: 18),
              suffixIcon: _callSearchController.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear_rounded, size: 16),
                      onPressed: () {
                        _callSearchController.clear();
                        setState(() {});
                      },
                    )
                  : null,
              filled: true,
              fillColor: AppColors.surface,
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
        ),
        SizedBox(
          height: 38,
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            itemCount: filters.length,
            separatorBuilder: (_, __) => const SizedBox(width: 6),
            itemBuilder: (_, idx) {
              final f = filters[idx];
              return ChoiceChip(
                label: Text(f == 'All' ? 'All Calls' : f, style: const TextStyle(fontSize: 11)),
                selected: _callFilter == f,
                selectedColor: AppColors.secondary.withValues(alpha: 0.25),
                onSelected: (_) => setState(() => _callFilter = f),
              );
            },
          ),
        ),
        const SizedBox(height: 8),
        Expanded(
          child: ValueListenableBuilder<List<CommunicationRecord>>(
            valueListenable: service.recordsNotifier,
            builder: (context, allRecords, _) {
              final query = _callSearchController.text.trim().toLowerCase();
              final filtered = allRecords.where((r) {
                if (!r.isCall) return false;
                if (_callFilter == 'Unknown') {
                  if (r.isKnownContact == true) return false;
                } else if (_callFilter != 'All' &&
                    r.classification.toLowerCase() != _callFilter.toLowerCase()) {
                  return false;
                }
                if (query.isNotEmpty) {
                  final hay = '${r.callerName ?? ''} ${r.senderIdentifier} '
                      '${_formatDateShort(r.timestamp)} ${r.spamReputation ?? ''}'.toLowerCase();
                  if (!hay.contains(query)) return false;
                }
                return true;
              }).toList();

              if (filtered.isEmpty) {
                return CyberEmptyState(
                  icon: Icons.phone_callback_outlined,
                  title: 'No Incoming Calls Recorded',
                  description:
                      'Incoming call metadata and caller reputation scores (never call audio) will appear here once synced or received.',
                  actionLabel: 'Sync Call History',
                  onAction: _triggerSync,
                );
              }

              return RefreshIndicator(
                onRefresh: () => service.refreshAll(period: _analyticsPeriod),
                child: ListView.separated(
                  padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
                  itemCount: filtered.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 10),
                  itemBuilder: (_, idx) => _buildCallCard(filtered[idx]),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildCallCard(CommunicationRecord rec) {
    final riskColor = _colorForRisk(rec);

    return CyberShieldCard(
      onTap: () {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => CommunicationDetailScreen(record: rec)),
        );
      },
      borderRadius: 12,
      borderColor: rec.isThreatFlagged ? riskColor.withValues(alpha: 0.45) : AppColors.cardBorder,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: riskColor.withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(
                  rec.callStatus == 'missed'
                      ? Icons.phone_missed_rounded
                      : (rec.callStatus == 'silenced'
                          ? Icons.phone_disabled_rounded
                          : Icons.call_received_rounded),
                  color: riskColor,
                  size: 18,
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      rec.displayTitle,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (rec.callerName != null && rec.callerName!.isNotEmpty)
                      Text(
                        rec.senderIdentifier,
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                      ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: riskColor.withValues(alpha: 0.16),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: riskColor.withValues(alpha: 0.5)),
                ),
                child: Text(
                  rec.isAnalyzed ? '${rec.riskScore}%' : 'N/A',
                  style: TextStyle(color: riskColor, fontSize: 12, fontWeight: FontWeight.w900),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              CyberBadge(label: rec.classification.toUpperCase(), type: _badgeForRisk(rec)),
              CyberBadge(
                label: rec.isKnownContact == true ? 'KNOWN CONTACT' : 'UNKNOWN CALLER',
                type: rec.isKnownContact == true ? BadgeType.safe : BadgeType.neutral,
              ),
              if (rec.callStatus != null)
                CyberBadge(label: rec.callStatus!.toUpperCase(), type: BadgeType.info),
            ],
          ),
          const SizedBox(height: 6),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                _formatDateShort(rec.timestamp),
                style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
              ),
              const Text(
                'Reputation only • No audio',
                style: TextStyle(color: AppColors.textMuted, fontSize: 10),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Tab 4: Threat Percentage Analytics (Daily, Weekly, Monthly)
  // ---------------------------------------------------------------------------
  Widget _buildAnalyticsTab() {
    final service = CommunicationService.instance;

    return ValueListenableBuilder<CommunicationAnalytics>(
      valueListenable: service.analyticsNotifier,
      builder: (context, analytics, _) {
        final maxTotal = analytics.trends.fold<int>(
          1,
          (prev, e) => e.total > prev ? e.total : prev,
        );

        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Period Switcher
            Row(
              children: [
                const Text(
                  'Timeframe:',
                  style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 13),
                ),
                const SizedBox(width: 10),
                for (final p in const ['daily', 'weekly', 'monthly'])
                  Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: ChoiceChip(
                      label: Text(
                        p[0].toUpperCase() + p.substring(1),
                        style: const TextStyle(fontSize: 11),
                      ),
                      selected: _analyticsPeriod == p,
                      selectedColor: AppColors.primary.withValues(alpha: 0.25),
                      onSelected: (_) {
                        setState(() => _analyticsPeriod = p);
                        service.refreshAll(period: p);
                      },
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 12),

            // Threat Rate Formula Card
            CyberShieldCard(
              borderColor: AppColors.primary.withValues(alpha: 0.35),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Threat Detection Rate',
                        style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                      ),
                      Text(
                        analytics.overall.hasAnalyzedData
                            ? '${analytics.overall.threatDetectionRate?.toStringAsFixed(1)}%'
                            : 'Unavailable',
                        style: const TextStyle(
                          color: AppColors.primary,
                          fontSize: 20,
                          fontWeight: FontWeight.w900,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    analytics.formula,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 14),

            // Volume & Threat Trend Chart
            CyberShieldCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${_analyticsPeriod[0].toUpperCase()}${_analyticsPeriod.substring(1)} Communication Volume & Threat %',
                    style: const TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Green = Safe/Low Risk • Red = Suspicious/High/Critical',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 10),
                  ),
                  const SizedBox(height: 14),
                  if (analytics.trends.isEmpty)
                    const Text('No trend records yet.', style: TextStyle(color: AppColors.textMuted, fontSize: 12))
                  else
                    SizedBox(
                      height: 150,
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: analytics.trends.map((pt) {
                          final safeH = (pt.safe / maxTotal) * 95.0;
                          final threatH = (pt.threats / maxTotal) * 95.0;
                          final shortLabel = pt.label.length >= 5
                              ? pt.label.substring(pt.label.length - 5)
                              : pt.label;
                          return Expanded(
                            child: Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 2),
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.end,
                                children: [
                                  if (pt.analyzed > 0)
                                    Text(
                                      '${pt.threatPercentage.round()}%',
                                      style: TextStyle(
                                        color: pt.threats > 0 ? AppColors.danger : AppColors.safe,
                                        fontSize: 8,
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  const SizedBox(height: 2),
                                  if (threatH > 0)
                                    Container(
                                      height: threatH.clamp(4.0, 95.0),
                                      decoration: BoxDecoration(
                                        color: AppColors.danger,
                                        borderRadius: BorderRadius.circular(3),
                                      ),
                                    ),
                                  if (safeH > 0)
                                    Container(
                                      height: safeH.clamp(4.0, 95.0),
                                      decoration: BoxDecoration(
                                        color: AppColors.safe,
                                        borderRadius: BorderRadius.circular(3),
                                      ),
                                    ),
                                  if (safeH == 0 && threatH == 0)
                                    Container(
                                      height: 3,
                                      color: AppColors.cardBorder,
                                    ),
                                  const SizedBox(height: 6),
                                  Text(
                                    shortLabel,
                                    style: const TextStyle(color: AppColors.textMuted, fontSize: 8),
                                    maxLines: 1,
                                    overflow: TextOverflow.clip,
                                  ),
                                ],
                              ),
                            ),
                          );
                        }).toList(),
                      ),
                    ),
                ],
              ),
            ),

            const SizedBox(height: 14),

            // SMS & Messages Threat Distribution
            _buildDistributionCard('SMS & Messages Threat Distribution', analytics.smsThreatDistribution),
            const SizedBox(height: 14),

            // Incoming Calls Threat Distribution
            _buildDistributionCard('Incoming Calls Threat Distribution', analytics.callThreatDistribution),
            const SizedBox(height: 14),

            // Top Threat Categories
            CyberShieldCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Most Common Threat Categories',
                    style: TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
                  ),
                  const SizedBox(height: 10),
                  if (analytics.topThreatCategories.isEmpty)
                    const Text(
                      'No threat categories flagged in stored communication records.',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                    )
                  else
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: analytics.topThreatCategories.map((c) {
                        final label = (c['category']?.toString() ?? '').replaceAll('_', ' ').toUpperCase();
                        final count = c['count'] ?? 0;
                        return CyberBadge(label: '$label ($count)', type: BadgeType.warning);
                      }).toList(),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 24),
          ],
        );
      },
    );
  }

  Widget _buildDistributionCard(String title, Map<String, int> dist) {
    final total = dist.values.fold<int>(0, (a, b) => a + b);
    final colors = {
      'Safe': AppColors.safe,
      'Low Risk': AppColors.info,
      'Suspicious': AppColors.warning,
      'High Risk': const Color(0xFFFF6D00),
      'Critical': AppColors.danger,
      'Unanalyzed': AppColors.textMuted,
    };

    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 14),
          ),
          const SizedBox(height: 10),
          if (total == 0)
            const Text('No records stored yet.', style: TextStyle(color: AppColors.textMuted, fontSize: 12))
          else
            ...dist.entries.map((e) {
              final pct = total > 0 ? (e.value / total) : 0.0;
              final color = colors[e.key] ?? AppColors.primary;
              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(e.key, style: const TextStyle(color: AppColors.textSecondary, fontSize: 11)),
                        Text(
                          '${e.value} (${(pct * 100).toStringAsFixed(0)}%)',
                          style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w700),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: pct,
                        minHeight: 6,
                        backgroundColor: AppColors.background,
                        valueColor: AlwaysStoppedAnimation<Color>(color),
                      ),
                    ),
                  ],
                ),
              );
            }),
        ],
      ),
    );
  }
}
