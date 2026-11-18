// CyberShield Real-Time Android Protection Dashboard Screen
// Multi-vector security control plane: Notification Listener, Call Screening,
// Installed Applications Inventory & Dangerous Permission Auditing.

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/protection_service.dart';

class ProtectionDashboardScreen extends StatefulWidget {
  const ProtectionDashboardScreen({super.key});

  @override
  State<ProtectionDashboardScreen> createState() => _ProtectionDashboardScreenState();
}

class _ProtectionDashboardScreenState extends State<ProtectionDashboardScreen>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  late TabController _tabController;

  String _searchQuery = '';
  int _selectedFilterIndex = 0; // 0: All, 1: Risky, 2: Safe
  final bool _includeSystemApps = false;
  final TextEditingController _manualPhoneController = TextEditingController();
  bool _isCheckingManualPhone = false;
  CallScreenResult? _manualPhoneResult;
  String? _manualPhoneError;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _tabController = TabController(length: 3, vsync: this);
    ProtectionService.instance.initialize();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _tabController.dispose();
    _manualPhoneController.dispose();
    super.dispose();
  }

  Future<void> _checkPhoneNumberManually() async {
    final phone = _manualPhoneController.text.trim();
    if (phone.isEmpty) {
      setState(() => _manualPhoneError = 'Enter a phone number (e.g. +18005550199) to check reputation.');
      return;
    }
    setState(() {
      _isCheckingManualPhone = true;
      _manualPhoneError = null;
      _manualPhoneResult = null;
    });
    final res = await ApiService.screenIncomingCall(phone);
    if (!mounted) return;
    setState(() {
      _isCheckingManualPhone = false;
      if (res != null) {
        _manualPhoneResult = res;
      } else {
        _manualPhoneError = 'Unable to reach CyberShield backend for phone reputation lookup.';
      }
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      ProtectionService.instance.refreshStatus();
      ProtectionService.instance.loadNativeScreenedCallHistory();
    }
  }

  Future<void> _handleRequestCallScreeningRole() async {
    final result = await ProtectionService.instance.requestCallScreeningRole();
    if (!mounted || result.isInProgress) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(result.message),
        backgroundColor: result.isGranted
            ? AppColors.safe
            : (result.isUnsupported || result.isDenied ? AppColors.warning : AppColors.danger),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  Future<void> _refreshStatus() async {
    await ProtectionService.instance.refreshStatus();
  }

  Future<void> _triggerAppsAudit() async {
    final messenger = ScaffoldMessenger.of(context);
    final result = await ProtectionService.instance.scanInstalledApplications(
      includeSystemApps: _includeSystemApps,
    );
    if (!mounted) return;

    if (result != null) {
      messenger.showSnackBar(
        SnackBar(
          content: Text(
            'Audited ${result.totalAppsAnalyzed} apps: ${result.criticalCount + result.highRiskCount} risky packages flagged.',
          ),
          backgroundColor: (result.criticalCount + result.highRiskCount > 0)
              ? AppColors.danger
              : AppColors.safe,
        ),
      );
    } else {
      messenger.showSnackBar(
        const SnackBar(
          content: Text('Unable to complete batch application audit.'),
          backgroundColor: AppColors.danger,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      drawer: const NavDrawer(currentRoute: '/protection'),
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.shield_rounded, color: AppColors.primary, size: 22),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                'Real-Time Protection',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontWeight: FontWeight.w700, fontSize: 17),
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Refresh Status',
            icon: const Icon(Icons.refresh_rounded, color: AppColors.textSecondary),
            onPressed: _refreshStatus,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppColors.primary,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textMuted,
          tabs: const [
            Tab(icon: Icon(Icons.dashboard_customize_rounded), text: 'Defense Hub'),
            Tab(icon: Icon(Icons.apps_rounded), text: 'Apps Sentry'),
            Tab(icon: Icon(Icons.radar_rounded), text: 'Live Interception'),
          ],
        ),
      ),
      body: ValueListenableBuilder<ProtectionStatus>(
        valueListenable: ProtectionService.instance.statusNotifier,
        builder: (context, status, _) {
          return TabBarView(
            controller: _tabController,
            children: [
              _buildDefenseHubTab(status),
              _buildInstalledAppsTab(),
              _buildLiveSentryTab(),
            ],
          );
        },
      ),
    );
  }

  // =========================================================================
  // TAB 1: DEFENSE HUB (Status, Modules, Controls)
  // =========================================================================

  Widget _buildDefenseHubTab(ProtectionStatus status) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 80),
      children: [
        _buildMasterShieldCard(status),
        const SizedBox(height: 20),
        const Text(
          'PROTECTION VECTORS',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 11,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.0,
          ),
        ),
        const SizedBox(height: 12),
        _buildNotificationGuardCard(status),
        const SizedBox(height: 12),
        _buildCallScreeningCard(status),
        const SizedBox(height: 12),
        _buildInstalledAppsOverviewCard(),
        const SizedBox(height: 12),
        _buildSmsScamCard(),
        const SizedBox(height: 24),
        _buildPrivacyAndBatteryNotice(),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildMasterShieldCard(ProtectionStatus status) {
    final isEnabled = status.isMasterEnabled;
    final primaryColor = isEnabled ? AppColors.primary : AppColors.textMuted;

    return CyberShieldCard(
      borderColor: isEnabled ? AppColors.primary.withValues(alpha: 0.5) : AppColors.cardBorder,
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Row(
          children: [
            Container(
              width: 52,
              height: 52,
              decoration: BoxDecoration(
                color: primaryColor.withValues(alpha: 0.12),
                shape: BoxShape.circle,
                border: Border.all(color: primaryColor.withValues(alpha: 0.4), width: 2),
              ),
              child: Icon(
                isEnabled ? Icons.security_rounded : Icons.shield_outlined,
                color: primaryColor,
                size: 28,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Wrap(
                    spacing: 8,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        isEnabled ? 'SHIELD ACTIVE' : 'PROTECTION PAUSED',
                        style: TextStyle(
                          color: isEnabled ? AppColors.primary : AppColors.textSecondary,
                          fontWeight: FontWeight.w800,
                          fontSize: 15,
                          letterSpacing: 0.5,
                        ),
                      ),
                      CyberBadge(
                        label: isEnabled ? 'ARMED' : 'PAUSED',
                        type: isEnabled ? BadgeType.safe : BadgeType.danger,
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    isEnabled
                        ? (status.isCallScreeningSupported && status.isCallScreeningRoleHeld
                            ? 'Real-time defense monitoring active for notifications, automatic call screening & apps.'
                            : (!status.isCallScreeningSupported
                                ? 'Real-time defense active for notifications & apps. Native call screening is unsupported on this Android version.'
                                : 'Real-time defense monitoring active for notifications & apps.'))
                        : 'All automatic real-time threat screening is currently paused.',
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                ],
              ),
            ),
            Switch(
              value: isEnabled,
              activeThumbColor: AppColors.primary,
              onChanged: (val) {
                ProtectionService.instance.setProtectionMasterEnabled(val);
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildNotificationGuardCard(ProtectionStatus status) {
    final granted = status.isNotificationAccessGranted;

    return CyberShieldCard(
      child: Padding(
        padding: const EdgeInsets.all(16),
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
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppColors.accent.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(
                          Icons.notifications_active_rounded,
                          color: AppColors.accent,
                          size: 20,
                        ),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Text(
                          'Notification Guard',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                CyberBadge(
                  label: granted ? 'ACTIVE' : 'SETUP REQUIRED',
                  type: granted ? BadgeType.safe : BadgeType.warning,
                ),
              ],
            ),
            const SizedBox(height: 10),
            const Text(
              'Screens incoming Android notifications for embedded phishing links, urgent financial manipulation, and credential theft attempts.',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
            ),
            const SizedBox(height: 12),
            const Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.lock_outline_rounded, color: AppColors.safe, size: 14),
                SizedBox(width: 6),
                Expanded(
                  child: Text(
                    'Zero raw OTP/card storage: credentials automatically redacted.',
                    style: TextStyle(color: AppColors.safe, fontSize: 11),
                  ),
                ),
              ],
            ),
            if (!granted) ...[
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: () {
                    ProtectionService.instance.openNotificationListenerSettings();
                  },
                  icon: const Icon(Icons.settings_suggest_rounded, size: 16),
                  label: const Text('Grant Notification Access in Settings'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.accent,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 10),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildCallScreeningCard(ProtectionStatus status) {
    final supported = status.isCallScreeningSupported;
    final held = supported && status.isCallScreeningRoleHeld;
    final silenceSpam = status.silenceSpamCalls;
    final sdkSummary = status.androidSdk > 0
        ? 'Android ${status.androidRelease ?? status.androidSdk} (API ${status.androidSdk})'
        : 'Android API < 29';

    return CyberShieldCard(
      child: Padding(
        padding: const EdgeInsets.all(16),
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
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppColors.secondary.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(
                          Icons.phone_in_talk_rounded,
                          color: AppColors.secondary,
                          size: 20,
                        ),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Text(
                          'Call Security & Reputation',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                CyberBadge(
                  label: !supported
                      ? 'UNSUPPORTED'
                      : (held ? 'ROLE ACTIVE' : 'ROLE NEEDED'),
                  type: !supported
                      ? BadgeType.neutral
                      : (held ? BadgeType.safe : BadgeType.warning),
                ),
              ],
            ),
            const SizedBox(height: 12),
            // SECTION 1: Automatic Incoming Call Screening (Android 10+ ONLY)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: supported
                    ? AppColors.surfaceSubtle
                    : AppColors.warning.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: supported
                      ? AppColors.cardBorder
                      : AppColors.warning.withValues(alpha: 0.35),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        supported ? Icons.verified_user_rounded : Icons.info_outline_rounded,
                        size: 16,
                        color: supported ? AppColors.secondary : AppColors.warning,
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          supported
                              ? 'Automatic Incoming Call Screening (Android 10+)'
                              : 'Native Call Screening Unsupported on This Device',
                          style: TextStyle(
                            color: supported ? AppColors.textPrimary : AppColors.warning,
                            fontSize: 12.5,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    supported
                        ? 'Uses official Android 10+ CallScreeningService to automatically evaluate incoming callers against CyberShield threat intelligence.'
                        : 'Detected $sdkSummary. Android introduced CallScreeningService in Android 10 (API 29). Incoming calls are NOT automatically blocked or screened on Android 9. All other CyberShield protection modules remain fully active.',
                    style: const TextStyle(color: AppColors.textSecondary, fontSize: 11.5, height: 1.4),
                  ),
                  if (supported) ...[
                    const SizedBox(height: 10),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Expanded(
                          child: Text(
                            'Auto-Silence Verified Spam Callers',
                            style: TextStyle(color: AppColors.textPrimary, fontSize: 12),
                          ),
                        ),
                        Switch(
                          value: silenceSpam,
                          activeThumbColor: AppColors.secondary,
                          onChanged: (val) {
                            ProtectionService.instance.setCallScreeningSilenceSpamEnabled(val);
                          },
                        ),
                      ],
                    ),
                    if (!held)
                      ValueListenableBuilder<bool>(
                        valueListenable: ProtectionService.instance.isRequestingCallRoleNotifier,
                        builder: (context, isRequesting, _) {
                          return SizedBox(
                            width: double.infinity,
                            child: OutlinedButton.icon(
                              onPressed: isRequesting ? null : _handleRequestCallScreeningRole,
                              icon: isRequesting
                                  ? const SizedBox(
                                      width: 14,
                                      height: 14,
                                      child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.secondary),
                                    )
                                  : const Icon(Icons.shield_outlined, size: 16),
                              label: Text(isRequesting ? 'Requesting Role...' : 'Set Call Screening Role'),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: AppColors.secondary,
                                side: const BorderSide(color: AppColors.secondary),
                              ),
                            ),
                          );
                        },
                      ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 12),
            // SECTION 2: Manual Phone-Number Reputation Check (Always Available on Android 9+)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.surfaceSubtle,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.cardBorder),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.manage_search_rounded, size: 16, color: AppColors.primary),
                      SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          'Manual Phone-Number Reputation Check',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 12.5,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Look up any caller number manually against CyberShield threat intelligence (works on Android 9 and all versions).',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.35),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _manualPhoneController,
                          keyboardType: TextInputType.phone,
                          style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                          decoration: InputDecoration(
                            hintText: 'e.g. +18005550199',
                            hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                            isDense: true,
                            filled: true,
                            fillColor: AppColors.background,
                            contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: const BorderSide(color: AppColors.cardBorder),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: const BorderSide(color: AppColors.cardBorder),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      ElevatedButton(
                        onPressed: _isCheckingManualPhone ? null : _checkPhoneNumberManually,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.black,
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        ),
                        child: _isCheckingManualPhone
                            ? const SizedBox(
                                width: 14,
                                height: 14,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                              )
                            : const Text('Check', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w800)),
                      ),
                    ],
                  ),
                  if (_manualPhoneError != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _manualPhoneError!,
                      style: const TextStyle(color: AppColors.danger, fontSize: 11),
                    ),
                  ],
                  if (_manualPhoneResult != null) ...[
                    const SizedBox(height: 8),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppColors.background,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: _manualPhoneResult!.spamScore >= 50
                              ? AppColors.danger.withValues(alpha: 0.6)
                              : (_manualPhoneResult!.spamScore >= 25
                                  ? AppColors.warning.withValues(alpha: 0.6)
                                  : AppColors.safe.withValues(alpha: 0.5)),
                        ),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Expanded(
                                child: Text(
                                  _manualPhoneResult!.normalizedNumber,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(
                                    color: AppColors.textPrimary,
                                    fontWeight: FontWeight.w700,
                                    fontSize: 12,
                                  ),
                                ),
                              ),
                              const SizedBox(width: 6),
                              CyberBadge(
                                label: '${_manualPhoneResult!.classification.toUpperCase()} (${_manualPhoneResult!.spamScore}%)',
                                type: _manualPhoneResult!.spamScore >= 50
                                    ? BadgeType.danger
                                    : (_manualPhoneResult!.spamScore >= 25 ? BadgeType.warning : BadgeType.safe),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _manualPhoneResult!.explanation,
                            style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, height: 1.35),
                          ),
                        ],
                      ),
                    ),
                  ],
                  const SizedBox(height: 8),
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton.icon(
                      onPressed: () => Navigator.pushNamed(context, AppRouter.communications, arguments: 2),
                      icon: const Icon(Icons.history_rounded, size: 15),
                      label: const Text(
                        'Open Call History Analysis (Requires Call Log Permission)',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(fontSize: 11),
                      ),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.textPrimary,
                        side: const BorderSide(color: AppColors.cardBorder),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInstalledAppsOverviewCard() {
    return ValueListenableBuilder<BatchAppScanResult?>(
      valueListenable: ProtectionService.instance.lastBatchScanNotifier,
      builder: (context, scanResult, _) {
        return CyberShieldCard(
          child: Padding(
            padding: const EdgeInsets.all(16),
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
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: AppColors.primary.withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: const Icon(
                              Icons.apps_rounded,
                              color: AppColors.primary,
                              size: 20,
                            ),
                          ),
                          const SizedBox(width: 10),
                          const Expanded(
                            child: Text(
                              'Installed Apps Inventory',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: AppColors.textPrimary,
                                fontSize: 15,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    CyberBadge(
                      label: scanResult != null
                          ? '${scanResult.totalAppsAnalyzed} AUDITED'
                          : 'NOT AUDITED',
                      type: scanResult != null
                          ? (scanResult.highRiskCount > 0 ? BadgeType.danger : BadgeType.safe)
                          : BadgeType.neutral,
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Text(
                  scanResult != null
                      ? scanResult.summary
                      : 'Audits accessible installed packages for trojan profiles, stalkerware indicators, and dangerous permission combos.',
                  style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
                ),
                const SizedBox(height: 14),
                ValueListenableBuilder<bool>(
                  valueListenable: ProtectionService.instance.isScanningAppsNotifier,
                  builder: (context, isScanning, _) {
                    return SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: isScanning ? null : _triggerAppsAudit,
                        icon: isScanning
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                              )
                            : const Icon(Icons.manage_search_rounded, size: 16),
                        label: Text(isScanning ? 'Auditing Applications...' : 'Audit Installed Apps Now'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.black,
                          padding: const EdgeInsets.symmetric(vertical: 11),
                        ),
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildSmsScamCard() {
    return CyberShieldCard(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppColors.warning.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(
                Icons.sms_rounded,
                color: AppColors.warning,
                size: 20,
              ),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'SMS Threat Protection',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  SizedBox(height: 2),
                  Text(
                    'Monitored via Notification Guard & manual scanner without requesting default SMS app status.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                  ),
                ],
              ),
            ),
            IconButton(
              icon: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: AppColors.textSecondary),
              onPressed: () {
                Navigator.of(context).pushNamed(AppRouter.smsScanner);
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPrivacyAndBatteryNotice() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.info_outline_rounded, color: AppColors.info, size: 16),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Privacy & Resource Transparency',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          SizedBox(height: 8),
          Text(
            '• Event-driven Android architecture uses zero background polling loops and negligible battery.\n'
            '• CyberShield never reads private application app data or storage without explicit authorization.\n'
            '• OTP codes, banking passwords, and credentials are redacted locally before any processing.',
            style: TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.4),
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // TAB 2: INSTALLED APPS SENTRY (Inventory, Filters, Risky Apps)
  // =========================================================================

  Widget _buildInstalledAppsTab() {
    return ValueListenableBuilder<BatchAppScanResult?>(
      valueListenable: ProtectionService.instance.lastBatchScanNotifier,
      builder: (context, scanResult, _) {
        return ValueListenableBuilder<bool>(
          valueListenable: ProtectionService.instance.isScanningAppsNotifier,
          builder: (context, isScanning, _) {
            if (isScanning) {
              return const CyberLoadingState(
                title: 'Auditing Installed Applications',
                subtitle: 'Analyzing declared permissions and detecting trojan combinations...',
              );
            }

            if (scanResult == null) {
              return Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.apps_rounded, size: 64, color: AppColors.textMuted),
                      const SizedBox(height: 16),
                      const Text(
                        'No Applications Audited Yet',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Run a security audit to discover accessible installed applications, dangerous combinations, and trojan indicators.',
                        textAlign: TextAlign.center,
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
                      ),
                      const SizedBox(height: 20),
                      ElevatedButton.icon(
                        onPressed: _triggerAppsAudit,
                        icon: const Icon(Icons.manage_search_rounded),
                        label: const Text('Start Installed Apps Audit'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.black,
                          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                        ),
                      ),
                    ],
                  ),
                ),
              );
            }

            return _buildAppsList(scanResult);
          },
        );
      },
    );
  }

  Widget _buildAppsList(BatchAppScanResult scanResult) {
    var apps = scanResult.allApps;

    if (_selectedFilterIndex == 1) {
      apps = apps.where((a) => a.isRisky).toList();
    } else if (_selectedFilterIndex == 2) {
      apps = apps.where((a) => !a.isRisky).toList();
    }

    if (_searchQuery.trim().isNotEmpty) {
      final q = _searchQuery.toLowerCase().trim();
      apps = apps
          .where((a) => a.appName.toLowerCase().contains(q) || a.packageName.toLowerCase().contains(q))
          .toList();
    }

    return Column(
      children: [
        Container(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          color: AppColors.surface,
          child: Column(
            children: [
              TextField(
                onChanged: (val) {
                  setState(() {
                    _searchQuery = val;
                  });
                },
                decoration: InputDecoration(
                  hintText: 'Search installed package or app name...',
                  hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                  prefixIcon: const Icon(Icons.search_rounded, color: AppColors.textSecondary, size: 20),
                  filled: true,
                  fillColor: AppColors.background,
                  isDense: true,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: AppColors.cardBorder),
                  ),
                  contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  _buildFilterChip('All (${scanResult.totalAppsAnalyzed})', 0),
                  const SizedBox(width: 8),
                  _buildFilterChip(
                      'Risky (${scanResult.criticalCount + scanResult.highRiskCount + scanResult.suspiciousCount})',
                      1),
                  const SizedBox(width: 8),
                  _buildFilterChip('Safe (${scanResult.safeCount})', 2),
                  const Spacer(),
                  IconButton(
                    tooltip: 'Analyze APK File',
                    icon: const Icon(Icons.file_upload_outlined, color: AppColors.primary),
                    onPressed: () {
                      Navigator.of(context).pushNamed(AppRouter.apkAnalysis);
                    },
                  ),
                ],
              ),
            ],
          ),
        ),
        Expanded(
          child: apps.isEmpty
              ? const Center(
                  child: Text(
                    'No applications matching filter criteria.',
                    style: TextStyle(color: AppColors.textMuted),
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: apps.length,
                  itemBuilder: (context, index) {
                    final app = apps[index];
                    return _buildAppItemCard(app);
                  },
                ),
        ),
      ],
    );
  }

  Widget _buildFilterChip(String label, int index) {
    final isSelected = _selectedFilterIndex == index;
    return ChoiceChip(
      label: Text(label, style: TextStyle(fontSize: 11, color: isSelected ? Colors.black : AppColors.textSecondary)),
      selected: isSelected,
      selectedColor: AppColors.primary,
      backgroundColor: AppColors.surface,
      onSelected: (_) {
        setState(() {
          _selectedFilterIndex = index;
        });
      },
      visualDensity: VisualDensity.compact,
    );
  }

  Widget _buildAppItemCard(InstalledAppInfo app) {
    final badgeType = app.isCritical
        ? BadgeType.danger
        : (app.isHighRisk
            ? BadgeType.danger
            : (app.isSuspicious ? BadgeType.warning : BadgeType.safe));

    return CyberShieldCard(
      child: ExpansionTile(
        leading: Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            color: app.isRisky
                ? AppColors.danger.withValues(alpha: 0.12)
                : AppColors.primary.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(
            app.isRisky ? Icons.warning_amber_rounded : Icons.android_rounded,
            color: app.isRisky ? AppColors.danger : AppColors.primary,
            size: 22,
          ),
        ),
        title: Text(
          app.appName,
          style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14, color: AppColors.textPrimary),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              app.packageName,
              style: const TextStyle(fontSize: 11, color: AppColors.textMuted),
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                CyberBadge(label: app.classification.toUpperCase(), type: badgeType),
                const SizedBox(width: 8),
                Text(
                  'Risk Score: ${app.riskScore}/100',
                  style: const TextStyle(fontSize: 11, color: AppColors.textSecondary),
                ),
              ],
            ),
          ],
        ),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Divider(color: AppColors.cardBorder),
                if (app.comboFindings.isNotEmpty) ...[
                  const Text(
                    'DANGEROUS PERMISSION COMBINATIONS',
                    style: TextStyle(
                      color: AppColors.danger,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.8,
                    ),
                  ),
                  const SizedBox(height: 6),
                  ...app.comboFindings.map((combo) => Padding(
                        padding: const EdgeInsets.only(bottom: 4),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text('• ', style: TextStyle(color: AppColors.danger)),
                            Expanded(
                              child: Text(
                                combo,
                                style: const TextStyle(fontSize: 12, color: AppColors.textPrimary),
                              ),
                            ),
                          ],
                        ),
                      )),
                  const SizedBox(height: 10),
                ],
                if (app.explanation.isNotEmpty) ...[
                  Text(
                    app.explanation,
                    style: const TextStyle(fontSize: 12, color: AppColors.textSecondary, height: 1.3),
                  ),
                  const SizedBox(height: 10),
                ],
                if (app.recommendations.isNotEmpty) ...[
                  const Text(
                    'RECOMMENDED DEFENSE ACTION',
                    style: TextStyle(
                      color: AppColors.primary,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.8,
                    ),
                  ),
                  const SizedBox(height: 4),
                  ...app.recommendations.map((rec) => Text(
                        '→ $rec',
                        style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                      )),
                ],
                const SizedBox(height: 10),
                Text(
                  'Permissions (${app.permissions.length}): ${app.permissions.take(6).join(", ")}${app.permissions.length > 6 ? "..." : ""}',
                  style: const TextStyle(fontSize: 10, color: AppColors.textMuted),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // TAB 3: LIVE SENTRY & CONFIG (Real-Time Interception Stream & Controls)
  // =========================================================================

  Widget _buildLiveSentryTab() {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 80),
      children: [
        // 1. Live Sentry Telemetry Header
        _buildSentryStatsOverview(),
        const SizedBox(height: 16),

        // 2. Alert Sensitivity Selector
        _buildSensitivitySelector(),
        const SizedBox(height: 16),

        // 3. Trusted Whitelist Apps
        _buildTrustedAppsCard(),
        const SizedBox(height: 20),

        // 4. Live Interception Stream
        _buildLiveEventStream(),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildSentryStatsOverview() {
    final service = ProtectionService.instance;

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Row(
                children: [
                  Icon(Icons.radar_rounded, color: AppColors.primary, size: 20),
                  SizedBox(width: 8),
                  Text(
                    'REAL-TIME SENTRY TELEMETRY',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w800,
                      fontSize: 13,
                      letterSpacing: 0.8,
                    ),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.safe.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppColors.safe.withValues(alpha: 0.4)),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.circle, color: AppColors.safe, size: 7),
                    SizedBox(width: 5),
                    Text(
                      'ACTIVE LISTENING',
                      style: TextStyle(
                        color: AppColors.safe,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: ValueListenableBuilder<int>(
                  valueListenable: service.totalInterceptedNotifier,
                  builder: (ctx, val, _) => _buildMetricCard(
                    title: 'Intercepted',
                    value: '$val',
                    color: AppColors.accent,
                    icon: Icons.hub_rounded,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ValueListenableBuilder<int>(
                  valueListenable: service.threatsBlockedNotifier,
                  builder: (ctx, val, _) => _buildMetricCard(
                    title: 'Threats Flagged',
                    value: '$val',
                    color: AppColors.danger,
                    icon: Icons.shield_rounded,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ValueListenableBuilder<int>(
                  valueListenable: service.safePassedNotifier,
                  builder: (ctx, val, _) => _buildMetricCard(
                    title: 'Safe Allowed',
                    value: '$val',
                    color: AppColors.safe,
                    icon: Icons.verified_user_rounded,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMetricCard({
    required String title,
    required String value,
    required Color color,
    required IconData icon,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                title,
                style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
              ),
              Icon(icon, size: 14, color: color),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 18,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSensitivitySelector() {
    final service = ProtectionService.instance;

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.tune_rounded, color: AppColors.primary, size: 18),
              SizedBox(width: 8),
              Text(
                'ALERT SENSITIVITY THRESHOLD',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontWeight: FontWeight.w700,
                  fontSize: 12,
                  letterSpacing: 0.6,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          const Text(
            'Calibrates real-time heuristic scoring thresholds to balance threat responsiveness with zero false alarm tolerance.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
          ),
          const SizedBox(height: 12),
          ValueListenableBuilder<String>(
            valueListenable: service.alertSensitivityNotifier,
            builder: (ctx, currentSensitivity, _) {
              return Row(
                children: [
                  for (final level in ['STANDARD', 'HIGH', 'MAXIMUM']) ...[
                    Expanded(
                      child: InkWell(
                        onTap: () {
                          service.alertSensitivityNotifier.value = level;
                        },
                        borderRadius: BorderRadius.circular(8),
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 8),
                          decoration: BoxDecoration(
                            color: currentSensitivity == level
                                ? AppColors.primary.withValues(alpha: 0.15)
                                : AppColors.surfaceLight,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: currentSensitivity == level
                                  ? AppColors.primary
                                  : AppColors.cardBorder,
                            ),
                          ),
                          child: Column(
                            children: [
                              Text(
                                level,
                                style: TextStyle(
                                  color: currentSensitivity == level
                                      ? AppColors.primary
                                      : AppColors.textSecondary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 11,
                                ),
                              ),
                              Text(
                                level == 'STANDARD'
                                    ? 'Score ≥ 60'
                                    : level == 'HIGH'
                                        ? 'Score ≥ 40'
                                        : 'Score ≥ 25',
                                style: TextStyle(
                                  color: currentSensitivity == level
                                      ? AppColors.primary
                                      : AppColors.textMuted,
                                  fontSize: 9,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                    if (level != 'MAXIMUM') const SizedBox(width: 6),
                  ],
                ],
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildTrustedAppsCard() {
    final service = ProtectionService.instance;

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Row(
                children: [
                  Icon(Icons.verified_rounded, color: AppColors.safe, size: 18),
                  SizedBox(width: 8),
                  Text(
                    'TRUSTED APP SOURCES (WHITELIST)',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 12,
                      letterSpacing: 0.6,
                    ),
                  ),
                ],
              ),
              CyberBadge(
                label: 'PROTECTED',
                type: BadgeType.safe,
              ),
            ],
          ),
          const SizedBox(height: 6),
          const Text(
            'Verified package identifiers bypass aggressive heuristic blocking to eliminate false positives on routine system notifications.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
          ),
          const SizedBox(height: 10),
          ValueListenableBuilder<List<String>>(
            valueListenable: service.trustedAppsNotifier,
            builder: (ctx, trustedList, _) {
              return Wrap(
                spacing: 6,
                runSpacing: 6,
                children: trustedList.map((pkg) {
                  return Chip(
                    label: Text(
                      pkg,
                      style: const TextStyle(fontSize: 10, color: AppColors.textPrimary),
                    ),
                    backgroundColor: AppColors.surfaceLight,
                    side: const BorderSide(color: AppColors.cardBorder),
                    avatar: const Icon(Icons.check_circle_outline, size: 14, color: AppColors.safe),
                  );
                }).toList(),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildLiveEventStream() {
    final service = ProtectionService.instance;

    return ValueListenableBuilder<List<ProtectionEventLogItem>>(
      valueListenable: service.recentEventsNotifier,
      builder: (ctx, events, _) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    const Text(
                      'REAL-TIME INTERCEPTION LOG',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.0,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                      decoration: BoxDecoration(
                        color: AppColors.surfaceLight,
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        '${events.length} Events',
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 10),
                      ),
                    ),
                  ],
                ),
                TextButton.icon(
                  icon: const Icon(Icons.flash_on_rounded, size: 14, color: AppColors.primary),
                  label: const Text(
                    'Simulate Test Vector',
                    style: TextStyle(fontSize: 11, color: AppColors.primary),
                  ),
                  onPressed: () {
                    service.recordEventLog(
                      type: 'notification',
                      source: 'com.fakebank.alert',
                      title: 'SBI Alert: KYC Pending',
                      rawContent:
                          'SBI Alert: Your NetBanking account will be blocked today! Update your KYC and verify OTP 849204 immediately at http://192.168.1.10/sbi-kyc',
                      riskScore: 88,
                      classification: 'Critical',
                      isSimulated: true,
                      recommendedAction: 'Do not click link or share OTP. Disconnect sender.',
                    );
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Simulated Smishing Vector dispatched to Live Sentry!'),
                        backgroundColor: AppColors.safe,
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                ),
              ],
            ),
            const SizedBox(height: 6),
            const Text(
              '🔒 Zero-Leak Privacy: OTPs and numeric sequences are automatically obscured (******).',
              style: TextStyle(color: AppColors.textMuted, fontSize: 10, fontStyle: FontStyle.italic),
            ),
            const SizedBox(height: 12),
            if (events.isEmpty)
              CyberShieldCard(
                padding: const EdgeInsets.all(24),
                child: Center(
                  child: Column(
                    children: [
                      const Icon(Icons.shield_outlined, size: 40, color: AppColors.textMuted),
                      const SizedBox(height: 10),
                      const Text(
                        'No Interception Events Recorded',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.w700,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 4),
                      const Text(
                        'Incoming notifications and screened calls will stream here automatically.',
                        style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 12),
                      ElevatedButton.icon(
                        icon: const Icon(Icons.science_rounded, size: 16),
                        label: const Text('Dispatch Test Smishing Vector'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.primary,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                        ),
                        onPressed: () {
                          service.recordEventLog(
                            type: 'notification',
                            source: 'com.bank.fraudalert',
                            title: 'HDFC Security Update',
                            rawContent:
                                'URGENT: HDFC Account suspended. OTP 918234 required to unlock at http://hdfc-verify.cc',
                            riskScore: 92,
                            classification: 'Critical',
                            isSimulated: true,
                            recommendedAction: 'Block sender and ignore phishing link.',
                          );
                        },
                      ),
                    ],
                  ),
                ),
              )
            else
              ...events.map((evt) => _buildEventCard(evt)),
          ],
        );
      },
    );
  }

  Widget _buildEventCard(ProtectionEventLogItem evt) {
    final isDanger = evt.riskScore >= 60;
    final isWarning = !isDanger && evt.riskScore >= 35;
    final badgeColor = isDanger
        ? AppColors.danger
        : (isWarning ? AppColors.warning : AppColors.safe);

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: CyberShieldCard(
        borderColor: badgeColor.withValues(alpha: 0.4),
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Expanded(
                  child: Row(
                    children: [
                      Icon(
                        evt.type == 'call'
                            ? Icons.phone_callback_rounded
                            : Icons.mark_chat_unread_rounded,
                        size: 16,
                        color: badgeColor,
                      ),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          evt.title,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w700,
                            fontSize: 12,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (evt.isSimulated) ...[
                        const SizedBox(width: 6),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                          decoration: BoxDecoration(
                            color: AppColors.accent.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text(
                            'SIMULATED',
                            style: TextStyle(
                              color: AppColors.accent,
                              fontSize: 9,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                CyberBadge(
                  label: '${evt.riskScore}/100 ${evt.classification.toUpperCase()}',
                  type: isDanger
                      ? BadgeType.danger
                      : (isWarning ? BadgeType.warning : BadgeType.safe),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              'Source: ${evt.source} • ${_formatEventTime(evt.timestamp)}',
              style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppColors.cardBorder),
              ),
              child: Text(
                evt.maskedContent,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            if (evt.recommendedAction != null) ...[
              const SizedBox(height: 6),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('→ ', style: TextStyle(color: AppColors.primary, fontSize: 11)),
                  Expanded(
                    child: Text(
                      evt.recommendedAction!,
                      style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                    ),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    side: const BorderSide(color: AppColors.primary),
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    minimumSize: const Size(0, 28),
                  ),
                  icon: const Icon(Icons.bolt_rounded, size: 13, color: AppColors.primary),
                  label: const Text(
                    'Consult CYBOR',
                    style: TextStyle(fontSize: 11, color: AppColors.primary),
                  ),
                  onPressed: () {
                    Navigator.pushNamed(
                      context,
                      AppRouter.aiAssistant,
                      arguments: {
                        'scan_type': evt.type == 'call' ? 'SPAM_CALLER' : 'NOTIFICATION',
                        'target': evt.title,
                        'risk_score': evt.riskScore,
                        'classification': evt.classification,
                        'details': {
                          'source': evt.source,
                          'payload': evt.maskedContent,
                          'recommended_action': evt.recommendedAction,
                        },
                      },
                    );
                  },
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _formatEventTime(DateTime dt) {
    final hour = dt.hour.toString().padLeft(2, '0');
    final min = dt.minute.toString().padLeft(2, '0');
    final sec = dt.second.toString().padLeft(2, '0');
    return '$hour:$min:$sec';
  }
}
