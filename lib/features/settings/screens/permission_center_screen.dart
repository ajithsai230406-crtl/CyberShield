// CyberShield Permission Center
// Provides transparent 5-state tracking and configuration for all device security permissions
// with zero-leak privacy guarantees and on-device redaction disclosures.

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/navigation/app_router.dart';

enum PermissionState {
  granted,
  denied,
  permanentlyDenied,
  notRequested,
  notApplicable,
}

class PermissionCenterScreen extends StatefulWidget {
  const PermissionCenterScreen({super.key});

  @override
  State<PermissionCenterScreen> createState() => _PermissionCenterScreenState();
}

class _PermissionCenterScreenState extends State<PermissionCenterScreen>
    with WidgetsBindingObserver {
  bool _notifGranted = false;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refreshPermissions();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _refreshPermissions();
    }
  }

  Future<void> _handleRequestCallRole() async {
    final result = await ProtectionService.instance.requestCallScreeningRole();
    await _refreshPermissions();
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

  Future<void> _refreshPermissions() async {
    setState(() => _isLoading = true);
    final notif = await ProtectionService.instance.isNotificationPermissionGranted();
    await ProtectionService.instance.refreshStatus();
    if (mounted) {
      setState(() {
        _notifGranted = notif;
        _isLoading = false;
      });
    }
  }

  BadgeType _badgeTypeFor(PermissionState state) {
    switch (state) {
      case PermissionState.granted:
        return BadgeType.safe;
      case PermissionState.denied:
        return BadgeType.danger;
      case PermissionState.permanentlyDenied:
        return BadgeType.danger;
      case PermissionState.notRequested:
        return BadgeType.warning;
      case PermissionState.notApplicable:
        return BadgeType.info;
    }
  }

  String _labelFor(PermissionState state) {
    switch (state) {
      case PermissionState.granted:
        return 'GRANTED';
      case PermissionState.denied:
        return 'DENIED';
      case PermissionState.permanentlyDenied:
        return 'SETTINGS REQUIRED';
      case PermissionState.notRequested:
        return 'NOT REQUESTED';
      case PermissionState.notApplicable:
        return 'NOT APPLICABLE';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Permission Center'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: _isLoading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                  )
                : const Icon(Icons.refresh_rounded, color: AppColors.primary),
            onPressed: _refreshPermissions,
            tooltip: 'Re-audit Permissions',
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: ValueListenableBuilder<ProtectionStatus>(
        valueListenable: ProtectionService.instance.statusNotifier,
        builder: (context, status, _) {
          return SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(18, 16, 18, 40),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildHeaderCard(),
                const SizedBox(height: 18),
                const Text(
                  'ACTIVE DEFENSE PERMISSIONS',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
                const SizedBox(height: 10),

                // 1. High-Priority Notifications
                _buildPermissionCard(
                  icon: Icons.notifications_active_rounded,
                  title: 'High-Priority Threat Alerts',
                  state: _notifGranted ? PermissionState.granted : PermissionState.notRequested,
                  category: 'SYSTEM NOTIFICATION',
                  description:
                      'Required to instantly alert you when a phishing URL, trojan APK, smishing attack, or rogue permission is detected in real time.',
                  privacyDisclosure:
                      'CyberShield only posts security threat notifications. We never send promotional ads or spam.',
                  actionButton: _notifGranted
                      ? null
                      : ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppColors.primary,
                            foregroundColor: Colors.black,
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                          ),
                          onPressed: () async {
                            await ProtectionService.instance.requestNotificationPermission();
                            await _refreshPermissions();
                          },
                          child: const Text('Request Permission', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                        ),
                ),
                const SizedBox(height: 12),

                // 2. Real-Time Notification Guard (Phishing & Smishing)
                _buildPermissionCard(
                  icon: Icons.mark_email_read_rounded,
                  title: 'Notification Threat Guard',
                  state: status.isNotificationAccessGranted ? PermissionState.granted : PermissionState.notRequested,
                  category: 'NOTIFICATION LISTENER',
                  description:
                      'Inspects incoming notifications from messaging apps, SMS, and browsers to flag malicious links before you tap them.',
                  privacyDisclosure:
                      'Zero-Leak Promise: Sensitive OTPs, bank authorization codes, and passwords are automatically redacted on-device. Raw notification bodies are never stored or transmitted.',
                  actionButton: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: BorderSide(
                        color: status.isNotificationAccessGranted ? AppColors.safe : AppColors.primary,
                      ),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onPressed: () async {
                      await ProtectionService.instance.openNotificationListenerSettings();
                      await _refreshPermissions();
                    },
                    icon: Icon(
                      status.isNotificationAccessGranted ? Icons.check_circle_rounded : Icons.launch_rounded,
                      size: 14,
                      color: status.isNotificationAccessGranted ? AppColors.safe : AppColors.primary,
                    ),
                    label: Text(
                      status.isNotificationAccessGranted ? 'Active in Settings' : 'Open System Settings',
                      style: TextStyle(
                        fontSize: 12,
                        color: status.isNotificationAccessGranted ? AppColors.safe : AppColors.primary,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 12),

                // 3. Call Screening (Fraud / Vishing)
                ValueListenableBuilder<bool>(
                  valueListenable: ProtectionService.instance.isRequestingCallRoleNotifier,
                  builder: (context, isRequestingRole, _) {
                    final supported = status.isCallScreeningSupported;
                    final held = supported && status.isCallScreeningRoleHeld;
                    final sdkText = status.androidSdk > 0
                        ? 'Android ${status.androidRelease ?? status.androidSdk} (API ${status.androidSdk})'
                        : 'API < 29';
                    return _buildPermissionCard(
                      icon: Icons.phone_callback_rounded,
                      title: supported
                          ? 'Automatic Call Screening (Android 10+)'
                          : 'Native Call Screening Unsupported on This Device',
                      state: held
                          ? PermissionState.granted
                          : (supported ? PermissionState.notRequested : PermissionState.notApplicable),
                      category: supported ? 'TELECOM ROLE (API 29+)' : 'UNSUPPORTED ON $sdkText',
                      description: supported
                          ? 'Automatically screens incoming caller IDs via official Android 10+ CallScreeningService against verified CyberShield threat intelligence.'
                          : 'Native Call Screening Unsupported on This Device ($sdkText). Automatic incoming call blocking/screening requires Android 10 (API 29)+. Manual phone-number checks and permission-gated Call History analysis remain available.',
                      privacyDisclosure:
                          'CyberShield NEVER records, listens to, or intercepts call audio. On Android 9, calls are never automatically blocked or screened.',
                      actionButton: supported
                          ? OutlinedButton.icon(
                              style: OutlinedButton.styleFrom(
                                side: BorderSide(
                                  color: held ? AppColors.safe : AppColors.primary,
                                ),
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              ),
                              onPressed: (held || isRequestingRole) ? null : _handleRequestCallRole,
                              icon: isRequestingRole
                                  ? const SizedBox(
                                      width: 14,
                                      height: 14,
                                      child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                                    )
                                  : Icon(
                                      held ? Icons.check_circle_rounded : Icons.security_rounded,
                                      size: 14,
                                      color: held ? AppColors.safe : AppColors.primary,
                                    ),
                              label: Text(
                                held ? 'Active' : 'Set Role',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: held ? AppColors.safe : AppColors.primary,
                                ),
                              ),
                            )
                          : OutlinedButton.icon(
                              style: OutlinedButton.styleFrom(
                                side: const BorderSide(color: AppColors.primary),
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              ),
                              onPressed: () => Navigator.pushNamed(context, AppRouter.protection),
                              icon: const Icon(Icons.search_rounded, size: 14, color: AppColors.primary),
                              label: const Text(
                                'Manual Number Check',
                                style: TextStyle(fontSize: 12, color: AppColors.primary),
                              ),
                            ),
                    );
                  },
                ),
                const SizedBox(height: 12),

                // 4. SMS Threat Scanner
                _buildPermissionCard(
                  icon: Icons.sms_rounded,
                  title: 'SMS Smishing Analysis',
                  state: PermissionState.notApplicable,
                  category: 'ON-DEMAND / INTENT',
                  description:
                      'Analyzes suspicious SMS messages for spoofed sender IDs, urgency cues, fake banking portals, and malicious shortlinks.',
                  privacyDisclosure:
                      'CyberShield relies on user-initiated paste and share intents. We do not demand default SMS app replacement, ensuring maximum user control and Google Play policy compliance.',
                  actionButton: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onPressed: () => Navigator.pushNamed(context, AppRouter.smsScanner),
                    icon: const Icon(Icons.arrow_forward_rounded, size: 14, color: AppColors.primary),
                    label: const Text('Open SMS Scanner', style: TextStyle(fontSize: 12, color: AppColors.primary)),
                  ),
                ),
                const SizedBox(height: 12),

                // 5. Gmail Security Scanner
                _buildPermissionCard(
                  icon: Icons.mail_lock_rounded,
                  title: 'Gmail Inbox Inspector',
                  state: PermissionState.notApplicable,
                  category: 'OAUTH 2.0 (READ-ONLY)',
                  description:
                      'Audits suspicious inbox emails for spear phishing, domain spoofing, and malicious links via explicit user consent.',
                  privacyDisclosure:
                      'Restricted Scope: CyberShield only requests temporary, read-only metadata. Email bodies are evaluated on-device and never stored permanently on our backend. Access can be revoked anytime.',
                  actionButton: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onPressed: () => Navigator.pushNamed(context, AppRouter.emailScanner),
                    icon: const Icon(Icons.arrow_forward_rounded, size: 14, color: AppColors.primary),
                    label: const Text('Open Email Scanner', style: TextStyle(fontSize: 12, color: AppColors.primary)),
                  ),
                ),
                const SizedBox(height: 12),

                // 6. APK & File Auditor
                _buildPermissionCard(
                  icon: Icons.android_rounded,
                  title: 'APK & File Static Auditor',
                  state: PermissionState.granted,
                  category: 'STORAGE ACCESS FRAMEWORK',
                  description:
                      'Audits Android application packages (.apk) and suspicious files for dangerous manifests, overlay permissions, and malware signatures.',
                  privacyDisclosure:
                      'Scoped Access: Only files explicitly selected by the user through Android SAF file picker are accessed. CyberShield never scans private personal photos or documents.',
                  actionButton: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onPressed: () => Navigator.pushNamed(context, AppRouter.apkAnalysis),
                    icon: const Icon(Icons.arrow_forward_rounded, size: 14, color: AppColors.primary),
                    label: const Text('Open APK Analyzer', style: TextStyle(fontSize: 12, color: AppColors.primary)),
                  ),
                ),
                const SizedBox(height: 12),

                // 7. Background Execution & Battery Optimization
                _buildPermissionCard(
                  icon: Icons.battery_saver_rounded,
                  title: 'Continuous Background Shield',
                  state: status.isMasterEnabled ? PermissionState.granted : PermissionState.notRequested,
                  category: 'BATTERY & SERVICE',
                  description:
                      'Allows the notification threat listener and call screening engine to stay active during low-power standby mode.',
                  privacyDisclosure:
                      'Minimal Overhead: Background checks only trigger on incoming alert events, using under 1% battery per day.',
                  actionButton: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    onPressed: () => Navigator.pushNamed(context, AppRouter.protection),
                    icon: const Icon(Icons.shield_rounded, size: 14, color: AppColors.primary),
                    label: const Text('Manage in Defense Hub', style: TextStyle(fontSize: 12, color: AppColors.primary)),
                  ),
                ),
                const SizedBox(height: 20),

                // Legal links
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceSubtle,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.cardBorder),
                  ),
                  child: Wrap(
                    alignment: WrapAlignment.center,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    spacing: 8,
                    runSpacing: 4,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.pushNamed(context, AppRouter.privacyPolicy),
                        child: const Text('Privacy Policy', style: TextStyle(color: AppColors.primary, fontSize: 12)),
                      ),
                      TextButton(
                        onPressed: () => Navigator.pushNamed(context, AppRouter.terms),
                        child: const Text('Terms of Use', style: TextStyle(color: AppColors.primary, fontSize: 12)),
                      ),
                      TextButton(
                        onPressed: () => Navigator.pushNamed(context, AppRouter.safetyCenter),
                        child: const Text('Safety Center', style: TextStyle(color: AppColors.primary, fontSize: 12)),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildHeaderCard() {
    return CyberShieldCard(
      borderColor: AppColors.primary.withValues(alpha: 0.35),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.15),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.verified_user_rounded, color: AppColors.primary, size: 24),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Zero-Trust Privacy Philosophy',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    SizedBox(height: 2),
                    Text(
                      'All permissions are optional, revocable, and audited.',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          const Divider(color: AppColors.cardBorder, height: 1),
          const SizedBox(height: 10),
          const Text(
            'CyberShield operates on the principle of least privilege. If you deny a permission, the app never crashes—it gracefully adapts by offering on-demand manual alternatives.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
          ),
        ],
      ),
    );
  }

  Widget _buildPermissionCard({
    required IconData icon,
    required String title,
    required PermissionState state,
    required String category,
    required String description,
    required String privacyDisclosure,
    Widget? actionButton,
  }) {
    final badgeType = _badgeTypeFor(state);
    final label = _labelFor(state);

    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(icon, color: AppColors.primary, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Expanded(
                          child: Text(
                            title,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontWeight: FontWeight.w700,
                              fontSize: 14,
                            ),
                          ),
                        ),
                        CyberBadge(label: label, type: badgeType),
                      ],
                    ),
                    const SizedBox(height: 2),
                    Text(
                      category,
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.5,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            description,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              height: 1.35,
            ),
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.cardBorder.withValues(alpha: 0.5)),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.lock_outline_rounded, size: 14, color: AppColors.safe),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    privacyDisclosure,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      height: 1.35,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
              ],
            ),
          ),
          if (actionButton != null) ...[
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: actionButton,
            ),
          ],
        ],
      ),
    );
  }
}
