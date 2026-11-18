// CyberShield Communication Monitoring & Privacy Settings Screen
// Granular per-source consent controls (SMS, Notifications, WhatsApp, Calls, Gmail),
// Android runtime permission triggers, retention policies, and data deletion.

import 'package:flutter/material.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/services/gmail_service.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class CommunicationSettingsScreen extends StatefulWidget {
  const CommunicationSettingsScreen({super.key});

  @override
  State<CommunicationSettingsScreen> createState() => _CommunicationSettingsScreenState();
}

class _CommunicationSettingsScreenState extends State<CommunicationSettingsScreen>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    CommunicationService.instance.refreshPermissions();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      CommunicationService.instance.refreshPermissions();
    }
  }

  Future<void> _requestPermission(String type, String label) async {
    final res = await CommunicationService.instance.requestNativePermission(type);
    if (!mounted) return;
    final granted = res['granted'] == true;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          granted
              ? '$label permission granted.'
              : (res['message']?.toString() ?? '$label permission was not granted.'),
        ),
        backgroundColor: granted ? AppColors.safe : AppColors.warning,
      ),
    );
  }

  Future<void> _applyRetention() async {
    final days = CommunicationService.instance.settingsNotifier.value.retentionDays;
    final deleted = await CommunicationService.instance.applyRetentionCleanup(daysOverride: days);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Retention cleanup complete: $deleted old record(s) removed (>$days days).'),
        backgroundColor: AppColors.safe,
      ),
    );
  }

  Future<void> _confirmPurgeAll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: const Text('Delete All Communication History?',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 16)),
        content: const Text(
          'This permanently deletes all recorded SMS, notification, call, and email threat logs from your device, Firestore, and backend.',
          style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete All', style: TextStyle(color: AppColors.danger)),
          ),
        ],
      ),
    );

    if (ok == true) {
      final count = await CommunicationService.instance.clearAllHistory();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Deleted $count communication history record(s).'),
          backgroundColor: AppColors.safe,
        ),
      );
    }
  }

  void _showTransparencyNotice() {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: const Text(
          'Communication Privacy & Transparency',
          style: TextStyle(color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.bold),
        ),
        content: const SingleChildScrollView(
          child: Text(
            '1. What is accessed: Only eligible SMS messages, notification text from approved apps, incoming call metadata (phone number/timestamp/contact match), and authorized Gmail messages when individually enabled.\n\n'
            '2. Why it is accessed: To calculate an accurate 0–100% cyber threat score (phishing links, smishing, robocall reputation) and show your unified security history.\n\n'
            '3. What is stored: Redacted previews (if enabled), sender identifiers, timestamps, risk percentages, and explanations — strictly isolated to your authenticated account.\n\n'
            '4. What is sent to backend: Redacted text or phone numbers over authenticated HTTPS/API calls. OTPs, card numbers, CVVs, and passwords are redacted on-device first. Call audio is NEVER accessed or analyzed.\n\n'
            '5. Retention: Controlled by your retention setting (7–365 days).\n\n'
            '6. Pause / Disable: Use "Pause All Monitoring" or disable any individual channel anytime.\n\n'
            '7. Delete Data: Delete individual items or purge all stored records instantly from this screen.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.45),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Understood', style: TextStyle(color: AppColors.primary)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final service = CommunicationService.instance;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Monitoring & Privacy Settings'),
        actions: [
          IconButton(
            icon: const Icon(Icons.privacy_tip_outlined, color: AppColors.primary),
            tooltip: 'Privacy & Transparency Notice',
            onPressed: _showTransparencyNotice,
          ),
        ],
      ),
      body: ValueListenableBuilder<CommunicationSettings>(
        valueListenable: service.settingsNotifier,
        builder: (context, settings, _) {
          return ValueListenableBuilder<CommunicationPermissionsStatus>(
            valueListenable: service.permissionsNotifier,
            builder: (context, perms, _) {
              return ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // Master Pause Control
                  CyberShieldCard(
                    borderColor: settings.monitoringPaused
                        ? AppColors.warning.withValues(alpha: 0.5)
                        : AppColors.primary.withValues(alpha: 0.4),
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                    child: SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      activeThumbColor: AppColors.warning,
                      title: const Text(
                        'Pause All Communication Monitoring',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      subtitle: Text(
                        settings.monitoringPaused
                            ? 'Monitoring is paused. No new communications are recorded.'
                            : 'Monitoring active for your individually enabled channels.',
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                      ),
                      value: settings.monitoringPaused,
                      onChanged: (v) => service.updateSettings(settings.copyWith(monitoringPaused: v)),
                    ),
                  ),

                  const SizedBox(height: 18),
                  const Text(
                    'Per-Channel Consent & Android Permissions',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 10),

                  // 1. SMS Channel
                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.sms_rounded, color: AppColors.primary, size: 20),
                            const SizedBox(width: 8),
                            const Expanded(
                              child: Text(
                                'Incoming SMS Messages',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                              ),
                            ),
                            CyberBadge(
                              label: perms.hasSmsPermission ? 'GRANTED' : 'PERMISSION NEEDED',
                              type: perms.hasSmsPermission ? BadgeType.safe : BadgeType.warning,
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'Analyzes eligible incoming SMS messages for phishing links and scam patterns. OTPs & card digits are redacted on-device.',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          activeThumbColor: AppColors.primary,
                          title: const Text('Monitor & Record SMS',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                          value: settings.monitorSms,
                          onChanged: (v) async {
                            await service.updateSettings(
                              settings.copyWith(monitorSms: v, consentAcknowledged: true),
                            );
                            if (v && !perms.hasSmsPermission) {
                              await _requestPermission('sms', 'SMS');
                            }
                          },
                        ),
                        if (!perms.hasSmsPermission)
                          OutlinedButton.icon(
                            onPressed: () => _requestPermission('sms', 'SMS'),
                            icon: const Icon(Icons.lock_open_rounded, size: 15),
                            label: const Text('Grant SMS Permission', style: TextStyle(fontSize: 11)),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 10),

                  // 2. Notification & WhatsApp Channel
                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.notifications_active_rounded, color: AppColors.primary, size: 20),
                            const SizedBox(width: 8),
                            const Expanded(
                              child: Text(
                                'Notifications & WhatsApp Alerts',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                              ),
                            ),
                            CyberBadge(
                              label: perms.notificationAccess ? 'ACTIVE' : 'ENABLE ACCESS',
                              type: perms.notificationAccess ? BadgeType.safe : BadgeType.warning,
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'Analyzes eligible notifications from user-approved apps (including WhatsApp notifications) without accessing private app databases.',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          activeThumbColor: AppColors.primary,
                          title: const Text('Monitor App Notifications',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                          value: settings.monitorNotifications,
                          onChanged: (v) => service.updateSettings(
                            settings.copyWith(monitorNotifications: v, consentAcknowledged: true),
                          ),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          activeThumbColor: AppColors.primary,
                          title: const Text('Monitor WhatsApp Notifications',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                          value: settings.monitorWhatsapp,
                          onChanged: (v) => service.updateSettings(
                            settings.copyWith(monitorWhatsapp: v, consentAcknowledged: true),
                          ),
                        ),
                        if (!perms.notificationAccess)
                          OutlinedButton.icon(
                            onPressed: () => ProtectionService.instance.openNotificationListenerSettings(),
                            icon: const Icon(Icons.settings_rounded, size: 15),
                            label: const Text('Open Notification Access Settings', style: TextStyle(fontSize: 11)),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 10),

                  // 3. Incoming Calls Channel
                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.phone_in_talk_rounded, color: AppColors.secondary, size: 20),
                            const SizedBox(width: 8),
                            const Expanded(
                              child: Text(
                                'Call History Analysis (Metadata Only)',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                              ),
                            ),
                            CyberBadge(
                              label: perms.hasCallMetadataPermission
                                  ? 'LOG ACCESS'
                                  : 'PERMISSION NEEDED',
                              type: perms.hasCallMetadataPermission
                                  ? BadgeType.safe
                                  : BadgeType.warning,
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        Text(
                          perms.callScreeningSupported
                              ? 'Supports Android 10+ automatic CallScreeningService AND permission-gated Call Log history analysis. Call audio is NEVER accessed.'
                              : 'Native Call Screening Unsupported on This Device (Android ${perms.androidRelease ?? perms.androidSdk}, API ${perms.androidSdk} < 29). Calls are NOT automatically blocked or screened on Android 9. Optional Call History analysis works only when Call Log permission and accessible records are granted. Call audio is NEVER accessed.',
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 11, height: 1.35),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          activeThumbColor: AppColors.secondary,
                          title: const Text('Monitor & Record Incoming Calls',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                          value: settings.monitorCalls,
                          onChanged: (v) async {
                            await service.updateSettings(
                              settings.copyWith(monitorCalls: v, consentAcknowledged: true),
                            );
                            if (v && !perms.hasCallMetadataPermission) {
                              await _requestPermission('call_log', 'Call Log & Phone State');
                            }
                          },
                        ),
                        Wrap(
                          spacing: 8,
                          runSpacing: 6,
                          children: [
                            if (!perms.hasCallMetadataPermission)
                              OutlinedButton.icon(
                                onPressed: () => _requestPermission('call_log', 'Call Log & Phone State'),
                                icon: const Icon(Icons.call_rounded, size: 14),
                                label: const Text('Grant Call Log Access', style: TextStyle(fontSize: 11)),
                              ),
                            if (!perms.readContacts)
                              OutlinedButton.icon(
                                onPressed: () => _requestPermission('contacts', 'Contacts'),
                                icon: const Icon(Icons.contacts_rounded, size: 14),
                                label: const Text('Known Contact Check', style: TextStyle(fontSize: 11)),
                              ),
                            if (perms.callScreeningSupported && !perms.callScreeningRole)
                              OutlinedButton.icon(
                                onPressed: () => ProtectionService.instance.requestCallScreeningRole(),
                                icon: const Icon(Icons.shield_outlined, size: 14),
                                label: const Text('Set Call Screening Role', style: TextStyle(fontSize: 11)),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 10),

                  // 4. Gmail Channel
                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.mark_email_read_rounded, color: AppColors.primary, size: 20),
                            const SizedBox(width: 8),
                            const Expanded(
                              child: Text(
                                'Gmail Notifications & Authorized Inbox',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                              ),
                            ),
                            CyberBadge(
                              label: GmailService.instance.isConnected ? 'OAUTH CONNECTED' : 'NOTIF ONLY',
                              type: GmailService.instance.isConnected ? BadgeType.safe : BadgeType.info,
                            ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'Notification access only sees Gmail notifications — full Gmail inbox inspection requires separate Google OAuth consent in Email Scanner.',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          activeThumbColor: AppColors.primary,
                          title: const Text('Record Analyzed Gmail Messages',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                          value: settings.monitorEmail,
                          onChanged: (v) => service.updateSettings(
                            settings.copyWith(monitorEmail: v, consentAcknowledged: true),
                          ),
                        ),
                        OutlinedButton.icon(
                          onPressed: () => Navigator.pushNamed(context, AppRouter.emailScanner),
                          icon: const Icon(Icons.mail_outline_rounded, size: 14),
                          label: const Text('Manage Gmail OAuth in Email Scanner', style: TextStyle(fontSize: 11)),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 18),
                  const Text(
                    'Privacy, Alerts & Data Retention',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 10),

                  CyberShieldCard(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                    child: Column(
                      children: [
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          activeThumbColor: AppColors.primary,
                          title: const Text('Store Redacted Message Previews',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                          subtitle: const Text(
                            'Disable to store only metadata & threat scores with zero message text.',
                            style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                          ),
                          value: settings.storeMessagePreview,
                          onChanged: (v) => service.updateSettings(settings.copyWith(storeMessagePreview: v)),
                        ),
                        const Divider(color: AppColors.cardBorder, height: 1),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          activeThumbColor: AppColors.warning,
                          title: const Text('Alert on Suspicious Communications (41–60%)',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                          value: settings.alertOnSuspicious,
                          onChanged: (v) => service.updateSettings(settings.copyWith(alertOnSuspicious: v)),
                        ),
                        const Divider(color: AppColors.cardBorder, height: 1),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          activeThumbColor: AppColors.danger,
                          title: const Text('Alert on High-Risk & Critical Threats (61–100%)',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 13)),
                          value: settings.alertOnHighRisk,
                          onChanged: (v) => service.updateSettings(settings.copyWith(alertOnHighRisk: v)),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 12),

                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'History Retention Policy',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          children: [7, 30, 90, 365].map((days) {
                            final selected = settings.retentionDays == days;
                            return ChoiceChip(
                              label: Text('$days Days', style: const TextStyle(fontSize: 11)),
                              selected: selected,
                              selectedColor: AppColors.primary.withValues(alpha: 0.25),
                              onSelected: (_) =>
                                  service.updateSettings(settings.copyWith(retentionDays: days)),
                            );
                          }).toList(),
                        ),
                        const SizedBox(height: 12),
                        Row(
                          children: [
                            Expanded(
                              child: OutlinedButton.icon(
                                onPressed: _applyRetention,
                                icon: const Icon(Icons.auto_delete_outlined, size: 16),
                                label: const Text('Apply Retention', style: TextStyle(fontSize: 12)),
                              ),
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: OutlinedButton.icon(
                                style: OutlinedButton.styleFrom(
                                  foregroundColor: AppColors.danger,
                                  side: const BorderSide(color: AppColors.danger),
                                ),
                                onPressed: _confirmPurgeAll,
                                icon: const Icon(Icons.delete_forever_rounded, size: 16),
                                label: const Text('Purge All', style: TextStyle(fontSize: 12)),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 24),
                ],
              );
            },
          );
        },
      ),
    );
  }
}
