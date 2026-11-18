// CyberShield Communication Detail Screen
// Displays full risk percentage, threat categories, findings, explanation,
// privacy disclosures, and deletion controls for a single communication record.

import 'package:flutter/material.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/services/communication_service.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class CommunicationDetailScreen extends StatelessWidget {
  final CommunicationRecord record;

  const CommunicationDetailScreen({super.key, required this.record});

  Color _riskColor() {
    if (!record.isAnalyzed) return AppColors.textMuted;
    if (record.riskScore >= 81) return AppColors.danger;
    if (record.riskScore >= 61) return const Color(0xFFFF6D00);
    if (record.riskScore >= 41) return AppColors.warning;
    if (record.riskScore >= 21) return AppColors.info;
    return AppColors.safe;
  }

  BadgeType _badgeType() {
    if (!record.isAnalyzed) return BadgeType.neutral;
    if (record.riskScore >= 61) return BadgeType.danger;
    if (record.riskScore >= 41) return BadgeType.warning;
    if (record.riskScore >= 21) return BadgeType.info;
    return BadgeType.safe;
  }

  String _formatDateTime(DateTime dt) {
    final y = dt.year.toString().padLeft(4, '0');
    final mo = dt.month.toString().padLeft(2, '0');
    final d = dt.day.toString().padLeft(2, '0');
    final h = dt.hour.toString().padLeft(2, '0');
    final mi = dt.minute.toString().padLeft(2, '0');
    return '$y-$mo-$d  $h:$mi';
  }

  Future<void> _confirmDelete(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: const Text('Delete Record?', style: TextStyle(color: AppColors.textPrimary)),
        content: const Text(
          'This communication record will be permanently deleted from your device, Firestore cloud history, and backend.',
          style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete', style: TextStyle(color: AppColors.danger)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await CommunicationService.instance.deleteRecord(record.recordId);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Communication record deleted.'),
            backgroundColor: AppColors.safe,
          ),
        );
        Navigator.pop(context, true);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final color = _riskColor();

    return Scaffold(
      appBar: AppBar(
        title: Text(record.isCall ? 'Call Risk Details' : 'Message Risk Details'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline_rounded, color: AppColors.danger),
            tooltip: 'Delete record',
            onPressed: () => _confirmDelete(context),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Risk Score Header Card
          CyberShieldCard(
            borderColor: color.withValues(alpha: 0.45),
            hasGlow: record.isThreatFlagged,
            child: Row(
              children: [
                Container(
                  width: 72,
                  height: 72,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: AppColors.background,
                    border: Border.all(color: color, width: 3),
                  ),
                  child: Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          record.isAnalyzed ? '${record.riskScore}%' : 'N/A',
                          style: TextStyle(
                            color: color,
                            fontSize: 18,
                            fontWeight: FontWeight.w900,
                          ),
                        ),
                        const Text(
                          'RISK',
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
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Wrap(
                        spacing: 6,
                        runSpacing: 4,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          CyberBadge(
                            label: record.classification.toUpperCase(),
                            type: _badgeType(),
                          ),
                          CyberBadge(
                            label: record.sourceApp.toUpperCase(),
                            type: BadgeType.info,
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        record.displayTitle,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      if (record.isCall && record.callerName != null && record.callerName!.isNotEmpty)
                        Text(
                          record.senderIdentifier,
                          style: const TextStyle(color: AppColors.textSecondary, fontSize: 12),
                        ),
                      const SizedBox(height: 4),
                      Text(
                        _formatDateTime(record.timestamp),
                        style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          if (record.isCall) ...[
            const SizedBox(height: 12),
            CyberShieldCard(
              borderColor: AppColors.info.withValues(alpha: 0.35),
              padding: const EdgeInsets.all(12),
              child: const Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.privacy_tip_outlined, color: AppColors.info, size: 18),
                  SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Caller Reputation Only: Risk percentage is evaluated from phone number spam intelligence and contact metadata. CyberShield never records or analyzes call audio.',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 11, height: 1.4),
                    ),
                  ),
                ],
              ),
            ),
          ],

          const SizedBox(height: 14),

          // Metadata Card
          CyberShieldCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Communication Metadata',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 10),
                _metaRow('Type', record.communicationType.toUpperCase()),
                _metaRow('Source Application', record.sourceApp),
                _metaRow('Sender / Number', record.senderIdentifier),
                _metaRow('Analysis Status', record.analysisStatus.toUpperCase()),
                if (record.isCall) ...[
                  _metaRow('Call Status', (record.callStatus ?? 'incoming').toUpperCase()),
                  _metaRow(
                    'Contact Status',
                    record.isKnownContact == true
                        ? 'Known Contact'
                        : (record.isKnownContact == false ? 'Unknown Caller' : 'Not Checked'),
                  ),
                  _metaRow('Spam Reputation', (record.spamReputation ?? 'unknown').replaceAll('_', ' ')),
                ],
              ],
            ),
          ),

          const SizedBox(height: 14),

          // Preview Card
          CyberShieldCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Content Preview',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  record.messagePreview.isNotEmpty
                      ? record.messagePreview
                      : 'Preview hidden per user privacy preferences or unavailable.',
                  style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 13,
                    height: 1.45,
                  ),
                ),
                if (record.metadata['was_redacted'] == true) ...[
                  const SizedBox(height: 8),
                  const Text(
                    'Sensitive tokens (OTPs, card digits, or passwords) were automatically redacted on-device.',
                    style: TextStyle(color: AppColors.primary, fontSize: 11),
                  ),
                ],
              ],
            ),
          ),

          if (record.threatCategories.isNotEmpty) ...[
            const SizedBox(height: 14),
            CyberShieldCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Detected Threat Categories',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: record.threatCategories
                        .map((c) => CyberBadge(
                              label: c.replaceAll('_', ' ').toUpperCase(),
                              type: _badgeType(),
                            ))
                        .toList(),
                  ),
                ],
              ),
            ),
          ],

          const SizedBox(height: 14),

          // Analysis Explanation & Findings
          CyberShieldCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Analysis Explanation & Findings',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  record.explanation.isNotEmpty
                      ? record.explanation
                      : 'No additional analysis explanation recorded.',
                  style: const TextStyle(color: AppColors.textSecondary, fontSize: 13, height: 1.45),
                ),
                if (record.findings.isNotEmpty) ...[
                  const SizedBox(height: 10),
                  const Divider(color: AppColors.cardBorder, height: 1),
                  const SizedBox(height: 10),
                  ...record.findings.map(
                    (f) => Padding(
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(Icons.shield_outlined, size: 15, color: color),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              f,
                              style: const TextStyle(color: AppColors.textPrimary, fontSize: 12),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),

          const SizedBox(height: 14),

          // Recommended Action Card
          CyberShieldCard(
            borderColor: AppColors.primary.withValues(alpha: 0.35),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.verified_user_rounded, color: AppColors.primary, size: 18),
                    SizedBox(width: 8),
                    Text(
                      'Recommended Action',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  record.recommendedAction.isNotEmpty
                      ? record.recommendedAction
                      : 'No special action required.',
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 13, height: 1.4),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Widget _metaRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 12)),
          const SizedBox(width: 12),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.end,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}
