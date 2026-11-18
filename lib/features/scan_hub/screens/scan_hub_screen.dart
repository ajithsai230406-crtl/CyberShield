// CyberShield Scanner Hub — Unified Threat Detection Launchpad

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/navigation/app_router.dart';

class ScanHubScreen extends StatelessWidget {
  const ScanHubScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.radar_rounded, color: AppColors.primary, size: 22),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                'Threat Detection Hub',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 16, 18, 80),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Top banner
            CyberShieldCard(
              padding: const EdgeInsets.all(16),
              borderColor: AppColors.primary.withValues(alpha: 0.3),
              child: Row(
                children: [
                  Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: AppColors.primary.withValues(alpha: 0.15),
                      shape: BoxShape.circle,
                      border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
                    ),
                    child: const Icon(Icons.shield_outlined, color: AppColors.primary, size: 24),
                  ),
                  const SizedBox(width: 14),
                  const Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Multi-Vector Threat Defense',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w800,
                            fontSize: 14,
                          ),
                        ),
                        SizedBox(height: 4),
                        Text(
                          'Select a specialized analyzer below to inspect untrusted inputs with heuristic & AI models.',
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 11,
                            height: 1.3,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            _buildSectionHeader('Web & Messaging Security'),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.link_rounded,
              color: const Color(0xFF00E5FF),
              title: 'URL Threat Scanner',
              subtitle: 'Heuristic phishing, IP addresses, URL shorteners, and malicious TLD detection',
              badge: 'HEURISTIC + AI',
              route: AppRouter.urlScanner,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.sms_rounded,
              color: const Color(0xFF30D158),
              title: 'SMS Threat Scanner',
              subtitle: 'Bank KYC suspensions, urgency fraud, APK lure extraction, and smishing patterns',
              badge: 'SMISHING ENGINE',
              route: AppRouter.smsScanner,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.qr_code_2_rounded,
              color: const Color(0xFFFFD60A),
              title: 'QR Code (Quishing) Scanner',
              subtitle: 'Detect disguised URL payloads, deceptive redirects, and fraudulent payment QR codes',
              badge: 'QUISHING SHIELD',
              route: AppRouter.qrScanner,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.mark_email_read_rounded,
              color: const Color(0xFFBF5AF2),
              title: 'Email Security Inspector',
              subtitle: 'Identify fake invoices, wire transfer spoofing, urgent threats, and malicious attachments',
              badge: 'EMAIL INSPECTOR',
              route: AppRouter.emailScanner,
            ),
            const SizedBox(height: 22),

            _buildSectionHeader('Files & Application Security'),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.image_search_rounded,
              color: const Color(0xFFFF9F0A),
              title: 'Screenshot Threat Analyzer',
              subtitle: 'NVIDIA Nemotron 3.5 Super VL Vision OCR extracts text from payment apps, chats, and screenshots',
              badge: 'NEMOTRON VISION OCR',
              route: AppRouter.screenshotAnalysis,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.android_rounded,
              color: const Color(0xFFFF453A),
              title: 'APK Security Analyzer',
              subtitle: 'Inspect AndroidManifest permissions, dangerous combinations, and cryptographic hashes',
              badge: 'STREAMING APK ENGINE',
              route: AppRouter.apkAnalysis,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.folder_zip_rounded,
              color: const Color(0xFF64D2FF),
              title: 'File & Executable Analyzer',
              subtitle: 'Static magic-byte validation, disguised PE binaries, and Zip Slip path traversal checks',
              badge: 'STATIC FILE ENGINE',
              route: AppRouter.fileScanner,
            ),
            const SizedBox(height: 10),
            _buildScannerTile(
              context,
              icon: Icons.security_rounded,
              color: const Color(0xFFFF2D55),
              title: 'Android Permission Analyzer',
              subtitle: 'Audit installed applications against high-risk permission combination clusters',
              badge: 'ON-DEVICE AUDIT',
              route: AppRouter.permissionAnalyzer,
            ),
            const SizedBox(height: 28),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Text(
      title,
      style: const TextStyle(
        color: AppColors.textPrimary,
        fontSize: 14,
        fontWeight: FontWeight.w700,
        letterSpacing: 0.3,
      ),
    );
  }

  Widget _buildScannerTile(
    BuildContext context, {
    required IconData icon,
    required Color color,
    required String title,
    required String subtitle,
    required String badge,
    required String route,
  }) {
    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      child: InkWell(
        onTap: () => Navigator.pushNamed(context, route),
        borderRadius: BorderRadius.circular(10),
        child: Row(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: color.withValues(alpha: 0.3)),
              ),
              child: Icon(icon, color: color, size: 22),
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
                      Text(
                        title,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.w700,
                          fontSize: 13,
                        ),
                      ),
                      CyberBadge(
                        label: badge,
                        type: BadgeType.info,
                        fontSize: 8,
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    subtitle,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      height: 1.3,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            const Icon(Icons.arrow_forward_ios_rounded, color: AppColors.textMuted, size: 14),
          ],
        ),
      ),
    );
  }
}

