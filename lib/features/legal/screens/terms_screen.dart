// CyberShield Terms of Service & Legal Disclaimers
// Academic examination, educational scope, and liability limitations

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class TermsScreen extends StatelessWidget {
  const TermsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Terms of Service'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 16, 18, 40),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            CyberShieldCard(
              borderColor: AppColors.warning.withValues(alpha: 0.4),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppColors.warning.withValues(alpha: 0.15),
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(Icons.gavel_rounded, color: AppColors.warning, size: 22),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Terms of Use & Disclaimer',
                              style: TextStyle(
                                color: AppColors.textPrimary,
                                fontSize: 16,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                            Text(
                              'Academic Evaluation & Research Project',
                              style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Please review these Terms of Service before using CyberShield. By accessing or using CyberShield, you acknowledge and agree to the disclaimers and operational boundaries set forth below.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            _buildSection(
              title: '1. Educational & Academic Demonstration Scope',
              content:
                  'CyberShield has been researched, architected, and engineered as a university Computer Science & Engineering mini-project, internal assessment demonstration, and external viva examination project. It exemplifies modern heuristic threat detection, on-device intelligence, and multi-vector cybersecurity modeling.',
            ),
            _buildSection(
              title: '2. No Guarantee of 100% Immunity (Zero-Day Notice)',
              content:
                  'No automated security software, antivirus tool, heuristic engine, or AI assistant can guarantee 100% immunity against emerging zero-day vulnerabilities, novel social engineering campaigns, or state-sponsored cyber warfare. CyberShield is designed as an advisory and threat-awareness defense layer, not an infallible guarantee.',
            ),
            _buildSection(
              title: '3. User Responsibility & Discretion',
              content:
                  'You remain solely responsible for your own cybersecurity decisions, including:\n'
                  '• Deciding whether to install third-party APK files or sideload software.\n'
                  '• Deciding whether to click links or enter credentials on web portals.\n'
                  '• Safeguarding your personal banking OTPs, private keys, and passwords.\n'
                  'CyberShield recommendations are heuristic advisories intended to inform, not replace, user critical judgment.',
            ),
            _buildSection(
              title: '4. Non-Destructive Operation & Policy Adherence',
              content:
                  'CyberShield is strictly defensive. It does not perform offensive penetration testing against third-party networks, does not deploy exploits, does not bypass Android platform security sandboxes, and respects Google Play Developer distribution policies.',
            ),
            _buildSection(
              title: '5. Limitation of Liability',
              content:
                  'To the maximum extent permitted by applicable law, the authors, developers, university faculty, and contributors of CyberShield shall not be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use the application, false positives, false negatives, or data loss.',
            ),
            _buildSection(
              title: '6. Intellectual Property & Academic Fair Use',
              content:
                  'All project source code, design models, custom algorithms, and UI assets are the academic work of the student project authors. Third-party libraries and AI providers (Flutter, FastAPI, Firebase, OpenRouter, NVIDIA Nemotron) remain the intellectual property of their respective maintainers under their open-source or commercial licenses.',
            ),
            const SizedBox(height: 20),
            Center(
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.primary,
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: () => Navigator.pop(context),
                child: const Text('Accept Terms & Return', style: TextStyle(fontWeight: FontWeight.bold)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSection({
    required String title,
    required String content,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            content,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }
}
