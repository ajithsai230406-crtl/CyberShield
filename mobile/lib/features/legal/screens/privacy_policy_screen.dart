// CyberShield Privacy Policy Screen
// Comprehensive 14-Point Privacy Architecture & Zero-Leak Disclosures

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class PrivacyPolicyScreen extends StatelessWidget {
  const PrivacyPolicyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Privacy Policy'),
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
            // Header summary
            CyberShieldCard(
              borderColor: AppColors.primary.withValues(alpha: 0.35),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppColors.primary.withValues(alpha: 0.15),
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(Icons.privacy_tip_rounded, color: AppColors.primary, size: 22),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'CyberShield Privacy Charter',
                              style: TextStyle(
                                color: AppColors.textPrimary,
                                fontSize: 16,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                            Text(
                              'Effective: Academic Year 2026–2027 • Version 1.0.0',
                              style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'At CyberShield, we believe privacy and cybersecurity are inseparable. We operate under a strict Zero-Leak Guarantee: private communications, passwords, and financial identifiers are never logged, stored, or monetized.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            _buildSection(
              number: '1',
              title: 'What Data Is Collected',
              content:
                  'We only process data necessary for cyber threat detection:\n'
                  '• SHA-256 and MD5 cryptographic hashes of audited files and APK packages.\n'
                  '• Anonymized URL strings, domain names, and IP targets submitted for phishing analysis.\n'
                  '• User-submitted text or SMS samples for smishing and social engineering classification.\n'
                  '• Device telemetry limited to Android OS version and screen size for responsive rendering.',
            ),
            _buildSection(
              number: '2',
              title: 'What Is Never Collected (Zero-Leak Guarantee)',
              content:
                  'CyberShield strictly guarantees we NEVER collect, store, or transmit:\n'
                  '• Passwords, PINs, or biometric credentials.\n'
                  '• Bank account numbers, credit card details, or CVVs.\n'
                  '• One-Time Passwords (OTPs) and 2-Factor Authentication SMS codes (automatically redacted on-device).\n'
                  '• Call audio, microphone recordings, or phone call logs.\n'
                  '• Private photos, videos, or files not explicitly selected through the Android Storage Access Framework.',
            ),
            _buildSection(
              number: '3',
              title: 'Processing Architecture (On-Device vs Remote Engine)',
              content:
                  'Threat analysis occurs through a tiered defense model:\n'
                  '• Local On-Device Heuristics: Regex checks, domain entropy calculation, OTP redaction, and local keyword matching execute entirely on your phone.\n'
                  '• Remote FastAPI Engine: Complex heuristic models, WHOIS age queries, certificate verification, and threat database lookups execute on the CyberShield backend over encrypted HTTP/TLS.\n'
                  '• CYBOR AI Engine: Conversational cybersecurity analysis is routed to NVIDIA Nemotron 3.5 Super VL via OpenRouter using structured prompt templates.',
            ),
            _buildSection(
              number: '4',
              title: 'Firebase Authentication Usage',
              content:
                  'Firebase Auth is utilized strictly to provide secure user sessions. Your password is never seen by our application or backend; authentication tokens are verified via Google Firebase public JWK keys. Guest and offline modes are supported without authentication.',
            ),
            _buildSection(
              number: '5',
              title: 'Cloud Firestore User Data Isolation',
              content:
                  'All cloud history and threat alert documents are strictly partitioned under user-isolated Firestore paths: `users/{userId}/scan_history/{scanId}`. Firestore security rules enforce that users can ONLY read and write their own documents.',
            ),
            _buildSection(
              number: '6',
              title: 'Gmail API Integration & Restricted Scope',
              content:
                  'Our Gmail Inbox Inspector utilizes Google OAuth 2.0 with restricted read-only scope (`https://www.googleapis.com/auth/gmail.readonly`).\n'
                  '• Gmail inspection is strictly user-initiated; background scraping is prohibited.\n'
                  '• OAuth tokens are held temporarily in memory and can be explicitly revoked at any time.\n'
                  '• Logging out of CyberShield immediately severs and revokes active Google OAuth credentials.',
            ),
            _buildSection(
              number: '7',
              title: 'Third-Party Services',
              content:
                  'We integrate with industry-standard security infrastructure:\n'
                  '• Google Firebase (Authentication & Cloud Firestore for user-isolated persistence).\n'
                  '• OpenRouter / NVIDIA Nemotron 3.5 Super VL (Generative AI cybersecurity reasoning, vision OCR, and advice).\n'
                  '• No advertising networks, commercial tracking SDKs, or data brokers are integrated.',
            ),
            _buildSection(
              number: '8',
              title: 'Data Retention & User Deletion Rights',
              content:
                  'You maintain complete ownership of your security records:\n'
                  '• You can delete individual scan entries or trigger "Clear All History" from the Audit History screen anytime.\n'
                  '• Deletion is immediate and irreversible across both device storage and Cloud Firestore.',
            ),
            _buildSection(
              number: '9',
              title: 'Telemetry & Crash Reporting',
              content:
                  'Diagnostics are limited to HTTP latency, module operational status, and caught exception messages. No personal identity is attached to telemetry logs.',
            ),
            _buildSection(
              number: '10',
              title: 'Local Storage vs Cloud Storage',
              content:
                  '• Local Storage: API endpoints, theme settings, and offline scan fallback cache are stored locally via Android SharedPreferences.\n'
                  '• Cloud Storage: Authenticated scan logs and security alerts are stored in Cloud Firestore.',
            ),
            _buildSection(
              number: '11',
              title: 'Children\'s Privacy',
              content:
                  'CyberShield is designed for university research, cyber defense education, and general public security awareness. It is not directed to children under 13 years of age, and we do not knowingly collect information from children.',
            ),
            _buildSection(
              number: '12',
              title: 'Security Practices',
              content:
                  '• Encryption in Transit: All API communications utilize TLS/HTTPS and Bearer token headers.\n'
                  '• Storage Protection: Android App Sandbox prevents external applications from accessing internal CyberShield storage.\n'
                  '• Threat Lookups: Performed via one-way cryptographic SHA-256 hashes whenever possible.',
            ),
            _buildSection(
              number: '13',
              title: 'User Rights (GDPR & Global Privacy Compliance)',
              content:
                  'You possess the right to:\n'
                  '• Access all stored scan history at any time.\n'
                  '• Permanently erase your scan records.\n'
                  '• Revoke granted Android runtime permissions through system settings.\n'
                  '• Disconnect third-party accounts (Google Gmail OAuth) with one tap.',
            ),
            _buildSection(
              number: '14',
              title: 'Contact Information & Security Officer',
              content:
                  'For inquiries regarding CyberShield privacy practices, security vulnerability disclosures, or academic examination verification, contact the CyberShield Project Development Team:\n'
                  '• Email: security@cybershield.internal\n'
                  '• Academic Institution: College Department of Computer Science & Engineering\n'
                  '• Project Repository: E:\\CyberShield',
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
                child: const Text('I Understand & Acknowledge', style: TextStyle(fontWeight: FontWeight.bold)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSection({
    required String number,
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
          Row(
            children: [
              Container(
                width: 24,
                height: 24,
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.15),
                  shape: BoxShape.circle,
                  border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
                ),
                child: Center(
                  child: Text(
                    number,
                    style: const TextStyle(
                      color: AppColors.primary,
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
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
