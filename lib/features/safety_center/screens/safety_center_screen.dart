// CyberShield Safety Center & Cyber Hygiene Guide
// Actionable security playbooks, threat identification rubrics, and incident response

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/navigation/app_router.dart';

class SafetyCenterScreen extends StatefulWidget {
  const SafetyCenterScreen({super.key});

  @override
  State<SafetyCenterScreen> createState() => _SafetyCenterScreenState();
}

class _SafetyCenterScreenState extends State<SafetyCenterScreen> {
  int _selectedCategory = 0;

  final List<String> _categories = [
    'All Guides',
    'Phishing & SMS',
    'Passwords & 2FA',
    'App Sideloading',
    'Incident Playbook',
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Safety Center & Hygiene'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.auto_awesome_rounded, color: Color(0xFFFFD60A)),
            onPressed: () => Navigator.pushNamed(context, AppRouter.aiAssistant),
            tooltip: 'Ask CYBOR AI',
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 16, 18, 40),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeroCard(),
            const SizedBox(height: 18),
            _buildCategoryFilter(),
            const SizedBox(height: 18),
            ..._buildGuideCards(),
          ],
        ),
      ),
    );
  }

  Widget _buildHeroCard() {
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
                child: const Icon(Icons.health_and_safety_rounded, color: AppColors.primary, size: 24),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Proactive Cyber Hygiene',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    SizedBox(height: 2),
                    Text(
                      'Practical, proven steps to defend against cyber threats.',
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
            'Over 85% of security breaches stem from social engineering, credential compromise, or unintended permissions. Master these fundamentals to harden your digital perimeter.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
          ),
        ],
      ),
    );
  }

  Widget _buildCategoryFilter() {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: List.generate(_categories.length, (idx) {
          final isSelected = _selectedCategory == idx;
          return Padding(
            padding: const EdgeInsets.only(right: 8.0),
            child: ChoiceChip(
              label: Text(
                _categories[idx],
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                  color: isSelected ? Colors.black : AppColors.textSecondary,
                ),
              ),
              selected: isSelected,
              selectedColor: AppColors.primary,
              backgroundColor: AppColors.surfaceLight,
              side: BorderSide(color: isSelected ? AppColors.primary : AppColors.cardBorder),
              onSelected: (val) {
                if (val) setState(() => _selectedCategory = idx);
              },
            ),
          );
        }),
      ),
    );
  }

  List<Widget> _buildGuideCards() {
    final cards = <Widget>[];

    // Phishing & SMS (Index 1 or 0)
    if (_selectedCategory == 0 || _selectedCategory == 1) {
      cards.add(
        _buildGuideTile(
          icon: Icons.link_off_rounded,
          color: const Color(0xFF00E5FF),
          title: 'Spotting Phishing & URL Spoofing',
          subtitle: 'Identify lookalike domains, punycode attacks, and suspicious subdomains.',
          content: [
            'Inspect Domain Spelling: Scammers use typosquatting like "paypa1.com" or "arnazon.com" to fool fast readers.',
            'Watch for Excessive Subdomains: Real portals use "account.bank.com", not "bank.com.verify-login-portal.net".',
            'Beware of Artificial Urgency: Threat actors threaten immediate account suspension to force hasty clicks.',
            'Scan Before Opening: Copy suspicious URLs and paste them into CyberShield URL Scanner before clicking.',
          ],
        ),
      );
      cards.add(const SizedBox(height: 14));
      cards.add(
        _buildGuideTile(
          icon: Icons.sms_failed_rounded,
          color: const Color(0xFF5E5CE6),
          title: 'Defending Against Smishing & KYC Scams',
          subtitle: 'Recognize courier tracking fraud, lottery hoaxes, and electricity bill scams.',
          content: [
            'Banks Never Request Passwords via SMS: Legitimate institutions never ask for your PIN or password in a text.',
            'Inspect the Sender Header: Official banking updates usually arrive via verified alpha sender headers, not 10-digit random mobile numbers.',
            'Look Out for Disguised APK Links: "Download KYC.apk to update PAN card" is always a malware payload designed to steal bank OTPs.',
          ],
        ),
      );
      cards.add(const SizedBox(height: 14));
    }

    // Passwords & 2FA (Index 2 or 0)
    if (_selectedCategory == 0 || _selectedCategory == 2) {
      cards.add(
        _buildGuideTile(
          icon: Icons.key_rounded,
          color: const Color(0xFFFFD60A),
          title: 'Passkeys & Modern Multi-Factor Auth (MFA)',
          subtitle: 'Move beyond vulnerable SMS OTPs to cryptographic hardware security.',
          content: [
            'Adopt Passkeys: Passkeys use FIDO2 public-key cryptography and are immune to phishing because they never leave your device.',
            'Prefer Authenticator Apps Over SMS: SMS is susceptible to SIM swapping. Use Google Authenticator or hardware keys (YubiKey).',
            'Unique Passwords Everywhere: Never reuse a master password across multiple platforms. If one breaches, all fall.',
          ],
        ),
      );
      cards.add(const SizedBox(height: 14));
      cards.add(
        _buildGuideTile(
          icon: Icons.lock_clock_rounded,
          color: const Color(0xFF30D158),
          title: 'OTP Redaction & Financial Hygiene',
          subtitle: 'Protect time-based authorization codes from social engineers.',
          content: [
            'Never Read OTPs Aloud on Phone Calls: Impersonators posing as bank officials will prompt you for OTPs. Hang up immediately.',
            'Read the Full Transaction SMS: Before entering an OTP, check the amount and merchant listed in the SMS body.',
          ],
        ),
      );
      cards.add(const SizedBox(height: 14));
    }

    // App Sideloading (Index 3 or 0)
    if (_selectedCategory == 0 || _selectedCategory == 3) {
      cards.add(
        _buildGuideTile(
          icon: Icons.install_mobile_rounded,
          color: const Color(0xFFFF453A),
          title: 'APK Sideloading & Android Overlay Risks',
          subtitle: 'Why installing packages from WhatsApp or Telegram channels is dangerous.',
          content: [
            'Accessibility Service Abuse: Dangerous APKs trick you into granting Accessibility access, allowing them to read screen text and click buttons invisibly.',
            'Overlay Permissions (SYSTEM_ALERT_WINDOW): Malware draws fake login screens over banking apps to harvest passwords.',
            'Always Audit Unknown APKs: Run CyberShield APK Security Analyzer to inspect manifests, requested permissions, and certificates before installing.',
          ],
        ),
      );
      cards.add(const SizedBox(height: 14));
    }

    // Incident Response (Index 4 or 0)
    if (_selectedCategory == 0 || _selectedCategory == 4) {
      cards.add(
        _buildGuideTile(
          icon: Icons.emergency_rounded,
          color: const Color(0xFFFF375F),
          title: 'Incident Response Playbook: "I Clicked a Scam Link"',
          subtitle: 'Four immediate emergency steps if you suspect credential compromise.',
          content: [
            '1. Disconnect Device from the Internet: Turn on Airplane Mode or turn off Wi-Fi and mobile data immediately to halt data exfiltration.',
            '2. Change Passwords from a Clean Device: Use another computer or trusted phone to change your primary email and banking passwords immediately.',
            '3. Revoke Active Sessions & 2FA: Log into your Google, Apple, and banking accounts to terminate all existing active sessions.',
            '4. Contact Your Bank: If financial details were submitted, request temporary freezing of debit/credit cards and net banking.',
            '5. File a Cyber Crime Report: In India, report fraud to the National Cyber Crime Reporting Portal (1930 or cybercrime.gov.in).',
          ],
        ),
      );
    }

    return cards;
  }

  Widget _buildGuideTile({
    required IconData icon,
    required Color color,
    required String title,
    required String subtitle,
    required List<String> content,
  }) {
    return CyberShieldCard(
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: EdgeInsets.zero,
          childrenPadding: const EdgeInsets.only(top: 8, bottom: 4),
          leading: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: color, size: 22),
          ),
          title: Text(
            title,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontWeight: FontWeight.w700,
              fontSize: 13,
            ),
          ),
          subtitle: Text(
            subtitle,
            style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
          ),
          children: content.map((item) {
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.shield_rounded, size: 14, color: color),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      item,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 12,
                        height: 1.4,
                      ),
                    ),
                  ),
                ],
              ),
            );
          }).toList(),
        ),
      ),
    );
  }
}
