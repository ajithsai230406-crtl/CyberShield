// CyberShield First-Launch Permission Onboarding & Product Tour Screen

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final PageController _pageController = PageController();
  int _currentPage = 0;
  bool _notifGranted = false;
  bool _termsAccepted = true;

  final List<Map<String, dynamic>> _slides = [
    {
      'title': 'Real-Time Cyber Defense',
      'subtitle':
          'Instant heuristic inspection across 8 core threat vectors: URLs, SMS smishing, QR barcodes, screenshots, APKs, permissions, emails, and disguised files.',
      'icon': Icons.shield_rounded,
      'color': const Color(0xFF00E5FF),
      'tag': 'MULTI-VECTOR INSPECTION',
    },
    {
      'title': 'CYBOR AI Security Assistant',
      'subtitle':
          'Interactive conversational cyber advisor powered by NVIDIA Nemotron 3.5 Super VL via OpenRouter to translate forensic indicators, explain risk scoring, and deliver tailored remediation steps.',
      'icon': Icons.smart_toy_rounded,
      'color': const Color(0xFFFFD60A),
      'tag': 'ADVISORY DEFENSE',
    },
    {
      'title': 'Crowd Threat Network',
      'subtitle':
          'Decentralized threat intelligence. Report scam numbers, phishing sites, and fraud targets with privacy-preserving confidence scoring.',
      'icon': Icons.public_rounded,
      'color': const Color(0xFF32D74B),
      'tag': 'COMMUNITY DEFENSE',
    },
    {
      'title': 'Permissions & Privacy Setup',
      'subtitle':
          'CyberShield only requests permissions essential for protection. Sensitive tokens and OTPs are automatically redacted on-device.',
      'icon': Icons.verified_user_rounded,
      'color': const Color(0xFF00E5FF),
      'tag': 'TRANSPARENT PERMISSIONS',
      'isPermissionSlide': true,
    },
  ];

  @override
  void initState() {
    super.initState();
    _checkPermissions();
  }

  Future<void> _checkPermissions() async {
    final notif = await ProtectionService.instance.isNotificationPermissionGranted();
    await ProtectionService.instance.refreshStatus();
    if (mounted) {
      setState(() {
        _notifGranted = notif;
      });
    }
  }

  void _onNext() {
    if (_currentPage < _slides.length - 1) {
      _pageController.nextPage(
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
    } else {
      if (!_termsAccepted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Please accept the Terms of Service & Privacy Policy to proceed'),
            backgroundColor: AppColors.danger,
          ),
        );
        return;
      }
      Navigator.pushReplacementNamed(context, AppRouter.dashboard);
    }
  }

  @override
  Widget build(BuildContext context) {
    final themeCtrl = ThemeController.instance;

    return Scaffold(
      backgroundColor: AppColors.background,
      body: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: themeCtrl.primaryColor.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Icon(Icons.shield_rounded, color: themeCtrl.primaryColor, size: 20),
                      ),
                      const SizedBox(width: 8),
                      const Text(
                        'CyberShield',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.w800,
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                  TextButton(
                    onPressed: () => Navigator.pushReplacementNamed(context, AppRouter.dashboard),
                    child: const Text('Skip Setup', style: TextStyle(color: AppColors.textMuted)),
                  ),
                ],
              ),
            ),
            Expanded(
              child: PageView.builder(
                controller: _pageController,
                itemCount: _slides.length,
                onPageChanged: (idx) {
                  setState(() => _currentPage = idx);
                  if (idx == 3) _checkPermissions();
                },
                itemBuilder: (context, index) {
                  final slide = _slides[index];
                  final Color color = slide['color'] as Color;

                  if (slide['isPermissionSlide'] == true) {
                    return _buildPermissionsSlide(color);
                  }

                  return Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 24),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Container(
                          width: 120,
                          height: 120,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: color.withValues(alpha: 0.12),
                            border: Border.all(color: color.withValues(alpha: 0.4), width: 2),
                            boxShadow: [
                              BoxShadow(
                                color: color.withValues(alpha: 0.25),
                                blurRadius: 28,
                                spreadRadius: 4,
                              ),
                            ],
                          ),
                          child: Icon(slide['icon'] as IconData, size: 54, color: color),
                        ),
                        const SizedBox(height: 32),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: color.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(color: color.withValues(alpha: 0.4)),
                          ),
                          child: Text(
                            slide['tag'] as String,
                            style: TextStyle(
                              color: color,
                              fontSize: 11,
                              fontWeight: FontWeight.w800,
                              letterSpacing: 0.8,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          slide['title'] as String,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 22,
                            fontWeight: FontWeight.w900,
                            letterSpacing: -0.5,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          slide['subtitle'] as String,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 13,
                            height: 1.45,
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: List.generate(
                      _slides.length,
                      (idx) => Container(
                        margin: const EdgeInsets.symmetric(horizontal: 4),
                        width: _currentPage == idx ? 24 : 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: _currentPage == idx ? themeCtrl.primaryColor : AppColors.cardBorder,
                          borderRadius: BorderRadius.circular(4),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  if (_currentPage == _slides.length - 1) ...[
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Checkbox(
                          value: _termsAccepted,
                          activeColor: themeCtrl.primaryColor,
                          checkColor: Colors.black,
                          onChanged: (v) => setState(() => _termsAccepted = v ?? false),
                        ),
                        Expanded(
                          child: Wrap(
                            crossAxisAlignment: WrapCrossAlignment.center,
                            children: [
                              const Text('I accept the ', style: TextStyle(color: AppColors.textSecondary, fontSize: 11)),
                              GestureDetector(
                                onTap: () => Navigator.pushNamed(context, AppRouter.terms),
                                child: const Text('Terms of Service',
                                    style: TextStyle(
                                        color: AppColors.primary,
                                        fontSize: 11,
                                        fontWeight: FontWeight.bold,
                                        decoration: TextDecoration.underline)),
                              ),
                              const Text(' and acknowledge the ', style: TextStyle(color: AppColors.textSecondary, fontSize: 11)),
                              GestureDetector(
                                onTap: () => Navigator.pushNamed(context, AppRouter.privacyPolicy),
                                child: const Text('Privacy Policy',
                                    style: TextStyle(
                                        color: AppColors.primary,
                                        fontSize: 11,
                                        fontWeight: FontWeight.bold,
                                        decoration: TextDecoration.underline)),
                              ),
                              const Text('.', style: TextStyle(color: AppColors.textSecondary, fontSize: 11)),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                  ],
                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: ElevatedButton(
                      onPressed: _onNext,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: themeCtrl.primaryColor,
                        foregroundColor: Colors.black,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: Text(
                        _currentPage == _slides.length - 1 ? 'Enter CyberShield Dashboard' : 'Continue',
                        style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
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

  Widget _buildPermissionsSlide(Color color) {
    return ValueListenableBuilder<ProtectionStatus>(
      valueListenable: ProtectionService.instance.statusNotifier,
      builder: (context, status, _) {
        return SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Column(
                  children: [
                    Icon(Icons.security_rounded, size: 48, color: color),
                    const SizedBox(height: 8),
                    const Text(
                      'Protection Permissions',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Configure permissions below to enable active protection. All permissions are optional and can be adjusted anytime in Settings.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              // 1. Notification Permission
              _buildPermTile(
                icon: Icons.notifications_active_rounded,
                title: 'High-Priority Threat Alerts',
                purpose: 'Alerts you instantly when a malicious URL, scam SMS, or trojan APK is intercepted.',
                statusLabel: _notifGranted ? 'Granted' : 'Optional',
                isGranted: _notifGranted,
                actionLabel: _notifGranted ? 'Active' : 'Allow',
                onAction: () async {
                  await ProtectionService.instance.requestNotificationPermission();
                  await _checkPermissions();
                },
              ),
              const SizedBox(height: 10),

              // 2. Notification Listener
              _buildPermTile(
                icon: Icons.mark_email_read_rounded,
                title: 'Real-Time Notification Guard',
                purpose: 'Inspects incoming notification text for phishing links. Sensitive tokens and OTPs are redacted on-device.',
                statusLabel: status.isNotificationAccessGranted ? 'Active' : 'Optional',
                isGranted: status.isNotificationAccessGranted,
                actionLabel: status.isNotificationAccessGranted ? 'Enabled' : 'Open Settings',
                onAction: () async {
                  await ProtectionService.instance.openNotificationListenerSettings();
                  await _checkPermissions();
                },
              ),
              const SizedBox(height: 10),

              // 3. Call Screening (Android 10+ only)
              _buildPermTile(
                icon: Icons.phone_callback_rounded,
                title: status.isCallScreeningSupported
                    ? 'Automatic Call Screening (Android 10+)'
                    : 'Native Call Screening Unsupported on This Device',
                purpose: status.isCallScreeningSupported
                    ? 'Checks incoming caller IDs against community reputation. CyberShield never records or listens to calls.'
                    : 'Requires Android 10 (API 29)+. Calls are not automatically blocked or screened on Android 9; manual phone-number checks remain available.',
                statusLabel: !status.isCallScreeningSupported
                    ? 'Unsupported'
                    : (status.isCallScreeningRoleHeld ? 'Active' : 'Optional'),
                isGranted: status.isCallScreeningSupported && status.isCallScreeningRoleHeld,
                actionLabel: !status.isCallScreeningSupported
                    ? 'Unsupported'
                    : (status.isCallScreeningRoleHeld ? 'Enabled' : 'Request Role'),
                onAction: !status.isCallScreeningSupported
                    ? null
                    : () async {
                        await ProtectionService.instance.requestCallScreeningRole();
                        await _checkPermissions();
                      },
              ),
              const SizedBox(height: 10),

              // 4. File / Media
              _buildPermTile(
                icon: Icons.folder_open_rounded,
                title: 'File & APK Scanner Access',
                purpose: 'Allows selecting APK packages, screenshots, and downloads for static security auditing.',
                statusLabel: 'On-Demand',
                isGranted: true,
                actionLabel: 'Ready',
                onAction: null,
              ),
              const SizedBox(height: 14),

              Center(
                child: Text(
                  '🔒 Zero-Leak Guarantee: OTPs & CVVs are never logged or stored.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 11, fontStyle: FontStyle.italic),
                ),
              ),
              const SizedBox(height: 8),
              Center(
                child: TextButton.icon(
                  onPressed: () => Navigator.pushNamed(context, AppRouter.permissionCenter),
                  icon: const Icon(Icons.tune_rounded, size: 14, color: AppColors.primary),
                  label: const Text('Open Detailed Permission Center',
                      style: TextStyle(color: AppColors.primary, fontSize: 12, fontWeight: FontWeight.bold)),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildPermTile({
    required IconData icon,
    required String title,
    required String purpose,
    required String statusLabel,
    required bool isGranted,
    required String actionLabel,
    required VoidCallback? onAction,
  }) {
    return CyberShieldCard(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 20, color: isGranted ? AppColors.safe : AppColors.primary),
              const SizedBox(width: 8),
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
              CyberBadge(
                label: statusLabel,
                type: isGranted ? BadgeType.safe : BadgeType.info,
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            purpose,
            style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, height: 1.3),
          ),
          if (onAction != null) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: SizedBox(
                height: 32,
                child: OutlinedButton(
                  onPressed: onAction,
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: isGranted ? AppColors.safe : AppColors.primary),
                    padding: const EdgeInsets.symmetric(horizontal: 12),
                  ),
                  child: Text(
                    actionLabel,
                    style: TextStyle(
                      color: isGranted ? AppColors.safe : AppColors.primary,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
