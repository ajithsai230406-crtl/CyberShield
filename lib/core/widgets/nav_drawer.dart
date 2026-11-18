
import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/alert_service.dart';

class NavDrawer extends StatelessWidget {
  static final ValueNotifier<int> _fallbackUnreadNotifier = ValueNotifier<int>(0);
  final String currentRoute;

  const NavDrawer({super.key, required this.currentRoute});

  ValueNotifier<int> _unreadCountNotifier() {
    try {
      return AlertService.instance.unreadCountNotifier;
    } catch (_) {
      return _fallbackUnreadNotifier;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Drawer(
      backgroundColor: AppColors.surface,
      surfaceTintColor: Colors.transparent,
      child: Column(
        children: [
          _buildHeader(context),
          const SizedBox(height: 8),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              children: [
                _buildNavItem(
                  context,
                  icon: Icons.dashboard_rounded,
                  label: 'Dashboard',
                  route: AppRouter.dashboard,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.radar_rounded,
                  label: 'Threat Detection Hub',
                  route: AppRouter.scanHub,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.shield_rounded,
                  label: 'Real-Time Protection',
                  route: AppRouter.protection,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.forum_rounded,
                  label: 'Communication History',
                  route: AppRouter.communications,
                ),
                ValueListenableBuilder<int>(
                  valueListenable: _unreadCountNotifier(),
                  builder: (context, unread, _) {
                    return _buildNavItem(
                      context,
                      icon: Icons.notifications_active_rounded,
                      label: 'Security Alerts',
                      route: AppRouter.alerts,
                      badgeCount: unread > 0 ? unread : null,
                    );
                  },
                ),
                const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Text(
                    'SECURITY SCANNERS',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.0,
                    ),
                  ),
                ),
                _buildNavItem(
                  context,
                  icon: Icons.link_rounded,
                  label: 'URL Scanner',
                  route: AppRouter.urlScanner,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.sms_rounded,
                  label: 'SMS Scam Detection',
                  route: AppRouter.smsScanner,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.qr_code_scanner_rounded,
                  label: 'QR Scanner',
                  route: AppRouter.qrScanner,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.screenshot_rounded,
                  label: 'Screenshot Analysis',
                  route: AppRouter.screenshotAnalysis,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.android_rounded,
                  label: 'APK Analyzer',
                  route: AppRouter.apkAnalysis,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.security_rounded,
                  label: 'Permission Analyzer',
                  route: AppRouter.permissionAnalyzer,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.mark_email_read_rounded,
                  label: 'Email Scanner',
                  route: AppRouter.emailScanner,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.folder_zip_rounded,
                  label: 'File Scanner',
                  route: AppRouter.fileScanner,
                ),
                const Divider(
                  color: AppColors.cardBorder,
                  height: 24,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.hub_rounded,
                  label: 'Unified Event Center (18)',
                  route: AppRouter.unifiedEvents,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.history_rounded,
                  label: 'Scan History',
                  route: AppRouter.history,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.public_rounded,
                  label: 'Community Threat Intel',
                  route: AppRouter.communityReports,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.auto_awesome_rounded,
                  label: 'AI Security Assistant',
                  route: AppRouter.aiAssistant,
                ),
                const Divider(
                  color: AppColors.cardBorder,
                  height: 24,
                ),
                const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Text(
                    'SECURITY & HYGIENE',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.0,
                    ),
                  ),
                ),
                _buildNavItem(
                  context,
                  icon: Icons.health_and_safety_rounded,
                  label: 'Safety Center & Hygiene',
                  route: AppRouter.safetyCenter,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.verified_user_rounded,
                  label: 'Permission Center',
                  route: AppRouter.permissionCenter,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.privacy_tip_rounded,
                  label: 'Privacy Policy',
                  route: AppRouter.privacyPolicy,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.gavel_rounded,
                  label: 'Terms of Service',
                  route: AppRouter.terms,
                ),
                const Divider(
                  color: AppColors.cardBorder,
                  height: 24,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.settings_suggest_rounded,
                  label: 'Settings & Profile',
                  route: AppRouter.settings,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.explore_rounded,
                  label: 'Product Tour',
                  route: AppRouter.onboarding,
                ),
              ],
            ),
          ),
          _buildAccountSection(context),
          _buildFooter(),
        ],
      ),
    );
  }

  // Logged-in account and logout
  Widget _buildAccountSection(BuildContext context) {
    User? user;
    try {
      user = FirebaseAuth.instance.currentUser;
    } catch (_) {
      user = null;
    }
    final tileShape = RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(10),
    );

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Divider(color: AppColors.cardBorder, height: 1, thickness: 1),
        Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: 12,
            vertical: 8,
          ),
          child: Material(
            color: Colors.transparent,
            child: Column(
              children: [
                ListTile(
                  shape: tileShape,
                  dense: true,
                  leading: CircleAvatar(
                    radius: 18,
                    backgroundColor: AppColors.primary,
                    backgroundImage: user?.photoURL != null
                        ? NetworkImage(user!.photoURL!)
                        : null,
                    child: user?.photoURL == null
                        ? const Icon(
                            Icons.person,
                            color: Colors.white,
                            size: 20,
                          )
                        : null,
                  ),
                  title: Text(
                    user?.displayName ?? 'CyberShield User',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 13,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  subtitle: Text(
                    user?.email ?? 'No email',
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                ListTile(
                  shape: tileShape,
                  dense: true,
                  leading: const Icon(
                    Icons.logout_rounded,
                    color: AppColors.danger,
                    size: 20,
                  ),
                  title: const Text(
                    'Logout / Switch Account',
                    style: TextStyle(
                      color: AppColors.danger,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  onTap: () async {
                    final confirmed = await showDialog<bool>(
                      context: context,
                      builder: (dialogContext) => AlertDialog(
                        title: const Text('Logout?'),
                        content: const Text(
                          'You will return to the login screen. '
                          'You can sign in with another account.',
                        ),
                        actions: [
                          TextButton(
                            onPressed: () =>
                                Navigator.pop(dialogContext, false),
                            child: const Text('Cancel'),
                          ),
                          TextButton(
                            onPressed: () =>
                                Navigator.pop(dialogContext, true),
                            child: const Text('Logout'),
                          ),
                        ],
                      ),
                    );

                    if (confirmed == true) {
                      await FirebaseAuth.instance.signOut();
                      if (context.mounted) {
                        Navigator.of(context).pushNamedAndRemoveUntil(
                          AppRouter.login,
                          (route) => false,
                        );
                      }
                    }
                  },
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      padding: EdgeInsets.only(
        top: MediaQuery.of(context).padding.top + 20,
        left: 20,
        right: 20,
        bottom: 20,
      ),
      decoration: const BoxDecoration(
        color: AppColors.surfaceSubtle,
        border: Border(
          bottom: BorderSide(
            color: AppColors.cardBorder,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: AppColors.primary.withValues(alpha: 0.35),
                width: 1,
              ),
            ),
            child: const Icon(
              Icons.shield_rounded,
              color: AppColors.primary,
              size: 26,
            ),
          ),
          const SizedBox(width: 14),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'CyberShield',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.2,
                  ),
                ),
                SizedBox(height: 2),
                Text(
                  'v1.0.0 • Mobile Security',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNavItem(
    BuildContext context, {
    required IconData icon,
    required String label,
    required String route,
    int? badgeCount,
  }) {
    final isSelected = currentRoute == route;
    final itemShape = RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(10),
      side: isSelected
          ? BorderSide(
              color: AppColors.primary.withValues(alpha: 0.4),
              width: 1,
            )
          : BorderSide.none,
    );

    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Material(
        color: isSelected
            ? AppColors.primary.withValues(alpha: 0.12)
            : Colors.transparent,
        shape: itemShape,
        clipBehavior: Clip.antiAlias,
        child: ListTile(
          shape: itemShape,
          dense: true,
          leading: Icon(
            icon,
            color: isSelected
                ? AppColors.primary
                : AppColors.textSecondary,
            size: 20,
          ),
          title: Text(
            label,
            style: TextStyle(
              color: isSelected
                  ? AppColors.primary
                  : AppColors.textPrimary,
              fontSize: 14,
              fontWeight:
                  isSelected ? FontWeight.w700 : FontWeight.w500,
            ),
          ),
          trailing: badgeCount != null && badgeCount > 0
              ? Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.danger,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Text(
                    '$badgeCount',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 10,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                )
              : (isSelected
                  ? Container(
                      width: 6,
                      height: 6,
                      decoration: const BoxDecoration(
                        color: AppColors.primary,
                        shape: BoxShape.circle,
                      ),
                    )
                  : null),
          onTap: () {
            Navigator.pop(context);
            if (!isSelected) {
              Navigator.pushReplacementNamed(context, route);
            }
          },
        ),
      ),
    );
  }

  Widget _buildFooter() {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: 20,
        vertical: 16,
      ),
      decoration: const BoxDecoration(
        border: Border(
          top: BorderSide(color: AppColors.cardBorder, width: 1),
        ),
      ),
      child: const Row(
        children: [
          Icon(
            Icons.lock_outline_rounded,
            size: 16,
            color: AppColors.textMuted,
          ),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              'CyberShield Engine Active',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
