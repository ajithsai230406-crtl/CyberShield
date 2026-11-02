import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/navigation/app_router.dart';

class NavDrawer extends StatelessWidget {
  final String currentRoute;

  const NavDrawer({super.key, required this.currentRoute});

  @override
  Widget build(BuildContext context) {
    return Drawer(
      backgroundColor: AppColors.surface,
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
                  icon: Icons.link_rounded,
                  label: 'URL Scanner',
                  route: AppRouter.urlScanner,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.sms_rounded,
                  label: 'SMS Scanner',
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
                  icon: Icons.screenshot_monitor_rounded,
                  label: 'Screenshot Analysis',
                  route: AppRouter.screenshotAnalysis,
                ),
                _buildNavItem(
                  context,
                  icon: Icons.android_rounded,
                  label: 'APK Analysis',
                  route: AppRouter.apkAnalysis,
                ),
                const Divider(color: AppColors.cardBorder, height: 32),
                _buildNavItem(
                  context,
                  icon: Icons.history_rounded,
                  label: 'Scan History',
                  route: AppRouter.history,
                ),
              ],
            ),
          ),
          _buildFooter(),
        ],
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(20, 56, 20, 20),
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF1A2940),
            AppColors.surface,
          ],
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(
              Icons.shield_rounded,
              color: AppColors.primary,
              size: 28,
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'CyberShield',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 22,
              fontWeight: FontWeight.w800,
              letterSpacing: -0.5,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Security Analysis Suite',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 13,
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
  }) {
    final isSelected = currentRoute == route;

    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      child: ListTile(
        leading: Icon(
          icon,
          color: isSelected ? AppColors.primary : AppColors.textSecondary,
          size: 22,
        ),
        title: Text(
          label,
          style: TextStyle(
            color: isSelected ? AppColors.primary : AppColors.textPrimary,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
            fontSize: 14,
          ),
        ),
        selected: isSelected,
        selectedTileColor: AppColors.primary.withValues(alpha: 0.1),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
        onTap: () {
          Navigator.pop(context);
          if (currentRoute != route) {
            Navigator.pushReplacementNamed(context, route);
          }
        },
      ),
    );
  }

  Widget _buildFooter() {
    return Container(
      padding: const EdgeInsets.all(20),
      child: const Row(
        children: [
          Icon(Icons.info_outline_rounded, color: AppColors.textMuted, size: 16),
          SizedBox(width: 8),
          Text(
            'v1.0.0 • Development',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }
}

