import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/widgets/status_indicator.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  String _serverStatus = 'checking';
  String _serverMessage = 'Connecting to backend...';

  @override
  void initState() {
    super.initState();
    _checkServerHealth();
  }

  Future<void> _checkServerHealth() async {
    final result = await ApiService.healthCheck();
    if (mounted) {
      setState(() {
        _serverStatus = result['status'] ?? 'unknown';
        _serverMessage = result['message'] ?? result['service'] ?? 'Unknown';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.shield_rounded, color: AppColors.primary, size: 20),
            ),
            const SizedBox(width: 12),
            const Text('CyberShield'),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: AppColors.textSecondary),
            onPressed: _checkServerHealth,
            tooltip: 'Refresh',
          ),
          const SizedBox(width: 8),
        ],
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.dashboard),
      body: RefreshIndicator(
        onRefresh: _checkServerHealth,
        color: AppColors.primary,
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildWelcomeSection(),
              const SizedBox(height: 24),
              _buildServerStatus(),
              const SizedBox(height: 24),
              _buildQuickActions(context),
              const SizedBox(height: 24),
              _buildScannerGrid(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildWelcomeSection() {
    return CyberShieldCard(
      gradientColors: const [
        Color(0xFF1A2940),
        Color(0xFF0F1B2D),
      ],
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.security_rounded, color: AppColors.primary, size: 32),
              SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Security Dashboard',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    SizedBox(height: 4),
                    Text(
                      'Analyze URLs, SMS, QR codes, screenshots, and APKs',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Wrap(
            spacing: 16,
            runSpacing: 8,
            children: [
              StatusIndicator(
                label: 'Real-time Analysis',
                color: AppColors.primary,
                isActive: _serverStatus == 'healthy',
              ),
              const StatusIndicator(
                label: 'Firebase',
                color: AppColors.warning,
                isActive: false,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildServerStatus() {
    Color statusColor;
    IconData statusIcon;

    switch (_serverStatus) {
      case 'healthy':
        statusColor = AppColors.success;
        statusIcon = Icons.check_circle_rounded;
        break;
      case 'checking':
        statusColor = AppColors.warning;
        statusIcon = Icons.hourglass_top_rounded;
        break;
      default:
        statusColor = AppColors.danger;
        statusIcon = Icons.error_rounded;
    }

    return CyberShieldCard(
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: statusColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(statusIcon, color: statusColor, size: 20),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Backend Server',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w600,
                    fontSize: 15,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  _serverStatus == 'healthy'
                      ? 'Connected • $_serverMessage'
                      : _serverMessage,
                  style: TextStyle(
                    color: statusColor,
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
          TextButton.icon(
            onPressed: _checkServerHealth,
            icon: const Icon(Icons.refresh_rounded, size: 16),
            label: const Text('Check'),
            style: TextButton.styleFrom(foregroundColor: statusColor),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActions(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Quick Actions',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 17,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _buildQuickActionButton(
                context,
                icon: Icons.link_rounded,
                label: 'Scan URL',
                color: AppColors.primary,
                route: AppRouter.urlScanner,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildQuickActionButton(
                context,
                icon: Icons.sms_rounded,
                label: 'Scan SMS',
                color: AppColors.secondary,
                route: AppRouter.smsScanner,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildQuickActionButton(
    BuildContext context, {
    required IconData icon,
    required String label,
    required Color color,
    required String route,
  }) {
    return CyberShieldCard(
      onTap: () => Navigator.pushNamed(context, route),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: 12),
          Text(
            label,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontWeight: FontWeight.w600,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScannerGrid(BuildContext context) {
    final scanners = [
      _ScannerItem(
        icon: Icons.link_rounded,
        title: 'URL Scanner',
        description: 'Analyze URLs for phishing and malware',
        color: AppColors.primary,
        route: AppRouter.urlScanner,
      ),
      _ScannerItem(
        icon: Icons.sms_rounded,
        title: 'SMS Scanner',
        description: 'Detect fraudulent text messages',
        color: AppColors.secondary,
        route: AppRouter.smsScanner,
      ),
      _ScannerItem(
        icon: Icons.qr_code_scanner_rounded,
        title: 'QR Scanner',
        description: 'Scan QR codes for hidden threats',
        color: AppColors.accent,
        route: AppRouter.qrScanner,
      ),
      _ScannerItem(
        icon: Icons.screenshot_monitor_rounded,
        title: 'Screenshot Analysis',
        description: 'Analyze screenshots for suspicious content',
        color: AppColors.warning,
        route: AppRouter.screenshotAnalysis,
      ),
      _ScannerItem(
        icon: Icons.android_rounded,
        title: 'APK Analysis',
        description: 'Inspect Android packages for threats',
        color: AppColors.danger,
        route: AppRouter.apkAnalysis,
      ),
      _ScannerItem(
        icon: Icons.history_rounded,
        title: 'Scan History',
        description: 'View past scan results',
        color: AppColors.textSecondary,
        route: AppRouter.history,
      ),
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Security Tools',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 17,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 12),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            crossAxisSpacing: 12,
            mainAxisSpacing: 12,
            childAspectRatio: 1.15,
          ),
          itemCount: scanners.length,
          itemBuilder: (context, index) {
            final scanner = scanners[index];
            return CyberShieldCard(
              onTap: () => Navigator.pushNamed(context, scanner.route),
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: scanner.color.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(scanner.icon, color: scanner.color, size: 22),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    scanner.title,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w600,
                      fontSize: 14,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    scanner.description,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }
}

class _ScannerItem {
  final IconData icon;
  final String title;
  final String description;
  final Color color;
  final String route;

  const _ScannerItem({
    required this.icon,
    required this.title,
    required this.description,
    required this.color,
    required this.route,
  });
}

