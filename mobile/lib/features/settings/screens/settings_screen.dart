// CyberShield Settings & User Profile Screen

import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/services/alert_service.dart';
import 'package:cybershield/core/services/protection_service.dart';
import 'package:cybershield/core/models/protection_models.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> with WidgetsBindingObserver {
  String _serverStatus = 'checking';
  String _connectionStatusLabel = 'CHECKING';
  String _serverVersion = '1.0.0';
  int _activeModuleCount = 0;
  int _latencyMs = 0;
  Map<String, dynamic>? _diagnosticsData;
  bool _isRunningDiagnostics = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _checkServerHealth();
    ProtectionService.instance.refreshStatus();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      ProtectionService.instance.refreshStatus();
    }
  }

  Future<void> _handleRequestCallScreeningRole() async {
    final result = await ProtectionService.instance.requestCallScreeningRole();
    if (!mounted || result.isInProgress) return;

    if (result.isUnsupported) {
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: AppColors.cardBorder),
          ),
          title: const Row(
            children: [
              Icon(Icons.info_outline_rounded, color: AppColors.warning, size: 22),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Call Screening Not Supported',
                  style: TextStyle(color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          content: Text(
            '${result.message}\n\n'
            'Android introduced the official RoleManager Call Screening API in Android 10 (API 29). '
            'Other CyberShield protection features (URL, SMS, QR, Screenshot, APK, File, Email, and Notification Listener) remain fully functional on this device.',
            style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.45),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('OK', style: TextStyle(color: AppColors.primary, fontWeight: FontWeight.bold)),
            ),
          ],
        ),
      );
      return;
    }

    final Color bgColor;
    if (result.isGranted) {
      bgColor = AppColors.safe;
    } else if (result.isDenied) {
      bgColor = AppColors.warning;
    } else {
      bgColor = AppColors.danger;
    }

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(result.message),
        backgroundColor: bgColor,
        duration: const Duration(seconds: 4),
      ),
    );
  }

  Future<void> _checkServerHealth() async {
    final sw = Stopwatch()..start();
    var res = await ApiService.healthCheck();
    if (res['status'] != 'healthy') {
      final autoRes = await ApiService.autoDiscoverAndConnect();
      if (autoRes['success'] == true) {
        res = autoRes;
        await ProtectionService.instance.syncNativeBackendConfig();
      }
    }
    sw.stop();

    if (mounted) {
      final isOnline = res['status'] == 'healthy';
      final label = res['connection_status']?.toString() ??
          (isOnline ? ApiService.statusOnline : ApiService.statusOffline);
      setState(() {
        _latencyMs = sw.elapsedMilliseconds;
        _serverStatus = isOnline ? 'healthy' : 'offline';
        _connectionStatusLabel = label;
        _serverVersion = res['version']?.toString() ?? (isOnline ? '1.0.0' : 'Unavailable');
        final mods = res['active_modules'] as List?;
        _activeModuleCount = isOnline ? (mods?.length ?? 0) : 0;
      });
    }
  }

  Future<void> _runFullDiagnostics() async {
    setState(() => _isRunningDiagnostics = true);
    final diag = await ApiService.checkDiagnostics();
    if (mounted) {
      final isOnline = diag['status'] == 'healthy';
      setState(() {
        _diagnosticsData = diag;
        _isRunningDiagnostics = false;
        _serverStatus = isOnline ? 'healthy' : 'offline';
        _connectionStatusLabel = diag['connection_status']?.toString() ??
            (isOnline ? ApiService.statusOnline : ApiService.statusOffline);
        _latencyMs = diag['latency_ms'] ?? 0;
        final mods = diag['active_modules'] as List?;
        _activeModuleCount = isOnline ? (mods?.length ?? 0) : 0;
      });
    }
  }

  Future<void> _showApiConfigDialog() async {
    final controller = TextEditingController(text: ApiService.baseUrl);
    final themeCtrl = ThemeController.instance;

    await showDialog(
      context: context,
      builder: (ctx) {
        bool isTesting = false;
        String? testMessage;
        bool? testSuccess;

        return StatefulBuilder(
          builder: (dialogCtx, setDialogState) {
            return AlertDialog(
              backgroundColor: AppColors.surface,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(16),
                side: const BorderSide(color: AppColors.cardBorder),
              ),
              title: const Row(
                children: [
                  Icon(Icons.dns_rounded, color: AppColors.primary, size: 22),
                  SizedBox(width: 10),
                  Text('Configure API Endpoint',
                      style: TextStyle(color: AppColors.textPrimary, fontSize: 16)),
                ],
              ),
              content: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Specify the FastAPI server address. Config is permanently saved to device storage and retained across app restarts.',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
                    ),
                    const SizedBox(height: 14),
                    TextField(
                      controller: controller,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 13,
                        fontFamily: 'monospace',
                      ),
                      decoration: InputDecoration(
                        labelText: 'API Base URL',
                        labelStyle: const TextStyle(color: AppColors.textSecondary, fontSize: 12),
                        hintText: 'http://192.168.1.X:8000',
                        hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                        filled: true,
                        fillColor: AppColors.surfaceSubtle,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                          borderSide: const BorderSide(color: AppColors.cardBorder),
                        ),
                        focusedBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                          borderSide: BorderSide(color: themeCtrl.primaryColor),
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        OutlinedButton.icon(
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                            side: BorderSide(color: themeCtrl.primaryColor.withValues(alpha: 0.6)),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                          onPressed: isTesting
                              ? null
                              : () async {
                                  setDialogState(() {
                                    isTesting = true;
                                    testMessage = null;
                                  });
                                  final candidate = controller.text.trim();
                                  final sw = Stopwatch()..start();
                                  final res = await ApiService.testCandidateUrl(candidate);
                                  sw.stop();

                                  setDialogState(() {
                                    isTesting = false;
                                    testSuccess = res['status'] == 'healthy';
                                    if (testSuccess!) {
                                      final mods = (res['active_modules'] as List?)?.length ?? 0;
                                      testMessage = 'ONLINE: ${sw.elapsedMilliseconds}ms ($mods modules active)';
                                    } else {
                                      final label = res['connection_status'] ?? 'OFFLINE';
                                      testMessage = '$label: ${res['error'] ?? 'Connection refused'}';
                                    }
                                  });
                                },
                          icon: isTesting
                              ? const SizedBox(
                                  width: 12,
                                  height: 12,
                                  child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                                )
                              : const Icon(Icons.network_check_rounded, size: 14),
                          label: Text(
                            isTesting ? 'Testing...' : 'Test Connection',
                            style: const TextStyle(fontSize: 11),
                          ),
                        ),
                        if (testMessage != null) ...[
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              testMessage!,
                              style: TextStyle(
                                color: testSuccess == true ? AppColors.safe : AppColors.danger,
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ],
                    ),
                    const SizedBox(height: 8),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: themeCtrl.primaryColor,
                          foregroundColor: Colors.black,
                          padding: const EdgeInsets.symmetric(vertical: 8),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        onPressed: isTesting
                            ? null
                            : () async {
                                setDialogState(() {
                                  isTesting = true;
                                  testMessage = 'Probing candidate addresses...';
                                });
                                final res = await ApiService.autoDiscoverAndConnect();
                                setDialogState(() {
                                  isTesting = false;
                                  testSuccess = res['success'] == true;
                                  if (testSuccess!) {
                                    controller.text = res['base_url'] ?? controller.text;
                                    testMessage = res['message'];
                                  } else {
                                    testMessage = res['message'] ?? 'Could not find active backend';
                                  }
                                });
                              },
                        icon: const Icon(Icons.radar_rounded, size: 16),
                        label: const Text('Auto-Detect & Probe Server', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                      ),
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Quick Presets:',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 11, fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: [
                        ActionChip(
                          backgroundColor: AppColors.surfaceLight,
                          side: BorderSide(color: AppColors.safe.withValues(alpha: 0.8)),
                          avatar: const Icon(Icons.cloud_done_rounded, size: 14, color: AppColors.safe),
                          label: Text(
                            ApiService.presetCloudUrl.isNotEmpty
                                ? 'Cloud HTTPS (Default)'
                                : 'Cloud HTTPS (Paste URL)',
                            style: const TextStyle(color: AppColors.safe, fontSize: 10, fontWeight: FontWeight.bold),
                          ),
                          onPressed: () {
                            setDialogState(() {
                              controller.text = ApiService.presetCloudUrl.isNotEmpty
                                  ? ApiService.presetCloudUrl
                                  : 'https://';
                            });
                          },
                        ),
                        ActionChip(
                          backgroundColor: AppColors.surfaceLight,
                          side: BorderSide(color: themeCtrl.primaryColor.withValues(alpha: 0.8)),
                          avatar: const Icon(Icons.usb_rounded, size: 14, color: AppColors.primary),
                          label: const Text('ADB Reverse (127.0.0.1:8000)',
                              style: TextStyle(color: AppColors.primary, fontSize: 10, fontWeight: FontWeight.bold)),
                          onPressed: () {
                            setDialogState(() {
                              controller.text = ApiService.presetAdbReverse;
                            });
                          },
                        ),
                        ActionChip(
                          backgroundColor: AppColors.surfaceLight,
                          side: BorderSide(color: themeCtrl.primaryColor.withValues(alpha: 0.6)),
                          avatar: const Icon(Icons.wifi_rounded, size: 14, color: AppColors.primary),
                          label: Text('Wi-Fi LAN (${ApiService.presetCurrentWifi.replaceFirst('http://', '')})',
                              style: const TextStyle(color: AppColors.primary, fontSize: 10, fontWeight: FontWeight.bold)),
                          onPressed: () {
                            setDialogState(() {
                              controller.text = ApiService.presetCurrentWifi;
                            });
                          },
                        ),
                        ActionChip(
                          backgroundColor: AppColors.surfaceLight,
                          side: const BorderSide(color: AppColors.cardBorder),
                          label: const Text('Emulator (10.0.2.2:8000)',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 10)),
                          onPressed: () {
                            setDialogState(() {
                              controller.text = ApiService.presetEmulator;
                            });
                          },
                        ),
                        ActionChip(
                          backgroundColor: AppColors.surfaceLight,
                          side: const BorderSide(color: AppColors.cardBorder),
                          label: const Text('Localhost (localhost:8000)',
                              style: TextStyle(color: AppColors.textPrimary, fontSize: 10)),
                          onPressed: () {
                            setDialogState(() {
                              controller.text = ApiService.presetLocalhost;
                            });
                          },
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    const Text(
                      'Connection Modes:\n• Cloud HTTPS (Recommended): Works anywhere on mobile data or Wi-Fi without PC (e.g. https://cybershield-api.up.railway.app).\n• Local Wi-Fi / USB: Same Wi-Fi LAN IP or "adb reverse tcp:8000 tcp:8000" (127.0.0.1:8000).',
                      style: TextStyle(color: AppColors.textMuted, fontSize: 10, height: 1.3),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: themeCtrl.primaryColor),
                  onPressed: () async {
                    final newUrl = controller.text.trim();
                    final validationError = ApiService.validateEndpointUrl(newUrl);
                    if (validationError != null) {
                      setDialogState(() {
                        testSuccess = false;
                        testMessage = validationError;
                      });
                      return;
                    }
                    await ApiService.saveCustomBaseUrl(newUrl.isNotEmpty ? newUrl : null);
                    await ProtectionService.instance.syncNativeBackendConfig();
                    if (dialogCtx.mounted) {
                      Navigator.pop(ctx);
                    }
                    await _checkServerHealth();
                    if (mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            'API Base URL saved: ${ApiService.baseUrl} (Status: ${_serverStatus.toUpperCase()}, ${_latencyMs}ms)',
                          ),
                          backgroundColor: _serverStatus == 'healthy' ? AppColors.safe : AppColors.danger,
                        ),
                      );
                    }
                  },
                  child: const Text('Save & Apply', style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold)),
                ),
              ],
            );
          },
        );
      },
    );
  }

  Future<void> _logout() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: const Row(
          children: [
            Icon(Icons.logout_rounded, color: AppColors.danger, size: 22),
            SizedBox(width: 10),
            Text('Sign Out of CyberShield',
                style: TextStyle(color: AppColors.textPrimary, fontSize: 16)),
          ],
        ),
        content: const Text(
          'Are you sure you want to log out? Your cloud history and security alerts will remain securely backed up in Firestore.',
          style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Sign Out', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await FirebaseAuth.instance.signOut();
      if (mounted) {
        Navigator.pushNamedAndRemoveUntil(context, AppRouter.login, (route) => false);
      }
    }
  }

  Future<void> _sendPasswordReset() async {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null || user.email == null) return;
    try {
      await FirebaseAuth.instance.sendPasswordResetEmail(email: user.email!);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Password reset dispatched to ${user.email}. Check your inbox.'),
            backgroundColor: AppColors.safe,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to send reset link: $e'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    }
  }

  Future<void> _deleteAccount() async {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.cardBorder),
        ),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: AppColors.danger, size: 24),
            SizedBox(width: 10),
            Text('Delete Defense Profile?',
                style: TextStyle(color: AppColors.textPrimary, fontSize: 16)),
          ],
        ),
        content: const Text(
          'Warning: This permanently purges your CyberShield account, all cloud scan history, and active security alerts. This action cannot be reversed.',
          style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete & Purge Data', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        await FirestoreHistoryService.instance.clearAllHistory();
        await AlertService.instance.clearAllAlerts();
        await user.delete();

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Your account and defense records have been purged.'),
              backgroundColor: AppColors.safe,
            ),
          );
          Navigator.pushNamedAndRemoveUntil(context, AppRouter.dashboard, (route) => false);
        }
      } on FirebaseAuthException catch (e) {
        if (mounted) {
          String msg = e.message ?? e.code;
          if (e.code == 'requires-recent-login') {
            msg = 'For security, account deletion requires recent sign-in. Please sign out, sign back in, and retry deletion.';
          }
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(msg),
              backgroundColor: AppColors.danger,
              duration: const Duration(seconds: 5),
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Account deletion failed: $e'),
              backgroundColor: AppColors.danger,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    User? user;
    try {
      user = FirebaseAuth.instance.currentUser;
    } catch (_) {
      user = null;
    }
    final themeCtrl = ThemeController.instance;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                color: themeCtrl.primaryColor.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: themeCtrl.primaryColor.withValues(alpha: 0.35),
                  width: 1,
                ),
              ),
              child: Icon(
                Icons.settings_suggest_rounded,
                color: themeCtrl.primaryColor,
                size: 20,
              ),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Text(
                'Settings & Profile',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.settings),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 16, 18, 80),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildProfileCard(user),
            const SizedBox(height: 18),
            _buildThemeAppearanceSection(themeCtrl),
            const SizedBox(height: 18),
            _buildAccentColorSection(themeCtrl),
            const SizedBox(height: 18),
            _buildNotificationSection(themeCtrl),
            const SizedBox(height: 18),
            _buildPermissionManagerSection(),
            const SizedBox(height: 18),
            _buildEngineDiagnosticsSection(),
            const SizedBox(height: 24),
            _buildGovernanceAndSafetySection(),
            const SizedBox(height: 24),
            _buildAccountSecuritySection(user),
            const SizedBox(height: 28),
          ],
        ),
      ),
    );
  }

  Widget _buildProfileCard(User? user) {
    final email = user?.email ?? 'Anonymous Sentinel';
    final uid = user?.uid ?? 'Local Offline Guest';
    final isVerified = user?.emailVerified ?? false;

    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      borderColor: ThemeController.instance.primaryColor.withValues(alpha: 0.3),
      child: Row(
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: ThemeController.instance.primaryColor.withValues(alpha: 0.15),
              border: Border.all(color: ThemeController.instance.primaryColor, width: 2),
            ),
            child: Center(
              child: Text(
                email.isNotEmpty ? email[0].toUpperCase() : 'C',
                style: TextStyle(
                  color: ThemeController.instance.primaryColor,
                  fontSize: 22,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Flexible(
                      child: Text(
                        email,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w800,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const SizedBox(width: 6),
                    if (isVerified)
                      const Icon(Icons.verified_rounded, color: AppColors.safe, size: 16),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  'UID: ${uid.length > 18 ? "${uid.substring(0, 18)}..." : uid}',
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 6),
                CyberBadge(
                  label: user != null ? 'CLOUD DEFENDER AUTHENTICATED' : 'LOCAL GUEST',
                  type: user != null ? BadgeType.safe : BadgeType.neutral,
                  fontSize: 9,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThemeAppearanceSection(ThemeController themeCtrl) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Appearance & Mode',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 10),
        CyberShieldCard(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              _buildThemeOption(
                label: 'Dark (Cyber)',
                icon: Icons.dark_mode_rounded,
                isSelected: themeCtrl.themeMode == ThemeMode.dark,
                onTap: () => themeCtrl.setThemeMode(ThemeMode.dark),
              ),
              const SizedBox(width: 8),
              _buildThemeOption(
                label: 'Light (Slate)',
                icon: Icons.light_mode_rounded,
                isSelected: themeCtrl.themeMode == ThemeMode.light,
                onTap: () => themeCtrl.setThemeMode(ThemeMode.light),
              ),
              const SizedBox(width: 8),
              _buildThemeOption(
                label: 'System OS',
                icon: Icons.settings_brightness_rounded,
                isSelected: themeCtrl.themeMode == ThemeMode.system,
                onTap: () => themeCtrl.setThemeMode(ThemeMode.system),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildThemeOption({
    required String label,
    required IconData icon,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    final color = isSelected ? ThemeController.instance.primaryColor : AppColors.textSecondary;

    return Expanded(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          decoration: BoxDecoration(
            color: isSelected ? ThemeController.instance.primaryColor.withValues(alpha: 0.15) : AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: isSelected ? ThemeController.instance.primaryColor : Colors.transparent,
              width: 1.5,
            ),
          ),
          child: Column(
            children: [
              Icon(icon, color: color, size: 20),
              const SizedBox(height: 6),
              Text(
                label,
                style: TextStyle(
                  color: isSelected ? AppColors.textPrimary : AppColors.textMuted,
                  fontSize: 11,
                  fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAccentColorSection(ThemeController themeCtrl) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Expanded(
              child: Text(
                'Cyber Accent Theme',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              'Active: ${themeCtrl.accent.name}',
              style: TextStyle(
                color: themeCtrl.primaryColor,
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        CyberShieldCard(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: AppColors.accentPresets.map((preset) {
              final isSelected = themeCtrl.accent.name == preset.name;
              return GestureDetector(
                onTap: () => themeCtrl.setAccentColor(preset),
                child: Column(
                  children: [
                    Container(
                      width: 42,
                      height: 42,
                      decoration: BoxDecoration(
                        color: preset.primary,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: isSelected ? Colors.white : Colors.transparent,
                          width: 2.5,
                        ),
                        boxShadow: isSelected
                            ? [
                                BoxShadow(
                                  color: preset.glow,
                                  blurRadius: 10,
                                  spreadRadius: 2,
                                ),
                              ]
                            : null,
                      ),
                      child: isSelected
                          ? const Center(
                              child: Icon(Icons.check, color: Colors.black, size: 20),
                            )
                          : null,
                    ),
                    const SizedBox(height: 6),
                    Text(
                      preset.name,
                      style: TextStyle(
                        color: isSelected ? AppColors.textPrimary : AppColors.textMuted,
                        fontSize: 10,
                        fontWeight: isSelected ? FontWeight.w800 : FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              );
            }).toList(),
          ),
        ),
      ],
    );
  }

  Widget _buildNotificationSection(ThemeController themeCtrl) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Security Alerts & Notifications',
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
                activeThumbColor: themeCtrl.primaryColor,
                activeTrackColor: themeCtrl.primaryColor.withValues(alpha: 0.4),
                title: const Text('High-Risk Threat Alerts',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13, fontWeight: FontWeight.w600)),
                subtitle: const Text('Show prominent banners for Critical and High-severity findings.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: themeCtrl.highRiskAlertsEnabled,
                onChanged: themeCtrl.setHighRiskAlerts,
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                activeThumbColor: themeCtrl.primaryColor,
                activeTrackColor: themeCtrl.primaryColor.withValues(alpha: 0.4),
                title: const Text('Haptic Threat Alerts',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13, fontWeight: FontWeight.w600)),
                subtitle: const Text('Trigger device feedback on malware or trojan detection.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: themeCtrl.hapticFeedbackEnabled,
                onChanged: themeCtrl.setHapticFeedback,
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                activeThumbColor: themeCtrl.primaryColor,
                activeTrackColor: themeCtrl.primaryColor.withValues(alpha: 0.4),
                title: const Text('Cloud Firestore History Sync',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 13, fontWeight: FontWeight.w600)),
                subtitle: const Text('Seamlessly synchronize scan history across authenticated devices.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
                value: themeCtrl.cloudSyncEnabled,
                onChanged: themeCtrl.setCloudSync,
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildPermissionManagerSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Android Protection Permissions',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 10),
        ValueListenableBuilder<ProtectionStatus>(
          valueListenable: ProtectionService.instance.statusNotifier,
          builder: (context, status, _) {
            return Column(
              children: [
                _buildPermissionTile(
                  icon: Icons.notifications_active_rounded,
                  title: 'Push Security Notifications',
                  subtitle: 'Immediate heads-up alerts on high-risk detections',
                  isGranted: true, // Core notification capability
                  buttonLabel: 'Active',
                  onTap: () => ProtectionService.instance.requestNotificationPermission(),
                ),
                const SizedBox(height: 8),
                _buildPermissionTile(
                  icon: Icons.mark_email_unread_rounded,
                  title: 'SMS & App Alert Interceptor',
                  subtitle: 'Real-time background scanning for phishing & OTP fraud',
                  isGranted: status.isNotificationAccessGranted,
                  buttonLabel: status.isNotificationAccessGranted ? 'Active' : 'Enable',
                  onTap: () => ProtectionService.instance.openNotificationListenerSettings(),
                ),
                const SizedBox(height: 8),
                ValueListenableBuilder<bool>(
                  valueListenable: ProtectionService.instance.isRequestingCallRoleNotifier,
                  builder: (context, isRequestingRole, _) {
                    final isSupported = status.isCallScreeningSupported;
                    final isHeld = isSupported && status.isCallScreeningRoleHeld;
                    final sdkLabel = status.androidSdk > 0
                        ? 'Android ${status.androidRelease ?? status.androidSdk} (API ${status.androidSdk})'
                        : 'API < 29';
                    final subtitle = !isSupported
                        ? 'Native Call Screening Unsupported on This Device ($sdkLabel — requires Android 10 / API 29+). Calls are not automatically blocked or screened; manual number checks remain available.'
                        : 'Automatic incoming call screening via Android 10+ CallScreeningService';

                    return _buildPermissionTile(
                      icon: Icons.phone_locked_rounded,
                      title: 'Native Automatic Call Screening',
                      subtitle: subtitle,
                      isGranted: isHeld,
                      isUnsupported: !isSupported,
                      isBusy: isRequestingRole,
                      buttonLabel: isHeld
                          ? 'Active'
                          : (!isSupported ? 'Unsupported' : 'Set Role'),
                      onTap: (isHeld || !isSupported) ? null : _handleRequestCallScreeningRole,
                    );
                  },
                ),
                const SizedBox(height: 8),
                _buildPermissionTile(
                  icon: Icons.security_rounded,
                  title: 'On-Device App & Storage Audit',
                  subtitle: 'Static permission combination & malware package audit',
                  isGranted: true,
                  buttonLabel: 'Active',
                  onTap: null,
                ),
              ],
            );
          },
        ),
      ],
    );
  }

  Widget _buildPermissionTile({
    required IconData icon,
    required String title,
    required String subtitle,
    required bool isGranted,
    required String buttonLabel,
    required VoidCallback? onTap,
    bool isBusy = false,
    bool isUnsupported = false,
  }) {
    final statusColor = isGranted
        ? AppColors.safe
        : (isUnsupported ? AppColors.textMuted : AppColors.warning);

    return CyberShieldCard(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: statusColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: statusColor, size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
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
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          if (onTap != null && !isGranted)
            isUnsupported
                ? OutlinedButton(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppColors.textSecondary,
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: isBusy ? null : onTap,
                    child: Text(
                      buttonLabel,
                      style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600),
                    ),
                  )
                : ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.primary,
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: isBusy ? null : onTap,
                    child: isBusy
                        ? const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Colors.black,
                            ),
                          )
                        : Text(
                            buttonLabel,
                            style: const TextStyle(color: Colors.black, fontSize: 11, fontWeight: FontWeight.bold),
                          ),
                  )
          else
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                color: statusColor.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: statusColor.withValues(alpha: 0.4)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(isGranted ? Icons.check_circle_rounded : Icons.info_outline_rounded,
                      color: statusColor, size: 12),
                  const SizedBox(width: 4),
                  Text(
                    buttonLabel,
                    style: TextStyle(
                      color: statusColor,
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildEngineDiagnosticsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Engine Diagnostics & Environment',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 10),
        CyberShieldCard(
          padding: const EdgeInsets.all(14),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Expanded(
                    child: Text('FastAPI Engine Status',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                  const SizedBox(width: 8),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: _serverStatus == 'healthy' ? AppColors.safe : AppColors.danger,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        _serverStatus == 'healthy' ? 'ONLINE' : _connectionStatusLabel,
                        style: TextStyle(
                          color: _serverStatus == 'healthy' ? AppColors.safe : AppColors.danger,
                          fontWeight: FontWeight.w800,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Expanded(
                    child: Text('Backend Threat Modules',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _serverStatus == 'healthy'
                        ? '$_activeModuleCount Verified Online'
                        : 'Unavailable (Offline)',
                    style: TextStyle(
                      color: _serverStatus == 'healthy' ? AppColors.textPrimary : AppColors.danger,
                      fontWeight: FontWeight.w700,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Expanded(
                    child: Text('API Latency',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _serverStatus == 'healthy' ? '${_latencyMs}ms' : '—',
                    style: const TextStyle(color: AppColors.textPrimary, fontWeight: FontWeight.w700, fontSize: 12),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Expanded(
                    child: Text('CyberShield Release',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _serverStatus == 'healthy' ? 'v$_serverVersion' : 'Offline',
                    style: TextStyle(
                      color: _serverStatus == 'healthy' ? AppColors.primary : AppColors.textMuted,
                      fontWeight: FontWeight.w800,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              const Divider(color: AppColors.cardBorder, height: 1),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('Active API Endpoint',
                            style: TextStyle(color: AppColors.textSecondary, fontSize: 11)),
                        const SizedBox(height: 2),
                        Text(
                          ApiService.baseUrl,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w600,
                            fontSize: 11,
                            fontFamily: 'monospace',
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      side: BorderSide(color: ThemeController.instance.primaryColor.withValues(alpha: 0.5)),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: _showApiConfigDialog,
                    icon: Icon(Icons.tune_rounded, size: 14, color: ThemeController.instance.primaryColor),
                    label: Text('Configure',
                        style: TextStyle(color: ThemeController.instance.primaryColor, fontSize: 11, fontWeight: FontWeight.w700)),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    side: const BorderSide(color: AppColors.cardBorder),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  onPressed: _isRunningDiagnostics ? null : _runFullDiagnostics,
                  icon: _isRunningDiagnostics
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                        )
                      : const Icon(Icons.troubleshoot_rounded, size: 16),
                  label: Text(_isRunningDiagnostics ? 'Running Diagnostics...' : 'Run Diagnostics & Network Test'),
                ),
              ),
              if (_diagnosticsData != null) ...[
                const SizedBox(height: 12),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceSubtle,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: _diagnosticsData!['status'] == 'healthy'
                          ? AppColors.safe.withValues(alpha: 0.4)
                          : AppColors.danger.withValues(alpha: 0.4),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            _diagnosticsData!['status'] == 'healthy'
                                ? Icons.check_circle_rounded
                                : Icons.warning_rounded,
                            color: _diagnosticsData!['status'] == 'healthy' ? AppColors.safe : AppColors.danger,
                            size: 16,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            _diagnosticsData!['status'] == 'healthy'
                                ? 'Full Connectivity Verified'
                                : 'Backend Connectivity Issue',
                            style: TextStyle(
                              color: _diagnosticsData!['status'] == 'healthy' ? AppColors.safe : AppColors.danger,
                              fontWeight: FontWeight.bold,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      Text(
                        _diagnosticsData!['message']?.toString() ?? '',
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
                      ),
                      if (_diagnosticsData!['ai_status'] is Map) ...[
                        const SizedBox(height: 6),
                        Builder(
                          builder: (_) {
                            final ai = _diagnosticsData!['ai_status'] as Map;
                            final provider = (ai['provider']?.toString() ?? 'openrouter').toUpperCase();
                            final model = ai['model']?.toString() ?? 'unknown';
                            final ready = ai['configured'] == true && ai['model_available'] == true;
                            return Text(
                              'AI Engine ($provider): $model (${ready ? 'Verified' : (ai['configured'] == true ? 'Configured' : 'Unconfigured')})',
                              style: const TextStyle(
                                color: AppColors.primary,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                              ),
                            );
                          },
                        ),
                      ],
                      if (_diagnosticsData!['help'] != null) ...[
                        const SizedBox(height: 6),
                        Text(
                          _diagnosticsData!['help']!.toString(),
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 10, height: 1.3),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildGovernanceAndSafetySection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Privacy, Terms & Security Governance',
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
              _buildGovernanceRow(
                icon: Icons.verified_user_rounded,
                title: 'Permission Center',
                subtitle: 'Audit, request, or toggle device defense permissions',
                route: AppRouter.permissionCenter,
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              _buildGovernanceRow(
                icon: Icons.health_and_safety_rounded,
                title: 'Safety Center & Cyber Hygiene',
                subtitle: 'Spotting phishing, passkey best practices & incident playbooks',
                route: AppRouter.safetyCenter,
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              _buildGovernanceRow(
                icon: Icons.privacy_tip_rounded,
                title: 'Privacy Policy',
                subtitle: '14-point data collection charter & Zero-Leak Guarantee',
                route: AppRouter.privacyPolicy,
              ),
              const Divider(color: AppColors.cardBorder, height: 1),
              _buildGovernanceRow(
                icon: Icons.gavel_rounded,
                title: 'Terms of Service',
                subtitle: 'Educational scope, zero-day notice & liability disclaimers',
                route: AppRouter.terms,
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildGovernanceRow({
    required IconData icon,
    required String title,
    required String subtitle,
    required String route,
  }) {
    return ListTile(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      contentPadding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: AppColors.primary.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Icon(icon, color: AppColors.primary, size: 20),
      ),
      title: Text(
        title,
        style: const TextStyle(
          color: AppColors.textPrimary,
          fontSize: 13,
          fontWeight: FontWeight.w700,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
      ),
      trailing: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: AppColors.textMuted),
      onTap: () => Navigator.pushNamed(context, route),
    );
  }

  Widget _buildAccountSecuritySection(User? user) {
    final themeCtrl = ThemeController.instance;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Account & Data Management',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 10),
        CyberShieldCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              if (user != null) ...[
                if (user.email != null)
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton.icon(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: themeCtrl.primaryColor,
                        side: BorderSide(color: themeCtrl.primaryColor.withValues(alpha: 0.5)),
                        padding: const EdgeInsets.symmetric(vertical: 12),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                      onPressed: _sendPasswordReset,
                      icon: const Icon(Icons.lock_reset_rounded, size: 18),
                      label: const Text('Send Password Reset Link'),
                    ),
                  ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppColors.textPrimary,
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    ),
                    onPressed: _logout,
                    icon: const Icon(Icons.logout_rounded, size: 18),
                    label: const Text('Sign Out of CyberShield'),
                  ),
                ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppColors.danger,
                      side: const BorderSide(color: AppColors.danger, width: 1.2),
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    ),
                    onPressed: _deleteAccount,
                    icon: const Icon(Icons.delete_forever_rounded, size: 18),
                    label: const Text('Delete Defense Profile & Purge Data'),
                  ),
                ),
              ] else ...[
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () => Navigator.pushNamed(context, AppRouter.login),
                    icon: const Icon(Icons.login_rounded, size: 18),
                    label: const Text('Sign In or Register Sentinel Profile'),
                  ),
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
}
