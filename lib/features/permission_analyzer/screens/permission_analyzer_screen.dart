// Permission Analyzer Screen for CyberShield

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/cyber_error_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/models/permission_scan_result.dart';

class _AppProfilePreset {
  final String label;
  final String subtitle;
  final String packageName;
  final IconData icon;
  final Color color;
  final List<String> permissions;

  const _AppProfilePreset({
    required this.label,
    required this.subtitle,
    required this.packageName,
    required this.icon,
    required this.color,
    required this.permissions,
  });
}

class _ApkPreset {
  final String label;
  final String subtitle;
  final IconData icon;
  final Color color;
  final String filename;
  final String base64Data;

  const _ApkPreset({
    required this.label,
    required this.subtitle,
    required this.icon,
    required this.color,
    required this.filename,
    required this.base64Data,
  });
}

class PermissionAnalyzerScreen extends StatefulWidget {
  const PermissionAnalyzerScreen({super.key});

  @override
  State<PermissionAnalyzerScreen> createState() => _PermissionAnalyzerScreenState();
}

class _PermissionAnalyzerScreenState extends State<PermissionAnalyzerScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;

  // Selected App Profile State
  int _selectedPresetIndex = 0;
  final Set<String> _customSelectedPermissions = {};
  bool _isCustomMode = false;

  // APK Upload State
  Uint8List? _selectedApkBytes;
  String? _selectedFilename;
  int? _selectedFileSize;

  // Async & Results State
  bool _isLoading = false;
  String? _errorMessage;
  PermissionScanResult? _scanResult;
  bool _showAllPermissions = false;

  // Curated Android Application Permission Profiles
  static const List<_AppProfilePreset> _appPresets = [
    _AppProfilePreset(
      label: 'Banking Trojan Profile',
      subtitle: 'Critical: SMS Interception + Accessibility Service + Overlay',
      packageName: 'com.fraud.banktrojan',
      icon: Icons.account_balance_rounded,
      color: Color(0xFFFF3B30),
      permissions: [
        'android.permission.READ_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.INTERNET',
      ],
    ),
    _AppProfilePreset(
      label: 'Stalkerware / Surveillance Profile',
      subtitle: 'Critical: Continuous Mic + Camera + Background Location + Boot',
      packageName: 'com.spyware.coverttracker',
      icon: Icons.track_changes_rounded,
      color: Color(0xFFFF453A),
      permissions: [
        'android.permission.RECORD_AUDIO',
        'android.permission.CAMERA',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.READ_CONTACTS',
      ],
    ),
    _AppProfilePreset(
      label: 'Social Media & Messaging App',
      subtitle: 'High Risk: Camera, Mic, Contacts, Location & Storage',
      packageName: 'com.social.network.connect',
      icon: Icons.forum_rounded,
      color: Color(0xFFFF9F0A),
      permissions: [
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.INTERNET',
      ],
    ),
    _AppProfilePreset(
      label: 'Verified Banking & UPI App',
      subtitle: 'Suspicious / Elevated: Biometrics, SMS (2FA), Network, Phone State',
      packageName: 'com.legit.mobilebanking',
      icon: Icons.verified_user_rounded,
      color: Color(0xFF0A84FF),
      permissions: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.READ_PHONE_STATE',
        'android.permission.USE_BIOMETRIC',
        'android.permission.RECEIVE_SMS',
      ],
    ),
    _AppProfilePreset(
      label: 'Safe Utility / Calculator App',
      subtitle: 'Safe: Standard Network and Vibration only',
      packageName: 'com.tools.clean.calculator',
      icon: Icons.calculate_rounded,
      color: Color(0xFF30D158),
      permissions: [
        'android.permission.INTERNET',
        'android.permission.VIBRATE',
        'android.permission.ACCESS_NETWORK_STATE',
      ],
    ),
  ];

  // Common Android Permissions for Custom Selection
  static const Map<String, List<Map<String, String>>> _categorizedPermissions = {
    'SMS & Telephony': [
      {'name': 'android.permission.READ_SMS', 'label': 'Read SMS (OTP Intercept)'},
      {'name': 'android.permission.RECEIVE_SMS', 'label': 'Receive SMS Silently'},
      {'name': 'android.permission.SEND_SMS', 'label': 'Send Premium SMS'},
      {'name': 'android.permission.READ_CALL_LOG', 'label': 'Read Call Log'},
      {'name': 'android.permission.READ_PHONE_STATE', 'label': 'Read Device IMEI/SIM'},
    ],
    'Accessibility & Control': [
      {'name': 'android.permission.BIND_ACCESSIBILITY_SERVICE', 'label': 'Accessibility Service (Full Control)'},
      {'name': 'android.permission.SYSTEM_ALERT_WINDOW', 'label': 'System Overlay (Draw on Top)'},
      {'name': 'android.permission.REQUEST_INSTALL_PACKAGES', 'label': 'Install APK Packages (Dropper)'},
      {'name': 'android.permission.PACKAGE_USAGE_STATS', 'label': 'Monitor App Usage'},
    ],
    'Location & Tracking': [
      {'name': 'android.permission.ACCESS_FINE_LOCATION', 'label': 'Precise GPS Location'},
      {'name': 'android.permission.ACCESS_BACKGROUND_LOCATION', 'label': 'Covert Background Tracking'},
      {'name': 'android.permission.RECEIVE_BOOT_COMPLETED', 'label': 'Auto-Start on Boot'},
    ],
    'Sensors & Storage': [
      {'name': 'android.permission.RECORD_AUDIO', 'label': 'Microphone Audio Recording'},
      {'name': 'android.permission.CAMERA', 'label': 'Camera Photos & Video'},
      {'name': 'android.permission.READ_CONTACTS', 'label': 'Read Device Contacts'},
      {'name': 'android.permission.MANAGE_EXTERNAL_STORAGE', 'label': 'All-Files Storage Access'},
    ],
  };

  // Synthetic APK Packages
  static const List<_ApkPreset> _apkPresets = [
    _ApkPreset(
      label: 'Banking Trojan APK',
      subtitle: 'SMS + Accessibility + Overlay Injected Manifest',
      icon: Icons.account_balance_rounded,
      color: Color(0xFFFF3B30),
      filename: 'banking_trojan_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY11epx67jwAAAI8AAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5SRUFEX1NNUyBhbmRyb2lkLnBlcm1pc3Npb24uUkVDRUlWRV9TTVMgYW5kcm9pZC5wZXJtaXNzaW9uLkJJTkRfQUNDRVNTSUJJTElUWV9TRVJWSUNFIGFuZHJvaWQucGVybWlzc2lvbi5TWVNURU1fQUxFUlRfV0lORE9XUEsDBBQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAY2xhc3Nlcy5kZXhkZXgKMDM1AFBLAwQUAAAAAACAEmNdet9aIBYAAAAWAAAAFAAAAE1FVEEtSU5GL01BTklGRVNULk1GTWFuaWZlc3QtVmVyc2lvbjogMS4wClBLAQIUABQAAAAAAIASY11epx67jwAAAI8AAAATAAAAAAAAAAAAAACAAQAAAABBbmRyb2lkTWFuaWZlc3QueG1sUEsBAhQAFAAAAAAAgBJjXbnk+zEIAAAACAAAAAsAAAAAAAAAAAAAAIABwAAAAGNsYXNzZXMuZGV4UEsBAhQAFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAAAAAAAAAAAAAIAB8QAAAE1FVEEtSU5GL01BTklGRVNULk1GUEsFBgAAAAADAAMAvAAAADkBAAAAAA==',
    ),
    _ApkPreset(
      label: 'Surveillance Tracker APK',
      subtitle: 'Fine Location + Audio + Contacts + Boot Manifest',
      icon: Icons.track_changes_rounded,
      color: Color(0xFFFF9500),
      filename: 'spyware_tracker_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY12xa5YdwAAAAMAAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5BQ0NFU1NfRklORV9MT0NBVElPTiBhbmRyb2lkLnBlcm1pc3Npb24uQUNDRVNTX0JBQ0tHUk9VTkRfTE9DQVRJT04gYW5kcm9pZC5wZXJtaXNzaW9uLlJFQURfQ09OVEFDVFMgYW5kcm9pZC5wZXJtaXNzaW9uLlJFQ09SRF9BVURJTyBhbmRyb2lkLnBlcm1pc3Npb24uUkVDRUlWRV9CT09UX0NPTVBMRVRFRFBLAwQUAAAAAACAEmNdueT7MQgAAAAIAAAACwAAAGNsYXNzZXMuZGV4ZGV4CjAzNQBQSwMEFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAABNRVRBLUlORi9NQU5JRkVTVC5NRk1hbmlmZXN0LVZlcnNpb246IDEuMApQSwECFAAUAAAAAACAEmNdsWuWHcAAAADAAAAAEwAAAAAAAAAAAAAAgAEAAAAAQW5kcm9pZE1hbmlmZXN0LnhtbFBLAQIUABQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAAAAAAAAAAACAAfEAAABjbGFzc2VzLmRleFBLAQIUABQAAAAAAIASY11631ogFgAAABYAAAAUAAAAAAAAAAAAAACAASIBAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLBQYAAAAAAwADALwAAABqAQAAAAA=',
    ),
    _ApkPreset(
      label: 'Safe Utility APK',
      subtitle: 'Minimal Network and Vibrate Manifest',
      icon: Icons.verified_user_rounded,
      color: Color(0xFF34C759),
      filename: 'utility_safe_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY12z5oNFNgAAADYAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5JTlRFUk5FVCBhbmRyb2lkLnBlcm1pc3Npb24uVklCUkFURVBLAwQUAAAAAACAEmNdueT7MQgAAAAIAAAACwAAAGNsYXNzZXMuZGV4ZGV4CjAzNQBQSwMEFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAABNRVRBLUlORi9NQU5JRkVTVC5NRk1hbmlmZXN0LVZlcnNpb246IDEuMApQSwECFAAUAAAAAACAEmNds+aDRTYAAAA2AAAAEwAAAAAAAAAAAAAAgAEAAAAAQW5kcm9pZE1hbmlmZXN0LnhtbFBLAQIUABQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAAAAAAAAAAACAAWcAAABjbGFzc2VzLmRleFBLAQIUABQAAAAAAIASY11631ogFgAAABYAAAAUAAAAAAAAAAAAAACAAZgAAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLBQYAAAAAAwADALwAAADgAAAAAAA=',
    ),
  ];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  // -------------------------------------------------------------------------
  // Analysis Actions
  // -------------------------------------------------------------------------

  Future<void> _analyzeSelectedAppProfile() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    List<String> perms;
    String appName;
    String packageName;

    if (_isCustomMode) {
      if (_customSelectedPermissions.isEmpty) {
        setState(() {
          _isLoading = false;
          _errorMessage = 'Please select at least one permission to inspect.';
        });
        return;
      }
      perms = _customSelectedPermissions.toList();
      appName = 'Custom Permission Set';
      packageName = 'custom.app.inspect';
    } else {
      final preset = _appPresets[_selectedPresetIndex];
      perms = preset.permissions;
      appName = preset.label;
      packageName = preset.packageName;
    }

    try {
      final result = await ApiService.analyzePermissionsList(
        permissions: perms,
        appName: appName,
        packageName: packageName,
      );

      if (result.isError) {
        setState(() {
          _isLoading = false;
          _errorMessage = result.errorMessage ?? 'Permission analysis failed.';
        });
        return;
      }

      setState(() {
        _isLoading = false;
        _scanResult = result;
      });

      // Save to Cloud Firestore
      await _saveCloudHistory(result);
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = 'Failed to analyze permissions: $e';
      });
    }
  }

  Future<void> _pickApkFile() async {
    try {
      final files = await FilePicker.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['apk'],
      );

      if (files.isNotEmpty) {
        final file = files.first;
        final bytes = await file.xFile.readAsBytes();

        setState(() {
          _selectedApkBytes = bytes;
          _selectedFilename = file.name;
          _selectedFileSize = bytes.length;
          _errorMessage = null;
          _scanResult = null;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Could not select APK file: $e';
      });
    }
  }

  void _loadApkPreset(_ApkPreset preset) {
    try {
      final bytes = base64Decode(preset.base64Data);
      setState(() {
        _selectedApkBytes = bytes;
        _selectedFilename = preset.filename;
        _selectedFileSize = bytes.length;
        _errorMessage = null;
        _scanResult = null;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Could not load preset APK: $e';
      });
    }
  }

  Future<void> _analyzeApkFile() async {
    if (_selectedApkBytes == null || _selectedFilename == null) {
      setState(() {
        _errorMessage = 'Please select or upload an APK file first.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    try {
      final result = await ApiService.analyzePermissionsApk(
        _selectedApkBytes!,
        filename: _selectedFilename!,
      );

      if (result.isError) {
        setState(() {
          _isLoading = false;
          _errorMessage = result.errorMessage ?? 'APK permission analysis failed.';
        });
        return;
      }

      setState(() {
        _isLoading = false;
        _scanResult = result;
      });

      // Save to Cloud Firestore
      await _saveCloudHistory(result);
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = 'APK permission analysis failed: $e';
      });
    }
  }

  Future<void> _saveCloudHistory(PermissionScanResult result) async {
    try {
      if (FirestoreHistoryService.instance.isAuthenticated) {
        await FirestoreHistoryService.instance.recordScan(
          scanType: 'PERMISSIONS',
          target: result.packageName.isNotEmpty ? result.packageName : result.appName,
          riskScore: result.riskScore,
          classification: result.classification,
          status: result.classification,
          summary:
              '${result.dangerousPermissionsCount}/${result.totalPermissionsCount} dangerous permissions (${result.classification})',
          result: result.toJson(),
          metadata: {
            'app_name': result.appName,
            'package_name': result.packageName,
            'combo_findings': result.comboFindings,
            'dangerous_permissions': result.dangerousPermissions,
          },
        );
      }
    } catch (_) {}
  }

  // -------------------------------------------------------------------------
  // UI Helpers
  // -------------------------------------------------------------------------

  Color _getClassificationColor(String classification) {
    switch (classification.toLowerCase()) {
      case 'critical':
        return const Color(0xFFFF2D55);
      case 'high risk':
        return AppColors.danger;
      case 'suspicious':
        return AppColors.warning;
      case 'safe':
        return AppColors.safe;
      default:
        return AppColors.textSecondary;
    }
  }

  BadgeType _getBadgeType(String classification) {
    switch (classification.toLowerCase()) {
      case 'critical':
      case 'high risk':
        return BadgeType.danger;
      case 'suspicious':
        return BadgeType.warning;
      case 'safe':
        return BadgeType.safe;
      default:
        return BadgeType.info;
    }
  }

  // -------------------------------------------------------------------------
  // Build Methods
  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        title: const Text('Permission Analyzer'),
        leading: Builder(
          builder: (context) => IconButton(
            icon: const Icon(Icons.menu_rounded),
            onPressed: () => Scaffold.of(context).openDrawer(),
          ),
        ),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppColors.primary,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textSecondary,
          tabs: const [
            Tab(icon: Icon(Icons.apps_rounded), text: 'Installed Profiles'),
            Tab(icon: Icon(Icons.android_rounded), text: 'APK File Upload'),
          ],
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.permissionAnalyzer),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAndroidLimitationsNotice(),
              const SizedBox(height: 16),
              SizedBox(
                height: 480,
                child: TabBarView(
                  controller: _tabController,
                  children: [
                    _buildInstalledProfilesTab(),
                    _buildApkUploadTab(),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              if (_isLoading)
                const CyberLoadingState(
                  title: 'Analyzing Permissions...',
                  subtitle: 'Evaluating sensitive permissions and combinations...',
                ),
              if (_errorMessage != null)
                CyberErrorState(
                  message: _errorMessage!,
                  onRetry: _tabController.index == 0
                      ? _analyzeSelectedAppProfile
                      : _analyzeApkFile,
                ),
              if (_scanResult != null && !_isLoading)
                _buildResultsSection(_scanResult!),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAndroidLimitationsNotice() {
    return CyberShieldCard(
      borderColor: AppColors.primary.withValues(alpha: 0.3),
      padding: const EdgeInsets.all(14),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.info_outline_rounded, color: AppColors.primary, size: 20),
          ),
          const SizedBox(width: 12),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Android Package Visibility Note',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  'In accordance with Android runtime permissions and package visibility restrictions (API 30+), CyberShield performs deep static heuristic analysis safely without rooting or invasive system access. Select an app profile or submit an APK for inspection.',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 11,
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInstalledProfilesTab() {
    return ListView(
      physics: const ClampingScrollPhysics(),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Expanded(
              child: Text(
                'Select Application Profile',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Row(
              children: [
                Text(
                  _isCustomMode ? 'Custom Mode' : 'Presets',
                  style: const TextStyle(
                    color: AppColors.primary,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Switch(
                  value: _isCustomMode,
                  activeTrackColor: AppColors.primary.withValues(alpha: 0.5),
                  activeThumbColor: AppColors.primary,
                  onChanged: (val) {
                    setState(() {
                      _isCustomMode = val;
                      _errorMessage = null;
                      _scanResult = null;
                    });
                  },
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (!_isCustomMode) ...[
          ...List.generate(_appPresets.length, (index) {
            final preset = _appPresets[index];
            final isSelected = _selectedPresetIndex == index;
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: CyberShieldCard(
                onTap: () {
                  setState(() {
                    _selectedPresetIndex = index;
                    _errorMessage = null;
                    _scanResult = null;
                  });
                },
                borderColor: isSelected ? preset.color : AppColors.cardBorder,
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: preset.color.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(preset.icon, color: preset.color, size: 22),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            preset.label,
                            style: TextStyle(
                              color: isSelected ? preset.color : AppColors.textPrimary,
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            preset.subtitle,
                            style: const TextStyle(
                              color: AppColors.textSecondary,
                              fontSize: 11,
                            ),
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                    Icon(
                      isSelected ? Icons.check_circle_rounded : Icons.radio_button_unchecked_rounded,
                      color: isSelected ? preset.color : AppColors.textMuted,
                      size: 20,
                    ),
                  ],
                ),
              ),
            );
          }),
        ] else ...[
          const Text(
            'Select permissions to analyze combination risk:',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
          ),
          const SizedBox(height: 8),
          ..._categorizedPermissions.entries.map((entry) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: CyberShieldCard(
                padding: const EdgeInsets.all(10),
                child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.key,
                    style: const TextStyle(
                      color: AppColors.primary,
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 6),
                  ...entry.value.map((item) {
                    final perm = item['name']!;
                    final isChecked = _customSelectedPermissions.contains(perm);
                    return CheckboxListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      activeColor: AppColors.primary,
                      title: Text(
                        item['label']!,
                        style: const TextStyle(color: AppColors.textPrimary, fontSize: 12),
                      ),
                      subtitle: Text(
                        perm.replaceFirst('android.permission.', ''),
                        style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                      ),
                      value: isChecked,
                      onChanged: (val) {
                        setState(() {
                          if (val == true) {
                            _customSelectedPermissions.add(perm);
                          } else {
                            _customSelectedPermissions.remove(perm);
                          }
                        });
                      },
                    );
                  }),
                ],
              ),
            ),
          );
        }),
        ],
        const SizedBox(height: 12),
        ElevatedButton.icon(
          onPressed: _isLoading ? null : _analyzeSelectedAppProfile,
          icon: const Icon(Icons.shield_rounded),
          label: const Text('Analyze Application Permissions'),
          style: ElevatedButton.styleFrom(
            backgroundColor: AppColors.primary,
            foregroundColor: AppColors.background,
            padding: const EdgeInsets.symmetric(vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          ),
        ),
      ],
    );
  }

  Widget _buildApkUploadTab() {
    return ListView(
      physics: const ClampingScrollPhysics(),
      children: [
        CyberShieldCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.upload_file_rounded, color: AppColors.primary, size: 36),
              ),
              const SizedBox(height: 12),
              const Text(
                'Submit Android APK Package',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 4),
              const Text(
                'Upload an APK file (.apk) to parse AndroidManifest.xml and extract requested permissions.',
                textAlign: TextAlign.center,
                style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
              ),
              const SizedBox(height: 16),
              OutlinedButton.icon(
                onPressed: _pickApkFile,
                icon: const Icon(Icons.folder_open_rounded, color: AppColors.primary),
                label: const Text('Choose APK from Device', style: TextStyle(color: AppColors.primary)),
                style: OutlinedButton.styleFrom(
                  side: const BorderSide(color: AppColors.primary),
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
              ),
              if (_selectedFilename != null) ...[
                const SizedBox(height: 14),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.cardBorder),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.android_rounded, color: AppColors.safe, size: 24),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              _selectedFilename!,
                              style: const TextStyle(
                                color: AppColors.textPrimary,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            if (_selectedFileSize != null)
                              Text(
                                '${(_selectedFileSize! / 1024).toStringAsFixed(1)} KB',
                                style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                              ),
                          ],
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close_rounded, color: AppColors.textMuted, size: 18),
                        onPressed: () {
                          setState(() {
                            _selectedApkBytes = null;
                            _selectedFilename = null;
                            _selectedFileSize = null;
                            _scanResult = null;
                          });
                        },
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),
        const Text(
          'Or try a synthetic APK sample:',
          style: TextStyle(color: AppColors.textMuted, fontSize: 12),
        ),
        const SizedBox(height: 8),
        ..._apkPresets.map((preset) {
          final isSelected = _selectedFilename == preset.filename;
          return Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: CyberShieldCard(
              onTap: () => _loadApkPreset(preset),
              borderColor: isSelected ? preset.color : AppColors.cardBorder,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Row(
                children: [
                  Icon(preset.icon, color: preset.color, size: 18),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      preset.label,
                      style: TextStyle(
                        color: isSelected ? preset.color : AppColors.textPrimary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  if (isSelected)
                    Icon(Icons.check_rounded, color: preset.color, size: 16),
                ],
              ),
            ),
          );
        }),
        const SizedBox(height: 12),
        ElevatedButton.icon(
          onPressed: (_selectedApkBytes != null && !_isLoading) ? _analyzeApkFile : null,
          icon: const Icon(Icons.security_rounded),
          label: const Text('Analyze APK Permissions'),
          style: ElevatedButton.styleFrom(
            backgroundColor: AppColors.primary,
            foregroundColor: AppColors.background,
            padding: const EdgeInsets.symmetric(vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          ),
        ),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // Results Section
  // -------------------------------------------------------------------------

  Widget _buildResultsSection(PermissionScanResult result) {
    final color = _getClassificationColor(result.classification);
    final badgeType = _getBadgeType(result.classification);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(color: AppColors.cardBorder, height: 32),
        const Text(
          'Analysis Results',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 16,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        const SizedBox(height: 12),

        // 1. Overall Risk Score Banner
        CyberShieldCard(
          borderColor: color.withValues(alpha: 0.4),
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        result.appName,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        result.packageName,
                        style: const TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                  CyberBadge(
                    label: result.classification.toUpperCase(),
                    type: badgeType,
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    width: 90,
                    height: 90,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: color, width: 4),
                      color: color.withValues(alpha: 0.1),
                    ),
                    child: Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            '${result.riskScore}',
                            style: TextStyle(
                              color: color,
                              fontSize: 28,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                          const Text(
                            '/ 100',
                            style: TextStyle(color: AppColors.textMuted, fontSize: 10),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 20),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _buildStatLine('Total Permissions', '${result.totalPermissionsCount}'),
                        const SizedBox(height: 6),
                        _buildStatLine('Dangerous Permissions', '${result.dangerousPermissionsCount}', color: color),
                        const SizedBox(height: 6),
                        _buildStatLine('High-Risk Combos', '${result.comboFindings.length}'),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Text(
                result.explanation,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 2. High Risk Combinations (if detected)
        if (result.comboFindings.isNotEmpty) ...[
          CyberShieldCard(
            borderColor: AppColors.danger.withValues(alpha: 0.4),
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.warning_amber_rounded, color: AppColors.danger, size: 20),
                    SizedBox(width: 8),
                    Text(
                      'Dangerous Permission Combinations',
                      style: TextStyle(
                        color: AppColors.danger,
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                ...result.comboFindings.map((combo) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('⚠️ ', style: TextStyle(fontSize: 13)),
                        Expanded(
                          child: Text(
                            combo,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                  );
                }),
              ],
            ),
          ),
          const SizedBox(height: 14),
        ],

        // 3. Dangerous Permissions Breakdown with explanations
        if (result.findingExplanations.isNotEmpty) ...[
          const Text(
            'Dangerous Permissions Explained',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 14,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          ...result.findingExplanations.map((item) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: CyberShieldCard(
                padding: const EdgeInsets.all(12),
                child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Text(
                          item.indicator,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: AppColors.surfaceLight,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: AppColors.cardBorder),
                        ),
                        child: Text(
                          item.category,
                          style: const TextStyle(color: AppColors.primary, fontSize: 10),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    item.permission,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    item.explanation,
                    style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, height: 1.3),
                  ),
                ],
              ),
            ),
          );
        }),
          const SizedBox(height: 10),
        ],

        // 4. Actionable Security Recommendations
        CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.25),
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.lightbulb_outline_rounded, color: AppColors.primary, size: 20),
                  SizedBox(width: 8),
                  Text(
                    'Security Recommendations',
                    style: TextStyle(
                      color: AppColors.primary,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              ...result.recommendations.map((rec) {
                return Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('• ', style: TextStyle(color: AppColors.primary, fontSize: 14)),
                      Expanded(
                        child: Text(
                          rec,
                          style: const TextStyle(color: AppColors.textPrimary, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                );
              }),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 5. Full Permissions List (Collapsible)
        CyberShieldCard(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              InkWell(
                onTap: () {
                  setState(() {
                    _showAllPermissions = !_showAllPermissions;
                  });
                },
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'All Permissions (${result.totalPermissionsCount})',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Icon(
                      _showAllPermissions ? Icons.keyboard_arrow_up_rounded : Icons.keyboard_arrow_down_rounded,
                      color: AppColors.textSecondary,
                    ),
                  ],
                ),
              ),
              if (_showAllPermissions) ...[
                const Divider(color: AppColors.cardBorder, height: 16),
                ...result.permissions.map((perm) {
                  final isDangerous = result.dangerousPermissions.contains(perm);
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Row(
                      children: [
                        Icon(
                          isDangerous ? Icons.warning_amber_rounded : Icons.check_circle_outline_rounded,
                          size: 14,
                          color: isDangerous ? AppColors.danger : AppColors.safe,
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            perm.replaceFirst('android.permission.', ''),
                            style: TextStyle(
                              color: isDangerous ? AppColors.textPrimary : AppColors.textSecondary,
                              fontSize: 11,
                              fontWeight: isDangerous ? FontWeight.w600 : FontWeight.w400,
                            ),
                          ),
                        ),
                      ],
                    ),
                  );
                }),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 6. Security Disclaimer Card
        CyberShieldCard(
          padding: const EdgeInsets.all(12),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.shield_outlined, color: AppColors.textMuted, size: 18),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'CyberShield Context: Requesting sensitive permissions does not mean the application is malicious. Legitimate apps frequently require sensitive access. Review permissions to ensure they match expected features.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 10, height: 1.3),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildStatLine(String label, String value, {Color? color}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
        ),
        Text(
          value,
          style: TextStyle(
            color: color ?? AppColors.textPrimary,
            fontSize: 12,
            fontWeight: FontWeight.w700,
          ),
        ),
      ],
    );
  }
}
