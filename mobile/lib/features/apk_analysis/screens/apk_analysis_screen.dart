// APK Security Analysis Screen for CyberShield

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/cyber_error_state.dart';
import 'package:cybershield/core/widgets/cyber_empty_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/models/apk_scan_result.dart';
import 'package:cybershield/core/widgets/cybor_floating_widget.dart';

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

class ApkAnalysisScreen extends StatefulWidget {
  const ApkAnalysisScreen({super.key});

  @override
  State<ApkAnalysisScreen> createState() => _ApkAnalysisScreenState();
}

class _ApkAnalysisScreenState extends State<ApkAnalysisScreen> {
  String? _selectedFilePath;
  Uint8List? _selectedApkBytes;
  String? _selectedFilename;
  int? _selectedFileSize;
  bool _isLoading = false;
  String _progressStage = 'Uploading & analyzing APK (up to 90s)...';
  String? _errorMessage;
  ApkScanResult? _scanResult;
  bool _showAllPermissions = false;

  // Preset synthetic APK packages encoded as standard ZIP archives containing AndroidManifest.xml
  static const List<_ApkPreset> _presets = [
    _ApkPreset(
      label: 'Banking Trojan Profile',
      subtitle: 'SMS Interception + Accessibility Service + Overlay',
      icon: Icons.account_balance_rounded,
      color: Color(0xFFFF3B30),
      filename: 'banking_trojan_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY11epx67jwAAAI8AAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5SRUFEX1NNUyBhbmRyb2lkLnBlcm1pc3Npb24uUkVDRUlWRV9TTVMgYW5kcm9pZC5wZXJtaXNzaW9uLkJJTkRfQUNDRVNTSUJJTElUWV9TRVJWSUNFIGFuZHJvaWQucGVybWlzc2lvbi5TWVNURU1fQUxFUlRfV0lORE9XUEsDBBQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAY2xhc3Nlcy5kZXhkZXgKMDM1AFBLAwQUAAAAAACAEmNdet9aIBYAAAAWAAAAFAAAAE1FVEEtSU5GL01BTklGRVNULk1GTWFuaWZlc3QtVmVyc2lvbjogMS4wClBLAQIUABQAAAAAAIASY11epx67jwAAAI8AAAATAAAAAAAAAAAAAACAAQAAAABBbmRyb2lkTWFuaWZlc3QueG1sUEsBAhQAFAAAAAAAgBJjXbnk+zEIAAAACAAAAAsAAAAAAAAAAAAAAIABwAAAAGNsYXNzZXMuZGV4UEsBAhQAFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAAAAAAAAAAAAAIAB8QAAAE1FVEEtSU5GL01BTklGRVNULk1GUEsFBgAAAAADAAMAvAAAADkBAAAAAA==',
    ),
    _ApkPreset(
      label: 'Spyware / Tracker Profile',
      subtitle: 'Precise Location + Audio Recording + Contacts + Boot Persistence',
      icon: Icons.track_changes_rounded,
      color: Color(0xFFFF9500),
      filename: 'spyware_tracker_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY12xa5YdwAAAAMAAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5BQ0NFU1NfRklORV9MT0NBVElPTiBhbmRyb2lkLnBlcm1pc3Npb24uQUNDRVNTX0JBQ0tHUk9VTkRfTE9DQVRJT04gYW5kcm9pZC5wZXJtaXNzaW9uLlJFQURfQ09OVEFDVFMgYW5kcm9pZC5wZXJtaXNzaW9uLlJFQ09SRF9BVURJTyBhbmRyb2lkLnBlcm1pc3Npb24uUkVDRUlWRV9CT09UX0NPTVBMRVRFRFBLAwQUAAAAAACAEmNdueT7MQgAAAAIAAAACwAAAGNsYXNzZXMuZGV4ZGV4CjAzNQBQSwMEFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAABNRVRBLUlORi9NQU5JRkVTVC5NRk1hbmlmZXN0LVZlcnNpb246IDEuMApQSwECFAAUAAAAAACAEmNdsWuWHcAAAADAAAAAEwAAAAAAAAAAAAAAgAEAAAAAQW5kcm9pZE1hbmlmZXN0LnhtbFBLAQIUABQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAAAAAAAAAAACAAfEAAABjbGFzc2VzLmRleFBLAQIUABQAAAAAAIASY11631ogFgAAABYAAAAUAAAAAAAAAAAAAACAASIBAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLBQYAAAAAAwADALwAAABqAQAAAAA=',
    ),
    _ApkPreset(
      label: 'Safe Utility Profile',
      subtitle: 'Standard Network and Vibration Permissions',
      icon: Icons.verified_user_rounded,
      color: Color(0xFF34C759),
      filename: 'utility_safe_sample.apk',
      base64Data:
          'UEsDBBQAAAAAAIASY12z5oNFNgAAADYAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbGFuZHJvaWQucGVybWlzc2lvbi5JTlRFUk5FVCBhbmRyb2lkLnBlcm1pc3Npb24uVklCUkFURVBLAwQUAAAAAACAEmNdueT7MQgAAAAIAAAACwAAAGNsYXNzZXMuZGV4ZGV4CjAzNQBQSwMEFAAAAAAAgBJjXXrfWiAWAAAAFgAAABQAAABNRVRBLUlORi9NQU5JRkVTVC5NRk1hbmlmZXN0LVZlcnNpb246IDEuMApQSwECFAAUAAAAAACAEmNds+aDRTYAAAA2AAAAEwAAAAAAAAAAAAAAgAEAAAAAQW5kcm9pZE1hbmlmZXN0LnhtbFBLAQIUABQAAAAAAIASY1255PsxCAAAAAgAAAALAAAAAAAAAAAAAACAAWcAAABjbGFzc2VzLmRleFBLAQIUABQAAAAAAIASY11631ogFgAAABYAAAAUAAAAAAAAAAAAAACAAZgAAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLBQYAAAAAAwADALwAAADgAAAAAAA=',
    ),
  ];

  Future<void> _pickApkFile() async {
    try {
      final files = await FilePicker.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['apk'],
      );

      if (files.isNotEmpty) {
        final file = files.first;
        final path = file.path;
        final int size = await file.xFile.length();

        Uint8List? bytes;
        if (path == null) {
          bytes = await file.xFile.readAsBytes();
        }

        setState(() {
          _selectedFilePath = path;
          _selectedApkBytes = bytes;
          _selectedFilename = file.name;
          _selectedFileSize = size;
          _errorMessage = null;
          _scanResult = null;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Failed to load APK file: $e';
      });
    }
  }

  void _loadPreset(_ApkPreset preset) {
    final bytes = base64Decode(preset.base64Data);
    setState(() {
      _selectedFilePath = null;
      _selectedApkBytes = bytes;
      _selectedFilename = preset.filename;
      _selectedFileSize = bytes.length;
      _errorMessage = null;
      _scanResult = null;
    });
    _analyzeSelectedApk();
  }

  Future<void> _analyzeSelectedApk() async {
    if (_selectedFilePath == null && _selectedApkBytes == null) {
      setState(() {
        _errorMessage = 'Please select an APK package first.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _progressStage = 'Uploading package to security engine (up to 90s)...';
      _errorMessage = null;
      _scanResult = null;
    });

    final ApkScanResult result;
    if (_selectedFilePath != null) {
      result = await ApiService.analyzeApkFile(
        _selectedFilePath!,
        filename: _selectedFilename,
      );
    } else {
      result = await ApiService.analyzeApk(
        _selectedApkBytes!,
        filename: _selectedFilename ?? 'package.apk',
      );
    }

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Inspection encountered an error.';
        } else {
          _scanResult = result;

          // Record scan to cloud Firestore history (asynchronous & non-blocking)
          final apkTarget = result.packageName.isNotEmpty
              ? result.packageName
              : (_selectedFilename ?? 'package.apk');
          FirestoreHistoryService.instance.recordScan(
            scanType: 'APK',
            target: apkTarget,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'filename': result.filename,
              'package_name': result.packageName,
              'app_name': result.appName,
              'version_name': result.versionName,
              'version_code': result.versionCode,
              'min_sdk': result.minSdk,
              'target_sdk': result.targetSdk,
              'permissions': result.permissions,
              'dangerous_permissions': result.dangerousPermissions,
              'combo_findings': result.comboFindings,
              'risk_score': result.riskScore,
              'classification': result.classification,
              'explanation': result.explanation,
              'recommendation': result.recommendation,
              'findings': result.findings,
              'detected_indicators': result.detectedIndicators,
              'finding_explanations': result.findingExplanations
                  .map((fe) => {
                        'indicator': fe.indicator,
                        'category': fe.category,
                        'explanation': fe.explanation,
                      })
                  .toList(),
              if (result.metadata != null) 'metadata': result.metadata,
              if (result.engineStatus != null)
                'engine_status': result.engineStatus,
            },
          );
        }
      });
    }
  }

  void _resetAnalysis() {
    setState(() {
      _selectedFilePath = null;
      _selectedApkBytes = null;
      _selectedFilename = null;
      _selectedFileSize = null;
      _scanResult = null;
      _errorMessage = null;
      _showAllPermissions = false;
    });
  }

  BadgeType _getBadgeType(String classification) {
    switch (classification.toLowerCase()) {
      case 'safe':
        return BadgeType.safe;
      case 'suspicious':
        return BadgeType.warning;
      case 'high risk':
      case 'malicious':
        return BadgeType.danger;
      default:
        return BadgeType.info;
    }
  }

  Color _getRiskColor(int score) {
    if (score >= 60) return AppColors.danger;
    if (score >= 30) return AppColors.warning;
    return AppColors.safe;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('APK Security Analyzer'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () =>
              Navigator.pushReplacementNamed(context, AppRouter.dashboard),
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.apkAnalysis),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildSelectionCard(),
            const SizedBox(height: 20),
            if (_isLoading)
              CyberLoadingState(
                title: 'Inspecting APK Package...',
                subtitle: _progressStage,
              )
            else if (_errorMessage != null)
              CyberErrorState(
                title: 'APK Inspection Failed',
                message: _errorMessage!,
                onRetry: _analyzeSelectedApk,
              )
            else if (_scanResult != null)
              _buildResultView()
            else
              const CyberEmptyState(
                icon: Icons.android_rounded,
                title: 'Ready for APK Package Audit',
                description:
                    'Select an Android APK file or tap one of the security presets above to analyze declared permissions and security vectors.',
              ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildSelectionCard() {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: AppColors.danger.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: const Icon(Icons.android_rounded,
                    color: AppColors.danger, size: 20),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Android Package Security Audit',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    Text(
                      'Static inspection of permissions, SDK targets, and dangerous vectors',
                      style: TextStyle(
                          color: AppColors.textSecondary, fontSize: 12),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Upload area
          InkWell(
            onTap: _pickApkFile,
            borderRadius: BorderRadius.circular(12),
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: _selectedApkBytes != null
                      ? AppColors.primary
                      : AppColors.cardBorder,
                  width: 1.5,
                ),
              ),
              child: Column(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: AppColors.primary.withValues(alpha: 0.12),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      _selectedApkBytes != null
                          ? Icons.check_circle_outline_rounded
                          : Icons.file_upload_outlined,
                      color: _selectedApkBytes != null
                          ? AppColors.safe
                          : AppColors.primary,
                      size: 36,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    _selectedFilename ?? 'Choose APK File (.apk)',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    _selectedFileSize != null
                        ? '${(_selectedFileSize! / 1024).toStringAsFixed(1)} KB'
                        : 'Tap to browse storage or emulator filesystem',
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Presets row
          const Text(
            'Or test with sample security profiles:',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: _presets.map((preset) {
              return ActionChip(
                avatar: Icon(preset.icon, size: 16, color: preset.color),
                label: Text(
                  preset.label,
                  style: TextStyle(
                    color: preset.color,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                backgroundColor: preset.color.withValues(alpha: 0.1),
                side: BorderSide(color: preset.color.withValues(alpha: 0.3)),
                onPressed: () => _loadPreset(preset),
              );
            }).toList(),
          ),
          const SizedBox(height: 16),
          // Scan button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _isLoading || _selectedApkBytes == null
                  ? null
                  : _analyzeSelectedApk,
              icon: const Icon(Icons.shield_rounded, size: 18),
              label: const Text(
                'Analyze APK Package',
                style: TextStyle(fontWeight: FontWeight.w700),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResultView() {
    final result = _scanResult!;
    final badgeType = _getBadgeType(result.classification);
    final riskColor = _getRiskColor(result.riskScore);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Primary Overview Card
        CyberShieldCard(
          borderColor: riskColor.withValues(alpha: 0.4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  CyberBadge(
                    label: result.classification.toUpperCase(),
                    type: badgeType,
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: riskColor.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                          color: riskColor.withValues(alpha: 0.3)),
                    ),
                    child: Text(
                      'Risk Score: ${result.riskScore}/100',
                      style: TextStyle(
                        color: riskColor,
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              // Risk score progress bar
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: result.riskScore / 100.0,
                  minHeight: 8,
                  backgroundColor: AppColors.surfaceLight,
                  valueColor: AlwaysStoppedAnimation<Color>(riskColor),
                ),
              ),
              const SizedBox(height: 16),
              // App metadata grid
              _buildMetadataRow('Application Name', result.appName),
              _buildMetadataRow('Package Identifier', result.packageName),
              _buildMetadataRow('Version', '${result.versionName} (${result.versionCode})'),
              _buildMetadataRow('SDK Target', 'Min: ${result.minSdk} | Target: ${result.targetSdk}'),
              _buildMetadataRow('Package Filename', result.filename),
            ],
          ),
        ),
        const SizedBox(height: 16),
        // Security Caveat Notice
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.primary.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: AppColors.primary.withValues(alpha: 0.25),
            ),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.info_outline_rounded,
                  color: AppColors.primary, size: 20),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Analysis Note: This static assessment inspects requested permissions and manifest configuration. Dangerous permissions highlight intrusive capabilities commonly abused by threats, but do not claim confirmed malware presence without behavioural sandbox testing.',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                    height: 1.4,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        // Dangerous Permissions Breakdown
        if (result.dangerousPermissions.isNotEmpty) ...[
          CyberShieldCard(
            borderColor: AppColors.danger.withValues(alpha: 0.3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.warning_amber_rounded,
                        color: AppColors.danger, size: 20),
                    const SizedBox(width: 8),
                    Text(
                      'Dangerous Permissions (${result.dangerousPermissions.length})',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                ListView.separated(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: result.findingExplanations.length,
                  separatorBuilder: (context, index) =>
                      const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final item = result.findingExplanations[index];
                    return Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.surfaceLight,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: AppColors.danger.withValues(alpha: 0.2),
                        ),
                      ),
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
                                    color: AppColors.danger,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                              ),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 8, vertical: 2),
                                decoration: BoxDecoration(
                                  color: AppColors.danger.withValues(alpha: 0.1),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: Text(
                                  item.category,
                                  style: const TextStyle(
                                    color: AppColors.danger,
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(
                            item.explanation,
                            style: const TextStyle(
                              color: AppColors.textSecondary,
                              fontSize: 12,
                              height: 1.35,
                            ),
                          ),
                        ],
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
        ],
        // Combination Vectors Card
        if (result.comboFindings.isNotEmpty) ...[
          CyberShieldCard(
            borderColor: AppColors.warning.withValues(alpha: 0.4),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.bolt_rounded,
                        color: AppColors.warning, size: 20),
                    SizedBox(width: 8),
                    Text(
                      'High-Risk Permission Combinations',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: result.comboFindings.map((combo) {
                    return Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        color: AppColors.warning.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                            color: AppColors.warning.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.shield_outlined,
                              color: AppColors.warning, size: 14),
                          const SizedBox(width: 6),
                          Text(
                            combo,
                            style: const TextStyle(
                              color: AppColors.warning,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    );
                  }).toList(),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
        ],
        // Explanation & Recommendation Card
        CyberShieldCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Assessment Explanation',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                result.explanation,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  height: 1.4,
                ),
              ),
              const Divider(height: 24, color: AppColors.cardBorder),
              const Text(
                'Security Recommendation',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                result.recommendation,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        // All Permissions Accordion
        CyberShieldCard(
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
                      'All Declared Permissions (${result.permissions.length})',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Icon(
                      _showAllPermissions
                          ? Icons.expand_less_rounded
                          : Icons.expand_more_rounded,
                      color: AppColors.textMuted,
                    ),
                  ],
                ),
              ),
              if (_showAllPermissions) ...[
                const SizedBox(height: 12),
                if (result.permissions.isEmpty)
                  const Text(
                    'No permissions declared in AndroidManifest.xml',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 12,
                    ),
                  )
                else
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: result.permissions.map((perm) {
                      final isDangerous =
                          result.dangerousPermissions.contains(perm);
                      return Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 4),
                        decoration: BoxDecoration(
                          color: isDangerous
                              ? AppColors.danger.withValues(alpha: 0.1)
                              : AppColors.surfaceLight,
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: isDangerous
                                ? AppColors.danger.withValues(alpha: 0.3)
                                : AppColors.cardBorder,
                          ),
                        ),
                        child: Text(
                          perm.replaceFirst('android.permission.', ''),
                          style: TextStyle(
                            color: isDangerous
                                ? AppColors.danger
                                : AppColors.textSecondary,
                            fontSize: 11,
                            fontWeight: isDangerous
                                ? FontWeight.w600
                                : FontWeight.normal,
                          ),
                        ),
                      );
                    }).toList(),
                  ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 12),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            onPressed: () {
              CyborFloatingWidget.openModal(
                context,
                scanContext: {
                  'scan_type': 'APK',
                  'target': result.packageName.isNotEmpty ? result.packageName : result.filename,
                  'risk_score': result.riskScore,
                  'classification': result.classification,
                  'findings': result.comboFindings,
                },
              );
            },
            icon: const Icon(Icons.smart_toy_rounded, size: 18),
            label: const Text('Consult CYBOR AI Assistant',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
          ),
        ),
        const SizedBox(height: 12),
        // Reset action button
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: _resetAnalysis,
            icon: const Icon(Icons.refresh_rounded, size: 18),
            label: const Text('Analyze Another Package'),
            style: OutlinedButton.styleFrom(
              foregroundColor: AppColors.textPrimary,
              side: const BorderSide(color: AppColors.cardBorder),
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildMetadataRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(
              label,
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
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
  }
}
