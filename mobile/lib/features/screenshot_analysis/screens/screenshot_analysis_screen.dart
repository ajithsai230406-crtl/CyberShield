import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
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
import 'package:cybershield/core/models/screenshot_scan_result.dart';
import 'package:cybershield/core/widgets/cybor_floating_widget.dart';

class ScreenshotAnalysisScreen extends StatefulWidget {
  const ScreenshotAnalysisScreen({super.key});

  @override
  State<ScreenshotAnalysisScreen> createState() =>
      _ScreenshotAnalysisScreenState();
}

class _ScreenshotAnalysisScreenState extends State<ScreenshotAnalysisScreen> {
  final ImagePicker _picker = ImagePicker();
  Uint8List? _selectedImageBytes;
  String? _selectedFilename;
  bool _isLoading = false;
  String? _errorMessage;
  ScreenshotScanResult? _scanResult;

  // Minimal valid 1x1 transparent PNG header + body bytes for preset fallback
  static final Uint8List _samplePngBytes = Uint8List.fromList([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
    0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
    0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
    0x0D, 0x0A, 0x2D, 0xB4,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
    0xAE, 0x42, 0x60, 0x82,
  ]);

  // Quick testing presets
  static const List<_ScreenshotPreset> _presets = [
    _ScreenshotPreset(
      label: 'Bank KYC Scam',
      icon: Icons.account_balance_rounded,
      color: Color(0xFFFF3B30),
      filename: 'sbi_kyc_suspension_alert.png',
      description: 'Urgent KYC suspension alert with bare IP login link',
    ),
    _ScreenshotPreset(
      label: 'Fake Payment Receipt',
      icon: Icons.receipt_long_rounded,
      color: Color(0xFFFFB300),
      filename: 'fake_upi_payment_receipt.png',
      description: 'Overpayment receipt claiming Rs.15,000 transferred',
    ),
    _ScreenshotPreset(
      label: 'OTP Phishing Alert',
      icon: Icons.password_rounded,
      color: Color(0xFFFF3B30),
      filename: 'otp_theft_sms_capture.png',
      description: 'Customer helpline requesting secret OTP',
    ),
    _ScreenshotPreset(
      label: 'Scareware Alert',
      icon: Icons.warning_rounded,
      color: Color(0xFFFFB300),
      filename: 'virus_detected_trojan_popup.png',
      description: 'Deceptive popup claiming device is infected',
    ),
    _ScreenshotPreset(
      label: 'Safe Conversational Chat',
      icon: Icons.chat_bubble_outline_rounded,
      color: Color(0xFF00E676),
      filename: 'family_dinner_chat.png',
      description: 'Ordinary personal message without threats',
    ),
  ];

  Future<void> _pickImageFromCamera() async {
    try {
      final XFile? file = await _picker.pickImage(
        source: ImageSource.camera,
        maxWidth: 1920,
        maxHeight: 1920,
        imageQuality: 85,
      );

      if (file != null) {
        final bytes = await file.readAsBytes();
        setState(() {
          _selectedImageBytes = bytes;
          _selectedFilename = file.name;
          _scanResult = null;
          _errorMessage = null;
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Could not access camera: $e. You can use gallery or preset samples below.'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    }
  }

  void _showImageSourceDialog() {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 20, horizontal: 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Select Screenshot Source',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              ListTile(
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                leading: const Icon(Icons.camera_alt_rounded, color: AppColors.primary),
                title: const Text('Capture with Camera', style: TextStyle(color: AppColors.textPrimary)),
                onTap: () {
                  Navigator.pop(ctx);
                  _pickImageFromCamera();
                },
              ),
              ListTile(
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                leading: const Icon(Icons.photo_library_rounded, color: AppColors.primary),
                title: const Text('Choose from Gallery', style: TextStyle(color: AppColors.textPrimary)),
                onTap: () {
                  Navigator.pop(ctx);
                  _pickImageFromGallery();
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _pickImageFromGallery() async {
    try {
      final XFile? file = await _picker.pickImage(
        source: ImageSource.gallery,
        maxWidth: 1920,
        maxHeight: 1920,
        imageQuality: 85,
      );

      if (file != null) {
        final bytes = await file.readAsBytes();
        setState(() {
          _selectedImageBytes = bytes;
          _selectedFilename = file.name;
          _scanResult = null;
          _errorMessage = null;
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Could not open gallery: $e. You can use preset samples below.'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    }
  }

  void _loadPreset(_ScreenshotPreset preset) {
    setState(() {
      _selectedImageBytes = _samplePngBytes;
      _selectedFilename = preset.filename;
      _scanResult = null;
      _errorMessage = null;
    });
  }

  Future<void> _performAnalysis() async {
    if (_selectedImageBytes == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please select a screenshot from gallery or choose a preset sample'),
          backgroundColor: AppColors.danger,
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    final filename = _selectedFilename ?? 'screenshot.png';
    final result = await ApiService.analyzeScreenshot(_selectedImageBytes!, filename);

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Failed to analyze screenshot';
        } else {
          _scanResult = result;

          // Record scan to cloud Firestore history (asynchronous & non-blocking)
          FirestoreHistoryService.instance.recordScan(
            scanType: 'SCREENSHOT',
            target: filename,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'filename': result.filename,
              'ocr_text': result.ocrText,
              'risk_score': result.riskScore,
              'classification': result.classification,
              'explanation': result.explanation,
              'recommendation': result.recommendation,
              'extracted_urls': result.extractedUrls,
              'threat_categories': result.threatCategories,
              'detected_indicators': result.detectedIndicators,
              'findings': result.findings,
              'finding_explanations': result.findingExplanations
                  .map((fe) => {
                        'indicator': fe.indicator,
                        'title': fe.title,
                        'risk_level': fe.riskLevel,
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

  void _clearAll() {
    setState(() {
      _selectedImageBytes = null;
      _selectedFilename = null;
      _scanResult = null;
      _errorMessage = null;
    });
  }

  Color _classificationColor(String cls) {
    switch (cls.toLowerCase()) {
      case 'malicious':
        return AppColors.danger;
      case 'suspicious':
        return AppColors.warning;
      default:
        return AppColors.safe;
    }
  }

  BadgeType _classificationBadgeType(String cls) {
    switch (cls.toLowerCase()) {
      case 'malicious':
        return BadgeType.danger;
      case 'suspicious':
        return BadgeType.warning;
      default:
        return BadgeType.safe;
    }
  }

  Color _riskScoreColor(int score) {
    if (score >= 70) return AppColors.danger;
    if (score >= 30) return AppColors.warning;
    return AppColors.safe;
  }

  Color _riskLevelColor(String level) {
    switch (level.toLowerCase()) {
      case 'high':
        return AppColors.danger;
      case 'medium':
        return AppColors.warning;
      default:
        return AppColors.safe;
    }
  }

  String _formatCategory(String cat) {
    return cat
        .replaceAll('_', ' ')
        .split(' ')
        .map((w) => w.isEmpty ? '' : '${w[0].toUpperCase()}${w.substring(1)}')
        .join(' ');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      drawer: const NavDrawer(currentRoute: AppRouter.screenshotAnalysis),
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        foregroundColor: AppColors.primary,
        title: const Row(
          children: [
            Icon(Icons.screenshot_monitor_rounded, size: 20),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'Screenshot Threat Analyzer',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.5,
                  fontSize: 17,
                ),
              ),
            ),
          ],
        ),
        actions: [
          if (_scanResult != null || _errorMessage != null || _selectedImageBytes != null)
            IconButton(
              icon: const Icon(Icons.refresh_rounded),
              tooltip: 'New Analysis',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildUploadCard(),
            const SizedBox(height: 12),
            _buildPresetsSection(),
            const SizedBox(height: 20),
            if (_isLoading) _buildLoadingState(),
            if (_errorMessage != null && !_isLoading)
              CyberErrorState(
                message: _errorMessage!,
                onRetry: _performAnalysis,
              ),
            if (_scanResult == null && _errorMessage == null && !_isLoading)
              const CyberEmptyState(
                icon: Icons.image_search_rounded,
                title: 'No Screenshot Analyzed',
                description:
                    'Select a screenshot from your gallery or choose a preset test sample to extract text and detect phishing, fake KYC alerts, and payment scams.',
              ),
            if (_scanResult != null && !_isLoading) ...[
              _buildResultHeader(_scanResult!),
              const SizedBox(height: 12),
              _buildOcrTextCard(_scanResult!),
              const SizedBox(height: 12),
              if (_scanResult!.extractedUrls.isNotEmpty) ...[
                _buildExtractedUrlsCard(_scanResult!),
                const SizedBox(height: 12),
              ],
              if (_scanResult!.detectedIndicators.isNotEmpty) ...[
                _buildIndicatorsCard(_scanResult!),
                const SizedBox(height: 12),
              ],
              if (_scanResult!.explanation.isNotEmpty) ...[
                _buildExplanationCard(_scanResult!),
                const SizedBox(height: 12),
              ],
              if (_scanResult!.findingExplanations.isNotEmpty) ...[
                _buildFindingsBreakdown(_scanResult!),
                const SizedBox(height: 12),
              ],
              _buildRecommendationCard(_scanResult!),
              const SizedBox(height: 14),
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
                        'scan_type': 'SCREENSHOT',
                        'target': _scanResult!.filename,
                        'risk_score': _scanResult!.riskScore,
                        'classification': _scanResult!.classification,
                        'findings': _scanResult!.detectedIndicators,
                      },
                    );
                  },
                  icon: const Icon(Icons.smart_toy_rounded, size: 18),
                  label: const Text('Consult CYBOR AI Assistant',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                ),
              ),
              const SizedBox(height: 12),
              _buildFooter(_scanResult!),
            ],
            const SizedBox(height: 30),
          ],
        ),
      ),
    );
  }

  Widget _buildUploadCard() {
    final hasImage = _selectedImageBytes != null;

    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.add_photo_alternate_rounded,
                  color: AppColors.primary, size: 18),
              const SizedBox(width: 8),
              const Text(
                'SCREENSHOT CAPTURE',
                style: TextStyle(
                  color: AppColors.primary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                  letterSpacing: 1.0,
                ),
              ),
              const Spacer(),
              if (hasImage)
                Text(
                  _selectedFilename ?? 'Selected',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                  overflow: TextOverflow.ellipsis,
                ),
            ],
          ),
          const SizedBox(height: 14),
          // Dropzone / Preview
          GestureDetector(
            onTap: _showImageSourceDialog,
            child: Container(
              height: 160,
              decoration: BoxDecoration(
                color: AppColors.background,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: hasImage ? AppColors.primary : AppColors.cardBorder,
                  width: hasImage ? 1.5 : 1,
                ),
              ),
              child: hasImage
                  ? Stack(
                      alignment: Alignment.center,
                      children: [
                        ClipRRect(
                          borderRadius: BorderRadius.circular(11),
                          child: Image.memory(
                            _selectedImageBytes!,
                            fit: BoxFit.cover,
                            width: double.infinity,
                            height: double.infinity,
                            errorBuilder: (context, error, stackTrace) => const Icon(
                              Icons.broken_image_rounded,
                              size: 48,
                              color: AppColors.textMuted,
                            ),
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                          decoration: BoxDecoration(
                            color: Colors.black.withValues(alpha: 0.7),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.photo_library_rounded,
                                  color: Colors.white, size: 14),
                              const SizedBox(width: 6),
                              Text(
                                _selectedFilename ?? 'Image Selected',
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    )
                  : Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: AppColors.primary.withValues(alpha: 0.1),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(
                            Icons.cloud_upload_rounded,
                            size: 36,
                            color: AppColors.primary,
                          ),
                        ),
                        const SizedBox(height: 10),
                        const Text(
                          'Tap to Capture or Select Screenshot',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Camera or Gallery • PNG, JPEG, WEBP, BMP',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                        ),
                      ],
                    ),
            ),
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _pickImageFromCamera,
                  icon: const Icon(Icons.camera_alt_rounded, size: 15),
                  label: const Text('Camera', style: TextStyle(fontSize: 12)),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.textPrimary,
                    side: const BorderSide(color: AppColors.cardBorder),
                    padding: const EdgeInsets.symmetric(vertical: 11),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _pickImageFromGallery,
                  icon: const Icon(Icons.photo_library_rounded, size: 15),
                  label: const Text('Gallery', style: TextStyle(fontSize: 12)),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.textPrimary,
                    side: const BorderSide(color: AppColors.cardBorder),
                    padding: const EdgeInsets.symmetric(vertical: 11),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _isLoading ? null : _performAnalysis,
              icon: const Icon(Icons.document_scanner_rounded, size: 18),
              label: Text(_isLoading ? 'Extracting & Scanning...' : 'Scan Screenshot'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: AppColors.background,
                padding: const EdgeInsets.symmetric(vertical: 13),
                textStyle: const TextStyle(
                  fontWeight: FontWeight.w700,
                  fontSize: 14,
                ),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPresetsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.only(left: 4, bottom: 8),
          child: Text(
            'Quick Test Samples:',
            style: TextStyle(color: AppColors.textMuted, fontSize: 12),
          ),
        ),
        SizedBox(
          height: 38,
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            itemCount: _presets.length,
            separatorBuilder: (context, index) => const SizedBox(width: 8),
            itemBuilder: (context, index) {
              final preset = _presets[index];
              return OutlinedButton.icon(
                onPressed: () => _loadPreset(preset),
                icon: Icon(preset.icon, size: 14, color: preset.color),
                label: Text(preset.label),
                style: OutlinedButton.styleFrom(
                  foregroundColor: preset.color,
                  side: BorderSide(color: preset.color.withValues(alpha: 0.4)),
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  textStyle: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildLoadingState() {
    return const CyberLoadingState(
      title: 'Running OCR & Visual Threat Intelligence...',
      subtitle: 'Extracting rendered text and inspecting for phishing, fake bank alerts, and OTP scams',
    );
  }

  Widget _buildResultHeader(ScreenshotScanResult result) {
    final color = _classificationColor(result.classification);

    return CyberShieldCard(
      borderColor: color,
      gradientColors: [
        color.withValues(alpha: 0.12),
        AppColors.surface,
      ],
      child: Column(
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.18),
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  result.isMalicious
                      ? Icons.gpp_bad_rounded
                      : (result.isSuspicious
                          ? Icons.warning_amber_rounded
                          : Icons.verified_user_rounded),
                  color: color,
                  size: 26,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        CyberBadge(
                          label: result.classification.toUpperCase(),
                          type: _classificationBadgeType(result.classification),
                        ),
                        const SizedBox(width: 8),
                        if (result.threatCategories.isNotEmpty)
                          Text(
                            '${result.threatCategories.length} vector${result.threatCategories.length > 1 ? 's' : ''}',
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Risk Score: ${result.riskScore}/100',
                      style: TextStyle(
                        color: _riskScoreColor(result.riskScore),
                        fontWeight: FontWeight.w700,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
              // Risk gauge
              SizedBox(
                width: 58,
                height: 58,
                child: Stack(
                  fit: StackFit.expand,
                  children: [
                    CircularProgressIndicator(
                      value: result.riskScore / 100,
                      strokeWidth: 5,
                      backgroundColor: AppColors.cardBorder,
                      valueColor: AlwaysStoppedAnimation<Color>(_riskScoreColor(result.riskScore)),
                    ),
                    Center(
                      child: Text(
                        '${result.riskScore}',
                        style: TextStyle(
                          color: _riskScoreColor(result.riskScore),
                          fontWeight: FontWeight.w900,
                          fontSize: 16,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          if (result.threatCategories.isNotEmpty) ...[
            const SizedBox(height: 14),
            const Divider(color: AppColors.cardBorder, height: 1),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerLeft,
              child: Wrap(
                spacing: 6,
                runSpacing: 6,
                children: result.threatCategories
                    .map((c) => _buildChip(_formatCategory(c), AppColors.warning))
                    .toList(),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildOcrTextCard(ScreenshotScanResult result) {
    final text = result.ocrText.isEmpty ? 'No text detected' : result.ocrText;

    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.text_snippet_rounded, color: AppColors.primary, size: 16),
              const SizedBox(width: 8),
              const Text(
                'OCR EXTRACTED TEXT',
                style: TextStyle(
                  color: AppColors.primary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                  letterSpacing: 0.5,
                ),
              ),
              const Spacer(),
              IconButton(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: text));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('OCR text copied to clipboard')),
                  );
                },
                icon: const Icon(Icons.copy_rounded, size: 16, color: AppColors.textMuted),
                tooltip: 'Copy extracted text',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.background,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.cardBorder),
            ),
            child: SelectableText(
              text,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildExtractedUrlsCard(ScreenshotScanResult result) {
    return CyberShieldCard(
      borderColor: AppColors.danger.withValues(alpha: 0.4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.link_off_rounded, 'Embedded URLs in Screenshot', AppColors.danger),
          const SizedBox(height: 10),
          ...result.extractedUrls.map((url) => Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                  decoration: BoxDecoration(
                    color: AppColors.danger.withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.danger.withValues(alpha: 0.3)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.link_rounded, color: AppColors.danger, size: 14),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          url,
                          style: const TextStyle(
                            color: AppColors.danger,
                            fontSize: 12,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildIndicatorsCard(ScreenshotScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.radar_rounded, 'Detected Indicators', AppColors.danger),
          const SizedBox(height: 12),
          ...result.detectedIndicators.map((indicator) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.warning_amber_rounded,
                        color: AppColors.warning, size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        indicator,
                        style: const TextStyle(
                            color: AppColors.textPrimary, fontSize: 13, height: 1.4),
                      ),
                    ),
                  ],
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildExplanationCard(ScreenshotScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.info_outline_rounded, 'Analysis Summary', AppColors.primary),
          const SizedBox(height: 10),
          Text(
            result.explanation,
            style: const TextStyle(
                color: AppColors.textSecondary, fontSize: 13, height: 1.6),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsBreakdown(ScreenshotScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.manage_search_rounded, 'Finding Breakdown', AppColors.primary),
          const SizedBox(height: 12),
          ...result.findingExplanations.map((f) => _buildFindingTile(f)),
        ],
      ),
    );
  }

  Widget _buildFindingTile(ScreenshotFindingDetail finding) {
    final levelColor = _riskLevelColor(finding.riskLevel);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: levelColor.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: levelColor.withValues(alpha: 0.25), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  finding.title,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontWeight: FontWeight.w700,
                    fontSize: 13,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              _buildChip(finding.riskLevel.toUpperCase(), levelColor),
            ],
          ),
          if (finding.explanation.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              finding.explanation,
              style: const TextStyle(
                  color: AppColors.textSecondary, fontSize: 12, height: 1.5),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildRecommendationCard(ScreenshotScanResult result) {
    final color = _classificationColor(result.classification);
    return CyberShieldCard(
      borderColor: color,
      gradientColors: [color.withValues(alpha: 0.08), AppColors.surface],
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.shield_outlined, 'Recommendation', color),
          const SizedBox(height: 10),
          Text(
            result.recommendation,
            style: const TextStyle(
                color: AppColors.textPrimary, fontSize: 13, height: 1.6),
          ),
        ],
      ),
    );
  }

  Widget _buildFooter(ScreenshotScanResult result) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          result.engineStatus ?? 'screenshot_threat_inspector_active',
          style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
        ),
        if (result.timestamp != null)
          Text(
            result.timestamp!.length > 19
                ? result.timestamp!.substring(0, 19).replaceAll('T', ' ')
                : result.timestamp!,
            style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
          ),
      ],
    );
  }

  Widget _sectionHeader(IconData icon, String title, Color color) {
    return Row(
      children: [
        Icon(icon, color: color, size: 16),
        const SizedBox(width: 8),
        Text(
          title,
          style: TextStyle(
            color: color,
            fontWeight: FontWeight.w700,
            fontSize: 13,
            letterSpacing: 0.5,
          ),
        ),
      ],
    );
  }

  Widget _buildChip(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.4), width: 1),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 10,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

class _ScreenshotPreset {
  final String label;
  final IconData icon;
  final Color color;
  final String filename;
  final String description;

  const _ScreenshotPreset({
    required this.label,
    required this.icon,
    required this.color,
    required this.filename,
    required this.description,
  });
}
