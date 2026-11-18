import 'dart:io' show File;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
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
import 'package:cybershield/core/models/qr_scan_result.dart';
import 'package:cybershield/features/qr_scanner/screens/live_qr_camera_screen.dart';

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen>
    with TickerProviderStateMixin {
  final _payloadController = TextEditingController();
  bool _isLoading = false;
  String? _errorMessage;
  QrScanResult? _scanResult;
  Uint8List? _capturedImageBytes;
  String? _capturedImageName;
  final ImagePicker _picker = ImagePicker();
  late AnimationController _scanLineController;
  late Animation<double> _scanLineAnimation;

  // --- Preset payloads covering all QR content types ---
  static const List<_QrPreset> _presets = [
    _QrPreset(
      label: 'Safe URL',
      icon: Icons.link_rounded,
      color: Color(0xFF00E676),
      payload: 'https://www.google.com',
    ),
    _QrPreset(
      label: 'Phishing URL',
      icon: Icons.dangerous_rounded,
      color: Color(0xFFFF3B30),
      payload: 'http://192.168.1.1/secure-login/verify-account?token=9a8b7c',
    ),
    _QrPreset(
      label: 'UPI Payment',
      icon: Icons.currency_rupee_rounded,
      color: Color(0xFFFFB300),
      payload: 'upi://pay?pa=suspicious_merchant_99@upi&pn=&am=5000&cu=INR',
    ),
    _QrPreset(
      label: 'Safe UPI',
      icon: Icons.payment_rounded,
      color: Color(0xFF00E676),
      payload: 'upi://pay?pa=merchant@okaxis&pn=TrustMart&am=150&cu=INR',
    ),
    _QrPreset(
      label: 'Plain Text',
      icon: Icons.text_fields_rounded,
      color: Color(0xFF00B0FF),
      payload: 'Call us at 1800-123-4567 for support',
    ),
    _QrPreset(
      label: 'WiFi QR',
      icon: Icons.wifi_rounded,
      color: Color(0xFF00B0FF),
      payload: 'WIFI:T:WPA;S:HomeNetwork;P:password123;;',
    ),
  ];

  @override
  void initState() {
    super.initState();
    _scanLineController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _scanLineAnimation = Tween<double>(begin: 0, end: 1).animate(
      CurvedAnimation(parent: _scanLineController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _payloadController.dispose();
    _scanLineController.dispose();
    super.dispose();
  }

  Future<void> _scanFromCamera() async {
    try {
      final result = await Navigator.of(context).push<LiveQrCaptureResult>(
        MaterialPageRoute(
          builder: (_) => const LiveQrCameraScreen(),
        ),
      );
      if (result == null || !mounted) return;

      if (result.hasDecodedPayload) {
        setState(() {
          _capturedImageBytes = null;
          _capturedImageName = null;
          _payloadController.text = result.payload!;
          _errorMessage = null;
          _scanResult = null;
        });
        await _performScan();
      } else if (result.galleryImagePath != null) {
        final bytes = await File(result.galleryImagePath!).readAsBytes();
        await _processImageBytes(
          bytes,
          result.galleryImageName ?? 'qr_gallery.jpg',
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Camera scanner error: $e'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    }
  }

  Future<void> _importFromGallery() async {
    try {
      final image = await _picker.pickImage(
        source: ImageSource.gallery,
        maxWidth: 2048,
        maxHeight: 2048,
      );
      if (image == null || !mounted) return;

      // 1. Try fast on-device ML Kit QR decoding first
      String? decodedPayload;
      final analyzerController = MobileScannerController(autoStart: false);
      try {
        final capture = await analyzerController.analyzeImage(image.path);
        if (capture != null && capture.barcodes.isNotEmpty) {
          for (final barcode in capture.barcodes) {
            final raw = barcode.rawValue?.trim();
            if (raw != null && raw.isNotEmpty) {
              decodedPayload = raw;
              break;
            }
          }
        }
      } catch (_) {
        // Fallback to backend QR image decoder below
      } finally {
        await analyzerController.dispose();
      }

      if (!mounted) return;
      final bytes = await image.readAsBytes();
      if (decodedPayload != null) {
        setState(() {
          _capturedImageBytes = bytes;
          _capturedImageName = image.name;
          _payloadController.text = decodedPayload!;
          _errorMessage = null;
          _scanResult = null;
        });
        await _performScan();
        return;
      }

      // 2. Backend QR decoder / OCR fallback
      await _processImageBytes(bytes, image.name);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Gallery error: $e'),
            backgroundColor: AppColors.danger,
          ),
        );
      }
    }
  }

  Future<void> _processImageBytes(Uint8List bytes, String filename) async {
    setState(() {
      _capturedImageBytes = bytes;
      _capturedImageName = filename;
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    final result = await ApiService.scanQrImage(bytes, filename);

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Failed to decode QR code image';
        } else {
          _scanResult = result;
          if (result.decodedPayload.isNotEmpty &&
              !result.decodedPayload.contains('No legible QR') &&
              !result.decodedPayload.contains('No QR barcode')) {
            _payloadController.text = result.decodedPayload;
          }

          // Record scan to persistent history
          FirestoreHistoryService.instance.recordScan(
            scanType: 'QR',
            target: result.decodedPayload.isNotEmpty ? result.decodedPayload : filename,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'content_type': result.contentType,
              'decoded_payload': result.decodedPayload,
              'risk_score': result.riskScore,
              'classification': result.classification,
              'explanation': result.explanation,
              'recommendation': result.recommendation,
              'detected_indicators': result.detectedIndicators,
              'findings': result.findings,
            },
          );
        }
      });
    }
  }

  Future<void> _performScan() async {
    final payload = _payloadController.text.trim();
    if (payload.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter or paste QR code content to analyze'),
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

    final result = await ApiService.scanQrPayload(payload);

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Failed to analyze QR payload';
        } else {
          _scanResult = result;

          // Record scan to cloud Firestore history (asynchronous & non-blocking)
          FirestoreHistoryService.instance.recordScan(
            scanType: 'QR',
            target: payload,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'content_type': result.contentType,
              'decoded_payload': result.decodedPayload,
              'risk_score': result.riskScore,
              'classification': result.classification,
              'explanation': result.explanation,
              'recommendation': result.recommendation,
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

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null && data!.text!.isNotEmpty) {
      setState(() {
        _payloadController.text = data.text!;
        _scanResult = null;
        _errorMessage = null;
      });
    }
  }

  void _clearAll() {
    setState(() {
      _payloadController.clear();
      _scanResult = null;
      _errorMessage = null;
    });
  }

  void _loadPreset(_QrPreset preset) {
    setState(() {
      _payloadController.text = preset.payload;
      _scanResult = null;
      _errorMessage = null;
    });
  }

  Color _classificationColor(String cls) {
    switch (cls.toLowerCase()) {
      case 'malicious':
      case 'critical':
      case 'high risk':
        return AppColors.danger;
      case 'suspicious':
        return AppColors.warning;
      case 'unverified':
      case 'failed':
        return AppColors.textSecondary;
      default:
        return AppColors.safe;
    }
  }

  BadgeType _classificationBadgeType(String cls) {
    switch (cls.toLowerCase()) {
      case 'malicious':
      case 'critical':
      case 'high risk':
        return BadgeType.danger;
      case 'suspicious':
        return BadgeType.warning;
      case 'unverified':
      case 'failed':
        return BadgeType.info;
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

  IconData _contentTypeIcon(String type) {
    switch (type.toLowerCase()) {
      case 'url':
        return Icons.link_rounded;
      case 'upi':
        return Icons.currency_rupee_rounded;
      case 'contact':
        return Icons.contact_phone_rounded;
      case 'wifi':
        return Icons.wifi_rounded;
      default:
        return Icons.text_fields_rounded;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      drawer: NavDrawer(currentRoute: AppRouter.qrScanner),
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        foregroundColor: AppColors.primary,
        title: const Row(
          children: [
            Icon(Icons.qr_code_scanner_rounded, size: 20),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'QR Threat Scanner',
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
          if (_scanResult != null || _errorMessage != null)
            IconButton(
              icon: const Icon(Icons.refresh_rounded),
              tooltip: 'New Scan',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildScanViewCard(),
            const SizedBox(height: 12),
            _buildInputCard(),
            const SizedBox(height: 12),
            _buildPresetsSection(),
            const SizedBox(height: 20),
            if (_isLoading) _buildLoadingState(),
            if (_errorMessage != null && !_isLoading)
              CyberErrorState(
                message: _errorMessage!,
                onRetry: _performScan,
              ),
            if (_scanResult == null && _errorMessage == null && !_isLoading)
              CyberEmptyState(
                icon: Icons.qr_code_2_rounded,
                title: 'No QR Code Analyzed',
                description:
                    'Paste a QR payload or select a preset above to detect phishing URLs, suspicious UPI links, and quishing attacks.',
              ),
            if (_scanResult != null && !_isLoading) ...[
              _buildResultHeader(_scanResult!),
              const SizedBox(height: 12),
              _buildPayloadCard(_scanResult!),
              const SizedBox(height: 12),
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
              const SizedBox(height: 12),
              _buildFooter(_scanResult!),
            ],
            const SizedBox(height: 30),
          ],
        ),
      ),
    );
  }

  Widget _buildScanViewCard() {
    return Column(
      children: [
        CyberShieldCard(
          padding: const EdgeInsets.all(0),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(16),
            child: Container(
              height: 190,
              decoration: BoxDecoration(
                color: AppColors.surfaceSubtle,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Stack(
                alignment: Alignment.center,
                children: [
                  if (_capturedImageBytes != null)
                    Positioned.fill(
                      child: Image.memory(
                        _capturedImageBytes!,
                        fit: BoxFit.cover,
                      ),
                    )
                  else
                    CustomPaint(
                      size: const Size(double.infinity, 190),
                      painter: _GridPainter(),
                    ),
                  // Scanner viewfinder overlay
                  Container(
                    width: 130,
                    height: 130,
                    decoration: BoxDecoration(
                      border: Border.all(
                          color: AppColors.primary.withValues(alpha: 0.8),
                          width: 2),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Stack(
                      children: [
                        // Corner brackets
                        ..._buildCornerBrackets(),
                        // Animated scan line
                        AnimatedBuilder(
                          animation: _scanLineAnimation,
                          builder: (context, child) => Positioned(
                            top: _scanLineAnimation.value * 126,
                            left: 4,
                            right: 4,
                            child: Container(
                              height: 2,
                              decoration: BoxDecoration(
                                gradient: LinearGradient(
                                  colors: [
                                    AppColors.primary.withValues(alpha: 0),
                                    AppColors.primary,
                                    AppColors.primary.withValues(alpha: 0),
                                  ],
                                ),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  // Status pill
                  Positioned(
                    bottom: 12,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.75),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: AppColors.cardBorder.withValues(alpha: 0.5)),
                      ),
                      child: Text(
                        _capturedImageName != null
                            ? 'Scanned: $_capturedImageName'
                            : 'Camera & Computer Vision Barcode Scanner Ready',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 10,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.primary,
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: _isLoading ? null : _scanFromCamera,
                icon: const Icon(Icons.camera_alt_rounded, size: 18),
                label: const Text(
                  'Scan with Camera',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  side: const BorderSide(color: AppColors.primary, width: 1.2),
                  foregroundColor: AppColors.primary,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: _isLoading ? null : _importFromGallery,
                icon: const Icon(Icons.photo_library_rounded, size: 18),
                label: const Text(
                  'Import QR Image',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }

  List<Widget> _buildCornerBrackets() {
    const color = AppColors.primary;
    const size = 16.0;
    const thickness = 3.0;
    return [
      // Top-left
      Positioned(
          top: 0,
          left: 0,
          child: _corner(color, size, thickness,
              top: true, left: true)),
      // Top-right
      Positioned(
          top: 0,
          right: 0,
          child: _corner(color, size, thickness,
              top: true, left: false)),
      // Bottom-left
      Positioned(
          bottom: 0,
          left: 0,
          child: _corner(color, size, thickness,
              top: false, left: true)),
      // Bottom-right
      Positioned(
          bottom: 0,
          right: 0,
          child: _corner(color, size, thickness,
              top: false, left: false)),
    ];
  }

  Widget _corner(Color color, double size, double thickness,
      {required bool top, required bool left}) {
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _CornerPainter(
            color: color,
            thickness: thickness,
            top: top,
            left: left),
      ),
    );
  }

  Widget _buildInputCard() {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.input_rounded,
                  color: AppColors.primary, size: 18),
              const SizedBox(width: 8),
              const Text(
                'QR PAYLOAD',
                style: TextStyle(
                  color: AppColors.primary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                  letterSpacing: 1.0,
                ),
              ),
              const Spacer(),
              IconButton(
                onPressed: _pasteFromClipboard,
                icon: const Icon(Icons.content_paste_rounded,
                    size: 18, color: AppColors.textMuted),
                tooltip: 'Paste from clipboard',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _payloadController,
            maxLines: 3,
            minLines: 2,
            onChanged: (_) => setState(() {}),
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontFamily: 'monospace',
              height: 1.5,
            ),
            decoration: InputDecoration(
              hintText:
                  'Paste decoded QR content here...\n\nExamples: https://..., upi://pay?pa=..., WIFI:T:WPA;...',
              hintStyle: const TextStyle(
                  color: AppColors.textMuted, fontSize: 12),
              filled: true,
              fillColor: AppColors.background,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(
                    color: AppColors.cardBorder, width: 1),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(
                    color: AppColors.cardBorder, width: 1),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: const BorderSide(
                    color: AppColors.primary, width: 1.5),
              ),
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _clearAll,
                  icon: const Icon(Icons.clear_rounded, size: 16),
                  label: const Text('Clear'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.textMuted,
                    side: const BorderSide(color: AppColors.cardBorder),
                    padding: const EdgeInsets.symmetric(vertical: 11),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                flex: 2,
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _performScan,
                  icon: const Icon(Icons.qr_code_scanner_rounded, size: 18),
                  label: Text(
                      _isLoading ? 'Analyzing...' : 'Analyze QR Payload'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: AppColors.background,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    textStyle: const TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 14,
                    ),
                  ),
                ),
              ),
            ],
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
            'Test Presets:',
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
                  side: BorderSide(
                      color: preset.color.withValues(alpha: 0.4)),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 10, vertical: 6),
                  textStyle: const TextStyle(
                      fontSize: 11, fontWeight: FontWeight.w600),
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
      title: 'Analyzing QR Payload...',
      subtitle:
          'Detecting content type and inspecting for threats, phishing, and suspicious patterns',
    );
  }

  Widget _buildResultHeader(QrScanResult result) {
    final color = _classificationColor(result.classification);
    final ctypeIcon = _contentTypeIcon(result.contentType);

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
                child: Icon(ctypeIcon, color: color, size: 24),
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
                          type: _classificationBadgeType(
                              result.classification),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 7, vertical: 3),
                          decoration: BoxDecoration(
                            color: AppColors.primary.withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                                color: AppColors.primary
                                    .withValues(alpha: 0.3)),
                          ),
                          child: Text(
                            result.contentTypeLabel,
                            style: const TextStyle(
                              color: AppColors.primary,
                              fontSize: 10,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
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
                      valueColor: AlwaysStoppedAnimation<Color>(
                          _riskScoreColor(result.riskScore)),
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
        ],
      ),
    );
  }

  Widget _buildPayloadCard(QrScanResult result) {
    final ctypeIcon = _contentTypeIcon(result.contentType);
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(ctypeIcon, color: AppColors.primary, size: 16),
              const SizedBox(width: 8),
              Text(
                'Decoded Content — ${result.contentTypeLabel}',
                style: const TextStyle(
                  color: AppColors.primary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                  letterSpacing: 0.5,
                ),
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
              result.decodedPayload,
              style: const TextStyle(
                color: AppColors.primary,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
          ),
          // Metadata tiles for UPI
          if (result.contentType == 'upi' && result.metadata != null)
            _buildUpiMetadata(result.metadata!),
        ],
      ),
    );
  }

  Widget _buildUpiMetadata(Map<String, dynamic> meta) {
    final fields = <String, String>{};
    if (meta['payee_address'] != null) {
      fields['Payee Address'] = meta['payee_address'].toString();
    }
    if (meta['payee_name'] != null) {
      fields['Payee Name'] = meta['payee_name'].toString();
    }
    if (meta['amount'] != null) {
      fields['Amount'] = '${meta['currency'] ?? 'INR'} ${meta['amount']}';
    }

    if (fields.isEmpty) return const SizedBox.shrink();

    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: fields.entries.map((e) {
          return Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.cardBorder),
            ),
            child: RichText(
              text: TextSpan(
                children: [
                  TextSpan(
                    text: '${e.key}: ',
                    style: const TextStyle(
                        color: AppColors.textMuted, fontSize: 11),
                  ),
                  TextSpan(
                    text: e.value,
                    style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 11,
                        fontWeight: FontWeight.w600),
                  ),
                ],
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildIndicatorsCard(QrScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(
              Icons.radar_rounded, 'Detected Indicators', AppColors.danger),
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
                            color: AppColors.textPrimary,
                            fontSize: 13,
                            height: 1.4),
                      ),
                    ),
                  ],
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildExplanationCard(QrScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.info_outline_rounded, 'Analysis Summary',
              AppColors.primary),
          const SizedBox(height: 10),
          Text(
            result.explanation,
            style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.6),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsBreakdown(QrScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(Icons.manage_search_rounded, 'Finding Breakdown',
              AppColors.primary),
          const SizedBox(height: 12),
          ...result.findingExplanations.map((f) => _buildFindingTile(f)),
        ],
      ),
    );
  }

  Widget _buildFindingTile(QrFindingDetail finding) {
    final levelColor = _riskLevelColor(finding.riskLevel);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: levelColor.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(10),
        border:
            Border.all(color: levelColor.withValues(alpha: 0.25), width: 1),
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
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  height: 1.5),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildRecommendationCard(QrScanResult result) {
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

  Widget _buildFooter(QrScanResult result) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          result.engineStatus ?? 'qr_threat_inspector_active',
          style: const TextStyle(
              color: AppColors.textMuted, fontSize: 11),
        ),
        if (result.timestamp != null)
          Text(
            result.timestamp!.length > 19
                ? result.timestamp!.substring(0, 19).replaceAll('T', ' ')
                : result.timestamp!,
            style: const TextStyle(
                color: AppColors.textMuted, fontSize: 11),
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

// ============================================================
// Supporting Classes
// ============================================================

class _QrPreset {
  final String label;
  final IconData icon;
  final Color color;
  final String payload;

  const _QrPreset({
    required this.label,
    required this.icon,
    required this.color,
    required this.payload,
  });
}

/// Grid background painter for the scanner viewfinder area
class _GridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = const Color(0xFF1E2C4F).withValues(alpha: 0.6)
      ..strokeWidth = 0.5;

    const step = 20.0;
    for (double x = 0; x < size.width; x += step) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
    }
    for (double y = 0; y < size.height; y += step) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), paint);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

/// Corner bracket painter for the QR viewfinder
class _CornerPainter extends CustomPainter {
  final Color color;
  final double thickness;
  final bool top;
  final bool left;

  const _CornerPainter({
    required this.color,
    required this.thickness,
    required this.top,
    required this.left,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = thickness
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.square;

    final double x = left ? 0 : size.width;
    final double y = top ? 0 : size.height;
    final double dx = left ? size.width : -size.width;
    final double dy = top ? size.height : -size.height;

    canvas.drawLine(Offset(x, y), Offset(x + dx, y), paint);
    canvas.drawLine(Offset(x, y), Offset(x, y + dy), paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
