// Dedicated Live ML Kit QR Code Camera Scanner Screen for CyberShield

import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:cybershield/core/theme/app_theme.dart';

/// Result returned by [LiveQrCameraScreen] when a QR code is scanned or an image is chosen.
class LiveQrCaptureResult {
  final String? payload;
  final String payloadType;
  final String? galleryImagePath;
  final String? galleryImageName;

  const LiveQrCaptureResult({
    this.payload,
    this.payloadType = 'text',
    this.galleryImagePath,
    this.galleryImageName,
  });

  bool get hasDecodedPayload => payload != null && payload!.trim().isNotEmpty;
}

class LiveQrCameraScreen extends StatefulWidget {
  const LiveQrCameraScreen({super.key});

  @override
  State<LiveQrCameraScreen> createState() => _LiveQrCameraScreenState();
}

class _LiveQrCameraScreenState extends State<LiveQrCameraScreen>
    with SingleTickerProviderStateMixin {
  late final MobileScannerController _controller;
  late final AnimationController _laserController;
  late final Animation<double> _laserAnimation;
  final ImagePicker _picker = ImagePicker();

  bool _isProcessingDetection = false;
  bool _isPaused = false;
  String? _detectedPayload;
  String _detectedType = 'text';
  String? _statusBanner;

  @override
  void initState() {
    super.initState();
    _controller = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      detectionTimeoutMs: 300,
      facing: CameraFacing.back,
      torchEnabled: false,
      formats: const [
        BarcodeFormat.qrCode,
        BarcodeFormat.aztec,
        BarcodeFormat.dataMatrix,
        BarcodeFormat.pdf417,
      ],
    );
    _laserController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1900),
    )..repeat(reverse: true);
    _laserAnimation = CurvedAnimation(
      parent: _laserController,
      curve: Curves.easeInOut,
    );
  }

  @override
  void dispose() {
    _laserController.dispose();
    _controller.dispose();
    super.dispose();
  }

  static String classifyPayloadType(String raw) {
    final trimmed = raw.trim();
    final lower = trimmed.toLowerCase();
    if (lower.startsWith('http://') ||
        lower.startsWith('https://') ||
        lower.startsWith('www.')) {
      return 'URL';
    }
    if (lower.startsWith('upi://') ||
        lower.startsWith('bitcoin:') ||
        lower.startsWith('ethereum:') ||
        lower.startsWith('paytmmp://') ||
        lower.startsWith('phonepe://')) {
      return 'Payment / UPI';
    }
    if (trimmed.toUpperCase().startsWith('WIFI:')) {
      return 'Wi-Fi Config';
    }
    if (lower.startsWith('mailto:') || lower.startsWith('matmsg:')) {
      return 'Email';
    }
    if (lower.startsWith('tel:')) {
      return 'Phone Number';
    }
    if (lower.startsWith('sms:') || lower.startsWith('smsto:')) {
      return 'SMS';
    }
    if (trimmed.toUpperCase().startsWith('BEGIN:VCARD') ||
        trimmed.toUpperCase().startsWith('MECARD:')) {
      return 'Contact / vCard';
    }
    return 'Plain Text';
  }

  void _onDetect(BarcodeCapture capture) {
    if (_isProcessingDetection || _isPaused) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue?.trim();
      if (raw != null && raw.isNotEmpty) {
        final type = classifyPayloadType(raw);
        setState(() {
          _isProcessingDetection = true;
          _isPaused = true;
          _detectedPayload = raw;
          _detectedType = type;
          _statusBanner = 'QR detected ($type)';
        });
        _controller.stop();
        return;
      }
    }
  }

  void _confirmAndAnalyze() {
    final payload = _detectedPayload;
    if (payload == null || payload.isEmpty) return;
    Navigator.of(context).pop(
      LiveQrCaptureResult(
        payload: payload,
        payloadType: _detectedType,
      ),
    );
  }

  Future<void> _resumeScanning() async {
    setState(() {
      _isProcessingDetection = false;
      _isPaused = false;
      _detectedPayload = null;
      _statusBanner = null;
    });
    try {
      await _controller.start();
    } catch (_) {}
  }

  Future<void> _pickAndScanGalleryImage() async {
    try {
      final image = await _picker.pickImage(
        source: ImageSource.gallery,
        maxWidth: 2048,
        maxHeight: 2048,
      );
      if (image == null || !mounted) return;

      setState(() {
        _statusBanner = 'Decoding QR from gallery image...';
      });

      final capture = await _controller.analyzeImage(image.path);
      if (!mounted) return;

      if (capture != null && capture.barcodes.isNotEmpty) {
        for (final barcode in capture.barcodes) {
          final raw = barcode.rawValue?.trim();
          if (raw != null && raw.isNotEmpty) {
            Navigator.of(context).pop(
              LiveQrCaptureResult(
                payload: raw,
                payloadType: classifyPayloadType(raw),
                galleryImagePath: image.path,
                galleryImageName: image.name,
              ),
            );
            return;
          }
        }
      }

      // If on-device ML Kit did not find a QR barcode, pass image back for backend fallback analysis
      Navigator.of(context).pop(
        LiveQrCaptureResult(
          galleryImagePath: image.path,
          galleryImageName: image.name,
        ),
      );
    } catch (e) {
      if (mounted) {
        setState(() {
          _statusBanner = 'Gallery scan failed: $e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final frameSide = (size.width * 0.72).clamp(210.0, 290.0);

    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            tapToFocus: true,
            fit: BoxFit.cover,
            errorBuilder: (context, error) {
              final isPermDenied =
                  error.errorCode == MobileScannerErrorCode.permissionDenied;
              return Container(
                color: AppColors.background,
                padding: const EdgeInsets.all(24),
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        isPermDenied
                            ? Icons.no_photography_rounded
                            : Icons.videocam_off_rounded,
                        color: AppColors.warning,
                        size: 56,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        isPermDenied
                            ? 'Camera Permission Required'
                            : 'Camera Unavailable',
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        isPermDenied
                            ? 'Allow camera permission in Android Settings to scan QR codes live, or pick a QR image from your gallery.'
                            : (error.errorDetails?.message ??
                                'Could not initialize the camera preview (${error.errorCode.name}).'),
                        style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 13,
                          height: 1.4,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 20),
                      Wrap(
                        spacing: 10,
                        runSpacing: 10,
                        alignment: WrapAlignment.center,
                        children: [
                          ElevatedButton.icon(
                            onPressed: _resumeScanning,
                            icon: const Icon(Icons.refresh_rounded, size: 18),
                            label: const Text('Retry Camera'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _pickAndScanGalleryImage,
                            icon: const Icon(Icons.photo_library_rounded, size: 18),
                            label: const Text('Scan from Gallery'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              );
            },
          ),

          // Darkened vignette with clear center QR scanning frame
          IgnorePointer(
            child: CustomPaint(
              painter: _QrFrameOverlayPainter(
                frameSize: frameSide,
                accentColor: _detectedPayload != null
                    ? AppColors.safe
                    : AppColors.primary,
              ),
              size: Size.infinite,
            ),
          ),

          // Animated cyan laser line inside the scan window
          if (!_isPaused)
            IgnorePointer(
              child: Center(
                child: SizedBox(
                  width: frameSide - 24,
                  height: frameSide - 24,
                  child: AnimatedBuilder(
                    animation: _laserAnimation,
                    builder: (context, _) {
                      return Align(
                        alignment: Alignment(0, -1.0 + (2.0 * _laserAnimation.value)),
                        child: Container(
                          height: 2.5,
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(2),
                            gradient: LinearGradient(
                              colors: [
                                Colors.transparent,
                                AppColors.primary,
                                AppColors.primary,
                                Colors.transparent,
                              ],
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: AppColors.primary.withValues(alpha: 0.7),
                                blurRadius: 8,
                                spreadRadius: 1,
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),
            ),

          // Top bar: Back, Title, Torch, Flip Camera
          SafeArea(
            child: Column(
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  child: Row(
                    children: [
                      _CircleControlButton(
                        icon: Icons.arrow_back_rounded,
                        tooltip: 'Close scanner',
                        onPressed: () => Navigator.of(context).pop(),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Text(
                          'Live QR Security Scanner',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                            shadows: [
                              Shadow(color: Colors.black87, blurRadius: 6),
                            ],
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      ValueListenableBuilder<MobileScannerState>(
                        valueListenable: _controller,
                        builder: (context, state, _) {
                          final torchOn = state.torchState == TorchState.on;
                          final torchAvailable =
                              state.torchState != TorchState.unavailable;
                          return _CircleControlButton(
                            icon: torchOn
                                ? Icons.flash_on_rounded
                                : Icons.flash_off_rounded,
                            iconColor:
                                torchOn ? AppColors.warning : Colors.white,
                            tooltip: 'Toggle flashlight',
                            onPressed: torchAvailable
                                ? () => _controller.toggleTorch()
                                : null,
                          );
                        },
                      ),
                      const SizedBox(width: 8),
                      _CircleControlButton(
                        icon: Icons.cameraswitch_rounded,
                        tooltip: 'Switch camera',
                        onPressed: () => _controller.switchCamera(),
                      ),
                    ],
                  ),
                ),

                if (_statusBanner != null)
                  Container(
                    margin: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.72),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: AppColors.primary.withValues(alpha: 0.5),
                      ),
                    ),
                    child: Text(
                      _statusBanner!,
                      style: const TextStyle(
                        color: AppColors.primary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),

                const Spacer(),

                // Bottom panel: either detected QR payload confirmation or scanning controls
                if (_detectedPayload != null)
                  _buildDetectedSheet()
                else
                  _buildBottomControls(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomControls() {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 0, 16, 18),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: AppColors.surface.withValues(alpha: 0.92),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text(
            'Align any QR code inside the frame for automatic detection',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 4),
          const Text(
            'Supports URLs, UPI payments, Wi-Fi, SMS, Phone, Email, vCard & text',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.primary,
                    side: BorderSide(
                      color: AppColors.primary.withValues(alpha: 0.6),
                    ),
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  onPressed: _pickAndScanGalleryImage,
                  icon: const Icon(Icons.photo_library_rounded, size: 16),
                  label: const Text(
                    'Scan Gallery Image',
                    style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildDetectedSheet() {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 0, 16, 18),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface.withValues(alpha: 0.96),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.safe.withValues(alpha: 0.7), width: 1.5),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.qr_code_scanner_rounded, color: AppColors.safe, size: 20),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'QR Code Decoded',
                  style: TextStyle(
                    color: AppColors.safe,
                    fontSize: 14,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  _detectedType,
                  style: const TextStyle(
                    color: AppColors.primary,
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.surfaceSubtle,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.cardBorder),
            ),
            child: Text(
              _detectedPayload!,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontFamily: 'monospace',
              ),
              maxLines: 4,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.textSecondary,
                    side: const BorderSide(color: AppColors.cardBorder),
                    padding: const EdgeInsets.symmetric(vertical: 11),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  onPressed: _resumeScanning,
                  icon: const Icon(Icons.refresh_rounded, size: 16),
                  label: const Text('Scan Again', style: TextStyle(fontSize: 12)),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                flex: 2,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 11),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  onPressed: _confirmAndAnalyze,
                  icon: const Icon(Icons.security_rounded, size: 17),
                  label: const Text(
                    'Analyze Threat',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w800),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _CircleControlButton extends StatelessWidget {
  final IconData icon;
  final Color iconColor;
  final String tooltip;
  final VoidCallback? onPressed;

  const _CircleControlButton({
    required this.icon,
    this.iconColor = Colors.white,
    required this.tooltip,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.black.withValues(alpha: 0.55),
      shape: const CircleBorder(),
      clipBehavior: Clip.antiAlias,
      child: IconButton(
        icon: Icon(icon, color: onPressed == null ? Colors.white38 : iconColor, size: 22),
        tooltip: tooltip,
        onPressed: onPressed,
      ),
    );
  }
}

class _QrFrameOverlayPainter extends CustomPainter {
  final double frameSize;
  final Color accentColor;

  _QrFrameOverlayPainter({
    required this.frameSize,
    required this.accentColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final frameRect = Rect.fromCenter(
      center: center,
      width: frameSize,
      height: frameSize,
    );
    final rrect = RRect.fromRectAndRadius(frameRect, const Radius.circular(18));

    // Semi-transparent dark mask around scan window
    final bgPath = Path()..addRect(Rect.fromLTWH(0, 0, size.width, size.height));
    final holePath = Path()..addRRect(rrect);
    final maskPath = Path.combine(PathOperation.difference, bgPath, holePath);

    canvas.drawPath(
      maskPath,
      Paint()..color = Colors.black.withValues(alpha: 0.60),
    );

    // Subtle border around frame
    canvas.drawRRect(
      rrect,
      Paint()
        ..color = accentColor.withValues(alpha: 0.35)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.5,
    );

    // Bold corner brackets
    final cornerPaint = Paint()
      ..color = accentColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = 4.0
      ..strokeCap = StrokeCap.round;

    const cornerLen = 28.0;
    final l = frameRect.left;
    final t = frameRect.top;
    final r = frameRect.right;
    final b = frameRect.bottom;

    // Top-left
    canvas.drawLine(Offset(l, t + cornerLen), Offset(l, t + 10), cornerPaint);
    canvas.drawLine(Offset(l + 10, t), Offset(l + cornerLen, t), cornerPaint);
    // Top-right
    canvas.drawLine(Offset(r - cornerLen, t), Offset(r - 10, t), cornerPaint);
    canvas.drawLine(Offset(r, t + 10), Offset(r, t + cornerLen), cornerPaint);
    // Bottom-left
    canvas.drawLine(Offset(l, b - cornerLen), Offset(l, b - 10), cornerPaint);
    canvas.drawLine(Offset(l + 10, b), Offset(l + cornerLen, b), cornerPaint);
    // Bottom-right
    canvas.drawLine(Offset(r - cornerLen, b), Offset(r - 10, b), cornerPaint);
    canvas.drawLine(Offset(r, b - 10), Offset(r, b - cornerLen), cornerPaint);
  }

  @override
  bool shouldRepaint(covariant _QrFrameOverlayPainter oldDelegate) {
    return oldDelegate.frameSize != frameSize ||
        oldDelegate.accentColor != accentColor;
  }
}
