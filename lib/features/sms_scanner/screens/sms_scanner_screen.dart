import 'package:flutter/material.dart';
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
import 'package:cybershield/core/models/sms_scan_result.dart';
import 'package:cybershield/core/widgets/cybor_floating_widget.dart';

class SmsScannerScreen extends StatefulWidget {
  final String? initialMessage;
  final String? initialSender;
  final String? initialSourceApp;
  final bool autoScan;

  const SmsScannerScreen({
    super.key,
    this.initialMessage,
    this.initialSender,
    this.initialSourceApp,
    this.autoScan = false,
  });

  @override
  State<SmsScannerScreen> createState() => _SmsScannerScreenState();
}

class _SmsScannerScreenState extends State<SmsScannerScreen>
    with TickerProviderStateMixin {
  final _smsController = TextEditingController();
  bool _isLoading = false;
  String? _errorMessage;
  SmsScanResult? _scanResult;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  static const Map<String, String> _presets = {
    'Safe':
        'Hi! Just wanted to remind you about our meeting tomorrow at 10am. See you then!',
    'Suspicious':
        'Dear customer, your package could not be delivered. Update your address within 24 hours: http://bit.ly/track-pkg',
    'Malicious':
        'URGENT: Your SBI account has been BLOCKED due to incomplete KYC! Click http://192.168.1.1/sbi-kyc to verify OTP immediately or account will be suspended.',
  };

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    )..repeat(reverse: true);
    _pulseAnimation = Tween<double>(begin: 0.85, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    if (widget.initialMessage != null && widget.initialMessage!.trim().isNotEmpty) {
      _smsController.text = widget.initialMessage!.trim();
      if (widget.autoScan) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          _performScan();
        });
      }
    }
  }

  @override
  void dispose() {
    _smsController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _performScan() async {
    final message = _smsController.text.trim();
    if (message.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please paste or type an SMS message to analyze'),
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

    final result = await ApiService.scanSms(message);

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Failed to analyze SMS';
        } else {
          _scanResult = result;

          // Record scan to cloud Firestore history (asynchronous & non-blocking)
          FirestoreHistoryService.instance.recordScan(
            scanType: 'SMS',
            target: message,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'scanned_message': result.scannedMessage,
              'risk_score': result.riskScore,
              'classification': result.classification,
              'explanation': result.explanation,
              'recommendation': result.recommendation,
              'detected_indicators': result.detectedIndicators,
              'threat_categories': result.threatCategories,
              'embedded_urls': result.embeddedUrls,
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
      _smsController.clear();
      _scanResult = null;
      _errorMessage = null;
    });
  }

  void _insertPreset(String message) {
    setState(() {
      _smsController.text = message;
      _scanResult = null;
      _errorMessage = null;
    });
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

  IconData _classificationIcon(String cls) {
    switch (cls.toLowerCase()) {
      case 'malicious':
        return Icons.dangerous_rounded;
      case 'suspicious':
        return Icons.warning_rounded;
      default:
        return Icons.verified_user_rounded;
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

  // Resolve the current route name for NavDrawer
  String get _currentRoute => AppRouter.smsScanner;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      drawer: NavDrawer(currentRoute: _currentRoute),
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        foregroundColor: AppColors.primary,
        title: const Row(
          children: [
            Icon(Icons.sms_failed_rounded, size: 20),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'SMS Threat Scanner',
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
            _buildInputCard(),
            const SizedBox(height: 12),
            _buildPresetsRow(),
            const SizedBox(height: 20),
            if (_isLoading) _buildLoadingState(),
            if (_errorMessage != null && !_isLoading)
              CyberErrorState(
                message: _errorMessage!,
                onRetry: _performScan,
              ),
            if (_scanResult == null && _errorMessage == null && !_isLoading)
              CyberEmptyState(
                icon: Icons.sms_outlined,
                title: 'No SMS Analyzed',
                description:
                    'Paste a suspicious SMS above and tap Analyze to detect scams, phishing, and smishing attacks.',
              ),
            if (_scanResult != null && !_isLoading) ...[
              _buildResultHeader(_scanResult!),
              const SizedBox(height: 12),
              _buildMetricsRow(_scanResult!),
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
              if (_scanResult!.embeddedUrls.isNotEmpty) ...[
                _buildEmbeddedUrlsCard(_scanResult!),
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
                        'scan_type': 'SMS',
                        'target': _scanResult!.scannedMessage,
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

  Widget _buildInputCard() {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.message_rounded,
                  color: AppColors.primary, size: 18),
              const SizedBox(width: 8),
              const Text(
                'SMS MESSAGE',
                style: TextStyle(
                  color: AppColors.primary,
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                  letterSpacing: 1.0,
                ),
              ),
              const Spacer(),
              Text(
                '${_smsController.text.length} chars',
                style: const TextStyle(
                    color: AppColors.textMuted, fontSize: 12),
              ),
            ],
          ),
          if (widget.initialSender != null || widget.initialSourceApp != null) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.primary.withValues(alpha: 0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.shield_outlined, size: 14, color: AppColors.primary),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      'Detected from ${widget.initialSourceApp ?? "Notification"}${widget.initialSender != null ? " • Sender: ${widget.initialSender}" : ""}',
                      style: const TextStyle(color: AppColors.primary, fontSize: 11, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
            ),
          ],
          const SizedBox(height: 12),
          TextField(
            controller: _smsController,
            maxLines: 5,
            minLines: 3,
            onChanged: (_) => setState(() {}),
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 14,
              height: 1.5,
            ),
            decoration: InputDecoration(
              hintText:
                  'Paste the suspicious SMS here...\n\nE.g. "URGENT: Your bank account is blocked. Click here to verify your KYC immediately."',
              hintStyle: const TextStyle(
                  color: AppColors.textMuted, fontSize: 13),
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
                borderSide:
                    const BorderSide(color: AppColors.primary, width: 1.5),
              ),
            ),
          ),
          const SizedBox(height: 14),
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
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                flex: 2,
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _performScan,
                  icon: AnimatedBuilder(
                    animation: _pulseAnimation,
                    builder: (context, child) => Transform.scale(
                      scale: _isLoading ? _pulseAnimation.value : 1.0,
                      child: child,
                    ),
                    child: const Icon(Icons.biotech_rounded, size: 18),
                  ),
                  label: Text(_isLoading ? 'Analyzing...' : 'Analyze SMS'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: AppColors.background,
                    padding: const EdgeInsets.symmetric(vertical: 13),
                    textStyle: const TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 14,
                      letterSpacing: 0.5,
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

  Widget _buildPresetsRow() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.only(left: 4, bottom: 8),
          child: Text(
            'Quick Presets:',
            style: TextStyle(color: AppColors.textMuted, fontSize: 12),
          ),
        ),
        Row(
          children: _presets.entries.map((e) {
            Color color;
            switch (e.key) {
              case 'Safe':
                color = AppColors.safe;
                break;
              case 'Suspicious':
                color = AppColors.warning;
                break;
              default:
                color = AppColors.danger;
            }
            return Expanded(
              child: Padding(
                padding: const EdgeInsets.only(right: 6),
                child: OutlinedButton(
                  onPressed: () => _insertPreset(e.value),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: color,
                    side: BorderSide(color: color.withValues(alpha: 0.5)),
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    textStyle: const TextStyle(
                        fontSize: 11, fontWeight: FontWeight.w600),
                  ),
                  child: Text(e.key),
                ),
              ),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildLoadingState() {
    return const CyberLoadingState(
      title: 'Inspecting SMS for threats...',
      subtitle: 'Scanning for smishing patterns, suspicious URLs, and social engineering',
    );
  }

  Widget _buildResultHeader(SmsScanResult result) {
    final color = _classificationColor(result.classification);
    final icon = _classificationIcon(result.classification);

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
                child: Icon(icon, color: color, size: 26),
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
                            '${result.threatCategories.length} threat vector${result.threatCategories.length > 1 ? 's' : ''}',
                            style: const TextStyle(
                                color: AppColors.textMuted, fontSize: 12),
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
                    .map((c) =>
                        _buildChip(_formatCategory(c), AppColors.warning))
                    .toList(),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildMetricsRow(SmsScanResult result) {
    final meta = result.metadata;
    final embeddedCount = result.embeddedUrls.length;
    final wordCount = meta?['word_count'] as int? ?? 0;
    final charCount = meta?['character_count'] as int? ?? 0;

    return Row(
      children: [
        Expanded(
            child: _buildMetricTile(
                'URLs Found', '$embeddedCount', Icons.link_rounded,
                color:
                    embeddedCount > 0 ? AppColors.danger : AppColors.safe)),
        const SizedBox(width: 8),
        Expanded(
            child: _buildMetricTile(
                'Words', '$wordCount', Icons.text_fields_rounded)),
        const SizedBox(width: 8),
        Expanded(
            child: _buildMetricTile(
                'Characters', '$charCount', Icons.format_size_rounded)),
      ],
    );
  }

  Widget _buildMetricTile(String label, String value, IconData icon,
      {Color? color}) {
    return CyberShieldCard(
      padding: const EdgeInsets.all(12),
      child: Column(
        children: [
          Icon(icon, color: color ?? AppColors.primary, size: 18),
          const SizedBox(height: 6),
          Text(
            value,
            style: TextStyle(
              color: color ?? AppColors.textPrimary,
              fontWeight: FontWeight.w800,
              fontSize: 16,
            ),
          ),
          const SizedBox(height: 2),
          Text(label,
              style: const TextStyle(
                  color: AppColors.textMuted, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildIndicatorsCard(SmsScanResult result) {
    return CyberShieldCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(
              Icons.radar_rounded, 'Detected Indicators', AppColors.danger),
          const SizedBox(height: 12),
          ...result.detectedIndicators.map((indicator) {
            return Padding(
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
            );
          }),
        ],
      ),
    );
  }

  Widget _buildExplanationCard(SmsScanResult result) {
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
                color: AppColors.textSecondary, fontSize: 13, height: 1.6),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsBreakdown(SmsScanResult result) {
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

  Widget _buildFindingTile(SmsFindingDetail finding) {
    final levelColor = _riskLevelColor(finding.riskLevel);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: levelColor.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
            color: levelColor.withValues(alpha: 0.25), width: 1),
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
          if (finding.indicator.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(
              'Pattern: ${finding.indicator}',
              style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                  fontStyle: FontStyle.italic),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildEmbeddedUrlsCard(SmsScanResult result) {
    return CyberShieldCard(
      borderColor: AppColors.danger,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionHeader(
              Icons.link_off_rounded,
              'Embedded Suspicious URLs',
              AppColors.danger),
          const SizedBox(height: 10),
          ...result.embeddedUrls.map((url) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 10, vertical: 7),
                decoration: BoxDecoration(
                  color: AppColors.danger.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                      color: AppColors.danger.withValues(alpha: 0.3),
                      width: 1),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.link_rounded,
                        color: AppColors.danger, size: 14),
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
            );
          }),
        ],
      ),
    );
  }

  Widget _buildRecommendationCard(SmsScanResult result) {
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

  Widget _buildFooter(SmsScanResult result) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          result.engineStatus ?? 'sms_threat_inspector_active',
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
        border: Border.all(
            color: color.withValues(alpha: 0.4), width: 1),
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
