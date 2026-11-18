import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/models/url_scan_result.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/cyber_error_state.dart';
import 'package:cybershield/core/widgets/cyber_empty_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/widgets/cybor_floating_widget.dart';

class UrlScannerScreen extends StatefulWidget {
  const UrlScannerScreen({super.key});

  @override
  State<UrlScannerScreen> createState() => _UrlScannerScreenState();
}

class _UrlScannerScreenState extends State<UrlScannerScreen> {
  final _formKey = GlobalKey<FormState>();
  final _urlController = TextEditingController();
  final _focusNode = FocusNode();

  bool _isLoading = false;
  String? _errorMessage;
  UrlScanResult? _scanResult;

  // Preset URLs for 1-tap fast testing
  final List<Map<String, String>> _presets = [
    {
      'label': 'Safe',
      'url': 'https://google.com',
      'type': 'safe',
    },
    {
      'label': 'Suspicious',
      'url': 'http://my-bank-account.top',
      'type': 'suspicious',
    },
    {
      'label': 'Malicious',
      'url': 'http://192.168.1.1/login/verify-account',
      'type': 'malicious',
    },
  ];

  @override
  void dispose() {
    _urlController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  String? _validateUrl(String? value) {
    if (value == null || value.trim().isEmpty) {
      return 'Please enter a target URL to scan';
    }
    final trimmed = value.trim();
    if (!trimmed.contains('.') && !trimmed.contains('localhost')) {
      return 'Enter a valid URL with domain or IP (e.g. https://example.com)';
    }
    final uri = Uri.tryParse(trimmed);
    if (uri == null) {
      return 'Invalid URL format';
    }
    return null;
  }

  Future<void> _performScan([String? prefilledUrl]) async {
    if (prefilledUrl != null) {
      _urlController.text = prefilledUrl;
    }

    if (!_formKey.currentState!.validate()) {
      return;
    }

    // Dismiss keyboard
    _focusNode.unfocus();

    String rawUrl = _urlController.text.trim();
    // Auto prefix scheme if omitted
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
      rawUrl = 'https://$rawUrl';
      _urlController.text = rawUrl;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    final result = await ApiService.scanUrl(rawUrl);

    if (mounted) {
      setState(() {
        _isLoading = false;
        if (result.hasError) {
          _errorMessage = result.errorMessage ?? 'Inspection failed.';
        } else {
          _scanResult = result;

          // Record scan to cloud Firestore history (asynchronous & non-blocking)
          FirestoreHistoryService.instance.recordScan(
            scanType: 'URL',
            target: result.scannedUrl.isNotEmpty ? result.scannedUrl : rawUrl,
            riskScore: result.riskScore,
            classification: result.classification,
            status: result.status,
            summary: result.explanation,
            result: {
              'scanned_url': result.scannedUrl,
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

  void _clearInput() {
    _urlController.clear();
    setState(() {
      _scanResult = null;
      _errorMessage = null;
    });
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null && data!.text!.isNotEmpty) {
      setState(() {
        _urlController.text = data.text!.trim();
      });
      _performScan();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('URL Threat Scanner'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () =>
              Navigator.pushReplacementNamed(context, AppRouter.dashboard),
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.urlScanner),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildInputCard(),
            const SizedBox(height: 16),
            _buildPresetsRow(),
            const SizedBox(height: 20),
            if (_isLoading)
              const CyberLoadingState(
                title: 'Inspecting URL Threat Vectors...',
                subtitle:
                    'Analyzing TLS protocol, raw IP hosting, keyword abuse, and suspicious TLD patterns',
              )
            else if (_errorMessage != null)
              CyberErrorState(
                title: 'URL Scan Failed',
                message: _errorMessage!,
                onRetry: () => _performScan(),
              )
            else if (_scanResult != null)
              _buildResultCard(_scanResult!)
            else
              const CyberEmptyState(
                icon: Icons.link_rounded,
                title: 'Awaiting Target URL',
                description:
                    'Enter or paste any suspicious web address above to analyze TLS encryption, domain reputation, and phishing indicators.',
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildInputCard() {
    return CyberShieldCard(
      child: Form(
        key: _formKey,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(
                    Icons.security_rounded,
                    color: AppColors.primary,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'URL Threat Detection',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 16,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Text(
                        'Heuristic phishing & malware inspection engine',
                        style: TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),
            TextFormField(
              controller: _urlController,
              focusNode: _focusNode,
              validator: _validateUrl,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontFamily: 'monospace',
              ),
              decoration: InputDecoration(
                hintText: 'https://example.com/login',
                prefixIcon: const Icon(
                  Icons.link_rounded,
                  color: AppColors.primary,
                ),
                suffixIcon: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (_urlController.text.isNotEmpty)
                      IconButton(
                        icon: const Icon(
                          Icons.clear_rounded,
                          color: AppColors.textMuted,
                          size: 18,
                        ),
                        onPressed: _clearInput,
                        tooltip: 'Clear',
                      ),
                    IconButton(
                      icon: const Icon(
                        Icons.content_paste_rounded,
                        color: AppColors.primary,
                        size: 18,
                      ),
                      onPressed: _pasteFromClipboard,
                      tooltip: 'Paste & Scan',
                    ),
                  ],
                ),
              ),
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.go,
              onFieldSubmitted: (_) => _performScan(),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _isLoading ? null : () => _performScan(),
                icon: const Icon(Icons.radar_rounded, size: 20),
                label: const Text('Scan URL'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPresetsRow() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Quick Test Presets:',
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
            Color chipColor;
            switch (preset['type']) {
              case 'safe':
                chipColor = AppColors.safe;
                break;
              case 'suspicious':
                chipColor = AppColors.warning;
                break;
              case 'malicious':
              default:
                chipColor = AppColors.danger;
                break;
            }

            return ActionChip(
              backgroundColor: chipColor.withValues(alpha: 0.12),
              side: BorderSide(
                color: chipColor.withValues(alpha: 0.4),
                width: 1,
              ),
              avatar: Icon(
                preset['type'] == 'safe'
                    ? Icons.check_circle_rounded
                    : preset['type'] == 'suspicious'
                        ? Icons.warning_amber_rounded
                        : Icons.dangerous_rounded,
                size: 16,
                color: chipColor,
              ),
              label: Text(
                '${preset['label']}: ${preset['url']!.replaceFirst('http://', '').replaceFirst('https://', '')}',
                style: TextStyle(
                  color: chipColor,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
              onPressed: () => _performScan(preset['url']),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildResultCard(UrlScanResult result) {
    Color statusColor;
    BadgeType badgeType;
    IconData statusIcon;

    if (result.isMalicious) {
      statusColor = AppColors.danger;
      badgeType = BadgeType.danger;
      statusIcon = Icons.dangerous_rounded;
    } else if (result.isSuspicious) {
      statusColor = AppColors.warning;
      badgeType = BadgeType.warning;
      statusIcon = Icons.warning_amber_rounded;
    } else {
      statusColor = AppColors.safe;
      badgeType = BadgeType.safe;
      statusIcon = Icons.verified_user_rounded;
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        CyberShieldCard(
          borderColor: statusColor.withValues(alpha: 0.5),
          hasGlow: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Score & Classification Header
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: statusColor.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: statusColor.withValues(alpha: 0.4),
                            width: 1.2,
                          ),
                        ),
                        child: Row(
                          children: [
                            Text(
                              '${result.riskScore}',
                              style: TextStyle(
                                color: statusColor,
                                fontSize: 22,
                                fontWeight: FontWeight.w900,
                              ),
                            ),
                            const Text(
                              ' / 100',
                              style: TextStyle(
                                color: AppColors.textMuted,
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 12),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Risk Score',
                            style: TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 14,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                          Text(
                            result.isMalicious
                                ? 'Severe Threat'
                                : result.isSuspicious
                                    ? 'Elevated Risk'
                                    : 'Verified Clean',
                            style: TextStyle(
                              color: statusColor,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                  CyberBadge(
                    label: result.classification.toUpperCase(),
                    type: badgeType,
                    icon: statusIcon,
                    fontSize: 12,
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Scanned URL Target Box
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: AppColors.cardBorder, width: 1),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.link_rounded,
                      color: AppColors.primary,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: SelectableText(
                        result.scannedUrl,
                        style: const TextStyle(
                          color: AppColors.primary,
                          fontSize: 13,
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(
                        Icons.copy_rounded,
                        color: AppColors.textMuted,
                        size: 16,
                      ),
                      onPressed: () {
                        Clipboard.setData(
                            ClipboardData(text: result.scannedUrl));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('URL copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      },
                      tooltip: 'Copy URL',
                    ),
                  ],
                ),
              ),

              // Explanation Box
              if (result.explanation.isNotEmpty) ...[
                const SizedBox(height: 14),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight.withValues(alpha: 0.6),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: AppColors.cardBorder.withValues(alpha: 0.6),
                      width: 1,
                    ),
                  ),
                  child: Text(
                    result.explanation,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      height: 1.45,
                    ),
                  ),
                ),
              ],

              // Detected Indicators
              const SizedBox(height: 20),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Detected Indicators (${result.detectedIndicators.length}):',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (result.detectedIndicators.isEmpty)
                    const CyberBadge(
                      label: 'NO THREATS',
                      type: BadgeType.safe,
                      fontSize: 10,
                    ),
                ],
              ),
              const SizedBox(height: 10),

              if (result.detectedIndicators.isEmpty)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.safe.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: AppColors.safe.withValues(alpha: 0.25),
                      width: 1,
                    ),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.check_circle_outline_rounded,
                          color: AppColors.safe, size: 20),
                      SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'No suspicious or malicious threat vectors found. Protocol, host structure, and reputation meet baseline trust standards.',
                          style: TextStyle(
                            color: AppColors.safe,
                            fontSize: 12,
                            height: 1.35,
                          ),
                        ),
                      ),
                    ],
                  ),
                )
              else
                ...result.detectedIndicators.map((indicator) {
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: statusColor.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: statusColor.withValues(alpha: 0.25),
                        width: 1,
                      ),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          result.isMalicious
                              ? Icons.error_rounded
                              : Icons.warning_amber_rounded,
                          color: statusColor,
                          size: 18,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            indicator,
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 13,
                              height: 1.35,
                            ),
                          ),
                        ),
                      ],
                    ),
                  );
                }),

              // Detailed Finding Explanations (if available)
              if (result.findingExplanations.isNotEmpty) ...[
                const SizedBox(height: 16),
                const Text(
                  'Heuristic Findings Breakdown:',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                ...result.findingExplanations.map((fe) {
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: AppColors.cardBorder, width: 1),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Expanded(
                              child: Text(
                                fe.title,
                                style: const TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 13,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: (fe.riskLevel.toLowerCase() == 'high'
                                        ? AppColors.danger
                                        : AppColors.warning)
                                    .withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                fe.riskLevel.toUpperCase(),
                                style: TextStyle(
                                  color: fe.riskLevel.toLowerCase() == 'high'
                                      ? AppColors.danger
                                      : AppColors.warning,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text(
                          fe.explanation,
                          style: const TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 12,
                            height: 1.35,
                          ),
                        ),
                      ],
                    ),
                  );
                }),
              ],

              // Recommendation
              if (result.recommendation.isNotEmpty) ...[
                const SizedBox(height: 16),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: statusColor.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: statusColor.withValues(alpha: 0.35),
                      width: 1,
                    ),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        Icons.shield_rounded,
                        color: statusColor,
                        size: 20,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Recommendation',
                              style: TextStyle(
                                color: statusColor,
                                fontSize: 13,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              result.recommendation,
                              style: TextStyle(
                                color: statusColor.withValues(alpha: 0.95),
                                fontSize: 12,
                                height: 1.35,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ],

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
                        'scan_type': 'URL',
                        'target': result.scannedUrl,
                        'risk_score': result.riskScore,
                        'classification': result.classification,
                        'findings': result.detectedIndicators,
                      },
                    );
                  },
                  icon: const Icon(Icons.smart_toy_rounded, size: 18),
                  label: const Text('Consult CYBOR AI Assistant',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                ),
              ),

              const Divider(color: AppColors.cardBorder, height: 28),

              // Footer Metadata
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'Engine: CyberShield Heuristics',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11),
                  ),
                  Text(
                    result.engineStatus ?? 'Active & Verified',
                    style: const TextStyle(
                      color: AppColors.primary,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        Center(
          child: TextButton.icon(
            onPressed: _clearInput,
            icon: const Icon(Icons.refresh_rounded, size: 16),
            label: const Text('Scan Another URL'),
            style: TextButton.styleFrom(
              foregroundColor: AppColors.textSecondary,
            ),
          ),
        ),
      ],
    );
  }
}

