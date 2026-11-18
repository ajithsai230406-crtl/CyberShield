// Email Threat Scanner Screen for CyberShield
// Combines Static Email Phishing Analysis with Secure Gmail OAuth Integration

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/widgets/cyber_loading_state.dart';
import 'package:cybershield/core/widgets/cyber_error_state.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/services/gmail_service.dart';
import 'package:cybershield/core/models/email_scan_result.dart';

class _EmailPreset {
  final String label;
  final String sender;
  final String subject;
  final String body;
  final Color color;

  const _EmailPreset({
    required this.label,
    required this.sender,
    required this.subject,
    required this.body,
    required this.color,
  });
}

class EmailScannerScreen extends StatefulWidget {
  final String? initialSender;
  final String? initialSubject;
  final String? initialBody;
  final bool autoScan;

  const EmailScannerScreen({
    super.key,
    this.initialSender,
    this.initialSubject,
    this.initialBody,
    this.autoScan = false,
  });

  @override
  State<EmailScannerScreen> createState() => _EmailScannerScreenState();
}

class _EmailScannerScreenState extends State<EmailScannerScreen> {
  // Mode selection: 0 = Manual Phishing Audit, 1 = Gmail Inbox Inspector
  int _selectedMode = 0;

  final TextEditingController _senderController = TextEditingController();
  final TextEditingController _subjectController = TextEditingController();
  final TextEditingController _bodyController = TextEditingController();

  bool _isLoading = false;
  String? _errorMessage;
  EmailScanResult? _scanResult;

  final GmailService _gmail = GmailService.instance;

  static const List<_EmailPreset> _presets = [
    _EmailPreset(
      label: 'PayPal Phishing Lure',
      sender: '"PayPal Security Support" <service-alert88@gmail.com>',
      subject: 'URGENT: Your account has been suspended within 24 hours!',
      body:
          'Dear Customer,\n\nWe detected suspicious login activity on your account. To prevent permanent termination, verify your password and confirm your billing identity immediately at http://192.168.1.1/paypal-verify.\n\nFailure to take immediate action within 24 hours will result in legal escalation.\n\nPayPal Support Team',
      color: Color(0xFFFF3B30),
    ),
    _EmailPreset(
      label: 'Microsoft 365 Password Scam',
      sender: '"Microsoft Office 365 Team" <noreply@freemail-service.xyz>',
      subject: 'Required: Your Office 365 password has expired',
      body:
          'Your corporate Microsoft 365 password will expire today. Please verify your identity and enter your OTP two-factor code to retain access to your mailbox and OneDrive documents.',
      color: Color(0xFFFF9500),
    ),
    _EmailPreset(
      label: 'CEO Wire Transfer / BEC',
      sender: 'CEO Office <executive-urgent@mail.com>',
      subject: 'Confidential: Wire Transfer Request',
      body:
          'Are you at your desk? I am currently in a closed board meeting and need an urgent wire transfer processed for an overdue vendor invoice. Please reply with confirmation.',
      color: Color(0xFFFFCC00),
    ),
    _EmailPreset(
      label: 'Legitimate Team Update',
      sender: 'alex@company.org',
      subject: 'Project Sprint Planning Notes',
      body:
          'Hi team,\n\nHere are the meeting notes from today\'s sprint planning session. We agreed to finalize the mobile modules by Friday. Please review the documentation on our internal wiki.\n\nBest,\nAlex',
      color: Color(0xFF34C759),
    ),
  ];

  @override
  void initState() {
    super.initState();
    _gmail.addListener(_onGmailServiceUpdated);

    if (widget.initialSender != null && widget.initialSender!.trim().isNotEmpty) {
      _senderController.text = widget.initialSender!.trim();
    }
    if (widget.initialSubject != null && widget.initialSubject!.trim().isNotEmpty) {
      _subjectController.text = widget.initialSubject!.trim();
    }
    if (widget.initialBody != null && widget.initialBody!.trim().isNotEmpty) {
      _bodyController.text = widget.initialBody!.trim();
      if (widget.autoScan) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          _analyzeEmail();
        });
      }
    }
  }

  void _onGmailServiceUpdated() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _gmail.removeListener(_onGmailServiceUpdated);
    _senderController.dispose();
    _subjectController.dispose();
    _bodyController.dispose();
    super.dispose();
  }

  void _applyPreset(_EmailPreset preset) {
    setState(() {
      _senderController.text = preset.sender;
      _subjectController.text = preset.subject;
      _bodyController.text = preset.body;
      _errorMessage = null;
      _scanResult = null;
    });
  }

  Future<void> _analyzeEmail() async {
    final bodyText = _bodyController.text.trim();
    if (bodyText.isEmpty) {
      setState(() {
        _errorMessage = 'Please enter or paste the email body text.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _scanResult = null;
    });

    try {
      final result = await ApiService.scanEmail(
        body: bodyText,
        sender: _senderController.text.trim(),
        subject: _subjectController.text.trim(),
      );

      if (result.isError) {
        setState(() {
          _isLoading = false;
          _errorMessage = result.errorMessage ?? 'Email analysis failed.';
        });
        return;
      }

      setState(() {
        _isLoading = false;
        _scanResult = result;
      });

      // Save to Cloud Firestore
      if (FirestoreHistoryService.instance.isAuthenticated) {
        final target = (result.subject.isNotEmpty
            ? result.subject
            : (result.sender.isNotEmpty ? result.sender : 'Email Scan'));
        await FirestoreHistoryService.instance.recordScan(
          scanType: 'EMAIL',
          target: target,
          riskScore: result.riskScore,
          classification: result.classification,
          status: result.classification,
          summary:
              'Risk Score: ${result.riskScore}/100 (${result.classification})',
          result: result.toJson(),
          metadata: {
            'sender': result.sender,
            'subject': result.subject,
            'threat_categories': result.threatCategories,
            'url_count': result.embeddedUrls.length,
          },
        );
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = 'Email analysis failed: $e';
      });
    }
  }

  // -------------------------------------------------------------------------
  // Gmail OAuth & Consent Dialogs
  // -------------------------------------------------------------------------

  void _showGmailConsentDialog() {
    final messenger = ScaffoldMessenger.of(context);

    showModalBottomSheet(
      context: context,
      backgroundColor: AppColors.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (sheetCtx) {
        final tokenCtrl = TextEditingController();
        bool connectingToken = false;

        return StatefulBuilder(
          builder: (context, setSheetState) {
            return Padding(
              padding: EdgeInsets.only(
                left: 20,
                right: 20,
                top: 20,
                bottom: MediaQuery.of(sheetCtx).viewInsets.bottom + 24,
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppColors.primary.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: const Icon(
                          Icons.mark_email_read_rounded,
                          color: AppColors.primary,
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 12),
                      const Expanded(
                        child: Text(
                          'Gmail Phishing Protection',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 17,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close_rounded,
                            color: AppColors.textMuted),
                        onPressed: () => Navigator.pop(sheetCtx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  const Text(
                    'CyberShield requests explicit user authorization to inspect your Gmail inbox for cyber threats:',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      height: 1.4,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: AppColors.cardBorder),
                    ),
                    child: const Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '🔐 Security & Privacy Policy Guarantees:',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w700,
                            fontSize: 12,
                          ),
                        ),
                        SizedBox(height: 6),
                        Text(
                          '• Read-Only Scope: https://www.googleapis.com/auth/gmail.readonly\n'
                          '• Zero Password Storage: We never request or store Google passwords\n'
                          '• In-Memory Inspection: OAuth tokens are kept in memory only\n'
                          '• Phishing Detection: Detects spoofed senders, BEC, and malicious links\n'
                          '• Immediate Revocation: You can disconnect anytime with 1 tap',
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 11,
                            height: 1.4,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Option A: Real Google OAuth2 Access Token (Primary)
                  const Text(
                    'Connect Real Gmail Account (OAuth2 Read-Only):',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 8),

                  TextField(
                    controller: tokenCtrl,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 12,
                    ),
                    decoration: InputDecoration(
                      labelText: 'Google OAuth Access Token (Bearer)',
                      labelStyle: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                      ),
                      hintText: 'Paste OAuth2 access token with gmail.readonly',
                      hintStyle: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                      ),
                      filled: true,
                      fillColor: AppColors.surfaceLight,
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide:
                            const BorderSide(color: AppColors.cardBorder),
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),

                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.primary,
                      foregroundColor: AppColors.background,
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    onPressed: connectingToken
                        ? null
                        : () async {
                            final raw = tokenCtrl.text.trim();
                            if (raw.isEmpty) {
                              ScaffoldMessenger.of(sheetCtx).showSnackBar(
                                const SnackBar(
                                  content: Text(
                                    'Paste a valid Google OAuth2 access token with gmail.readonly scope.',
                                  ),
                                  backgroundColor: AppColors.warning,
                                ),
                              );
                              return;
                            }
                            setSheetState(() => connectingToken = true);
                            final success = await _gmail.connectWithAccessToken(
                              accessToken: raw,
                            );
                            setSheetState(() => connectingToken = false);
                            if (sheetCtx.mounted) Navigator.pop(sheetCtx);

                            if (mounted) {
                              if (success) {
                                messenger.showSnackBar(
                                  SnackBar(
                                    content: Text(
                                      'Connected to Gmail: ${_gmail.connectedEmail}',
                                    ),
                                    backgroundColor: AppColors.safe,
                                  ),
                                );
                              } else {
                                messenger.showSnackBar(
                                  SnackBar(
                                    content: Text(
                                      _gmail.lastError ??
                                          'OAuth Authorization Failed.',
                                    ),
                                    backgroundColor: AppColors.danger,
                                  ),
                                );
                              }
                            }
                          },
                    icon: connectingToken
                        ? const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: AppColors.background,
                            ),
                          )
                        : const Icon(Icons.verified_user_rounded, size: 18),
                    label: Text(
                      connectingToken
                          ? 'Authorizing with Gmail API...'
                          : 'Connect Real Gmail via OAuth Token',
                      style: const TextStyle(fontWeight: FontWeight.w700),
                    ),
                  ),
                  const SizedBox(height: 12),

                  // Option B: Secondary Offline Test Feed (Clearly Marked Simulated)
                  const Center(
                    child: Text(
                      '— OR DEVELOPER OFFLINE SANDBOX —',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.5,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),

                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppColors.cardBorder),
                      padding: const EdgeInsets.symmetric(vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    onPressed: () async {
                      Navigator.pop(sheetCtx);
                      await _gmail.connectSimulatedInbox(autoScan: true);
                      if (mounted) {
                        messenger.showSnackBar(
                          const SnackBar(
                            content: Text(
                              'Loaded simulated sample emails (not real Gmail inbox data).',
                            ),
                            backgroundColor: AppColors.warning,
                          ),
                        );
                      }
                    },
                    icon: const Icon(Icons.science_outlined, size: 16),
                    label: const Text(
                      'Load Simulated Sample Emails (Test Only)',
                      style: TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  void _showGmailMessageDetails(GmailMessageItem item) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppColors.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        final scan = item.scanResult;
        final color = scan != null
            ? _getClassificationColor(scan.classification)
            : AppColors.primary;
        final badgeType = scan != null
            ? _getBadgeType(scan.classification)
            : BadgeType.info;

        return DraggableScrollableSheet(
          initialChildSize: 0.85,
          maxChildSize: 0.95,
          minChildSize: 0.5,
          expand: false,
          builder: (context, scrollCtrl) {
            return Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
              child: ListView(
                controller: scrollCtrl,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'Gmail Threat Analysis',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 17,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close_rounded,
                            color: AppColors.textMuted),
                        onPressed: () => Navigator.pop(ctx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),

                  // Header Info
                  CyberShieldCard(
                    padding: const EdgeInsets.all(14),
                    borderColor: color.withValues(alpha: 0.4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Expanded(
                              child: Text(
                                item.subject,
                                style: const TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 14,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                            if (scan != null)
                              CyberBadge(
                                label: scan.classification.toUpperCase(),
                                type: badgeType,
                              ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        Text(
                          'From: ${item.sender}',
                          style: const TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 12,
                          ),
                        ),
                        Text(
                          'Date: ${item.date}',
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                          ),
                        ),
                        if (scan != null) ...[
                          const SizedBox(height: 12),
                          Row(
                            children: [
                              Text(
                                'Risk Score: ${scan.riskScore}/100',
                                style: TextStyle(
                                  color: color,
                                  fontWeight: FontWeight.w800,
                                  fontSize: 13,
                                ),
                              ),
                              const Spacer(),
                              Text(
                                'Threats: ${scan.threatCategories.length} | URLs: ${item.extractedUrls.length}',
                                style: const TextStyle(
                                  color: AppColors.textMuted,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ],
                    ),
                  ),
                  const SizedBox(height: 14),

                  // Scan Result Details if scanned
                  if (scan != null) ...[
                    if (scan.explanation.isNotEmpty) ...[
                      const Text(
                        'Security Assessment',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        scan.explanation,
                        style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 12,
                          height: 1.4,
                        ),
                      ),
                      const SizedBox(height: 12),
                    ],

                    if (scan.findingExplanations.isNotEmpty) ...[
                      const Text(
                        'Phishing & Spoofing Indicators',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      ...scan.findingExplanations.map((f) {
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 6),
                          child: CyberShieldCard(
                            padding: const EdgeInsets.all(10),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  f.title,
                                  style: const TextStyle(
                                    color: AppColors.danger,
                                    fontSize: 12,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  f.explanation,
                                  style: const TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      }),
                      const SizedBox(height: 12),
                    ],

                    if (item.extractedUrls.isNotEmpty) ...[
                      const Text(
                        'Extracted Links',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      ...item.extractedUrls.map((url) {
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 4),
                          child: Row(
                            children: [
                              const Icon(Icons.link_rounded,
                                  color: AppColors.primary, size: 16),
                              const SizedBox(width: 6),
                              Expanded(
                                child: Text(
                                  url,
                                  style: const TextStyle(
                                    color: AppColors.primary,
                                    fontSize: 11,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                        );
                      }),
                      const SizedBox(height: 12),
                    ],

                    // Actionable Recommendations
                    if (scan.recommendations.isNotEmpty) ...[
                      const Text(
                        'Protective Recommendations',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      ...scan.recommendations.map((rec) {
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 4),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text('• ',
                                  style: TextStyle(
                                      color: AppColors.primary, fontSize: 13)),
                              Expanded(
                                child: Text(
                                  rec,
                                  style: const TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 12,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        );
                      }),
                      const SizedBox(height: 16),
                    ],

                    // Consult AI Security Assistant
                    SizedBox(
                      height: 44,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.surfaceLight,
                          foregroundColor: AppColors.primary,
                          side: const BorderSide(color: AppColors.primary),
                        ),
                        onPressed: () {
                          Navigator.pop(ctx);
                          Navigator.pushNamed(
                            context,
                            AppRouter.aiAssistant,
                            arguments: {
                              'scan_type': 'EMAIL',
                              'target': item.subject,
                              'risk_score': scan.riskScore,
                              'classification': scan.classification,
                              'findings': scan.findings,
                              'threat_categories': scan.threatCategories,
                              'details': {
                                'sender': item.sender,
                                'subject': item.subject,
                                'url_count': item.extractedUrls.length,
                              },
                            },
                          );
                        },
                        icon: const Icon(Icons.bolt_rounded, size: 18),
                        label: const Text(
                          'Consult CYBOR About This Email',
                          style: TextStyle(fontWeight: FontWeight.w700),
                        ),
                      ),
                    ),
                  ] else ...[
                    // Not scanned yet
                    SizedBox(
                      height: 44,
                      child: ElevatedButton.icon(
                        onPressed: () async {
                          Navigator.pop(ctx);
                          await _gmail.scanMessage(item);
                        },
                        icon: const Icon(Icons.search_rounded, size: 18),
                        label: const Text('Scan This Email Now'),
                      ),
                    ),
                  ],
                ],
              ),
            );
          },
        );
      },
    );
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
        title: const Text('Email Threat Scanner'),
        leading: Builder(
          builder: (context) => IconButton(
            icon: const Icon(Icons.menu_rounded),
            onPressed: () => Scaffold.of(context).openDrawer(),
          ),
        ),
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.emailScanner),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildModeSwitcher(),
              const SizedBox(height: 16),
              if (_selectedMode == 0) ...[
                _buildPresetsSection(),
                const SizedBox(height: 16),
                _buildInputForm(),
                const SizedBox(height: 16),
                if (_isLoading)
                  const CyberLoadingState(
                    title: 'Analyzing Email Phishing Patterns...',
                    subtitle:
                        'Checking sender spoofing, urgency manipulation, and embedded links',
                  ),
                if (_errorMessage != null)
                  CyberErrorState(
                      message: _errorMessage!, onRetry: _analyzeEmail),
                if (_scanResult != null && !_isLoading)
                  _buildResultsSection(_scanResult!),
              ] else ...[
                _buildGmailSection(),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildModeSwitcher() {
    final themeCtrl = ThemeController.instance;

    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.cardBorder),
      ),
      child: Row(
        children: [
          Expanded(
            child: InkWell(
              onTap: () => setState(() => _selectedMode = 0),
              borderRadius: BorderRadius.circular(8),
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 10),
                decoration: BoxDecoration(
                  color: _selectedMode == 0
                      ? themeCtrl.primaryColor.withValues(alpha: 0.15)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(8),
                  border: _selectedMode == 0
                      ? Border.all(color: themeCtrl.primaryColor)
                      : null,
                ),
                child: Center(
                  child: Text(
                    'Manual Phishing Audit',
                    style: TextStyle(
                      color: _selectedMode == 0
                          ? themeCtrl.primaryColor
                          : AppColors.textMuted,
                      fontWeight: _selectedMode == 0
                          ? FontWeight.w800
                          : FontWeight.w500,
                      fontSize: 12,
                    ),
                  ),
                ),
              ),
            ),
          ),
          Expanded(
            child: InkWell(
              onTap: () => setState(() => _selectedMode = 1),
              borderRadius: BorderRadius.circular(8),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 10),
                decoration: BoxDecoration(
                  color: _selectedMode == 1
                      ? themeCtrl.primaryColor.withValues(alpha: 0.15)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(8),
                  border: _selectedMode == 1
                      ? Border.all(color: themeCtrl.primaryColor)
                      : null,
                ),
                child: Center(
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.mark_email_read_rounded,
                        size: 14,
                        color: _selectedMode == 1
                            ? themeCtrl.primaryColor
                            : AppColors.textMuted,
                      ),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          'Gmail Inbox',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: _selectedMode == 1
                                ? themeCtrl.primaryColor
                                : AppColors.textMuted,
                            fontWeight: _selectedMode == 1
                                ? FontWeight.w800
                                : FontWeight.w500,
                            fontSize: 12,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Gmail Inbox Inspector UI
  // -------------------------------------------------------------------------

  Widget _buildGmailSection() {
    final status = _gmail.status;
    final isConn = _gmail.isConnected;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Connection Status Banner
        CyberShieldCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    isConn
                        ? Icons.check_circle_rounded
                        : Icons.cloud_off_rounded,
                    color: isConn ? AppColors.safe : AppColors.textMuted,
                    size: 20,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          isConn
                              ? 'Connected: ${_gmail.connectedEmail}'
                              : 'Gmail Integration Disconnected',
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontWeight: FontWeight.w700,
                            fontSize: 13,
                          ),
                        ),
                        Text(
                          isConn
                              ? 'Read-only access granted via Google OAuth'
                              : 'Requires explicit user authorization before reading messages',
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (isConn)
                    TextButton(
                      style: TextButton.styleFrom(
                        foregroundColor: AppColors.danger,
                        padding: const EdgeInsets.symmetric(horizontal: 8),
                      ),
                      onPressed: () async {
                        await _gmail.disconnect();
                        if (mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Gmail account disconnected.'),
                              backgroundColor: AppColors.surface,
                            ),
                          );
                        }
                      },
                      child: const Text('Disconnect',
                          style: TextStyle(fontSize: 11)),
                    ),
                ],
              ),
              if (_gmail.lastError != null) ...[
                const SizedBox(height: 10),
                Text(
                  _gmail.lastError!,
                  style:
                      const TextStyle(color: AppColors.danger, fontSize: 11),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        if (!isConn) ...[
          // Connect Button & Security Notice
          CyberShieldCard(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                const Icon(
                  Icons.shield_outlined,
                  size: 40,
                  color: AppColors.primary,
                ),
                const SizedBox(height: 12),
                const Text(
                  'Authorize Real-Time Email Threat Audit',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 6),
                const Text(
                  'Inspect your recent Gmail messages for deceptive spoofing, BEC wire lures, and dangerous phishing links. CyberShield uses read-only OAuth tokens and never stores passwords.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                    height: 1.4,
                  ),
                ),
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  height: 46,
                  child: ElevatedButton.icon(
                    onPressed: status == GmailConnectionStatus.authorizing
                        ? null
                        : _showGmailConsentDialog,
                    icon: status == GmailConnectionStatus.authorizing
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: AppColors.background,
                            ),
                          )
                        : const Icon(Icons.security_rounded),
                    label: Text(
                      status == GmailConnectionStatus.authorizing
                          ? 'Authorizing Gmail Access...'
                          : 'Connect Gmail Account for Threat Scan',
                      style: const TextStyle(fontWeight: FontWeight.w700),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ] else ...[
          if (_gmail.isSandbox) ...[
            Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.accent.withValues(alpha: 0.6)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.science_rounded, color: AppColors.accent, size: 20),
                  SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'DEMO SANDBOX INBOX (OFFLINE EXAMINER FEED)',
                          style: TextStyle(
                            color: AppColors.accent,
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.5,
                          ),
                        ),
                        SizedBox(height: 2),
                        Text(
                          'Using synthetic threat vectors (PayPal lure, M365 credential harvesting, BEC wire request) for safe laboratory & viva demonstration.',
                          style: TextStyle(color: AppColors.textSecondary, fontSize: 10),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
          // Action Bar for connected Gmail
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: AppColors.background,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                  onPressed: _gmail.isLoadingMessages
                      ? null
                      : () => _gmail.scanAllMessages(),
                  icon: const Icon(Icons.radar_rounded, size: 18),
                  label: const Text(
                    'Scan All Inbox Emails',
                    style: TextStyle(fontWeight: FontWeight.w700, fontSize: 12),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              IconButton.filledTonal(
                icon: const Icon(Icons.refresh_rounded, size: 18),
                onPressed: _gmail.isLoadingMessages
                    ? null
                    : () => _gmail.fetchRecentInbox(),
                tooltip: 'Refresh Inbox Messages',
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Message List
          if (_gmail.isLoadingMessages)
            const CyberLoadingState(
              title: 'Ingesting Gmail Telemetry...',
              subtitle: 'Extracting headers, body snippets, and URLs via Gmail API',
            )
          else if (_gmail.messages.isEmpty)
            CyberShieldCard(
              padding: const EdgeInsets.all(24),
              child: Column(
                children: [
                  const Icon(Icons.inbox_rounded,
                      size: 36, color: AppColors.textMuted),
                  const SizedBox(height: 8),
                  const Text(
                    'No messages loaded yet.',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 10),
                  ElevatedButton(
                    onPressed: () => _gmail.fetchRecentInbox(),
                    child: const Text('Fetch Recent Messages'),
                  ),
                ],
              ),
            )
          else ...[
            Text(
              'Recent Inbox Messages (${_gmail.messages.length})',
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 8),
            ..._gmail.messages.map((item) => _buildGmailMessageCard(item)),
          ],
        ],
      ],
    );
  }

  Widget _buildGmailMessageCard(GmailMessageItem item) {
    final scan = item.scanResult;
    final color = scan != null
        ? _getClassificationColor(scan.classification)
        : AppColors.cardBorder;
    final badgeType =
        scan != null ? _getBadgeType(scan.classification) : BadgeType.info;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        onTap: () => _showGmailMessageDetails(item),
        borderRadius: BorderRadius.circular(12),
        child: CyberShieldCard(
          padding: const EdgeInsets.all(12),
          borderColor: scan != null
              ? color.withValues(alpha: 0.5)
              : AppColors.cardBorder,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  CircleAvatar(
                    radius: 16,
                    backgroundColor: scan != null
                        ? color.withValues(alpha: 0.15)
                        : AppColors.surfaceLight,
                    child: Icon(
                      Icons.mail_outline_rounded,
                      size: 16,
                      color: scan != null ? color : AppColors.textMuted,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          item.subject,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          item.sender,
                          style: const TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  if (scan != null) ...[
                    CyberBadge(
                      label: scan.classification.toUpperCase(),
                      type: badgeType,
                      fontSize: 9,
                    ),
                  ] else if (item.isScanning) ...[
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: AppColors.primary,
                      ),
                    ),
                  ] else ...[
                    TextButton(
                      style: TextButton.styleFrom(
                        padding: const EdgeInsets.symmetric(horizontal: 8),
                        minimumSize: const Size(40, 28),
                      ),
                      onPressed: () => _gmail.scanMessage(item),
                      child: const Text('Scan', style: TextStyle(fontSize: 11)),
                    ),
                  ],
                ],
              ),
              const SizedBox(height: 8),
              Text(
                item.snippet,
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 11,
                  height: 1.3,
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 6),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    item.date,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 10,
                    ),
                  ),
                  if (scan != null)
                    Text(
                      'Score: ${scan.riskScore}/100',
                      style: TextStyle(
                        color: color,
                        fontWeight: FontWeight.w800,
                        fontSize: 11,
                      ),
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Manual Phishing Audit UI
  // -------------------------------------------------------------------------

  Widget _buildPresetsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Quick Test Presets',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 13,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: _presets.map((preset) {
            return ActionChip(
              avatar: CircleAvatar(
                radius: 5,
                backgroundColor: preset.color,
              ),
              label: Text(
                preset.label,
                style:
                    const TextStyle(fontSize: 11, color: AppColors.textPrimary),
              ),
              backgroundColor: AppColors.surface,
              side: const BorderSide(color: AppColors.cardBorder),
              onPressed: () => _applyPreset(preset),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildInputForm() {
    return CyberShieldCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _senderController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              labelText: 'Sender Address / Display Name (Optional)',
              labelStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              hintText: 'e.g. PayPal Security <support@alert.com>',
              hintStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              prefixIcon: const Icon(Icons.person_outline_rounded,
                  color: AppColors.primary, size: 20),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _subjectController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              labelText: 'Subject Line (Optional)',
              labelStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              hintText: 'e.g. Urgent: Account Security Verification Required',
              hintStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              prefixIcon: const Icon(Icons.subject_rounded,
                  color: AppColors.primary, size: 20),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _bodyController,
            maxLines: 6,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
            decoration: InputDecoration(
              labelText: 'Email Body Content *',
              labelStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              hintText: 'Paste complete email message body here...',
              hintStyle:
                  const TextStyle(color: AppColors.textMuted, fontSize: 12),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.cardBorder),
              ),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: _isLoading ? null : _analyzeEmail,
            icon: const Icon(Icons.search_rounded),
            label: const Text('Scan Email for Phishing'),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.primary,
              foregroundColor: AppColors.background,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResultsSection(EmailScanResult result) {
    final color = _getClassificationColor(result.classification);
    final badgeType = _getBadgeType(result.classification);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(color: AppColors.cardBorder, height: 32),
        const Text(
          'Email Assessment Results',
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
                          result.subject.isNotEmpty
                              ? result.subject
                              : 'Email Message',
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.w800,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        if (result.sender.isNotEmpty) ...[
                          const SizedBox(height: 2),
                          Text(
                            result.sender,
                            style: const TextStyle(
                                color: AppColors.textMuted, fontSize: 11),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
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
                            style: TextStyle(
                                color: AppColors.textMuted, fontSize: 10),
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
                        _buildStatLine('Threat Categories',
                            '${result.threatCategories.length}'),
                        const SizedBox(height: 6),
                        _buildStatLine(
                            'Embedded URLs', '${result.embeddedUrls.length}'),
                        const SizedBox(height: 6),
                        _buildStatLine('Flagged Indicators',
                            '${result.detectedIndicators.length}',
                            color: color),
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
                    height: 1.4),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 2. Detected Indicators Breakdown
        if (result.findingExplanations.isNotEmpty) ...[
          const Text(
            'Detected Phishing Indicators',
            style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w700),
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
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
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
                      'Matched text: "${item.indicator}"',
                      style: const TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                          fontStyle: FontStyle.italic),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      item.explanation,
                      style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 11,
                          height: 1.3),
                    ),
                  ],
                ),
              ),
            );
          }),
        ],

        // 3. Embedded URLs
        if (result.embeddedUrls.isNotEmpty) ...[
          const SizedBox(height: 8),
          const Text(
            'Embedded URLs Analyzed',
            style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 8),
          ...result.embeddedUrls.map((url) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: CyberShieldCard(
                padding: const EdgeInsets.all(10),
                child: Row(
                  children: [
                    const Icon(Icons.link_rounded,
                        color: AppColors.primary, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        url,
                        style: const TextStyle(
                            color: AppColors.primary, fontSize: 11),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
            );
          }),
        ],

        // 4. Actionable Security Recommendations
        const SizedBox(height: 8),
        CyberShieldCard(
          borderColor: AppColors.primary.withValues(alpha: 0.25),
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.security_rounded,
                      color: AppColors.primary, size: 18),
                  SizedBox(width: 8),
                  Text(
                    'Recommended Protective Actions',
                    style: TextStyle(
                        color: AppColors.primary,
                        fontSize: 13,
                        fontWeight: FontWeight.w700),
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
                      const Text('• ',
                          style: TextStyle(
                              color: AppColors.primary, fontSize: 14)),
                      Expanded(
                        child: Text(rec,
                            style: const TextStyle(
                                color: AppColors.textPrimary, fontSize: 12)),
                      ),
                    ],
                  ),
                );
              }),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // 5. Consult AI Security Assistant button
        SizedBox(
          height: 46,
          child: ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.surfaceLight,
              foregroundColor: AppColors.primary,
              side: const BorderSide(color: AppColors.primary),
            ),
            onPressed: () {
              Navigator.pushNamed(
                context,
                AppRouter.aiAssistant,
                arguments: {
                  'scan_type': 'EMAIL',
                  'target': result.subject.isNotEmpty
                      ? result.subject
                      : (result.sender.isNotEmpty
                          ? result.sender
                          : 'Email Phishing Scan'),
                  'risk_score': result.riskScore,
                  'classification': result.classification,
                  'findings': result.findings,
                  'threat_categories': result.threatCategories,
                  'details': {
                    'sender': result.sender,
                    'subject': result.subject,
                    'url_count': result.embeddedUrls.length,
                  },
                },
              );
            },
            icon: const Icon(Icons.auto_awesome_rounded, size: 18),
            label: const Text(
              'Ask AI Assistant to Explain This Email Scan',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildStatLine(String label, String value, {Color? color}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label,
            style: const TextStyle(
                color: AppColors.textSecondary, fontSize: 11)),
        Text(
          value,
          style: TextStyle(
              color: color ?? AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w700),
        ),
      ],
    );
  }
}
