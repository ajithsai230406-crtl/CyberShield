// CYBOR — Floating AI Security Assistant Widget & Modal Sheet
// Provides immediate access to NVIDIA Nemotron 3.5 Super VL (via OpenRouter) & SecurityExpertEngine
// from any screen across CyberShield.

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/models/chat_message.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/widgets/cyber_markdown_view.dart';

class CyborFloatingWidget extends StatefulWidget {
  final Map<String, dynamic>? initialScanContext;

  const CyborFloatingWidget({
    super.key,
    this.initialScanContext,
  });

  /// Static helper to trigger the CYBOR AI Chat modal from any button or scan result
  static Future<void> openModal(
    BuildContext context, {
    Map<String, dynamic>? scanContext,
  }) {
    return showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => CyborChatModalSheet(scanContext: scanContext),
    );
  }

  @override
  State<CyborFloatingWidget> createState() => _CyborFloatingWidgetState();
}

class _CyborFloatingWidgetState extends State<CyborFloatingWidget>
    with SingleTickerProviderStateMixin {
  late AnimationController _animController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _pulseAnimation = Tween<double>(begin: 0.95, end: 1.08).animate(
      CurvedAnimation(parent: _animController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _animController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ScaleTransition(
      scale: _pulseAnimation,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(28),
          onTap: () => CyborFloatingWidget.openModal(
            context,
            scanContext: widget.initialScanContext,
          ),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  AppColors.primary,
                  AppColors.primary.withValues(alpha: 0.8),
                  const Color(0xFF00B0FF),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(28),
              boxShadow: [
                BoxShadow(
                  color: AppColors.primary.withValues(alpha: 0.4),
                  blurRadius: 12,
                  spreadRadius: 2,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.smart_toy_rounded, color: Colors.black, size: 20),
                SizedBox(width: 8),
                Text(
                  'CYBOR AI',
                  style: TextStyle(
                    color: Colors.black,
                    fontSize: 12,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 0.8,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class CyborChatModalSheet extends StatefulWidget {
  final Map<String, dynamic>? scanContext;

  const CyborChatModalSheet({
    super.key,
    this.scanContext,
  });

  @override
  State<CyborChatModalSheet> createState() => _CyborChatModalSheetState();
}

class _CyborChatModalSheetState extends State<CyborChatModalSheet> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final List<ChatMessage> _messages = [];

  bool _isThinking = false;
  String? _sessionId;
  Map<String, dynamic>? _activeScanContext;

  static const List<String> _quickPrompts = [
    'Dissect this KYC scam SMS',
    'Why is an APK overlay dangerous?',
    'Explain dangerous Android permissions',
    'How does 2FA protect my accounts?',
  ];

  @override
  void initState() {
    super.initState();
    _activeScanContext = widget.scanContext;
    _sessionId = 'sess-modal-${DateTime.now().millisecondsSinceEpoch}';

    // Inject greeting immediately so sheet is instantly usable without delay
    _messages.add(
      ChatMessage(
        id: 'msg-welcome',
        sessionId: _sessionId ?? 'default',
        role: 'assistant',
        content:
            "👋 **Greetings! I am CYBOR — your Cyber Intelligence Assistant.**\n\n"
            "I provide real-time explanations for threat scores, suspicious messages, malicious URLs, APK permissions, and cryptographic indicators.\n\n"
            "Ask me anything or tap a prompt below to begin.",
        provider: 'openrouter',
        isAiGenerated: true,
        createdAt: DateTime.now().toUtc().toIso8601String(),
      ),
    );

    // If initial scan telemetry was passed, trigger targeted threat explanation
    if (_activeScanContext != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _requestScanExplanation(_activeScanContext!);
      });
    }
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _requestScanExplanation(Map<String, dynamic> telemetry) async {
    final target = telemetry['target'] ??
        telemetry['filename'] ??
        telemetry['scanned_url'] ??
        'Inspected Item';
    final scanType = telemetry['scan_type'] ?? 'SCAN';
    final riskScore = telemetry['risk_score'] ?? 0;
    final classification = telemetry['classification'] ?? 'Safe';

    final prompt = 'Explain this $scanType finding for $target (Score: $riskScore/100, $classification)';
    await _sendMessage(prompt, contextOverride: telemetry);
  }

  Future<void> _sendMessage(String text, {Map<String, dynamic>? contextOverride}) async {
    final trimmed = text.trim();
    if (trimmed.isEmpty || _isThinking) return;

    _inputController.clear();
    final userMsgId = 'msg-user-${DateTime.now().millisecondsSinceEpoch}';
    final userMsg = ChatMessage(
      id: userMsgId,
      sessionId: _sessionId ?? 'default',
      role: 'user',
      content: trimmed,
      createdAt: DateTime.now().toUtc().toIso8601String(),
      scanContext: contextOverride ?? _activeScanContext,
    );

    setState(() {
      _messages.add(userMsg);
      _isThinking = true;
    });
    _scrollToBottom();

    // Mirror to Firestore history if authenticated
    if (FirestoreHistoryService.instance.isAuthenticated) {
      FirestoreHistoryService.instance.recordAssistantChat(
        messageId: userMsgId,
        role: 'user',
        content: trimmed,
        sessionId: _sessionId,
      );
    }

    try {
      final reply = await ApiService.sendAssistantMessage(
        message: trimmed,
        sessionId: _sessionId,
        scanContext: contextOverride ?? _activeScanContext,
      );

      if (mounted) {
        setState(() {
          _isThinking = false;
          if (reply != null) {
            _messages.add(reply);
          } else {
            _messages.add(
              ChatMessage(
                id: 'msg-err-${DateTime.now().millisecondsSinceEpoch}',
                sessionId: _sessionId ?? 'default',
                role: 'assistant',
                content:
                    "⚠️ **Unable to reach CyberShield Assistant**\n\n"
                    "The backend returned an empty response. "
                    "Verify in **Settings** that your API endpoint matches your host (e.g. PC LAN IP over Wi-Fi, or 127.0.0.1:8000 via ADB reverse).",
                provider: 'cybershield_fallback',
                isAiGenerated: true,
                createdAt: DateTime.now().toUtc().toIso8601String(),
              ),
            );
          }
        });
        _scrollToBottom();
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isThinking = false;
          final errMsg = e.toString().replaceFirst('Exception: ', '');
          _messages.add(
            ChatMessage(
              id: 'msg-err-${DateTime.now().millisecondsSinceEpoch}',
              sessionId: _sessionId ?? 'default',
              role: 'assistant',
              content: "⚠️ **Assistant Error:** $errMsg",
              provider: 'error',
              isAiGenerated: true,
              createdAt: DateTime.now().toUtc().toIso8601String(),
            ),
          );
        });
        _scrollToBottom();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final bottomInset = MediaQuery.of(context).viewInsets.bottom;
    final screenHeight = MediaQuery.of(context).size.height;

    return AnimatedPadding(
      padding: EdgeInsets.only(bottom: bottomInset),
      duration: const Duration(milliseconds: 180),
      curve: Curves.easeOut,
      child: Container(
        height: screenHeight * 0.85,
        decoration: const BoxDecoration(
          color: AppColors.background,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
          border: Border(
            top: BorderSide(color: AppColors.cardBorder, width: 1.5),
            left: BorderSide(color: AppColors.cardBorder, width: 1.5),
            right: BorderSide(color: AppColors.cardBorder, width: 1.5),
          ),
        ),
        child: SafeArea(
          top: false,
          child: Column(
            children: [
              // Drag handle
          Center(
            child: Container(
              margin: const EdgeInsets.only(top: 10, bottom: 8),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: AppColors.cardBorder,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),

          // Header
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppColors.primary.withValues(alpha: 0.4)),
                  ),
                  child: const Icon(Icons.smart_toy_rounded, color: AppColors.primary, size: 20),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Text(
                            'CYBOR ASSISTANT',
                            style: TextStyle(
                              color: AppColors.textPrimary,
                              fontWeight: FontWeight.w900,
                              fontSize: 14,
                              letterSpacing: 0.5,
                            ),
                          ),
                          SizedBox(width: 6),
                          Icon(Icons.verified_rounded, color: AppColors.primary, size: 14),
                        ],
                      ),
                      Text(
                        'Powered by NVIDIA Nemotron 3.5 Super VL',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 10,
                        ),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.delete_sweep_rounded, color: AppColors.textMuted, size: 20),
                  tooltip: 'Clear Conversation',
                  onPressed: () {
                    setState(() {
                      _messages.clear();
                      _messages.add(
                        ChatMessage(
                          id: 'msg-welcome-new',
                          sessionId: _sessionId ?? 'default',
                          role: 'assistant',
                          content: "Chat cleared. What threat or question would you like to explore next?",
                          provider: 'openrouter',
                          isAiGenerated: true,
                          createdAt: DateTime.now().toUtc().toIso8601String(),
                        ),
                      );
                    });
                  },
                ),
                IconButton(
                  icon: const Icon(Icons.close_rounded, color: AppColors.textSecondary, size: 22),
                  onPressed: () => Navigator.pop(context),
                ),
              ],
            ),
          ),
          const Divider(color: AppColors.cardBorder, height: 1),

          // Scan Context indicator if attached
          if (_activeScanContext != null) _buildScanContextChip(),

          // Chat messages list
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              itemCount: _messages.length + (_isThinking ? 1 : 0),
              itemBuilder: (ctx, idx) {
                if (idx == _messages.length && _isThinking) {
                  return _buildThinkingBubble();
                }
                return _buildMessageBubble(_messages[idx]);
              },
            ),
          ),

          // Suggested Prompts
          _buildQuickPromptsBar(),

          // Input Bar
          _buildInputBar(),
        ],
      ),
    ),
    ),
    );
  }

  Widget _buildScanContextChip() {
    final ctx = _activeScanContext!;
    final scanType = ctx['scan_type']?.toString().toUpperCase() ?? 'SCAN';
    final target = ctx['target'] ?? ctx['filename'] ?? ctx['scanned_url'] ?? 'Item';
    final riskScore = ctx['risk_score'] ?? 0;
    final isDanger = riskScore >= 50;

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isDanger ? AppColors.danger.withValues(alpha: 0.5) : AppColors.safe.withValues(alpha: 0.5),
        ),
      ),
      child: Row(
        children: [
          Icon(
            isDanger ? Icons.warning_amber_rounded : Icons.shield_rounded,
            color: isDanger ? AppColors.danger : AppColors.safe,
            size: 16,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              '$scanType: $target (Score: $riskScore/100)',
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.close_rounded, size: 14, color: AppColors.textMuted),
            onPressed: () {
              setState(() {
                _activeScanContext = null;
              });
            },
          ),
        ],
      ),
    );
  }

  Widget _buildMessageBubble(ChatMessage msg) {
    final isUser = msg.role == 'user';
    final provider = msg.provider;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Column(
        crossAxisAlignment: isUser ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (!isUser) ...[
                const Icon(Icons.smart_toy_rounded, size: 12, color: AppColors.primary),
                const SizedBox(width: 4),
                Text(
                  provider == 'openrouter'
                      ? 'CYBOR • Nemotron 3.5 VL'
                      : (provider == 'error' || provider == 'cybershield_fallback'
                          ? 'CYBOR • Status'
                          : 'CYBOR • Security Engine'),
                  style: const TextStyle(
                    color: AppColors.primary,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ] else ...[
                const Text(
                  'YOU',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ],
          ),
          const SizedBox(height: 4),
          Container(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.82,
            ),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: isUser
                  ? AppColors.primary.withValues(alpha: 0.15)
                  : AppColors.surface,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(14),
                topRight: const Radius.circular(14),
                bottomLeft: isUser ? const Radius.circular(14) : const Radius.circular(2),
                bottomRight: isUser ? const Radius.circular(2) : const Radius.circular(14),
              ),
              border: Border.all(
                color: isUser
                    ? AppColors.primary.withValues(alpha: 0.4)
                    : AppColors.cardBorder,
              ),
            ),
            child: isUser
                ? SelectableText(
                    msg.content,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 13,
                      height: 1.4,
                    ),
                  )
                : CyberMarkdownView(
                    data: msg.content,
                    baseStyle: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 13,
                      height: 1.45,
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildThinkingBubble() {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: AppColors.cardBorder),
            ),
            child: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                ),
                SizedBox(width: 10),
                Text(
                  'CYBOR analyzing security posture...',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                    fontStyle: FontStyle.italic,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickPromptsBar() {
    return Container(
      height: 38,
      margin: const EdgeInsets.symmetric(vertical: 6),
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        scrollDirection: Axis.horizontal,
        itemCount: _quickPrompts.length,
        separatorBuilder: (context, index) => const SizedBox(width: 8),
        itemBuilder: (ctx, idx) {
          final prompt = _quickPrompts[idx];
          return ActionChip(
            backgroundColor: AppColors.surfaceLight,
            side: const BorderSide(color: AppColors.cardBorder),
            padding: const EdgeInsets.symmetric(horizontal: 8),
            label: Text(
              prompt,
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 11),
            ),
            onPressed: () => _sendMessage(prompt),
          );
        },
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.cardBorder)),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _inputController,
              textInputAction: TextInputAction.send,
              onSubmitted: (txt) => _sendMessage(txt),
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
              decoration: InputDecoration(
                hintText: 'Ask CYBOR cybersecurity question...',
                hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                filled: true,
                fillColor: AppColors.surfaceSubtle,
                contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: const BorderSide(color: AppColors.cardBorder),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: const BorderSide(color: AppColors.cardBorder),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(20),
                  borderSide: const BorderSide(color: AppColors.primary),
                ),
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            style: IconButton.styleFrom(
              backgroundColor: AppColors.primary,
              foregroundColor: Colors.black,
            ),
            icon: _isThinking
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                  )
                : const Icon(Icons.send_rounded, size: 18),
            onPressed: _isThinking ? null : () => _sendMessage(_inputController.text),
          ),
        ],
      ),
    );
  }
}
