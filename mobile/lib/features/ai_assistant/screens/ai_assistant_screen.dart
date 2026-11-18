// CYBOR — Cyber Intelligence & Threat Awareness Assistant Chat Screen

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';
import 'package:cybershield/core/models/chat_message.dart';
import 'package:cybershield/core/widgets/cyber_markdown_view.dart';

class AiAssistantScreen extends StatefulWidget {
  final Map<String, dynamic>? initialScanContext;

  const AiAssistantScreen({
    super.key,
    this.initialScanContext,
  });

  @override
  State<AiAssistantScreen> createState() => _AiAssistantScreenState();
}

class _AiAssistantScreenState extends State<AiAssistantScreen> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  final List<ChatMessage> _messages = [];
  bool _isLoadingHistory = true;
  bool _isThinking = false;
  String? _sessionId;
  Map<String, dynamic>? _activeScanContext;
  String _selectedLanguage = 'en';

  static const List<String> _suggestedPrompts = [
    'Dissect this suspicious bank KYC SMS',
    'What makes a URL high risk?',
    'Explain dangerous Android permission combinations',
    'What is a disguised PE executable?',
    'How does 2FA protect my banking accounts?',
    'What is a Zip Slip path traversal attack?',
  ];

  @override
  void initState() {
    super.initState();
    _activeScanContext = widget.initialScanContext;
    _sessionId = 'sess-${DateTime.now().millisecondsSinceEpoch}';
    _isLoadingHistory = false;
    _injectWelcomeMessage();
    _loadHistoryInBackground();
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadHistoryInBackground() async {
    // Only attempt history fetch if user has active session
    final token = await ApiService.getIdToken();
    if (token == null) {
      if (_activeScanContext != null && mounted) {
        _requestScanExplanation(_activeScanContext!);
      }
      return;
    }

    try {
      final history = await ApiService.getAssistantHistory(limit: 30);
      if (mounted && history.isNotEmpty) {
        setState(() {
          _messages.clear();
          _messages.addAll(history);
        });
        if (_activeScanContext != null) {
          _requestScanExplanation(_activeScanContext!);
        }
        _scrollToBottom();
      }
    } catch (_) {
      // Keep welcome message intact on error
    }
  }

  void _injectWelcomeMessage() {
    _messages.add(
      ChatMessage(
        id: 'msg-welcome',
        sessionId: _sessionId ?? 'default',
        role: 'assistant',
        content:
            "👋 **Greetings! I am CYBOR — your Cyber Intelligence & Threat Awareness Assistant.**\n\n"
            "I provide real-time forensic explanations for threat scores, smishing texts, malicious URLs, APK dangerous permission combinations, and cryptographic hash indicators.\n\n"
            "Ask me any cybersecurity question, paste a suspicious message to dissect, or tap one of the suggested prompts below to begin.",
        provider: 'cybershield_ai',
        isAiGenerated: true,
        createdAt: DateTime.now().toUtc().toIso8601String(),
      ),
    );
  }

  Future<void> _requestScanExplanation(Map<String, dynamic> scanTelemetry) async {
    final target = scanTelemetry['target'] ??
        scanTelemetry['filename'] ??
        scanTelemetry['scanned_url'] ??
        'Inspected Item';
    final scanType = scanTelemetry['scan_type'] ?? 'SCAN';
    final riskScore = scanTelemetry['risk_score'] ?? 0;
    final classification = scanTelemetry['classification'] ?? 'Safe';

    final prompt = 'Explain this $scanType inspection for $target ($riskScore/100 - $classification)';
    await _sendMessage(prompt, contextOverride: scanTelemetry);
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

    // Mirror user message to Firestore
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
        language: _selectedLanguage,
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
                    "The backend engine did not return a response in time. "
                    "Please check **Settings -> API Endpoint** to ensure the URL matches your server (e.g. PC LAN IP over Wi-Fi, or `127.0.0.1:8000` via ADB reverse).",
                provider: 'cybershield_fallback',
                isAiGenerated: true,
                createdAt: DateTime.now().toUtc().toIso8601String(),
              ),
            );
          }
        });

        // Mirror assistant reply to Firestore
        if (reply != null && FirestoreHistoryService.instance.isAuthenticated) {
          FirestoreHistoryService.instance.recordAssistantChat(
            messageId: reply.id,
            role: 'assistant',
            content: reply.content,
            sessionId: _sessionId,
            metadata: reply.metadata,
          );
        }

        _scrollToBottom();
      }
    } catch (e) {
      if (mounted) {
        final errMsg = e.toString().replaceFirst('Exception: ', '');
        setState(() {
          _isThinking = false;
          _messages.add(
            ChatMessage(
              id: 'msg-err-${DateTime.now().millisecondsSinceEpoch}',
              sessionId: _sessionId ?? 'default',
              role: 'assistant',
              content: "⚠️ **Assistant Error**\n\n$errMsg",
              provider: 'error',
              isAiGenerated: true,
              createdAt: DateTime.now().toUtc().toIso8601String(),
            ),
          );
        });
        _scrollToBottom();
      }
    } finally {
      if (mounted && _isThinking) {
        setState(() {
          _isThinking = false;
        });
      }
    }
  }

  Future<void> _clearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text('Clear Chat History?'),
        content: const Text(
          'This will permanently delete all conversation records for your account.',
          style: TextStyle(color: AppColors.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.danger),
            child: const Text('Clear All'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await ApiService.clearAssistantHistory();
      if (mounted) {
        setState(() {
          _messages.clear();
          _injectWelcomeMessage();
        });
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Chat history cleared.'),
            backgroundColor: AppColors.safe,
          ),
        );
      }
    }
  }

  void _showAnalyzeMessageModal() {
    final textController = TextEditingController();
    String detectedCategory = 'SMS / Smishing';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: AppColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setModalState) => Padding(
          padding: EdgeInsets.only(
            left: 20,
            right: 20,
            top: 20,
            bottom: MediaQuery.of(ctx).viewInsets.bottom + 20,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.shield_rounded, color: AppColors.primary, size: 20),
                      SizedBox(width: 8),
                      Text(
                        'Dissect Message with CYBOR',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                  IconButton(
                    icon: const Icon(Icons.close_rounded, color: AppColors.textMuted),
                    onPressed: () => Navigator.pop(ctx),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'Paste any suspicious SMS, notification, email excerpt, or URL to receive a forensic threat assessment from CYBOR.',
                style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  for (final cat in ['SMS / Smishing', 'URL / Phish', 'General Alert']) ...[
                    ChoiceChip(
                      label: Text(cat, style: const TextStyle(fontSize: 11)),
                      selected: detectedCategory == cat,
                      onSelected: (selected) {
                        if (selected) {
                          setModalState(() {
                            detectedCategory = cat;
                          });
                        }
                      },
                      selectedColor: AppColors.primary.withValues(alpha: 0.25),
                      backgroundColor: AppColors.surfaceLight,
                    ),
                    const SizedBox(width: 6),
                  ],
                ],
              ),
              const SizedBox(height: 12),
              TextField(
                controller: textController,
                maxLines: 4,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                decoration: InputDecoration(
                  hintText: 'Paste suspicious text here (e.g. "Dear customer, your bank account is suspended... click http://...")',
                  hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
                  filled: true,
                  fillColor: AppColors.surfaceLight,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: AppColors.cardBorder),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  icon: const Icon(Icons.bolt_rounded, size: 18),
                  label: const Text('Dissect with CYBOR'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  onPressed: () {
                    final content = textController.text.trim();
                    if (content.isEmpty) return;
                    Navigator.pop(ctx);
                    final query = 'Perform a forensic analysis of this $detectedCategory:\n\n"$content"\n\nIdentify deceptive social engineering, urgency tactics, spoofed identities, and specific risks.';
                    _sendMessage(query);
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(
                  'CYBOR',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, letterSpacing: 0.5),
                ),
                SizedBox(width: 6),
                Icon(Icons.verified_rounded, size: 14, color: AppColors.primary),
              ],
            ),
            Row(
              children: [
                Icon(Icons.circle, size: 7, color: AppColors.safe),
                SizedBox(width: 4),
                Expanded(
                  child: Text(
                    'Cyber Intelligence & Threat Awareness Assistant',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(fontSize: 10, color: AppColors.safe, fontWeight: FontWeight.w500),
                  ),
                ),
              ],
            ),
          ],
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () =>
              Navigator.pushReplacementNamed(context, AppRouter.dashboard),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.document_scanner_rounded, color: AppColors.primary, size: 20),
            tooltip: 'Analyze suspicious text/SMS',
            onPressed: _showAnalyzeMessageModal,
          ),
          // Language selector popup
          PopupMenuButton<String>(
            icon: const Icon(Icons.translate_rounded, color: AppColors.primary, size: 20),
            tooltip: 'Response Language',
            onSelected: (lang) {
              setState(() {
                _selectedLanguage = lang;
              });
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Assistant language set to ${lang.toUpperCase()}'),
                  duration: const Duration(seconds: 1),
                ),
              );
            },
            itemBuilder: (ctx) => [
              const PopupMenuItem(value: 'en', child: Text('English (EN)')),
              const PopupMenuItem(value: 'es', child: Text('Español (ES)')),
              const PopupMenuItem(value: 'fr', child: Text('Français (FR)')),
              const PopupMenuItem(value: 'hi', child: Text('हिन्दी (HI)')),
              const PopupMenuItem(value: 'de', child: Text('Deutsch (DE)')),
            ],
          ),
          IconButton(
            icon: const Icon(Icons.delete_sweep_rounded, color: AppColors.textMuted),
            tooltip: 'Clear Chat History',
            onPressed: _clearHistory,
          ),
          const SizedBox(width: 4),
        ],
      ),
      drawer: const NavDrawer(currentRoute: AppRouter.aiAssistant),
      body: Column(
        children: [
          // Active Scan Context Banner (if any)
          if (_activeScanContext != null) _buildScanContextBanner(),

          // Messages stream
          Expanded(
            child: _isLoadingHistory
                ? const Center(
                    child: CircularProgressIndicator(color: AppColors.primary),
                  )
                : ListView.builder(
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

          // Suggested Questions Chips
          _buildSuggestedPromptsBar(),

          // Input field
          _buildInputBar(),
        ],
      ),
    );
  }

  Widget _buildScanContextBanner() {
    final ctx = _activeScanContext!;
    final scanType = ctx['scan_type']?.toString().toUpperCase() ?? 'SCAN';
    final target = ctx['target'] ?? ctx['filename'] ?? ctx['scanned_url'] ?? 'Item';
    final riskScore = ctx['risk_score'] ?? 0;
    final classification = ctx['classification']?.toString() ?? 'Safe';

    final isDanger = riskScore >= 60;
    final isWarning = !isDanger && riskScore >= 30;
    final badgeColor = isDanger
        ? AppColors.danger
        : (isWarning ? AppColors.warning : AppColors.safe);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        border: const Border(
          bottom: BorderSide(color: AppColors.cardBorder),
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Icon(Icons.radar_rounded, color: badgeColor, size: 16),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      '$scanType Context Attached',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      'Score: $riskScore/100 ($classification)',
                      style: TextStyle(
                        color: badgeColor,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                Text(
                  target.toString(),
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close_rounded, size: 16, color: AppColors.textMuted),
            tooltip: 'Detach scan context',
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
    if (msg.isUser) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 12.0),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.end,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Flexible(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: AppColors.primary,
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(14),
                    topRight: Radius.circular(4),
                    bottomLeft: Radius.circular(14),
                    bottomRight: Radius.circular(14),
                  ),
                ),
                child: Text(
                  msg.content,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 13,
                    height: 1.35,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 8),
            const CircleAvatar(
              radius: 14,
              backgroundColor: AppColors.surfaceLight,
              child: Icon(Icons.person_rounded, size: 16, color: AppColors.primary),
            ),
          ],
        ),
      );
    }

    // Assistant reply
    return Padding(
      padding: const EdgeInsets.only(bottom: 14.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.shield_rounded, size: 16, color: AppColors.primary),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: CyberShieldCard(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Row(
                          children: [
                            const Flexible(
                              child: Text(
                                'CYBOR Security AI',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  color: AppColors.primary,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                            const SizedBox(width: 6),
                            Flexible(
                              child: Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                                decoration: BoxDecoration(
                                  color: AppColors.surfaceLight,
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  msg.provider == 'openrouter'
                                      ? 'Nemotron 3.5 VL'
                                      : (msg.provider == 'error' || msg.provider == 'cybershield_fallback'
                                          ? 'Status'
                                          : 'CYBOR Heuristic'),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(color: AppColors.textMuted, fontSize: 9),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          IconButton(
                            icon: const Icon(Icons.copy_rounded, size: 14, color: AppColors.textMuted),
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(),
                            tooltip: 'Copy response',
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: msg.content));
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                  content: Text('CYBOR response copied to clipboard'),
                                  duration: Duration(seconds: 1),
                                ),
                              );
                            },
                          ),
                          const SizedBox(width: 8),
                          Text(
                            _formatMessageTime(msg.createdAt),
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                          ),
                        ],
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  CyberMarkdownView(
                    data: msg.content,
                    baseStyle: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 13,
                      height: 1.45,
                    ),
                  ),
                  if (msg.metadata.containsKey('disclaimer')) ...[
                    const SizedBox(height: 10),
                    const Divider(color: AppColors.cardBorder, height: 1),
                    const SizedBox(height: 6),
                    Text(
                      msg.metadata['disclaimer'].toString(),
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThinkingBubble() {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: AppColors.primary.withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.shield_rounded, size: 16, color: AppColors.primary),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(12),
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
                SizedBox(width: 8),
                Text(
                  'CyberShield analyzing defense telemetry...',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSuggestedPromptsBar() {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 6),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(
          top: BorderSide(color: AppColors.cardBorder),
        ),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Row(
          children: _suggestedPrompts.map((prompt) {
            return Padding(
              padding: const EdgeInsets.only(right: 6.0),
              child: ActionChip(
                label: Text(
                  prompt,
                  style: const TextStyle(fontSize: 11, color: AppColors.textSecondary),
                ),
                backgroundColor: AppColors.surfaceLight,
                side: const BorderSide(color: AppColors.cardBorder),
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                onPressed: () => _sendMessage(prompt),
              ),
            );
          }).toList(),
        ),
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(
          top: BorderSide(color: AppColors.cardBorder),
        ),
      ),
      child: SafeArea(
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: _inputController,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                maxLines: 3,
                minLines: 1,
                decoration: InputDecoration(
                  hintText: 'Ask a security question or paste content...',
                  hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                  filled: true,
                  fillColor: AppColors.surfaceLight,
                  contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: AppColors.cardBorder),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: AppColors.cardBorder),
                  ),
                ),
                onSubmitted: (txt) => _sendMessage(txt),
              ),
            ),
            const SizedBox(width: 8),
            ElevatedButton(
              onPressed: _isThinking ? null : () => _sendMessage(_inputController.text),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              child: const Icon(Icons.send_rounded, size: 18),
            ),
          ],
        ),
      ),
    );
  }

  String _formatMessageTime(String? isoString) {
    if (isoString == null || isoString.isEmpty) return '';
    try {
      final dt = DateTime.parse(isoString).toLocal();
      final hour = dt.hour.toString().padLeft(2, '0');
      final min = dt.minute.toString().padLeft(2, '0');
      return '$hour:$min';
    } catch (_) {
      return '';
    }
  }
}
