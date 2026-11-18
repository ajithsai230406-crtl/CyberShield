// AI Security Assistant Chat Models for CyberShield

class ChatMessage {
  final String id;
  final String sessionId;
  final String role; // 'user' or 'assistant'
  final String content;
  final String provider;
  final bool isAiGenerated;
  final String createdAt;
  final Map<String, dynamic> metadata;
  final Map<String, dynamic>? scanContext;

  const ChatMessage({
    required this.id,
    required this.sessionId,
    required this.role,
    required this.content,
    this.provider = 'cybershield_ai',
    this.isAiGenerated = false,
    required this.createdAt,
    this.metadata = const {},
    this.scanContext,
  });

  bool get isUser => role.toLowerCase() == 'user';
  bool get isAssistant => role.toLowerCase() == 'assistant';

  factory ChatMessage.fromJson(Map<String, dynamic> json) {
    final rawMeta = json['metadata'];
    Map<String, dynamic> metaMap = {};
    if (rawMeta is Map) {
      metaMap = Map<String, dynamic>.from(rawMeta);
    }

    final rawContext = json['scan_context'] ?? metaMap['scan_context'];
    Map<String, dynamic>? ctxMap;
    if (rawContext is Map) {
      ctxMap = Map<String, dynamic>.from(rawContext);
    }

    return ChatMessage(
      id: json['id']?.toString() ?? '',
      sessionId: json['session_id']?.toString() ?? 'default-session',
      role: json['role']?.toString() ?? 'user',
      content: json['content']?.toString() ?? '',
      provider: json['provider']?.toString() ?? metaMap['provider']?.toString() ?? 'cybershield_ai',
      isAiGenerated: json['is_ai_generated'] as bool? ?? (json['role'] == 'assistant'),
      createdAt: json['created_at']?.toString() ?? DateTime.now().toUtc().toIso8601String(),
      metadata: metaMap,
      scanContext: ctxMap,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'session_id': sessionId,
    'role': role,
    'content': content,
    'provider': provider,
    'is_ai_generated': isAiGenerated,
    'created_at': createdAt,
    'metadata': metadata,
    'scan_context': scanContext,
  };
}

