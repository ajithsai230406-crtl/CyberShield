import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/models/chat_message.dart';

void main() {
  group('ChatMessage Model Unit Tests', () {
    test('ChatMessage parses user message correctly', () {
      final json = {
        'id': 'msg-101',
        'session_id': 'sess-alpha',
        'role': 'user',
        'content': 'Explain this phishing URL for me',
        'created_at': '2026-11-09T20:00:00Z',
      };

      final msg = ChatMessage.fromJson(json);
      expect(msg.id, 'msg-101');
      expect(msg.sessionId, 'sess-alpha');
      expect(msg.role, 'user');
      expect(msg.isUser, true);
      expect(msg.isAssistant, false);
      expect(msg.content, 'Explain this phishing URL for me');
      expect(msg.isAiGenerated, false);
    });

    test('ChatMessage parses assistant response with telemetry metadata', () {
      final json = {
        'id': 'msg-202',
        'session_id': 'sess-alpha',
        'role': 'assistant',
        'content': '### High Risk Threat Detected\nDo not click this link.',
        'provider': 'google_gemini',
        'is_ai_generated': true,
        'created_at': '2026-11-09T20:01:00Z',
        'metadata': {
          'provider': 'google_gemini',
          'disclaimer': 'Advisory only',
        },
        'scan_context': {
          'scan_type': 'URL',
          'target': 'http://192.168.1.1/login',
          'risk_score': 85,
        },
      };

      final msg = ChatMessage.fromJson(json);
      expect(msg.id, 'msg-202');
      expect(msg.isAssistant, true);
      expect(msg.isUser, false);
      expect(msg.provider, 'google_gemini');
      expect(msg.isAiGenerated, true);
      expect(msg.scanContext, isNotNull);
      expect(msg.scanContext!['scan_type'], 'URL');
      expect(msg.scanContext!['risk_score'], 85);
      expect(msg.metadata['disclaimer'], 'Advisory only');
    });
  });
}

