// Unit Tests for GmailService Integration

import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/services/gmail_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('GmailService Integration Tests', () {
    late GmailService service;

    setUp(() {
      service = GmailService.instance;
    });

    tearDown(() async {
      await service.disconnect();
    });

    test('initial state defaults to disconnected with no messages', () {
      expect(service.status, equals(GmailConnectionStatus.disconnected));
      expect(service.isConnected, isFalse);
      expect(service.connectedEmail, isNull);
      expect(service.messages, isEmpty);
    });

    test('connectSimulatedInbox initializes connected state and test messages', () async {
      await service.connectSimulatedInbox(testEmail: 'analyst@cybershield.org');

      expect(service.isConnected, isTrue);
      expect(service.status, equals(GmailConnectionStatus.connected));
      expect(service.connectedEmail, equals('analyst@cybershield.org'));
      expect(service.messages, isNotEmpty);

      final firstMsg = service.messages.first;
      expect(firstMsg.sender, contains('PayPal'));
      expect(firstMsg.extractedUrls, contains('http://192.168.1.1/paypal-verify'));
    });

    test('disconnect cleanly purges in-memory state and messages', () async {
      await service.connectSimulatedInbox();
      expect(service.isConnected, isTrue);
      expect(service.messages.isNotEmpty, isTrue);

      await service.disconnect();

      expect(service.isConnected, isFalse);
      expect(service.status, equals(GmailConnectionStatus.disconnected));
      expect(service.connectedEmail, isNull);
      expect(service.messages, isEmpty);
      expect(service.lastError, isNull);
    });

    test('GmailMessageItem serialization produces expected keys', () {
      final item = GmailMessageItem(
        id: 'msg-999',
        threadId: 'th-999',
        sender: 'sender@example.com',
        subject: 'Test Subject',
        date: '2026-11-10',
        snippet: 'Snippet preview',
        bodyText: 'Full email body text',
        extractedUrls: ['https://example.com/login'],
      );

      final json = item.toJson();
      expect(json['id'], equals('msg-999'));
      expect(json['sender'], equals('sender@example.com'));
      expect(json['extracted_urls'], contains('https://example.com/login'));
    });
  });
}

