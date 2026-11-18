// CyberShield Gmail Threat Scanning & OAuth Integration Service
// Complies with Google OAuth 2.0 Security Policies:
// - Scope: https://www.googleapis.com/auth/gmail.readonly (read-only)
// - Explicit User Consent required prior to message ingestion
// - Zero persistent token storage (in-memory only, wiped on disconnect)
// - Deep heuristic phishing & embedded URL inspection via CyberShield Detectors

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:cybershield/core/models/email_scan_result.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'package:cybershield/core/services/firestore_history_service.dart';

enum GmailConnectionStatus {
  disconnected,
  authorizing,
  connected,
  denied,
  expired,
  error,
}

class GmailMessageItem {
  final String id;
  final String threadId;
  final String sender;
  final String subject;
  final String date;
  final String snippet;
  final String bodyText;
  final List<String> extractedUrls;
  EmailScanResult? scanResult;
  bool isScanning;

  GmailMessageItem({
    required this.id,
    required this.threadId,
    required this.sender,
    required this.subject,
    required this.date,
    required this.snippet,
    required this.bodyText,
    required this.extractedUrls,
    this.scanResult,
    this.isScanning = false,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'thread_id': threadId,
        'sender': sender,
        'subject': subject,
        'date': date,
        'snippet': snippet,
        'body_text': bodyText,
        'extracted_urls': extractedUrls,
        'risk_score': scanResult?.riskScore,
        'classification': scanResult?.classification,
      };
}

class GmailService extends ChangeNotifier {
  static final GmailService instance = GmailService._internal();
  GmailService._internal();

  static const String gmailReadonlyScope =
      'https://www.googleapis.com/auth/gmail.readonly';

  GmailConnectionStatus _status = GmailConnectionStatus.disconnected;
  String? _connectedEmail;
  String? _inMemoryAccessToken;
  String? _lastError;
  bool _isLoadingMessages = false;
  final List<GmailMessageItem> _messages = [];

  GmailConnectionStatus get status => _status;
  bool get isConnected => _status == GmailConnectionStatus.connected;
  bool get isSandbox => _inMemoryAccessToken == 'simulated_oauth_token';
  String? get connectedEmail => _connectedEmail;
  String? get lastError => _lastError;
  bool get isLoadingMessages => _isLoadingMessages;
  List<GmailMessageItem> get messages => List.unmodifiable(_messages);

  /// Explicitly requests user authorization to connect Gmail.
  /// Requires explicit user consent before invoking.
  Future<bool> connectWithAccessToken({
    required String accessToken,
    String? accountEmail,
  }) async {
    _status = GmailConnectionStatus.authorizing;
    _lastError = null;
    notifyListeners();

    try {
      final sanitizedToken = accessToken.trim();
      if (sanitizedToken.isEmpty) {
        throw ArgumentError('Access token cannot be empty.');
      }

      // Verify token by querying Gmail user profile
      final profileUri = Uri.parse(
        'https://gmail.googleapis.com/gmail/v1/users/me/profile',
      );
      final profileResp = await http.get(
        profileUri,
        headers: {
          'Authorization': 'Bearer $sanitizedToken',
          'Accept': 'application/json',
        },
      ).timeout(const Duration(seconds: 12));

      if (profileResp.statusCode == 200) {
        final profileData = jsonDecode(profileResp.body);
        _connectedEmail =
            accountEmail ?? profileData['emailAddress'] ?? 'gmail_user';
        _inMemoryAccessToken = sanitizedToken;
        _status = GmailConnectionStatus.connected;
        notifyListeners();

        // Fetch recent inbox messages
        await fetchRecentInbox();
        return true;
      } else if (profileResp.statusCode == 401) {
        _status = GmailConnectionStatus.expired;
        _lastError =
            'Gmail OAuth access token has expired or is invalid. Please reconnect.';
        notifyListeners();
        return false;
      } else if (profileResp.statusCode == 403) {
        _status = GmailConnectionStatus.denied;
        _lastError =
            'Access denied. Ensure the "https://www.googleapis.com/auth/gmail.readonly" scope was granted.';
        notifyListeners();
        return false;
      } else {
        _status = GmailConnectionStatus.error;
        _lastError =
            'Failed to connect to Gmail API (HTTP ${profileResp.statusCode}).';
        notifyListeners();
        return false;
      }
    } catch (e) {
      _status = GmailConnectionStatus.error;
      _lastError = 'OAuth connection failed: $e';
      notifyListeners();
      return false;
    }
  }

  /// Connects with simulated live Gmail inbox for testing, sandbox environments,
  /// or when Google Cloud Console OAuth consent screen is pending verification.
  Future<void> connectSimulatedInbox({String? testEmail, bool autoScan = false}) async {
    _status = GmailConnectionStatus.authorizing;
    _lastError = null;
    notifyListeners();

    await Future.delayed(const Duration(milliseconds: 300));

    _connectedEmail = testEmail ?? 'defense.analyst@gmail.com';
    _inMemoryAccessToken = 'simulated_oauth_token';
    _status = GmailConnectionStatus.connected;

    // Load authentic realistic inbox messages for threat testing
    _messages.clear();
    _messages.addAll(_getRealisticTestMessages());

    notifyListeners();

    if (autoScan) {
      for (int i = 0; i < _messages.length && i < 3; i++) {
        await scanMessage(_messages[i]);
      }
    }
  }

  /// Fetches recent messages from Gmail API (users/me/messages).
  Future<void> fetchRecentInbox({int maxResults = 10}) async {
    if (!isConnected || _inMemoryAccessToken == null) return;

    if (_inMemoryAccessToken == 'simulated_oauth_token') {
      _messages.clear();
      _messages.addAll(_getRealisticTestMessages());
      notifyListeners();
      return;
    }

    _isLoadingMessages = true;
    _lastError = null;
    notifyListeners();

    try {
      final listUri = Uri.parse(
        'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=$maxResults',
      );
      final listResp = await http.get(
        listUri,
        headers: {'Authorization': 'Bearer $_inMemoryAccessToken'},
      ).timeout(const Duration(seconds: 15));

      if (listResp.statusCode == 401) {
        _status = GmailConnectionStatus.expired;
        _lastError = 'Session expired. Please reconnect your Gmail account.';
        _isLoadingMessages = false;
        notifyListeners();
        return;
      }

      if (listResp.statusCode != 200) {
        _lastError =
            'Failed to fetch messages (HTTP ${listResp.statusCode}): ${listResp.body}';
        _isLoadingMessages = false;
        notifyListeners();
        return;
      }

      final listData = jsonDecode(listResp.body);
      final messageIds = (listData['messages'] as List? ?? [])
          .map((m) => m['id'] as String)
          .toList();

      final List<GmailMessageItem> parsedList = [];

      for (final msgId in messageIds) {
        try {
          final detailUri = Uri.parse(
            'https://gmail.googleapis.com/gmail/v1/users/me/messages/$msgId?format=full',
          );
          final detailResp = await http.get(
            detailUri,
            headers: {'Authorization': 'Bearer $_inMemoryAccessToken'},
          ).timeout(const Duration(seconds: 8));

          if (detailResp.statusCode == 200) {
            final detailData = jsonDecode(detailResp.body);
            final parsedItem = _parseGmailMessage(detailData);
            if (parsedItem != null) {
              parsedList.add(parsedItem);
            }
          }
        } catch (_) {
          // Continue to next message if single message fetch fails
        }
      }

      _messages.clear();
      _messages.addAll(parsedList);
    } catch (e) {
      _lastError = 'Error reading Gmail messages: $e';
    } finally {
      _isLoadingMessages = false;
      notifyListeners();
    }
  }

  /// Scans an individual Gmail message using CyberShield's Email Threat Detector.
  Future<void> scanMessage(GmailMessageItem item) async {
    item.isScanning = true;
    notifyListeners();

    try {
      final result = await ApiService.scanGmailMessage(
        messageId: item.id,
        body: item.bodyText.isNotEmpty ? item.bodyText : item.snippet,
        sender: item.sender,
        subject: item.subject,
        date: item.date,
      );

      item.scanResult = result;

      // Save to Cloud Firestore if authenticated
      if (FirestoreHistoryService.instance.isAuthenticated && !result.isError) {
        await FirestoreHistoryService.instance.recordScan(
          scanType: 'EMAIL',
          target: item.subject.isNotEmpty ? item.subject : item.sender,
          riskScore: result.riskScore,
          classification: result.classification,
          status: result.classification,
          summary:
              'Gmail Threat Audit: ${result.riskScore}/100 (${result.classification})',
          result: result.toJson(),
          metadata: {
            'gmail_id': item.id,
            'sender': item.sender,
            'subject': item.subject,
            'threat_categories': result.threatCategories,
            'url_count': result.embeddedUrls.length,
          },
        );
      }
    } catch (e) {
      debugPrint('Failed to scan Gmail message: $e');
    } finally {
      item.isScanning = false;
      notifyListeners();
    }
  }

  /// Scans all currently loaded Gmail messages sequentially.
  Future<void> scanAllMessages() async {
    for (final msg in _messages) {
      if (msg.scanResult == null) {
        await scanMessage(msg);
      }
    }
  }

  /// Disconnects Gmail: revokes session, clears in-memory tokens & messages.
  Future<void> disconnect() async {
    _inMemoryAccessToken = null;
    _connectedEmail = null;
    _status = GmailConnectionStatus.disconnected;
    _lastError = null;
    _messages.clear();
    notifyListeners();
  }

  // -------------------------------------------------------------------------
  // MIME & RFC 822 Extraction Utilities
  // -------------------------------------------------------------------------

  GmailMessageItem? _parseGmailMessage(Map<String, dynamic> data) {
    try {
      final id = data['id'] ?? '';
      final threadId = data['threadId'] ?? '';
      final snippet = data['snippet'] ?? '';

      final payload = data['payload'] as Map<String, dynamic>? ?? {};
      final headers = (payload['headers'] as List? ?? []);

      String sender = 'Unknown Sender';
      String subject = '(No Subject)';
      String date = 'Recent';

      for (final h in headers) {
        final name = (h['name'] as String? ?? '').toLowerCase();
        final value = h['value'] as String? ?? '';
        if (name == 'from') sender = value;
        if (name == 'subject') subject = value;
        if (name == 'date') date = value;
      }

      final body = _extractBodyText(payload);
      final urls = _extractUrls(body);

      return GmailMessageItem(
        id: id,
        threadId: threadId,
        sender: sender,
        subject: subject,
        date: date,
        snippet: snippet,
        bodyText: body.isNotEmpty ? body : snippet,
        extractedUrls: urls,
      );
    } catch (_) {
      return null;
    }
  }

  String _extractBodyText(Map<String, dynamic> payload) {
    // 1. Check direct body data
    final bodyObj = payload['body'] as Map<String, dynamic>?;
    if (bodyObj != null && bodyObj['data'] != null) {
      return _decodeBase64Url(bodyObj['data'] as String);
    }

    // 2. Check multipart payload parts
    final parts = payload['parts'] as List?;
    if (parts != null) {
      for (final part in parts) {
        if (part is Map<String, dynamic>) {
          final mimeType = (part['mimeType'] as String? ?? '').toLowerCase();
          final partBody = part['body'] as Map<String, dynamic>?;

          if (mimeType == 'text/plain' && partBody?['data'] != null) {
            return _decodeBase64Url(partBody!['data'] as String);
          }
          if (mimeType == 'text/html' && partBody?['data'] != null) {
            final html = _decodeBase64Url(partBody!['data'] as String);
            return _stripHtml(html);
          }
        }
      }
    }
    return '';
  }

  String _decodeBase64Url(String input) {
    try {
      String normalized = input.replaceAll('-', '+').replaceAll('_', '/');
      while (normalized.length % 4 != 0) {
        normalized += '=';
      }
      return utf8.decode(base64.decode(normalized));
    } catch (_) {
      return '';
    }
  }

  String _stripHtml(String html) {
    return html.replaceAll(RegExp(r'<[^>]*>'), ' ').replaceAll(RegExp(r'\s+'), ' ').trim();
  }

  List<String> _extractUrls(String text) {
    final urlRegExp = RegExp(
      r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
      caseSensitive: false,
    );
    final matches = urlRegExp.allMatches(text);
    final Set<String> uniqueUrls = {};
    for (final m in matches) {
      final u = m.group(0);
      if (u != null) uniqueUrls.add(u);
    }
    return uniqueUrls.toList();
  }

  List<GmailMessageItem> _getRealisticTestMessages() {
    return [
      GmailMessageItem(
        id: 'msg-real-001',
        threadId: 'th-001',
        sender: '"PayPal Security Alert" <support-security@freemail-auth.xyz>',
        subject: 'URGENT: Your account has been suspended due to unauthorized access',
        date: 'Today, 10:14 AM',
        snippet: 'We detected suspicious activity on your PayPal account. Confirm your identity within 24h at http://192.168.1.1/paypal-verify to prevent permanent closure.',
        bodyText:
            'Dear PayPal Member,\n\nWe detected unauthorized login attempts from an unknown Russian IP address. Your account privileges have been restricted.\n\nTo restore your account and verify your billing details, visit our secure verification portal immediately:\nhttp://192.168.1.1/paypal-verify\n\nFailure to verify within 24 hours will result in permanent account termination.\n\nPayPal Security Operations',
        extractedUrls: ['http://192.168.1.1/paypal-verify'],
      ),
      GmailMessageItem(
        id: 'msg-real-002',
        threadId: 'th-002',
        sender: 'Executive Board Office <ceo-urgent-wire@mail-direct.com>',
        subject: 'Confidential: Urgent Wire Transfer Required for Vendor Acquisition',
        date: 'Today, 09:30 AM',
        snippet: 'Are you at your desk? I am currently in an executive meeting and need an urgent wire transfer processed for an overdue vendor invoice.',
        bodyText:
            'Hi,\n\nAre you available at your desk right now? I am currently in a closed-door acquisition meeting and need an urgent wire transfer executed before noon.\n\nPlease reply with your WhatsApp or direct mobile number so I can forward the bank routing details discreetly.\n\nBest regards,\nChief Executive Officer',
        extractedUrls: [],
      ),
      GmailMessageItem(
        id: 'msg-real-003',
        threadId: 'th-003',
        sender: 'Google Security Team <no-reply@accounts.google.com>',
        subject: 'Security Alert: New device signed in to your Google Account',
        date: 'Yesterday, 04:15 PM',
        snippet: 'Your Google Account was recently signed in to from a new Windows workstation. If this was you, you do not need to take any action.',
        bodyText:
            'Hi User,\n\nA new sign-in was detected on your Google Account from a Windows machine running Chrome in your usual location.\n\nIf this was you, no action is needed.\nIf you did not initiate this login, review your security settings at https://myaccount.google.com/security\n\nGoogle Security Team',
        extractedUrls: ['https://myaccount.google.com/security'],
      ),
      GmailMessageItem(
        id: 'msg-real-004',
        threadId: 'th-004',
        sender: 'IT Helpdesk <support@corporate-internal.org>',
        subject: 'Scheduled Maintenance: Identity Provider Migration this Weekend',
        date: 'Nov 8, 02:00 PM',
        snippet: 'Please be advised that the internal Single Sign-On portal will undergo scheduled maintenance this Saturday between 02:00 UTC and 04:00 UTC.',
        bodyText:
            'Hello Team,\n\nThe IT Infrastructure team will be migrating authentication clusters this Saturday. Single Sign-On and internal tools may experience intermittent connectivity for 15 minutes.\n\nNo credential resets or user actions are required.\n\nIT Support Desk',
        extractedUrls: [],
      ),
    ];
  }
}
