import 'dart:async';
import 'dart:convert';
import 'dart:io' show InternetAddress, Platform, RawDatagramSocket, RawSocketEvent;
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/models/url_scan_result.dart';
import 'package:cybershield/core/models/sms_scan_result.dart';
import 'package:cybershield/core/models/qr_scan_result.dart';
import 'package:cybershield/core/models/screenshot_scan_result.dart';
import 'package:cybershield/core/models/apk_scan_result.dart';
import 'package:cybershield/core/models/permission_scan_result.dart';
import 'package:cybershield/core/models/email_scan_result.dart';
import 'package:cybershield/core/models/file_scan_result.dart';
import 'package:cybershield/core/models/community_report.dart';
import 'package:cybershield/core/models/chat_message.dart';
import 'package:cybershield/core/models/dashboard_analytics.dart';
import 'package:cybershield/core/models/security_alert.dart';
import 'package:cybershield/core/models/protection_models.dart';
import 'package:cybershield/core/models/communication_models.dart';
import 'package:cybershield/core/models/security_event_model.dart';

class ApiService {
  static const String _prefKeyApiBaseUrl = 'cybershield_api_base_url';
  static const String _prefKeyCloudMigrated = 'cybershield_cloud_migrated_v1';

  static String? _customBaseUrl;
  static bool _initialized = false;

  /// Production Railway Cloud HTTPS backend URL (live & verified).
  /// Can be overridden at build time via --dart-define=CLOUD_API_URL=https://...
  /// or --dart-define=API_BASE_URL=https://...
  static const String defaultCloudUrl = 'https://cybershield-api-production-3d05c0b0.up.railway.app';
  static const String _envCloudApiUrl = String.fromEnvironment('CLOUD_API_URL');
  static const String _envApiBaseUrl = String.fromEnvironment('API_BASE_URL');

  /// Active Cloud HTTPS endpoint (compile-time override or verified Railway production default).
  static String get presetCloudUrl {
    if (_envCloudApiUrl.trim().isNotEmpty) {
      return _sanitizeUrl(_envCloudApiUrl);
    }
    if (_envApiBaseUrl.trim().isNotEmpty) {
      return _sanitizeUrl(_envApiBaseUrl);
    }
    return defaultCloudUrl;
  }

  /// Quick connection presets for supported device environments
  static const String presetAdbReverse = 'http://127.0.0.1:8000';
  static const String presetCurrentWifi = 'http://10.96.179.98:8000';
  static const String presetHomeWifi = 'http://192.168.1.10:8000';
  static const String presetLanWifi = 'http://10.96.179.98:8000';
  static const String presetLocalhost = 'http://localhost:8000';
  static const String presetEmulator = 'http://10.0.2.2:8000';
  static const String presetAlternatePort = 'http://10.0.2.2:8001';

  /// Standardized connection state labels
  static const String statusOnline = 'ONLINE';
  static const String statusOffline = 'OFFLINE';
  static const String statusConnectionError = 'CONNECTION ERROR';
  static const String statusTimeout = 'TIMEOUT';
  static const String statusAuthRequired = 'AUTHENTICATION REQUIRED';
  static const String statusServerError = 'SERVER ERROR';

  /// Standard candidate presets evaluated during auto-discovery.
  /// Cloud HTTPS (when configured) is prioritized first, followed by Wi-Fi LAN & ADB reverse.
  static List<String> get candidatePresets {
    final list = <String>[];
    if (presetCloudUrl.isNotEmpty) {
      list.add(presetCloudUrl);
    }
    list.addAll([
      presetCurrentWifi,
      presetHomeWifi,
      presetAdbReverse,
      presetEmulator,
      presetLocalhost,
    ]);
    return list;
  }

  /// Single-flight guard to prevent duplicate parallel auto-discovery storms
  static Future<Map<String, dynamic>>? _inFlightDiscovery;

  /// Standardized timeout durations
  static const Duration defaultTimeout = Duration(seconds: 35);
  static const Duration healthTimeout = Duration(seconds: 8);
  static const Duration uploadTimeout = Duration(seconds: 90);
  static const Duration aiTimeout = Duration(seconds: 60);

  /// Backward-compatible alias
  static const Duration timeoutDuration = defaultTimeout;

  /// Initialize and load persistently saved API Base URL from SharedPreferences.
  /// Defaults to the deployed Railway Cloud HTTPS URL so CyberShield works anywhere
  /// without PC/USB/same-Wi-Fi. Performs a one-time migration off legacy local LAN IPs
  /// while preserving any subsequent custom endpoint chosen by the user in Settings.
  static Future<void> init() async {
    if (_initialized) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      final savedUrl = prefs.getString(_prefKeyApiBaseUrl);
      final migrated = prefs.getBool(_prefKeyCloudMigrated) ?? false;

      if (!migrated && presetCloudUrl.isNotEmpty) {
        if (savedUrl == null || savedUrl.trim().isEmpty || isLocalHostUrl(savedUrl)) {
          _customBaseUrl = presetCloudUrl;
          await prefs.setString(_prefKeyApiBaseUrl, presetCloudUrl);
        } else {
          _customBaseUrl = _sanitizeUrl(savedUrl);
        }
        await prefs.setBool(_prefKeyCloudMigrated, true);
      } else if (savedUrl != null && savedUrl.trim().isNotEmpty) {
        _customBaseUrl = _sanitizeUrl(savedUrl);
      } else if (presetCloudUrl.isNotEmpty) {
        _customBaseUrl = presetCloudUrl;
      } else {
        try {
          if (Platform.isAndroid) {
            _customBaseUrl = presetLanWifi;
          }
        } catch (_) {}
      }
    } catch (_) {}
    _initialized = true;
  }

  /// Returns true if the URL targets localhost, ADB reverse, Android emulator, or a private RFC1918 LAN IP.
  static bool isLocalHostUrl(String url) {
    final uri = Uri.tryParse(url.contains('://') ? url : 'http://$url');
    final host = (uri?.host ?? '').toLowerCase();
    if (host.isEmpty) return false;
    if (host == 'localhost' || host == '127.0.0.1' || host == '10.0.2.2' || host == '::1') {
      return true;
    }
    if (host.startsWith('192.168.') || host.startsWith('10.')) {
      return true;
    }
    final m172 = RegExp(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.').hasMatch(host);
    return m172;
  }

  /// Returns true if the URL is a public Cloud HTTPS backend endpoint.
  static bool isCloudUrl(String url) {
    final lower = url.trim().toLowerCase();
    return lower.startsWith('https://') && !isLocalHostUrl(lower);
  }

  /// Human-readable label for the active connection mode.
  static String get connectionModeLabel {
    final current = baseUrl;
    if (isCloudUrl(current)) return 'CLOUD HTTPS';
    if (current.contains('127.0.0.1')) return 'USB ADB REVERSE';
    if (current.contains('10.0.2.2')) return 'ANDROID EMULATOR';
    if (current.contains('localhost')) return 'LOCALHOST';
    return 'LOCAL WI-FI LAN';
  }

  /// Validates an endpoint URL. Enforces HTTPS-only for public cloud domains
  /// while permitting HTTP for local development (localhost, ADB reverse, emulator, LAN IP).
  /// Returns null if valid, or a user-facing validation error string.
  static String? validateEndpointUrl(String rawUrl) {
    final trimmed = rawUrl.trim();
    if (trimmed.isEmpty) return null; // Empty resets to default
    final sanitized = _sanitizeUrl(trimmed);
    final uri = Uri.tryParse(sanitized);
    if (uri == null || uri.host.isEmpty) {
      return 'Invalid URL format. Example: https://cybershield-api.up.railway.app';
    }
    if (uri.scheme != 'https' && !isLocalHostUrl(sanitized)) {
      return 'Cloud endpoints must use HTTPS (https://) for encrypted communication.';
    }
    return null;
  }

  /// Custom Base URL override configured at runtime.
  static String? get customBaseUrl => _customBaseUrl;

  /// Save and persist a custom API Base URL to SharedPreferences
  static Future<void> saveCustomBaseUrl(String? url) async {
    final sanitized = (url == null || url.trim().isEmpty) ? null : _sanitizeUrl(url);
    _customBaseUrl = sanitized;
    try {
      final prefs = await SharedPreferences.getInstance();
      if (sanitized != null) {
        await prefs.setString(_prefKeyApiBaseUrl, sanitized);
      } else {
        await prefs.remove(_prefKeyApiBaseUrl);
      }
    } catch (_) {}
  }

  /// In-memory setter for custom base URL
  static set customBaseUrl(String? url) {
    if (url == null || url.trim().isEmpty) {
      _customBaseUrl = null;
    } else {
      _customBaseUrl = _sanitizeUrl(url);
    }
  }

  static String _sanitizeUrl(String url) {
    var s = url.trim();
    while (s.endsWith('/')) {
      s = s.substring(0, s.length - 1);
    }
    if (!s.startsWith('http://') && !s.startsWith('https://')) {
      // Automatically enforce HTTPS for public cloud domains, HTTP for local IPs/hosts
      s = isLocalHostUrl(s) ? 'http://$s' : 'https://$s';
    }
    return s;
  }

  /// Active API Base URL priority:
  /// 1. Persisted user override in SharedPreferences (Cloud HTTPS or custom local endpoint)
  /// 2. Build-time Cloud HTTPS URL (--dart-define=CLOUD_API_URL or API_BASE_URL)
  /// 3. Local development fallback (Wi-Fi LAN on Android, localhost on desktop)
  static String get baseUrl {
    if (_customBaseUrl != null && _customBaseUrl!.isNotEmpty) {
      return _customBaseUrl!;
    }
    if (presetCloudUrl.isNotEmpty) {
      return presetCloudUrl;
    }
    try {
      if (Platform.isAndroid) {
        return presetLanWifi;
      }
    } catch (_) {}
    return presetLocalhost;
  }

  static String _classifyHttpStatus(int statusCode) {
    if (statusCode == 200) return statusOnline;
    if (statusCode == 401 || statusCode == 403) return statusAuthRequired;
    if (statusCode >= 500) return statusServerError;
    return statusConnectionError;
  }

  static String _classifyExceptionStatus(Object error) {
    if (error is TimeoutException) return statusTimeout;
    final msg = error.toString().toLowerCase();
    if (msg.contains('timed out') || msg.contains('timeout')) {
      return statusTimeout;
    }
    if (msg.contains('connection refused') ||
        msg.contains('network is unreachable') ||
        msg.contains('no route to host') ||
        msg.contains('failed host lookup')) {
      return statusOffline;
    }
    return statusConnectionError;
  }

  /// Fetch backend AI service readiness (never exposes API keys)
  static Future<Map<String, dynamic>?> getAiStatus() async {
    try {
      final response = await http
          .get(Uri.parse('$baseUrl/api/v1/ai/status'))
          .timeout(healthTimeout);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return decoded;
        }
      }
    } catch (_) {}
    return null;
  }

  /// Comprehensive backend diagnostics checking health, latency, auth, AI model status, and actionable physical device guidance
  static Future<Map<String, dynamic>> checkDiagnostics() async {
    final currentUrl = baseUrl;
    final stopwatch = Stopwatch()..start();
    try {
      final response = await http.get(Uri.parse('$currentUrl/health')).timeout(healthTimeout);
      stopwatch.stop();

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body) as Map<String, dynamic>;
        final modules = decoded['active_modules'] as List? ?? [];

        // Check Firebase Auth token validity
        String authStatus = 'Not signed in';
        try {
          final user = FirebaseAuth.instance.currentUser;
          if (user != null) {
            final token = await user.getIdToken();
            authStatus = (token != null && token.isNotEmpty) ? 'Valid Firebase ID Token' : 'Token expired';
          }
        } catch (_) {
          authStatus = 'Firebase Auth not initialized';
        }

        final aiStatus = await getAiStatus();

        return {
          'is_online': true,
          'status': 'healthy',
          'connection_status': statusOnline,
          'base_url': currentUrl,
          'latency_ms': stopwatch.elapsedMilliseconds,
          'service': decoded['service'] ?? 'CyberShield API',
          'version': decoded['version'] ?? '1.0.0',
          'active_modules': modules,
          'active_modules_count': modules.length,
          'auth_status': authStatus,
          if (aiStatus != null) 'ai_status': aiStatus,
          'message': 'Connected to CyberShield backend (${stopwatch.elapsedMilliseconds}ms)',
        };
      } else {
        final connStatus = _classifyHttpStatus(response.statusCode);
        return {
          'is_online': false,
          'status': connStatus.toLowerCase(),
          'connection_status': connStatus,
          'base_url': currentUrl,
          'latency_ms': stopwatch.elapsedMilliseconds,
          'message': 'Server responded with HTTP ${response.statusCode} ($connStatus)',
        };
      }
    } on TimeoutException {
      return {
        'is_online': false,
        'status': 'timeout',
        'connection_status': statusTimeout,
        'base_url': currentUrl,
        'latency_ms': stopwatch.elapsedMilliseconds,
        'message': 'Connection timed out at $currentUrl. Check if backend is running.',
        'help': _getPhysicalPhoneHelp(currentUrl),
      };
    } catch (e) {
      final connStatus = _classifyExceptionStatus(e);
      return {
        'is_online': false,
        'status': connStatus == statusOffline ? 'offline' : 'error',
        'connection_status': connStatus,
        'base_url': currentUrl,
        'latency_ms': stopwatch.elapsedMilliseconds,
        'message': 'Cannot reach backend at $currentUrl: $e',
        'help': _getPhysicalPhoneHelp(currentUrl),
      };
    }
  }

  static String _getPhysicalPhoneHelp(String currentUrl) {
    if (currentUrl.contains('10.0.2.2')) {
      return 'Notice: 10.0.2.2 only works in the Android Emulator. For a physical phone, connect phone and PC to the same Wi-Fi and set your PC LAN IP (e.g. http://192.168.1.X:8000) or connect via USB and run "adb reverse tcp:8000 tcp:8000".';
    }
    return 'Ensure FastAPI backend is running with: uvicorn app.main:app --host 0.0.0.0 --port 8000';
  }

  /// Retrieves a valid Firebase ID Token for the currently signed-in user,
  /// automatically refreshing expired tokens using Firebase Auth.
  static Future<String?> getIdToken({bool forceRefresh = false}) async {
    try {
      final user = FirebaseAuth.instance.currentUser;
      if (user != null) {
        return await user.getIdToken(forceRefresh);
      }
    } catch (_) {
      // In tests or if Firebase is uninitialized/unavailable
    }
    return null;
  }

  /// Builds standard request headers with Content-Type and Authorization Bearer token.
  static Future<Map<String, String>> _authHeaders({
    Map<String, String>? extra,
    bool forceRefresh = false,
  }) async {
    final headers = <String, String>{
      'Content-Type': 'application/json',
    };
    if (extra != null) {
      headers.addAll(extra);
    }
    final token = await getIdToken(forceRefresh: forceRefresh);
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    return headers;
  }

  /// Attaches Authorization Bearer token header to a multipart or custom HTTP request.
  static Future<void> _attachAuthHeader(http.BaseRequest request) async {
    final token = await getIdToken();
    if (token != null && token.isNotEmpty) {
      request.headers['Authorization'] = 'Bearer $token';
    }
  }

  /// Check FastAPI server health status (public, unauthenticated) with controlled
  /// retry and automatic endpoint failover (Wi-Fi LAN <-> ADB reverse) so closing
  /// the app or unplugging USB never leaves the UI stuck on OFFLINE.
  static Future<Map<String, dynamic>> healthCheck({
    int maxAttempts = 2,
    bool allowAutoFailover = true,
  }) async {
    Object? lastError;
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        final response = await http
            .get(Uri.parse('$baseUrl/health'))
            .timeout(healthTimeout);

        if (response.statusCode == 200) {
          final decoded = jsonDecode(response.body);
          if (decoded is Map<String, dynamic>) {
            return {
              ...decoded,
              'status': 'healthy',
              'connection_status': statusOnline,
            };
          }
          return {
            'status': 'healthy',
            'connection_status': statusOnline,
            'message': 'API online',
          };
        }
        final connStatus = _classifyHttpStatus(response.statusCode);
        return {
          'status': connStatus == statusAuthRequired ? 'auth_required' : 'error',
          'connection_status': connStatus,
          'message': 'Server responded with code ${response.statusCode} ($connStatus)',
        };
      } on TimeoutException catch (e) {
        lastError = e;
        if (attempt < maxAttempts) {
          await Future<void>.delayed(const Duration(milliseconds: 250));
          continue;
        }
      } catch (e) {
        lastError = e;
        if (attempt < maxAttempts) {
          await Future<void>.delayed(const Duration(milliseconds: 250));
          continue;
        }
      }
    }

    // Current baseUrl failed — probe all valid presets (Wi-Fi LAN, ADB reverse, Emulator)
    if (allowAutoFailover) {
      final discovered = await autoDiscoverAndConnect();
      if (discovered['is_online'] == true) {
        return discovered;
      }
    }

    final connStatus = lastError != null ? _classifyExceptionStatus(lastError) : statusOffline;
    return {
      'status': connStatus == statusTimeout ? 'timeout' : 'offline',
      'connection_status': connStatus,
      'message': lastError is TimeoutException
          ? 'Connection timed out. Ensure backend is running at $baseUrl'
          : 'Cannot reach backend at $baseUrl${lastError != null ? ' ($lastError)' : ''}',
    };
  }

  /// Test connectivity to a candidate URL before saving
  static Future<Map<String, dynamic>> testCandidateUrl(String candidateUrl) async {
    final clean = _sanitizeUrl(candidateUrl).replaceAll(RegExp(r'/+$'), '');
    if (candidateUrl.trim().isEmpty || clean.isEmpty) {
      return {
        'status': 'offline',
        'connection_status': statusConnectionError,
        'error': 'URL cannot be empty',
      };
    }
    try {
      final response = await http
          .get(Uri.parse('$clean/health'))
          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return {
            ...decoded,
            'status': 'healthy',
            'connection_status': statusOnline,
          };
        }
        return {
          'status': 'healthy',
          'connection_status': statusOnline,
          'message': 'API online',
        };
      }
      final connStatus = _classifyHttpStatus(response.statusCode);
      return {
        'status': 'error',
        'connection_status': connStatus,
        'error': 'Server returned HTTP ${response.statusCode} ($connStatus)',
      };
    } on TimeoutException {
      return {
        'status': 'timeout',
        'connection_status': statusTimeout,
        'error': 'Connection timed out (5s)',
      };
    } catch (e) {
      final connStatus = _classifyExceptionStatus(e);
      return {
        'status': connStatus == statusOffline ? 'offline' : 'error',
        'connection_status': connStatus,
        'error': e.toString(),
      };
    }
  }

  /// Real auto-discovery / probing mechanism that tests candidates in parallel,
  /// preferring persistent Wi-Fi LAN (192.168.1.10:8000) ahead of transient USB ADB reverse (127.0.0.1:8000).
  /// Coalesces concurrent calls into a single probe so startup doesn't spam `/health`.
  static Future<Map<String, dynamic>> autoDiscoverAndConnect({List<String>? candidates}) async {
    if (candidates == null && _inFlightDiscovery != null) {
      return _inFlightDiscovery!;
    }
    final future = _runAutoDiscovery(candidates: candidates);
    if (candidates == null) {
      _inFlightDiscovery = future;
      future.whenComplete(() {
        if (identical(_inFlightDiscovery, future)) {
          _inFlightDiscovery = null;
        }
      });
    }
    return future;
  }

  /// Broadcast a lightweight UDP beacon on the local Wi-Fi / hotspot subnet so the app
  /// automatically finds the PC's current IP even after switching Wi-Fi networks or hotspots.
  static Future<List<String>> _discoverViaUdpBroadcast({
    int udpPort = 8001,
    Duration timeout = const Duration(milliseconds: 500),
  }) async {
    final found = <String>[];
    try {
      if (Platform.environment.containsKey('FLUTTER_TEST')) {
        return found;
      }
    } catch (_) {}
    RawDatagramSocket? socket;
    Timer? timer;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.broadcastEnabled = true;

      final completer = Completer<void>();
      final sub = socket.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          final dg = socket?.receive();
          if (dg != null) {
            try {
              final raw = utf8.decode(dg.data);
              final decoded = jsonDecode(raw);
              if (decoded is Map && decoded['service'] == 'CyberShield API') {
                final port = decoded['port'] ?? 8000;
                final url = 'http://${dg.address.address}:$port';
                if (!found.contains(url)) {
                  found.add(url);
                }
                if (!completer.isCompleted) {
                  completer.complete();
                }
              }
            } catch (_) {}
          }
        }
      });

      timer = Timer(timeout, () {
        if (!completer.isCompleted) completer.complete();
      });

      final beacon = utf8.encode('CYBERSHIELD_DISCOVER');
      socket.send(beacon, InternetAddress('255.255.255.255'), udpPort);

      await completer.future;
      await sub.cancel();
    } catch (_) {
      // UDP broadcast unsupported in some test/sandboxed environments — ignore gracefully
    } finally {
      timer?.cancel();
      try {
        socket?.close();
      } catch (_) {}
    }
    return found;
  }

  static Future<Map<String, dynamic>> _runAutoDiscovery({List<String>? candidates}) async {
    final candidateList = <String>[];

    // 1. Prioritize any configured Cloud HTTPS URL (saved or build-time) first for anywhere access
    if (_customBaseUrl != null && isCloudUrl(_customBaseUrl!)) {
      candidateList.add(_customBaseUrl!);
    }
    if (presetCloudUrl.isNotEmpty && !candidateList.contains(presetCloudUrl)) {
      candidateList.add(presetCloudUrl);
    }

    // 2. Dynamically discover any local CyberShield backend on the current Wi-Fi/hotspot via UDP beacon
    final udpDiscovered = await _discoverViaUdpBroadcast();
    for (final u in udpDiscovered) {
      final clean = _sanitizeUrl(u);
      if (!candidateList.contains(clean)) candidateList.add(clean);
    }

    // 3. Local dev presets (Wi-Fi LAN & ADB reverse) probed in parallel as fallback
    for (final p in [presetCurrentWifi, presetHomeWifi, presetAdbReverse]) {
      if (!candidateList.contains(p)) candidateList.add(p);
    }

    if (_customBaseUrl != null && _customBaseUrl!.isNotEmpty) {
      if (!candidateList.contains(_customBaseUrl!)) {
        candidateList.add(_customBaseUrl!);
      }
    }
    if (candidates != null) {
      for (final c in candidates) {
        final clean = _sanitizeUrl(c);
        if (!candidateList.contains(clean)) candidateList.add(clean);
      }
    }
    for (final p in candidatePresets) {
      if (!candidateList.contains(p)) candidateList.add(p);
    }

    final tested = <Map<String, dynamic>>[];

    // Probe all candidates in parallel so switching between USB and Wi-Fi reconnects in < 200ms
    final futures = candidateList.map((candidate) async {
      final sw = Stopwatch()..start();
      try {
        final probeTimeout = isCloudUrl(candidate)
            ? const Duration(milliseconds: 5000)
            : const Duration(milliseconds: 2200);
        final res = await http
            .get(Uri.parse('$candidate/health'))
            .timeout(probeTimeout);
        sw.stop();
        if (res.statusCode == 200) {
          final decoded = jsonDecode(res.body) as Map<String, dynamic>;
          final modules = decoded['active_modules'] as List? ?? [];
          return {
            'ok': true,
            'candidate': candidate,
            'latency_ms': sw.elapsedMilliseconds,
            'decoded': decoded,
            'modules': modules,
          };
        }
        return {
          'ok': false,
          'url': candidate,
          'error': 'HTTP ${res.statusCode}',
          'latency_ms': sw.elapsedMilliseconds,
        };
      } catch (e) {
        sw.stop();
        return {
          'ok': false,
          'url': candidate,
          'error': e.toString(),
          'latency_ms': sw.elapsedMilliseconds,
        };
      }
    }).toList();

    final results = await Future.wait(futures);
    Map<String, dynamic>? winner;
    for (final r in results) {
      if (r['ok'] == true && winner == null) {
        winner = r;
      } else if (r['ok'] != true) {
        tested.add({
          'url': r['url'],
          'error': r['error'],
          'latency_ms': r['latency_ms'],
        });
      }
    }

    if (winner != null) {
      final candidate = winner['candidate'] as String;
      final decoded = winner['decoded'] as Map<String, dynamic>;
      final modules = winner['modules'] as List;
      final latency = winner['latency_ms'] as int;
      await saveCustomBaseUrl(candidate);
      return {
        'success': true,
        'is_online': true,
        'status': 'healthy',
        'connection_status': statusOnline,
        'base_url': candidate,
        'latency_ms': latency,
        'service': decoded['service'] ?? 'FastAPI',
        'version': decoded['version'] ?? '1.0.0',
        'active_modules': modules,
        'active_modules_count': modules.length,
        'message': 'Connected to $candidate (${latency}ms, ${modules.length} modules)',
      };
    }

    return {
      'success': false,
      'is_online': false,
      'status': 'offline',
      'connection_status': statusOffline,
      'base_url': baseUrl,
      'tested_candidates': tested,
      'message': 'Could not reach backend on any probed candidate address.',
      'help': 'Ensure laptop and phone are on the same Wi-Fi (e.g. $presetLanWifi), or run "adb reverse tcp:8000 tcp:8000" in PC terminal and use $presetAdbReverse.',
    };
  }

  /// Shared POST JSON helper with automatic endpoint failover (Wi-Fi <-> ADB reverse)
  /// and single Firebase ID token force-refresh on HTTP 401.
  static Future<http.Response> _postJsonWithFailover(
    String path,
    Map<String, dynamic> payload, {
    Duration? timeout,
  }) async {
    final effectiveTimeout = timeout ?? defaultTimeout;
    final body = jsonEncode(payload);

    Future<http.Response> doPost({bool forceRefresh = false}) async {
      final headers = await _authHeaders(forceRefresh: forceRefresh);
      return http
          .post(
            Uri.parse('$baseUrl$path'),
            headers: headers,
            body: body,
          )
          .timeout(effectiveTimeout);
    }

    http.Response response;
    try {
      response = await doPost();
    } catch (_) {
      final previousUrl = baseUrl;
      final discovered = await autoDiscoverAndConnect();
      if (discovered['is_online'] == true && baseUrl != previousUrl) {
        response = await doPost();
      } else {
        rethrow;
      }
    }

    if (response.statusCode == 401) {
      final refreshed = await getIdToken(forceRefresh: true);
      if (refreshed != null && refreshed.isNotEmpty) {
        response = await doPost(forceRefresh: true);
      }
    }
    return response;
  }

  /// Submit URL to backend for deep heuristic threat inspection (strongly typed)
  static Future<UrlScanResult> scanUrl(String url) async {
    try {
      final response = await _postJsonWithFailover('/api/v1/url/scan', {'url': url});

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body);
        return UrlScanResult.fromJson(data);
      } else {
        String errorMsg = 'Server returned code ${response.statusCode}';
        try {
          final errBody = jsonDecode(response.body);
          if (errBody is Map && errBody.containsKey('detail')) {
            errorMsg = errBody['detail'].toString();
          }
        } catch (_) {}
        return UrlScanResult.error(errorMsg);
      }
    } on TimeoutException {
      return UrlScanResult.error(
          'Analysis timed out (${defaultTimeout.inSeconds}s). Please check your network connection and backend status.');
    } catch (e) {
      return UrlScanResult.error(
          'Failed to connect to backend at $baseUrl. Ensure server is online. ($e)');
    }
  }

  /// Raw map endpoint for modules expecting `Map<String, dynamic>`
  static Future<Map<String, dynamic>> scanUrlMap(String url) async {
    try {
      final response = await _postJsonWithFailover('/api/v1/url/scan', {'url': url});

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return {
        'status': 'error',
        'message': errorMsg,
      };
    } on TimeoutException {
      return {
        'status': 'error',
        'message': 'Analysis request timed out.',
      };
    } catch (e) {
      return {
        'status': 'error',
        'message': 'Request failed: $e',
      };
    }
  }

  /// Submit SMS text to backend for smishing threat inspection (strongly typed)
  static Future<SmsScanResult> scanSms(String message) async {
    try {
      final response = await _postJsonWithFailover('/api/v1/sms/scan', {'message': message});

      if (response.statusCode == 200) {
        return SmsScanResult.fromJson(jsonDecode(response.body));
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return SmsScanResult.error(errorMsg);
    } on TimeoutException {
      return SmsScanResult.error('Analysis request timed out. Check backend status at $baseUrl.');
    } catch (e) {
      return SmsScanResult.error('Request failed: $e');
    }
  }

  /// Submit QR code decoded payload for deep threat analysis (strongly typed)
  static Future<QrScanResult> scanQrPayload(String payload) async {
    try {
      final response = await _postJsonWithFailover('/api/v1/qr/scan', {'payload': payload});

      if (response.statusCode == 200) {
        return QrScanResult.fromJson(jsonDecode(response.body));
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return QrScanResult.error(errorMsg);
    } on TimeoutException {
      return QrScanResult.error('Analysis timed out. Check backend connection at $baseUrl.');
    } catch (e) {
      return QrScanResult.error('Request failed: $e');
    }
  }

  /// Upload and analyze QR code image file from camera or gallery
  static Future<QrScanResult> scanQrImage(
    Uint8List imageBytes,
    String filename,
  ) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/qr/scan-image'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        http.MultipartFile.fromBytes('file', imageBytes, filename: filename),
      );

      final streamed = await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamed);

      if (response.statusCode == 200) {
        return QrScanResult.fromJson(jsonDecode(response.body));
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return QrScanResult.error(errorMsg);
    } on TimeoutException {
      return QrScanResult.error('QR image analysis timed out. Check backend status at $baseUrl.');
    } catch (e) {
      return QrScanResult.error('Failed to upload QR image: $e');
    }
  }

  /// Upload and analyze screenshot using OCR and threat intelligence
  static Future<ScreenshotScanResult> analyzeScreenshot(
    Uint8List imageBytes,
    String filename,
  ) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/screenshot/analyze'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        http.MultipartFile.fromBytes(
          'file',
          imageBytes,
          filename: filename,
        ),
      );

      final streamedResponse = await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return ScreenshotScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return ScreenshotScanResult.error(errorMsg);
    } on TimeoutException {
      return ScreenshotScanResult.error('Screenshot analysis timed out (90s limit). Ensure backend is accessible at $baseUrl.');
    } catch (e) {
      return ScreenshotScanResult.error('Screenshot analysis failed: $e');
    }
  }

  /// Analyze an Android APK package from a file path using streaming upload
  static Future<ApkScanResult> analyzeApkFile(
    String filePath, {
    String? filename,
  }) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/apk/analyze'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        await http.MultipartFile.fromPath(
          'file',
          filePath,
          filename: filename,
        ),
      );

      final streamedResponse = await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return ApkScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return ApkScanResult.error(errorMsg);
    } on TimeoutException {
      return ApkScanResult.error('APK upload or analysis timed out (90s limit). Check network connection.');
    } catch (e) {
      return ApkScanResult.error('APK analysis failed: $e');
    }
  }

  /// Analyze an Android APK package (.apk) via multipart upload from memory bytes
  static Future<ApkScanResult> analyzeApk(
    Uint8List apkBytes, {
    String filename = 'package.apk',
  }) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/apk/analyze'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        http.MultipartFile.fromBytes(
          'file',
          apkBytes,
          filename: filename,
        ),
      );

      final streamedResponse = await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return ApkScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return ApkScanResult.error(errorMsg);
    } on TimeoutException {
      return ApkScanResult.error('APK analysis request timed out (90s limit). Check connection to $baseUrl.');
    } catch (e) {
      return ApkScanResult.error('APK analysis failed: $e');
    }
  }

  /// Analyze AndroidManifest permissions from an uploaded APK file via multipart upload
  static Future<PermissionScanResult> analyzePermissionsApk(
    Uint8List apkBytes, {
    String filename = 'package.apk',
  }) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/permissions/analyze'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        http.MultipartFile.fromBytes(
          'file',
          apkBytes,
          filename: filename,
        ),
      );

      final streamedResponse =
          await request.send().timeout(const Duration(seconds: 30));
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return PermissionScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return PermissionScanResult.error(errorMsg);
    } on TimeoutException {
      return PermissionScanResult.error('Permission analysis request timed out.');
    } catch (e) {
      return PermissionScanResult.error('Permission analysis failed: $e');
    }
  }

  /// Analyze an array of Android permissions (e.g. from an installed application profile)
  static Future<PermissionScanResult> analyzePermissionsList({
    required List<String> permissions,
    String appName = 'Android Application',
    String packageName = 'custom.app.inspect',
    int minSdk = 0,
    int targetSdk = 0,
    String versionName = '1.0',
  }) async {
    try {
      final headers = await _authHeaders();
      final body = jsonEncode({
        'permissions': permissions,
        'app_name': appName,
        'package_name': packageName,
        'min_sdk': minSdk,
        'target_sdk': targetSdk,
        'version_name': versionName,
      });

      final response = await http
          .post(
            Uri.parse('$baseUrl/api/v1/permissions/analyze-list'),
            headers: headers,
            body: body,
          )
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return PermissionScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return PermissionScanResult.error(errorMsg);
    } on TimeoutException {
      return PermissionScanResult.error('Permission analysis request timed out.');
    } catch (e) {
      return PermissionScanResult.error('Permission analysis failed: $e');
    }
  }

  /// Submit QR code data/stub to backend (legacy Map endpoint)
  static Future<Map<String, dynamic>> scanQr(String qrData) async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .post(
            Uri.parse('$baseUrl/api/v1/scan/url'),
            headers: headers,
            body: jsonEncode({'url': qrData}),
          )
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return {
        'status': 'error',
        'message': errorMsg,
      };
    } catch (e) {
      return {
        'status': 'error',
        'message': 'Scan request failed: $e',
      };
    }
  }

  /// Analyze email content, sender, subject, and embedded links for phishing
  static Future<EmailScanResult> scanEmail({
    required String body,
    String? sender,
    String? subject,
    String? replyTo,
  }) async {
    try {
      final payload = <String, dynamic>{
        'body': body,
      };
      if (sender != null && sender.trim().isNotEmpty) {
        payload['sender'] = sender.trim();
      }
      if (subject != null && subject.trim().isNotEmpty) {
        payload['subject'] = subject.trim();
      }
      if (replyTo != null && replyTo.trim().isNotEmpty) {
        payload['reply_to'] = replyTo.trim();
      }

      final response = await _postJsonWithFailover('/api/v1/email/scan', payload);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return EmailScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return EmailScanResult.error(errorMsg);
    } on TimeoutException {
      return EmailScanResult.error('Email analysis request timed out.');
    } catch (e) {
      return EmailScanResult.error('Email analysis failed: $e');
    }
  }

  /// Scan Gmail message payload via dedicated backend endpoint
  static Future<EmailScanResult> scanGmailMessage({
    required String messageId,
    required String sender,
    required String subject,
    required String body,
    String? date,
    String? replyTo,
  }) async {
    try {
      final headers = await _authHeaders();
      final payload = <String, dynamic>{
        'message_id': messageId,
        'sender': sender,
        'subject': subject,
        'body': body,
      };
      if (date != null && date.trim().isNotEmpty) {
        payload['date'] = date.trim();
      }
      if (replyTo != null && replyTo.trim().isNotEmpty) {
        payload['reply_to'] = replyTo.trim();
      }

      final response = await http
          .post(
            Uri.parse('$baseUrl/api/v1/scan/gmail-message'),
            headers: headers,
            body: jsonEncode(payload),
          )
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return EmailScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server returned code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return EmailScanResult.error(errorMsg);
    } on TimeoutException {
      return EmailScanResult.error('Gmail scan request timed out.');
    } catch (e) {
      return EmailScanResult.error('Gmail scan failed: $e');
    }
  }

  /// Analyze uploaded file for deceptive signatures, double extensions, scripts, and archives
  static Future<FileScanResult> scanFile(
    Uint8List fileBytes, {
    required String filename,
  }) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/file/scan'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        http.MultipartFile.fromBytes(
          'file',
          fileBytes,
          filename: filename,
        ),
      );

      final streamedResponse =
          await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return FileScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return FileScanResult.error(errorMsg);
    } on TimeoutException {
      return FileScanResult.error('File threat analysis timed out (90s limit).');
    } catch (e) {
      return FileScanResult.error('File scan failed: $e');
    }
  }

  /// Scan a file by file path using streaming upload
  static Future<FileScanResult> scanFileFromPath(
    String filePath, {
    String? filename,
  }) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$baseUrl/api/v1/file/scan'),
      );
      await _attachAuthHeader(request);
      request.files.add(
        await http.MultipartFile.fromPath(
          'file',
          filePath,
          filename: filename,
        ),
      );

      final streamedResponse = await request.send().timeout(uploadTimeout);
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        return FileScanResult.fromJson(decoded as Map<String, dynamic>);
      }
      String errorMsg = 'Server responded with code ${response.statusCode}';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return FileScanResult.error(errorMsg);
    } on TimeoutException {
      return FileScanResult.error('File upload or analysis timed out (90s limit).');
    } catch (e) {
      return FileScanResult.error('File scan failed: $e');
    }
  }

  /// Fetch scan history from backend with optional filters
  static Future<Map<String, dynamic>> getHistory({
    String? scanType,
    String? classification,
  }) async {
    try {
      final queryParams = <String, String>{};
      if (scanType != null &&
          scanType.isNotEmpty &&
          scanType.toLowerCase() != 'all') {
        queryParams['scan_type'] = scanType;
      }
      if (classification != null &&
          classification.isNotEmpty &&
          classification.toLowerCase() != 'all') {
        queryParams['classification'] = classification;
      }

      final uri = Uri.parse('$baseUrl/api/v1/history').replace(
        queryParameters: queryParams.isNotEmpty ? queryParams : null,
      );

      final headers = await _authHeaders();
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      String errorMsg = 'Failed to retrieve history (${response.statusCode})';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return {
        'status': 'error',
        'message': errorMsg,
      };
    } catch (e) {
      return {
        'status': 'error',
        'message': 'Could not connect to backend: $e',
      };
    }
  }

  /// Fetch full scan detail by scan_id
  static Future<Map<String, dynamic>> getHistoryDetail(String scanId) async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .get(Uri.parse('$baseUrl/api/v1/history/$scanId'), headers: headers)
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      String errorMsg = 'Record not found (${response.statusCode})';
      try {
        final err = jsonDecode(response.body);
        if (err is Map && err.containsKey('detail')) {
          errorMsg = err['detail'].toString();
        }
      } catch (_) {}
      return {
        'status': 'error',
        'message': errorMsg,
      };
    } catch (e) {
      return {
        'status': 'error',
        'message': 'Failed to fetch scan detail: $e',
      };
    }
  }

  /// Delete a scan record by scan_id
  static Future<bool> deleteHistoryItem(String scanId) async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .delete(Uri.parse('$baseUrl/api/v1/history/$scanId'), headers: headers)
          .timeout(timeoutDuration);

      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Submit a community threat report (requires Firebase Bearer auth)
  static Future<Map<String, dynamic>> submitCommunityReport({
    required String category,
    required String target,
    required String title,
    String? description,
    List<String>? tags,
  }) async {
    try {
      final headers = await _authHeaders();
      final body = jsonEncode({
        'category': category.toLowerCase(),
        'target': target,
        'title': title,
        'description': description ?? '',
        'tags': tags ?? [],
      });

      final response = await http
          .post(
            Uri.parse('$baseUrl/api/v1/community/report'),
            headers: headers,
            body: body,
          )
          .timeout(timeoutDuration);

      final Map<String, dynamic> data = jsonDecode(response.body);
      if (response.statusCode == 201) {
        return {
          'success': true,
          'report': CommunityReport.fromJson(data),
        };
      }

      final errorMsg = data['detail']?.toString() ??
          'Failed to submit report (HTTP ${response.statusCode})';
      return {
        'success': false,
        'error': errorMsg,
        'status_code': response.statusCode,
      };
    } catch (e) {
      return {
        'success': false,
        'error': 'Network or backend error: $e',
      };
    }
  }

  /// List community threat reports with optional category or status filter
  static Future<List<CommunityReport>> getCommunityReports({
    String? category,
    String? status,
    String? search,
    int limit = 50,
    int offset = 0,
  }) async {
    try {
      final headers = await _authHeaders();
      final queryParams = <String, String>{
        'limit': limit.toString(),
        'offset': offset.toString(),
      };
      if (category != null && category.toUpperCase() != 'ALL') {
        queryParams['category'] = category.toLowerCase();
      }
      if (status != null && status.toUpperCase() != 'ALL') {
        queryParams['status'] = status.toUpperCase();
      }
      if (search != null && search.trim().isNotEmpty) {
        queryParams['search'] = search.trim();
      }

      final uri = Uri.parse('$baseUrl/api/v1/community/reports')
          .replace(queryParameters: queryParams);

      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map && decoded['reports'] is List) {
          final list = decoded['reports'] as List;
          return list
              .whereType<Map<String, dynamic>>()
              .map((item) => CommunityReport.fromJson(item))
              .toList();
        }
      }
      return [];
    } catch (_) {
      return [];
    }
  }

  /// Look up community reputation for a target
  static Future<CommunityReputation?> getCommunityReputation({
    required String category,
    required String target,
  }) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/community/reputation').replace(
        queryParameters: {
          'category': category.toLowerCase(),
          'target': target,
        },
      );

      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return CommunityReputation.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Retrieve high-level community statistics
  static Future<CommunityStats?> getCommunityStats() async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .get(Uri.parse('$baseUrl/api/v1/community/stats'), headers: headers)
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return CommunityStats.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Internal helper to POST to an AI assistant endpoint with automatic
  /// endpoint failover (USB <-> Wi-Fi) and Firebase token force-refresh on 401.
  static Future<ChatMessage?> _postAssistantEndpoint(
    String path,
    Map<String, dynamic> payload,
  ) async {
    final body = jsonEncode(payload);

    Future<http.Response> attemptPost({bool forceRefresh = false}) async {
      final headers = await _authHeaders(forceRefresh: forceRefresh);
      return http
          .post(
            Uri.parse('$baseUrl$path'),
            headers: headers,
            body: body,
          )
          .timeout(aiTimeout);
    }

    http.Response response;
    try {
      response = await attemptPost();
    } catch (firstErr) {
      // If current baseUrl failed (e.g. USB unplugged while saved on 127.0.0.1:8000),
      // probe LAN Wi-Fi / ADB reverse / Emulator presets and retry once if a healthy host is found.
      final previousUrl = baseUrl;
      final discovery = await autoDiscoverAndConnect();
      if (discovery['is_online'] == true && baseUrl != previousUrl) {
        try {
          response = await attemptPost();
        } on TimeoutException {
          throw Exception(
            'Request timed out at $baseUrl. Check your network and OpenRouter connectivity.',
          );
        } catch (retryErr) {
          throw Exception(
            'Unable to reach CyberShield backend at $baseUrl ($retryErr).',
          );
        }
      } else if (firstErr is TimeoutException) {
        throw Exception(
          'Request timed out at $previousUrl. Ensure the FastAPI backend is running and reachable.',
        );
      } else {
        throw Exception(
          'Cannot connect to backend at $previousUrl. If USB is disconnected, switch API Endpoint in Settings to your PC Wi-Fi IP ($presetLanWifi).',
        );
      }
    }

    // On 401, retry once with a force-refreshed Firebase ID token if a user is signed in
    if (response.statusCode == 401) {
      final refreshed = await getIdToken(forceRefresh: true);
      if (refreshed != null && refreshed.isNotEmpty) {
        response = await attemptPost(forceRefresh: true);
      }
    }

    if (response.statusCode == 200) {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        return ChatMessage.fromJson(decoded);
      }
      return null;
    }

    if (response.statusCode == 401) {
      throw Exception(
        'Authentication required. Please sign in to your CyberShield account to use CYBOR Assistant.',
      );
    }
    if (response.statusCode == 429) {
      throw Exception('Rate limit exceeded. Please wait a moment before asking again.');
    }

    String detail = 'Server error (HTTP ${response.statusCode})';
    try {
      final errBody = jsonDecode(response.body);
      if (errBody is Map && errBody['detail'] != null) {
        detail = errBody['detail'].toString();
      }
    } catch (_) {}
    throw Exception(detail);
  }

  /// Send chat message to CyberShield AI Security Assistant
  /// Returns a ChatMessage on success, or throws an exception with a descriptive error.
  static Future<ChatMessage?> sendAssistantMessage({
    required String message,
    String? sessionId,
    Map<String, dynamic>? scanContext,
    String language = 'en',
  }) async {
    return _postAssistantEndpoint('/api/v1/assistant/chat', {
      'message': message,
      'session_id': sessionId,
      'scan_context': scanContext,
      'language': language,
    });
  }

  /// Request immediate AI technical breakdown of a scan result
  static Future<ChatMessage?> explainScanResult(Map<String, dynamic> scanTelemetry) async {
    try {
      return await _postAssistantEndpoint('/api/v1/assistant/explain-scan', scanTelemetry);
    } catch (_) {
      return null;
    }
  }

  /// Retrieve persistent chat history for authenticated user
  static Future<List<ChatMessage>> getAssistantHistory({
    String? sessionId,
    int limit = 50,
  }) async {
    try {
      final token = await getIdToken();
      if (token == null) {
        return [];
      }
      final headers = await _authHeaders();
      final queryParams = <String, String>{
        'limit': limit.toString(),
      };
      if (sessionId != null && sessionId.isNotEmpty) {
        queryParams['session_id'] = sessionId;
      }

      final uri = Uri.parse('$baseUrl/api/v1/assistant/history')
          .replace(queryParameters: queryParams);

      final response = await http.get(uri, headers: headers).timeout(const Duration(seconds: 6));

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map && decoded['messages'] is List) {
          final list = decoded['messages'] as List;
          return list
              .whereType<Map<String, dynamic>>()
              .map((m) => ChatMessage.fromJson(m))
              .toList();
        }
      }
      return [];
    } catch (_) {
      return [];
    }
  }

  /// Clear persistent chat history for authenticated user
  static Future<bool> clearAssistantHistory({String? sessionId}) async {
    try {
      final headers = await _authHeaders();
      final queryParams = <String, String>{};
      if (sessionId != null && sessionId.isNotEmpty) {
        queryParams['session_id'] = sessionId;
      }

      final uri = Uri.parse('$baseUrl/api/v1/assistant/history')
          .replace(queryParameters: queryParams);

      final response = await http.delete(uri, headers: headers).timeout(timeoutDuration);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Retrieve comprehensive dashboard analytics and security score
  static Future<DashboardAnalytics?> getDashboardAnalytics({int days = 30}) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/analytics/dashboard').replace(
        queryParameters: {'days': days.toString()},
      );

      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return DashboardAnalytics.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Retrieve security alerts with optional filters
  static Future<List<SecurityAlertModel>> getAlerts({
    String? severity,
    bool? isRead,
    bool? isResolved,
    int limit = 50,
  }) async {
    try {
      final headers = await _authHeaders();
      final queryParams = <String, String>{
        'limit': limit.toString(),
      };
      if (severity != null && severity.isNotEmpty) {
        queryParams['severity'] = severity;
      }
      if (isRead != null) {
        queryParams['is_read'] = isRead.toString();
      }
      if (isResolved != null) {
        queryParams['is_resolved'] = isResolved.toString();
      }

      final uri = Uri.parse('$baseUrl/api/v1/alerts').replace(queryParameters: queryParams);
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map && decoded['alerts'] is List) {
          final list = decoded['alerts'] as List;
          return list
              .whereType<Map<String, dynamic>>()
              .map((a) => SecurityAlertModel.fromJson(a))
              .toList();
        }
      }
      return [];
    } catch (_) {
      return [];
    }
  }

  /// Retrieve security alert counts and unread badges
  static Future<AlertStatsModel?> getAlertStats() async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/alerts/stats');
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return AlertStatsModel.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Retrieve details for a specific alert
  static Future<SecurityAlertModel?> getAlertDetail(String alertId) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/alerts/$alertId');
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return SecurityAlertModel.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Mark alert read/unread
  static Future<bool> markAlertRead(String alertId, bool isRead) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/alerts/$alertId/read')
          .replace(queryParameters: {'is_read': isRead.toString()});
      final response = await http.patch(uri, headers: headers).timeout(timeoutDuration);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Mark alert resolved
  static Future<bool> markAlertResolved(String alertId, bool isResolved) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/alerts/$alertId/resolve')
          .replace(queryParameters: {'is_resolved': isResolved.toString()});
      final response = await http.patch(uri, headers: headers).timeout(timeoutDuration);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Create or deduplicate a security alert on backend
  static Future<SecurityAlertModel?> createAlert(Map<String, dynamic> data) async {
    try {
      final headers = await _authHeaders();
      headers['Content-Type'] = 'application/json';
      final uri = Uri.parse('$baseUrl/api/v1/alerts');
      final response = await http
          .post(uri, headers: headers, body: jsonEncode(data))
          .timeout(timeoutDuration);

      if (response.statusCode == 201 || response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return SecurityAlertModel.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Batch analyze permissions of installed applications on an Android device
  static Future<BatchAppScanResult?> analyzeInstalledAppsBatch(
      List<InstalledAppInfo> apps) async {
    try {
      final headers = await _authHeaders();
      headers['Content-Type'] = 'application/json';
      final uri = Uri.parse('$baseUrl/api/v1/permissions/analyze-batch');
      final payload = {
        'apps': apps.map((a) => a.toBatchRequestJson()).toList(),
      };
      final response = await http
          .post(uri, headers: headers, body: jsonEncode(payload))
          .timeout(uploadTimeout);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return BatchAppScanResult.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Screen incoming phone number against community spam reputation
  static Future<CallScreenResult?> screenIncomingCall(
    String phoneNumber, {
    String? callerName,
  }) async {
    try {
      final headers = await _authHeaders();
      headers['Content-Type'] = 'application/json';
      final uri = Uri.parse('$baseUrl/api/v1/calls/screen');
      final payload = <String, dynamic>{
        'phone_number': phoneNumber,
      };
      if (callerName != null) {
        payload['caller_name'] = callerName;
      }
      final response = await http
          .post(uri, headers: headers, body: jsonEncode(payload))
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return CallScreenResult.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Analyze incoming notification content for phishing links and scam language
  static Future<NotificationScanResult?> analyzeNotification({
    required String packageName,
    String? title,
    String? text,
    String? subText,
  }) async {
    try {
      final headers = await _authHeaders();
      headers['Content-Type'] = 'application/json';
      final uri = Uri.parse('$baseUrl/api/v1/notifications/analyze');
      final payload = {
        'package_name': packageName,
        'title': title ?? '',
        'text': text ?? '',
        'sub_text': subText ?? '',
      };
      final response = await http
          .post(uri, headers: headers, body: jsonEncode(payload))
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return NotificationScanResult.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Ingest & analyze an eligible communication (SMS, notification, call, email, WhatsApp)
  static Future<CommunicationRecord?> ingestCommunication({
    required String communicationType,
    required String sourceApp,
    required String senderIdentifier,
    String? callerName,
    String? subject,
    String? content,
    String? timestamp,
    bool storePreview = true,
    bool? isKnownContact,
    String? callStatus,
    String? externalId,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final headers = await _authHeaders();
      headers['Content-Type'] = 'application/json';
      final uri = Uri.parse('$baseUrl/api/v1/communications/ingest');
      final payload = <String, dynamic>{
        'communication_type': communicationType,
        'source_app': sourceApp,
        'sender_identifier': senderIdentifier,
        'store_preview': storePreview,
        if (callerName != null) 'caller_name': callerName,
        if (subject != null) 'subject': subject,
        if (content != null) 'content': content,
        if (timestamp != null) 'timestamp': timestamp,
        if (isKnownContact != null) 'is_known_contact': isKnownContact,
        if (callStatus != null) 'call_status': callStatus,
        if (externalId != null) 'external_id': externalId,
        if (metadata != null) 'metadata': metadata,
      };
      final response = await http
          .post(uri, headers: headers, body: jsonEncode(payload))
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return CommunicationRecord.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Fetch paginated, user-isolated communication history
  static Future<Map<String, dynamic>?> getCommunicationHistory({
    String category = 'all',
    String? communicationType,
    String? classification,
    String? search,
    String? startDate,
    String? endDate,
    int limit = 50,
    int offset = 0,
  }) async {
    try {
      final headers = await _authHeaders();
      final query = <String, String>{
        'category': category,
        'limit': '$limit',
        'offset': '$offset',
        if (communicationType != null && communicationType.isNotEmpty)
          'communication_type': communicationType,
        if (classification != null && classification.isNotEmpty && classification != 'all')
          'classification': classification,
        if (search != null && search.trim().isNotEmpty) 'search': search.trim(),
        if (startDate != null && startDate.isNotEmpty) 'start_date': startDate,
        if (endDate != null && endDate.isNotEmpty) 'end_date': endDate,
      };
      final uri = Uri.parse('$baseUrl/api/v1/communications/history').replace(queryParameters: query);
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          final records = (decoded['records'] as List?)
                  ?.whereType<Map>()
                  .map((e) => CommunicationRecord.fromJson(Map<String, dynamic>.from(e)))
                  .toList() ??
              <CommunicationRecord>[];
          return {
            'total': decoded['total'] ?? records.length,
            'has_more': decoded['has_more'] == true,
            'records': records,
          };
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Fetch daily, weekly, or monthly communication threat analytics
  static Future<CommunicationAnalytics?> getCommunicationAnalytics({
    String period = 'daily',
  }) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/communications/analytics')
          .replace(queryParameters: {'period': period});
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return CommunicationAnalytics.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Delete a single communication record owned by current user
  static Future<bool> deleteCommunicationRecord(String recordId) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/communications/$recordId');
      final response = await http.delete(uri, headers: headers).timeout(timeoutDuration);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Delete all records or apply retention policy (olderThanDays)
  static Future<int?> purgeCommunicationHistory({int? olderThanDays}) async {
    try {
      final headers = await _authHeaders();
      final query = <String, String>{
        if (olderThanDays != null && olderThanDays > 0) 'older_than_days': '$olderThanDays',
      };
      final uri = Uri.parse('$baseUrl/api/v1/communications')
          .replace(queryParameters: query.isEmpty ? null : query);
      final response = await http.delete(uri, headers: headers).timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return decoded['deleted_count'] is int ? decoded['deleted_count'] as int : 0;
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Centralized Smart Alert & All-18-Module Security Event Engine APIs
  // ---------------------------------------------------------------------------

  static Future<SecurityEventModel?> processSecurityEvent({
    required String moduleName,
    required String targetIdentifier,
    int? riskScore = 0,
    String? classification,
    String? eventCategory,
    String? source,
    List<String> findings = const [],
    String explanation = '',
    List<String> recommendedActions = const [],
    String analysisStatus = 'analyzed',
    String? detectionTimestamp,
    String? idempotencyKey,
    bool createAlert = true,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final headers = await _authHeaders();
      final payload = <String, dynamic>{
        'module_name': moduleName,
        'target_identifier': targetIdentifier,
        'risk_score': riskScore,
        if (classification != null) 'classification': classification,
        if (eventCategory != null) 'event_category': eventCategory,
        if (source != null) 'source': source,
        'findings': findings,
        'explanation': explanation,
        'recommended_actions': recommendedActions,
        'analysis_status': analysisStatus,
        if (detectionTimestamp != null) 'detection_timestamp': detectionTimestamp,
        if (idempotencyKey != null) 'idempotency_key': idempotencyKey,
        'create_alert': createAlert,
        if (metadata != null) 'metadata': metadata,
      };

      final response = await http
          .post(
            Uri.parse('$baseUrl/api/v1/events/process'),
            headers: headers,
            body: jsonEncode(payload),
          )
          .timeout(timeoutDuration);

      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return SecurityEventModel.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<Map<String, dynamic>?> getUnifiedEventHistory({
    String? moduleName,
    String? eventCategory,
    String? source,
    String? severity,
    String? classification,
    int? minRisk,
    int? maxRisk,
    String? startDate,
    String? endDate,
    String? search,
    int limit = 60,
    int offset = 0,
  }) async {
    try {
      final headers = await _authHeaders();
      final params = <String, String>{
        'limit': '$limit',
        'offset': '$offset',
        if (moduleName != null && moduleName.isNotEmpty && moduleName != 'all')
          'module_name': moduleName,
        if (eventCategory != null && eventCategory.isNotEmpty && eventCategory != 'all')
          'event_category': eventCategory,
        if (source != null && source.isNotEmpty && source != 'all')
          'source': source,
        if (severity != null && severity.isNotEmpty && severity != 'all')
          'severity': severity,
        if (classification != null && classification.isNotEmpty && classification != 'all')
          'classification': classification,
        if (minRisk != null) 'min_risk': '$minRisk',
        if (maxRisk != null) 'max_risk': '$maxRisk',
        if (startDate != null && startDate.isNotEmpty) 'start_date': startDate,
        if (endDate != null && endDate.isNotEmpty) 'end_date': endDate,
        if (search != null && search.trim().isNotEmpty) 'search': search.trim(),
      };
      final uri = Uri.parse('$baseUrl/api/v1/events/history')
          .replace(queryParameters: params);
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          final events = (decoded['events'] is List)
              ? (decoded['events'] as List)
                  .whereType<Map<String, dynamic>>()
                  .map(SecurityEventModel.fromJson)
                  .toList()
              : <SecurityEventModel>[];
          return {
            'total': decoded['total'] ?? events.length,
            'has_more': decoded['has_more'] == true,
            'events': events,
          };
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<UnifiedSecurityAnalytics?> getUnifiedEventAnalytics({
    String period = 'daily',
  }) async {
    try {
      final headers = await _authHeaders();
      final uri = Uri.parse('$baseUrl/api/v1/events/analytics')
          .replace(queryParameters: {'period': period});
      final response = await http.get(uri, headers: headers).timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return UnifiedSecurityAnalytics.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<SecurityEventModel?> generateDailySecurityReport() async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .post(Uri.parse('$baseUrl/api/v1/events/daily-report'), headers: headers)
          .timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic> && decoded['report_event'] is Map<String, dynamic>) {
          return SecurityEventModel.fromJson(decoded['report_event'] as Map<String, dynamic>);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<SecurityEventModel?> updateEventNotificationStatus({
    required String eventId,
    required String notificationStatus,
  }) async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .patch(
            Uri.parse('$baseUrl/api/v1/events/$eventId/notification-status'),
            headers: headers,
            body: jsonEncode({'notification_status': notificationStatus}),
          )
          .timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return SecurityEventModel.fromJson(decoded);
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  static Future<bool> deleteSecurityEvent(String eventId) async {
    try {
      final headers = await _authHeaders();
      final response = await http
          .delete(Uri.parse('$baseUrl/api/v1/events/$eventId'), headers: headers)
          .timeout(timeoutDuration);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  static Future<int?> purgeSecurityEvents({int? olderThanDays}) async {
    try {
      final headers = await _authHeaders();
      final query = <String, String>{
        if (olderThanDays != null && olderThanDays > 0) 'older_than_days': '$olderThanDays',
      };
      final uri = Uri.parse('$baseUrl/api/v1/events')
          .replace(queryParameters: query.isEmpty ? null : query);
      final response = await http.delete(uri, headers: headers).timeout(timeoutDuration);
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) {
          return decoded['deleted_count'] is int ? decoded['deleted_count'] as int : 0;
        }
      }
      return null;
    } catch (_) {
      return null;
    }
  }
}
