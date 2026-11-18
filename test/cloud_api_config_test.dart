import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/services/api_service.dart';

void main() {
  group('Cloud HTTPS & Local Endpoint Configuration', () {
    test('detects local vs cloud hosts accurately', () {
      expect(ApiService.isLocalHostUrl('http://127.0.0.1:8000'), isTrue);
      expect(ApiService.isLocalHostUrl('http://localhost:8000'), isTrue);
      expect(ApiService.isLocalHostUrl('http://10.0.2.2:8000'), isTrue);
      expect(ApiService.isLocalHostUrl('http://192.168.1.10:8000'), isTrue);
      expect(ApiService.isLocalHostUrl('http://10.96.179.98:8000'), isTrue);

      expect(ApiService.isLocalHostUrl('https://cybershield-api.up.railway.app'), isFalse);
      expect(ApiService.isCloudUrl('https://cybershield-api.up.railway.app'), isTrue);
      expect(ApiService.isCloudUrl('https://cybershield-api.onrender.com'), isTrue);
      expect(ApiService.isCloudUrl('http://192.168.1.10:8000'), isFalse);
    });

    test('enforces HTTPS for public cloud domains while permitting local HTTP', () {
      expect(ApiService.validateEndpointUrl('https://cybershield-api.up.railway.app'), isNull);
      expect(ApiService.validateEndpointUrl('https://cybershield-api.onrender.com'), isNull);
      expect(ApiService.validateEndpointUrl('http://127.0.0.1:8000'), isNull);
      expect(ApiService.validateEndpointUrl('http://10.0.2.2:8000'), isNull);
      expect(ApiService.validateEndpointUrl('http://192.168.1.10:8000'), isNull);
      expect(ApiService.validateEndpointUrl('http://localhost:8000'), isNull);

      // Insecure HTTP for a public cloud domain must be rejected
      final err = ApiService.validateEndpointUrl('http://cybershield-api.up.railway.app');
      expect(err, isNotNull);
      expect(err!.toLowerCase(), contains('https'));
    });

    test('auto-upgrades bare public domains to HTTPS when saved', () {
      ApiService.customBaseUrl = 'cybershield-api.up.railway.app/';
      expect(ApiService.baseUrl, 'https://cybershield-api.up.railway.app');
      expect(ApiService.connectionModeLabel, 'CLOUD HTTPS');

      ApiService.customBaseUrl = '127.0.0.1:8000';
      expect(ApiService.baseUrl, 'http://127.0.0.1:8000');
      expect(ApiService.connectionModeLabel, 'USB ADB REVERSE');

      // Reset cleanly
      ApiService.customBaseUrl = null;
    });
  });
}
