import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  static const String baseUrl = 'http://localhost:8000';

  static Future<Map<String, dynamic>> healthCheck() async {
    try {
      final response = await http.get(Uri.parse('$baseUrl/health'));
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      return {'status': 'error', 'message': 'Server returned ${response.statusCode}'};
    } catch (e) {
      return {'status': 'offline', 'message': 'Cannot connect to server: $e'};
    }
  }

  static Future<Map<String, dynamic>> scanUrl(String url) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/scan/url'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'url': url}),
      );
      return jsonDecode(response.body);
    } catch (e) {
      return {'status': 'error', 'message': 'Request failed: $e'};
    }
  }

  static Future<Map<String, dynamic>> scanSms(String message) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/v1/scan/sms'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'message': message}),
      );
      return jsonDecode(response.body);
    } catch (e) {
      return {'status': 'error', 'message': 'Request failed: $e'};
    }
  }

  static Future<Map<String, dynamic>> getHistory() async {
    try {
      final response = await http.get(Uri.parse('$baseUrl/api/v1/history'));
      return jsonDecode(response.body);
    } catch (e) {
      return {'status': 'error', 'message': 'Request failed: $e'};
    }
  }
}

