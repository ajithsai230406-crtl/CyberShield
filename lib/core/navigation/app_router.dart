import 'package:flutter/material.dart';
import 'package:cybershield/features/dashboard/screens/dashboard_screen.dart';
import 'package:cybershield/features/url_scanner/screens/url_scanner_screen.dart';
import 'package:cybershield/features/sms_scanner/screens/sms_scanner_screen.dart';
import 'package:cybershield/features/qr_scanner/screens/qr_scanner_screen.dart';
import 'package:cybershield/features/screenshot_analysis/screens/screenshot_analysis_screen.dart';
import 'package:cybershield/features/apk_analysis/screens/apk_analysis_screen.dart';
import 'package:cybershield/features/history/screens/history_screen.dart';

class AppRouter {
  static const String dashboard = '/';
  static const String urlScanner = '/url-scanner';
  static const String smsScanner = '/sms-scanner';
  static const String qrScanner = '/qr-scanner';
  static const String screenshotAnalysis = '/screenshot-analysis';
  static const String apkAnalysis = '/apk-analysis';
  static const String history = '/history';

  static Route<dynamic> generateRoute(RouteSettings settings) {
    switch (settings.name) {
      case dashboard:
        return _buildRoute(const DashboardScreen());
      case urlScanner:
        return _buildRoute(const UrlScannerScreen());
      case smsScanner:
        return _buildRoute(const SmsScannerScreen());
      case qrScanner:
        return _buildRoute(const QrScannerScreen());
      case screenshotAnalysis:
        return _buildRoute(const ScreenshotAnalysisScreen());
      case apkAnalysis:
        return _buildRoute(const ApkAnalysisScreen());
      case history:
        return _buildRoute(const HistoryScreen());
      default:
        return _buildRoute(const DashboardScreen());
    }
  }

  static MaterialPageRoute _buildRoute(Widget page) {
    return MaterialPageRoute(builder: (_) => page);
  }
}

