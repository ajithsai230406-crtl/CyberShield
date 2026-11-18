import 'package:flutter/material.dart';
import 'package:cybershield/features/url_scanner/screens/url_scanner_screen.dart';
import 'package:cybershield/features/sms_scanner/screens/sms_scanner_screen.dart';
import 'package:cybershield/features/qr_scanner/screens/qr_scanner_screen.dart';
import 'package:cybershield/features/screenshot_analysis/screens/screenshot_analysis_screen.dart';
import 'package:cybershield/features/apk_analysis/screens/apk_analysis_screen.dart';
import 'package:cybershield/features/permission_analyzer/screens/permission_analyzer_screen.dart';
import 'package:cybershield/features/email_scanner/screens/email_scanner_screen.dart';
import 'package:cybershield/features/file_scanner/screens/file_scanner_screen.dart';
import 'package:cybershield/features/community_reports/screens/community_reports_screen.dart';
import 'package:cybershield/features/ai_assistant/screens/ai_assistant_screen.dart';
import 'package:cybershield/features/alerts/screens/alerts_screen.dart';
import 'package:cybershield/features/onboarding/screens/onboarding_screen.dart';
import 'package:cybershield/features/auth/screens/login_screen.dart';
import 'package:cybershield/features/auth/screens/email_verification_screen.dart';
import 'package:cybershield/features/settings/screens/permission_center_screen.dart';
import 'package:cybershield/features/legal/screens/privacy_policy_screen.dart';
import 'package:cybershield/features/legal/screens/terms_screen.dart';
import 'package:cybershield/features/safety_center/screens/safety_center_screen.dart';
import 'package:cybershield/features/communications/screens/communication_hub_screen.dart';
import 'package:cybershield/features/communications/screens/communication_settings_screen.dart';
import 'package:cybershield/features/unified_events/screens/unified_security_hub_screen.dart';
import 'package:cybershield/core/widgets/main_navigation_scaffold.dart';

class AppRouter {
  static const String dashboard = '/';
  static const String scanHub = '/scan-hub';
  static const String protection = '/protection';
  static const String communications = '/communications';
  static const String communicationSettings = '/communication-settings';
  static const String unifiedEvents = '/unified-events';
  static const String alerts = '/alerts';
  static const String onboarding = '/onboarding';
  static const String login = '/login';
  static const String verifyEmail = '/verify-email';
  static const String settings = '/settings';
  static const String urlScanner = '/url-scanner';
  static const String smsScanner = '/sms-scanner';
  static const String qrScanner = '/qr-scanner';
  static const String screenshotAnalysis = '/screenshot-analysis';
  static const String apkAnalysis = '/apk-analysis';
  static const String permissionAnalyzer = '/permission-analyzer';
  static const String emailScanner = '/email-scanner';
  static const String fileScanner = '/file-scanner';
  static const String communityReports = '/community-reports';
  static const String aiAssistant = '/ai-assistant';
  static const String history = '/history';
  static const String permissionCenter = '/permission-center';
  static const String privacyPolicy = '/privacy-policy';
  static const String terms = '/terms';
  static const String safetyCenter = '/safety-center';

  static Route<dynamic> generateRoute(RouteSettings routeSettings) {
    switch (routeSettings.name) {
      case dashboard:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 0));
      case scanHub:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 1));
      case protection:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 2));
      case communications:
        final initialTab = routeSettings.arguments is int ? routeSettings.arguments as int : 0;
        return _buildRoute(CommunicationHubScreen(initialTab: initialTab));
      case communicationSettings:
        return _buildRoute(const CommunicationSettingsScreen());
      case unifiedEvents:
        final initialTab = routeSettings.arguments is int ? routeSettings.arguments as int : 0;
        return _buildRoute(UnifiedSecurityHubScreen(initialTab: initialTab));
      case alerts:
        return _buildRoute(const AlertsScreen());
      case onboarding:
        return _buildRoute(const OnboardingScreen());
      case login:
        return _buildRoute(const LoginScreen());
      case verifyEmail:
        return _buildRoute(const EmailVerificationScreen());
      case settings:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 4));
      case urlScanner:
        return _buildRoute(const UrlScannerScreen());
      case smsScanner:
        if (routeSettings.arguments is Map) {
          final args = Map<String, dynamic>.from(routeSettings.arguments as Map);
          return _buildRoute(SmsScannerScreen(
            initialMessage: args['content']?.toString() ?? args['message']?.toString(),
            initialSender: args['sender']?.toString(),
            initialSourceApp: args['sourceApp']?.toString(),
            autoScan: args['autoScan'] == true,
          ));
        } else if (routeSettings.arguments is String) {
          return _buildRoute(SmsScannerScreen(
            initialMessage: routeSettings.arguments as String,
            autoScan: true,
          ));
        }
        return _buildRoute(const SmsScannerScreen());
      case qrScanner:
        return _buildRoute(const QrScannerScreen());
      case screenshotAnalysis:
        return _buildRoute(const ScreenshotAnalysisScreen());
      case apkAnalysis:
        return _buildRoute(const ApkAnalysisScreen());
      case permissionAnalyzer:
        return _buildRoute(const PermissionAnalyzerScreen());
      case emailScanner:
        if (routeSettings.arguments is Map) {
          final args = Map<String, dynamic>.from(routeSettings.arguments as Map);
          return _buildRoute(EmailScannerScreen(
            initialSender: args['sender']?.toString(),
            initialSubject: args['subject']?.toString() ?? args['title']?.toString(),
            initialBody: args['content']?.toString() ?? args['body']?.toString(),
            autoScan: args['autoScan'] == true,
          ));
        }
        return _buildRoute(const EmailScannerScreen());
      case fileScanner:
        return _buildRoute(const FileScannerScreen());
      case communityReports:
        return _buildRoute(const CommunityReportsScreen());
      case aiAssistant:
        final args = routeSettings.arguments as Map<String, dynamic>?;
        return _buildRoute(AiAssistantScreen(initialScanContext: args));
      case history:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 3));
      case permissionCenter:
        return _buildRoute(const PermissionCenterScreen());
      case privacyPolicy:
        return _buildRoute(const PrivacyPolicyScreen());
      case terms:
        return _buildRoute(const TermsScreen());
      case safetyCenter:
        return _buildRoute(const SafetyCenterScreen());
      default:
        return _buildRoute(const MainNavigationScaffold(initialIndex: 0));
    }
  }

  static MaterialPageRoute _buildRoute(Widget page) {
    return MaterialPageRoute(builder: (_) => page);
  }
}

