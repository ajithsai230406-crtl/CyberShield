import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/features/auth/screens/login_screen.dart';
import 'package:cybershield/features/auth/screens/email_verification_screen.dart';
import 'package:cybershield/core/widgets/main_navigation_scaffold.dart';

class CyberShieldApp extends StatefulWidget {
  final Widget? home;

  const CyberShieldApp({super.key, this.home});

  @override
  State<CyberShieldApp> createState() => _CyberShieldAppState();
}

class _CyberShieldAppState extends State<CyberShieldApp> {
  @override
  void initState() {
    super.initState();
    ThemeController.instance.loadPreferences();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: ThemeController.instance,
      builder: (context, _) {
        return MaterialApp(
          title: 'CyberShield',
          debugShowCheckedModeBanner: false,
          themeMode: ThemeController.instance.themeMode,
          theme: AppTheme.lightTheme(),
          darkTheme: AppTheme.darkTheme(),
          home: widget.home ??
              StreamBuilder<User?>(
                stream: FirebaseAuth.instance.userChanges(),
                builder: (context, snapshot) {
                  if (snapshot.connectionState == ConnectionState.waiting) {
                    return const Scaffold(
                      body: Center(
                        child: CircularProgressIndicator(color: AppColors.primary),
                      ),
                    );
                  }

                  final user = snapshot.data;
                  if (user != null) {
                    final isGoogle = user.providerData.any((p) => p.providerId == 'google.com');
                    if (isGoogle || user.emailVerified) {
                      return const MainNavigationScaffold();
                    } else {
                      return EmailVerificationScreen(user: user);
                    }
                  }

                  return const LoginScreen();
                },
              ),
          onGenerateRoute: AppRouter.generateRoute,
        );
      },
    );
  }
}
