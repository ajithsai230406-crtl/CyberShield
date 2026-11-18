// CyberShield Premium Authentication & Registration Portal

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/utils/validators.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final formKey = GlobalKey<FormState>();
  final emailController = TextEditingController();
  final passwordController = TextEditingController();
  final confirmController = TextEditingController();

  bool isLogin = true;
  bool loading = false;
  bool obscurePassword = true;
  bool obscureConfirm = true;
  String? inlineErrorMessage;

  @override
  void initState() {
    super.initState();
    _checkExistingSession();
    passwordController.addListener(_onPasswordChanged);
  }

  void _onPasswordChanged() {
    if (!isLogin && mounted) {
      setState(() {});
    }
  }

  void _checkExistingSession() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final user = FirebaseAuth.instance.currentUser;
      if (user != null && mounted) {
        final isGoogle =
            user.providerData.any((p) => p.providerId == 'google.com');
        if (isGoogle || user.emailVerified) {
          Navigator.of(context).pushReplacementNamed(AppRouter.dashboard);
        } else {
          Navigator.of(context).pushReplacementNamed(AppRouter.verifyEmail);
        }
      }
    });
  }

  @override
  void dispose() {
    passwordController.removeListener(_onPasswordChanged);
    emailController.dispose();
    passwordController.dispose();
    confirmController.dispose();
    super.dispose();
  }

  String _getFriendlyErrorMessage(FirebaseAuthException e, bool isLoginMode) {
    switch (e.code) {
      case 'invalid-credential':
        return isLoginMode
            ? 'Invalid email or defense password. If you have not created an account yet, switch to Register. If you forgot your password, tap "Forgot Password?".'
            : 'Authentication credential details provided are invalid. Please check your inputs.';
      case 'user-not-found':
        return 'No CyberShield account found for this email address. Please register an account.';
      case 'wrong-password':
        return 'Incorrect defense password entered. If you forgot your credentials, tap "Forgot Password?".';
      case 'email-already-in-use':
        return 'This email address is already registered. Please switch to Sign In or reset your password.';
      case 'weak-password':
        return 'The selected password is too weak. Ensure at least 8 characters with upper, lower, number, and special symbol.';
      case 'invalid-email':
        return 'The email format entered is invalid. Please double check for typos.';
      case 'user-disabled':
        return 'This CyberShield defense account has been disabled. Please contact security operations.';
      case 'too-many-requests':
        return 'Too many consecutive failed authorization attempts. Access is temporarily rate-limited for security. Please try again shortly or reset your password.';
      case 'network-request-failed':
        return 'Defense network unreachable. Please check your device Wi-Fi or cellular connection.';
      case 'operation-not-allowed':
        return 'Email/Password authorization is disabled in Firebase Console. Please contact security admin.';
      default:
        return e.message ??
            'Authentication failed (${e.code}). Please verify your credentials and try again.';
    }
  }

  Future<void> submit() async {
    setState(() => inlineErrorMessage = null);

    if (!formKey.currentState!.validate()) return;

    setState(() => loading = true);

    final normalizedEmail = emailController.text.trim().toLowerCase();
    final rawPassword = passwordController.text;

    try {
      if (isLogin) {
        final credential =
            await FirebaseAuth.instance.signInWithEmailAndPassword(
          email: normalizedEmail,
          password: rawPassword,
        );

        final user = credential.user;
        if (user == null) {
          throw FirebaseAuthException(
            code: 'user-not-found',
            message: 'User session could not be established.',
          );
        }

        final isGoogle =
            user.providerData.any((p) => p.providerId == 'google.com');

        if (!isGoogle && !user.emailVerified) {
          if (mounted) {
            Navigator.of(context).pushReplacementNamed(AppRouter.verifyEmail);
          }
          return;
        }

        if (mounted) {
          Navigator.of(context).pushReplacementNamed(AppRouter.dashboard);
        }
      } else {
        final credential =
            await FirebaseAuth.instance.createUserWithEmailAndPassword(
          email: normalizedEmail,
          password: rawPassword,
        );

        final user = credential.user;
        if (user != null) {
          try {
            await user.sendEmailVerification();
          } catch (_) {}

          if (mounted) {
            Navigator.of(context).pushReplacementNamed(AppRouter.verifyEmail);
          }
        }
      }
    } on FirebaseAuthException catch (e) {
      if (mounted) {
        final friendlyMsg = _getFriendlyErrorMessage(e, isLogin);
        setState(() {
          inlineErrorMessage = friendlyMsg;
        });

        final isInvalidCred =
            e.code == 'invalid-credential' || e.code == 'user-not-found';

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(friendlyMsg),
            backgroundColor: AppColors.danger,
            duration: const Duration(seconds: 6),
            action: (isLogin && isInvalidCred)
                ? SnackBarAction(
                    label: 'Register',
                    textColor: Colors.white,
                    onPressed: () {
                      setState(() {
                        isLogin = false;
                        inlineErrorMessage = null;
                      });
                    },
                  )
                : null,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          inlineErrorMessage = 'Unexpected error occurred: $e';
        });
      }
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> _showForgotPasswordDialog() async {
    final resetController = TextEditingController(
      text: emailController.text.trim().toLowerCase(),
    );
    final resetFormKey = GlobalKey<FormState>();
    bool resetting = false;

    await showDialog(
      context: context,
      builder: (dialogCtx) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            final themeCtrl = ThemeController.instance;

            return AlertDialog(
              backgroundColor: AppColors.surface,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(16),
                side: const BorderSide(color: AppColors.cardBorder),
              ),
              title: Row(
                children: [
                  Icon(
                    Icons.lock_reset_rounded,
                    color: themeCtrl.primaryColor,
                    size: 24,
                  ),
                  const SizedBox(width: 10),
                  const Text(
                    'Reset Defense Password',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              content: Form(
                key: resetFormKey,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Enter your registered email address. We will dispatch a secure link to reset your defense credentials.',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 13,
                        height: 1.4,
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: resetController,
                      keyboardType: TextInputType.emailAddress,
                      validator: CyberValidators.validateEmail,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                      ),
                      decoration: const InputDecoration(
                        labelText: 'Registered Security Email *',
                        prefixIcon: Icon(
                          Icons.email_outlined,
                          color: AppColors.textMuted,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: resetting ? null : () => Navigator.pop(dialogCtx),
                  child: const Text(
                    'Cancel',
                    style: TextStyle(color: AppColors.textMuted),
                  ),
                ),
                ElevatedButton(
                  onPressed: resetting
                      ? null
                      : () async {
                          if (!resetFormKey.currentState!.validate()) return;
                          setDialogState(() => resetting = true);
                          final targetEmail =
                              resetController.text.trim().toLowerCase();
                          try {
                            await FirebaseAuth.instance.sendPasswordResetEmail(
                              email: targetEmail,
                            );
                            if (dialogCtx.mounted) {
                              Navigator.pop(dialogCtx);
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text(
                                    'Password reset link dispatched to $targetEmail. Check your inbox to proceed.',
                                  ),
                                  backgroundColor: AppColors.safe,
                                  duration: const Duration(seconds: 5),
                                ),
                              );
                            }
                          } on FirebaseAuthException catch (e) {
                            setDialogState(() => resetting = false);
                            if (dialogCtx.mounted) {
                              ScaffoldMessenger.of(dialogCtx).showSnackBar(
                                SnackBar(
                                  content: Text(
                                    _getFriendlyErrorMessage(e, true),
                                  ),
                                  backgroundColor: AppColors.danger,
                                ),
                              );
                            }
                          } catch (e) {
                            setDialogState(() => resetting = false);
                            if (dialogCtx.mounted) {
                              ScaffoldMessenger.of(dialogCtx).showSnackBar(
                                SnackBar(
                                  content: Text('Failed to send reset link: $e'),
                                  backgroundColor: AppColors.danger,
                                ),
                              );
                            }
                          }
                        },
                  child: resetting
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: AppColors.background,
                          ),
                        )
                      : const Text('Send Reset Link'),
                ),
              ],
            );
          },
        );
      },
    );
    resetController.dispose();
  }

  Future<void> googleSignIn() async {
    setState(() {
      loading = true;
      inlineErrorMessage = null;
    });

    try {
      final provider = GoogleAuthProvider();
      UserCredential userCred;

      if (kIsWeb) {
        userCred = await FirebaseAuth.instance.signInWithPopup(provider);
      } else {
        userCred = await FirebaseAuth.instance.signInWithProvider(provider);
      }

      if (userCred.user != null && mounted) {
        Navigator.of(context).pushReplacementNamed(AppRouter.dashboard);
      }
    } on FirebaseAuthException catch (e) {
      if (mounted) {
        String msg = e.message ?? e.code;
        if (e.code == '10' || e.message?.contains('developer error') == true) {
          msg =
              'Google Sign-In SHA-1 fingerprint needs to be registered in Firebase Console. Please sign in using Email & Defense Password.';
        } else if (e.code == 'network-request-failed') {
          msg = 'Network connection failure during Google authentication.';
        }
        setState(() {
          inlineErrorMessage = msg;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(msg),
            backgroundColor: AppColors.danger,
            duration: const Duration(seconds: 5),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        final errText =
            'Google Sign-In unavailable ($e). Please use Email & Password.';
        setState(() {
          inlineErrorMessage = errText;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(errText),
            backgroundColor: AppColors.danger,
            duration: const Duration(seconds: 5),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Widget _buildPasswordRequirements() {
    final pwd = passwordController.text;
    final hasLength = pwd.length >= 8;
    final hasUpper = RegExp(r'[A-Z]').hasMatch(pwd);
    final hasLower = RegExp(r'[a-z]').hasMatch(pwd);
    final hasNumber = RegExp(r'[0-9]').hasMatch(pwd);
    final hasSpecial = RegExp(r'[!@#$%^&*(),.?":{}|<>_\-+=]').hasMatch(pwd);

    final score = [hasLength, hasUpper, hasLower, hasNumber, hasSpecial]
        .where((x) => x)
        .length;

    Color strengthColor = AppColors.danger;
    String strengthLabel = 'Weak';
    if (score >= 5) {
      strengthColor = AppColors.safe;
      strengthLabel = 'Military-Grade';
    } else if (score >= 4) {
      strengthColor = AppColors.safe;
      strengthLabel = 'Strong';
    } else if (score >= 3) {
      strengthColor = AppColors.warning;
      strengthLabel = 'Fair';
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 8),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text(
              'Password Strength',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
            Text(
              strengthLabel,
              style: TextStyle(
                color: strengthColor,
                fontSize: 11,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: pwd.isEmpty ? 0 : (score / 5.0),
            backgroundColor: AppColors.cardBorder,
            valueColor: AlwaysStoppedAnimation<Color>(strengthColor),
            minHeight: 4,
          ),
        ),
        const SizedBox(height: 10),
        Wrap(
          spacing: 6,
          runSpacing: 4,
          children: [
            _buildReqChip('8+ Chars', hasLength),
            _buildReqChip('A-Z', hasUpper),
            _buildReqChip('a-z', hasLower),
            _buildReqChip('0-9', hasNumber),
            _buildReqChip('!@#\$%', hasSpecial),
          ],
        ),
      ],
    );
  }

  Widget _buildReqChip(String label, bool satisfied) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: satisfied
            ? AppColors.safe.withValues(alpha: 0.15)
            : AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(
          color: satisfied
              ? AppColors.safe.withValues(alpha: 0.5)
              : AppColors.cardBorder,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            satisfied ? Icons.check : Icons.circle,
            size: 10,
            color: satisfied ? AppColors.safe : AppColors.textMuted,
          ),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              color: satisfied ? AppColors.textPrimary : AppColors.textMuted,
              fontWeight: satisfied ? FontWeight.w700 : FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final themeCtrl = ThemeController.instance;

    return Scaffold(
      backgroundColor: AppColors.background,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Form(
              key: formKey,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Glowing Shield Emblem
                  Container(
                    width: 76,
                    height: 76,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: themeCtrl.primaryColor.withValues(alpha: 0.15),
                      border: Border.all(
                        color: themeCtrl.primaryColor.withValues(alpha: 0.5),
                        width: 2,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: themeCtrl.glowColor,
                          blurRadius: 24,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                    child: Center(
                      child: Icon(
                        Icons.shield_rounded,
                        size: 38,
                        color: themeCtrl.primaryColor,
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  const Text(
                    'CyberShield',
                    style: TextStyle(
                      fontSize: 28,
                      fontWeight: FontWeight.w900,
                      color: AppColors.textPrimary,
                      letterSpacing: -0.5,
                    ),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'Unified Multi-Vector Cyber Defense Suite',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 14),
                  const CyberBadge(
                    label: 'ZERO-TRUST GATEWAY & SOC-GRADE DEFENSE',
                    type: BadgeType.info,
                    fontSize: 9,
                  ),
                  const SizedBox(height: 24),

                  // Mode Switcher (Sign In / Register)
                  Container(
                    padding: const EdgeInsets.all(4),
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppColors.cardBorder),
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: InkWell(
                            onTap: () {
                              setState(() {
                                isLogin = true;
                                inlineErrorMessage = null;
                              });
                            },
                            borderRadius: BorderRadius.circular(8),
                            child: Container(
                              padding: const EdgeInsets.symmetric(vertical: 10),
                              decoration: BoxDecoration(
                                color: isLogin
                                    ? themeCtrl.primaryColor
                                        .withValues(alpha: 0.15)
                                    : Colors.transparent,
                                borderRadius: BorderRadius.circular(8),
                                border: isLogin
                                    ? Border.all(color: themeCtrl.primaryColor)
                                    : null,
                              ),
                              child: Center(
                                child: Text(
                                  'Sign In',
                                  style: TextStyle(
                                    color: isLogin
                                        ? themeCtrl.primaryColor
                                        : AppColors.textMuted,
                                    fontWeight: isLogin
                                        ? FontWeight.w800
                                        : FontWeight.w500,
                                    fontSize: 13,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                        Expanded(
                          child: InkWell(
                            onTap: () {
                              setState(() {
                                isLogin = false;
                                inlineErrorMessage = null;
                              });
                            },
                            borderRadius: BorderRadius.circular(8),
                            child: Container(
                              padding: const EdgeInsets.symmetric(vertical: 10),
                              decoration: BoxDecoration(
                                color: !isLogin
                                    ? themeCtrl.primaryColor
                                        .withValues(alpha: 0.15)
                                    : Colors.transparent,
                                borderRadius: BorderRadius.circular(8),
                                border: !isLogin
                                    ? Border.all(color: themeCtrl.primaryColor)
                                    : null,
                              ),
                              child: Center(
                                child: Text(
                                  'Register',
                                  style: TextStyle(
                                    color: !isLogin
                                        ? themeCtrl.primaryColor
                                        : AppColors.textMuted,
                                    fontWeight: !isLogin
                                        ? FontWeight.w800
                                        : FontWeight.w500,
                                    fontSize: 13,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),

                  // Inline Error Banner
                  if (inlineErrorMessage != null) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.danger.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: AppColors.danger.withValues(alpha: 0.4),
                        ),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(
                            Icons.error_outline_rounded,
                            color: AppColors.danger,
                            size: 18,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              inlineErrorMessage!,
                              style: const TextStyle(
                                color: AppColors.danger,
                                fontSize: 12,
                                height: 1.35,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],

                  // Form Card
                  CyberShieldCard(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        TextFormField(
                          controller: emailController,
                          keyboardType: TextInputType.emailAddress,
                          validator: CyberValidators.validateEmail,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 14,
                          ),
                          decoration: const InputDecoration(
                            labelText: 'Security Email Address *',
                            prefixIcon: Icon(
                              Icons.email_outlined,
                              color: AppColors.textMuted,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        TextFormField(
                          controller: passwordController,
                          obscureText: obscurePassword,
                          validator: (v) => CyberValidators.validatePassword(
                            v,
                            isLogin: isLogin,
                          ),
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 14,
                          ),
                          decoration: InputDecoration(
                            labelText: isLogin
                                ? 'Defense Password *'
                                : 'Create Defense Password *',
                            prefixIcon: const Icon(
                              Icons.lock_outline,
                              color: AppColors.textMuted,
                            ),
                            suffixIcon: IconButton(
                              icon: Icon(
                                obscurePassword
                                    ? Icons.visibility_outlined
                                    : Icons.visibility_off_outlined,
                                color: AppColors.textMuted,
                              ),
                              onPressed: () => setState(
                                () => obscurePassword = !obscurePassword,
                              ),
                            ),
                          ),
                        ),

                        // Registration: Password Strength Meter
                        if (!isLogin) ...[
                          _buildPasswordRequirements(),
                          const SizedBox(height: 16),
                          TextFormField(
                            controller: confirmController,
                            obscureText: obscureConfirm,
                            validator: (value) {
                              if (value == null || value.isEmpty) {
                                return 'Confirm password is required';
                              }
                              if (value != passwordController.text) {
                                return 'Passwords do not match';
                              }
                              return null;
                            },
                            style: const TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 14,
                            ),
                            decoration: InputDecoration(
                              labelText: 'Confirm Defense Password *',
                              prefixIcon: const Icon(
                                Icons.lock_clock_outlined,
                                color: AppColors.textMuted,
                              ),
                              suffixIcon: IconButton(
                                icon: Icon(
                                  obscureConfirm
                                      ? Icons.visibility_outlined
                                      : Icons.visibility_off_outlined,
                                  color: AppColors.textMuted,
                                ),
                                onPressed: () => setState(
                                  () => obscureConfirm = !obscureConfirm,
                                ),
                              ),
                            ),
                          ),
                        ],

                        if (isLogin) ...[
                          const SizedBox(height: 8),
                          Align(
                            alignment: Alignment.centerRight,
                            child: TextButton(
                              style: TextButton.styleFrom(
                                padding: EdgeInsets.zero,
                                minimumSize: const Size(50, 30),
                                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                              ),
                              onPressed: _showForgotPasswordDialog,
                              child: Text(
                                'Forgot Defense Password?',
                                style: TextStyle(
                                  color: themeCtrl.primaryColor,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ),
                        ],

                        const SizedBox(height: 22),
                        SizedBox(
                          width: double.infinity,
                          height: 48,
                          child: ElevatedButton(
                            onPressed: loading ? null : submit,
                            child: loading
                                ? const SizedBox(
                                    width: 20,
                                    height: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: AppColors.background,
                                    ),
                                  )
                                : Text(
                                    isLogin
                                        ? 'Authorize & Enter CyberShield'
                                        : 'Create Security Profile',
                                    style: const TextStyle(
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 18),
                  const Row(
                    children: [
                      Expanded(child: Divider(color: AppColors.cardBorder)),
                      Padding(
                        padding: EdgeInsets.symmetric(horizontal: 12),
                        child: Text(
                          'FEDERATED ZERO-TRUST IDENTITY',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1,
                          ),
                        ),
                      ),
                      Expanded(child: Divider(color: AppColors.cardBorder)),
                    ],
                  ),
                  const SizedBox(height: 18),

                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: OutlinedButton.icon(
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: AppColors.cardBorder),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                      onPressed: loading ? null : googleSignIn,
                      icon: const Icon(
                        Icons.g_mobiledata,
                        size: 28,
                        color: Colors.white,
                      ),
                      label: const Text(
                        'Authenticate with Google',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Product Tour Link
                  TextButton.icon(
                    onPressed: () =>
                        Navigator.pushNamed(context, AppRouter.onboarding),
                    icon: const Icon(
                      Icons.explore_rounded,
                      size: 16,
                      color: AppColors.textMuted,
                    ),
                    label: const Text(
                      'Explore Product Tour & Capabilities',
                      style:
                          TextStyle(color: AppColors.textMuted, fontSize: 12),
                    ),
                  ),
                  const SizedBox(height: 8),

                  // Footer Security Badges
                  const Wrap(
                    alignment: WrapAlignment.center,
                    spacing: 12,
                    children: [
                      Text(
                        '🔒 256-Bit SSL Encrypted',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 10,
                        ),
                      ),
                      Text(
                        '🛡️ Zero-Knowledge Auditing',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 10,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
