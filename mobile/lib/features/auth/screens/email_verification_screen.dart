// CyberShield Zero-Trust Email Verification Screen

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/cyber_badge.dart';
import 'package:cybershield/core/navigation/app_router.dart';

class EmailVerificationScreen extends StatefulWidget {
  final User? user;

  const EmailVerificationScreen({super.key, this.user});

  @override
  State<EmailVerificationScreen> createState() => _EmailVerificationScreenState();
}

class _EmailVerificationScreenState extends State<EmailVerificationScreen> {
  bool _isChecking = false;
  bool _isResending = false;
  int _resendCooldown = 0;
  Timer? _cooldownTimer;
  Timer? _autoCheckTimer;
  String? _statusFeedback;
  bool _isSuccessFeedback = false;

  User? get _currentUser => widget.user ?? FirebaseAuth.instance.currentUser;

  @override
  void initState() {
    super.initState();
    // Start periodic auto-check every 5 seconds to automatically detect when user clicks link
    _startAutoCheckTimer();
  }

  @override
  void dispose() {
    _cooldownTimer?.cancel();
    _autoCheckTimer?.cancel();
    super.dispose();
  }

  void _startAutoCheckTimer() {
    _autoCheckTimer = Timer.periodic(const Duration(seconds: 5), (_) async {
      await _checkVerificationStatus(isAuto: true);
    });
  }

  void _startCooldown(int seconds) {
    setState(() {
      _resendCooldown = seconds;
    });
    _cooldownTimer?.cancel();
    _cooldownTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (_resendCooldown <= 1) {
        timer.cancel();
        if (mounted) {
          setState(() {
            _resendCooldown = 0;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _resendCooldown--;
          });
        }
      }
    });
  }

  Future<void> _checkVerificationStatus({bool isAuto = false}) async {
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) return;

    if (!isAuto && mounted) {
      setState(() {
        _isChecking = true;
        _statusFeedback = null;
      });
    }

    try {
      await user.reload();
      final refreshedUser = FirebaseAuth.instance.currentUser;

      if (refreshedUser != null && refreshedUser.emailVerified) {
        _autoCheckTimer?.cancel();
        if (mounted) {
          setState(() {
            _isChecking = false;
            _statusFeedback = 'Email verified successfully! Authorizing entry...';
            _isSuccessFeedback = true;
          });

          await Future.delayed(const Duration(milliseconds: 600));
          if (mounted) {
            Navigator.of(context).pushNamedAndRemoveUntil(
              AppRouter.dashboard,
              (route) => false,
            );
          }
        }
        return;
      }

      if (!isAuto && mounted) {
        setState(() {
          _isChecking = false;
          _statusFeedback =
              'Verification link not yet clicked. Please check your inbox and tap the confirmation link.';
          _isSuccessFeedback = false;
        });
      }
    } catch (e) {
      if (!isAuto && mounted) {
        setState(() {
          _isChecking = false;
          _statusFeedback = 'Verification check failed: $e';
          _isSuccessFeedback = false;
        });
      }
    }
  }

  Future<void> _resendVerificationEmail() async {
    if (_resendCooldown > 0 || _isResending) return;

    final user = FirebaseAuth.instance.currentUser;
    if (user == null) return;

    setState(() {
      _isResending = true;
      _statusFeedback = null;
    });

    try {
      await user.sendEmailVerification();
      _startCooldown(60);

      if (mounted) {
        setState(() {
          _isResending = false;
          _statusFeedback =
              'A fresh verification link has been dispatched to ${user.email}.';
          _isSuccessFeedback = true;
        });

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Verification link dispatched to ${user.email}'),
            backgroundColor: AppColors.safe,
            duration: const Duration(seconds: 4),
          ),
        );
      }
    } on FirebaseAuthException catch (e) {
      if (mounted) {
        setState(() {
          _isResending = false;
          if (e.code == 'too-many-requests') {
            _statusFeedback =
                'Rate limited: Too many requests. Please wait a minute before requesting another verification email.';
            _startCooldown(60);
          } else {
            _statusFeedback =
                e.message ?? 'Failed to dispatch verification email.';
          }
          _isSuccessFeedback = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isResending = false;
          _statusFeedback = 'Error sending verification: $e';
          _isSuccessFeedback = false;
        });
      }
    }
  }

  Future<void> _signOut() async {
    _autoCheckTimer?.cancel();
    _cooldownTimer?.cancel();
    await FirebaseAuth.instance.signOut();
    if (mounted) {
      Navigator.of(context).pushNamedAndRemoveUntil(
        AppRouter.login,
        (route) => false,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final themeCtrl = ThemeController.instance;
    final email = _currentUser?.email ?? 'Your registered email';

    return Scaffold(
      backgroundColor: AppColors.background,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Glowing Shield & Envelope Emblem
                Stack(
                  alignment: Alignment.center,
                  children: [
                    Container(
                      width: 84,
                      height: 84,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: themeCtrl.primaryColor.withValues(alpha: 0.12),
                        border: Border.all(
                          color: themeCtrl.primaryColor.withValues(alpha: 0.45),
                          width: 2,
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: themeCtrl.glowColor,
                            blurRadius: 28,
                            spreadRadius: 2,
                          ),
                        ],
                      ),
                      child: Center(
                        child: Icon(
                          Icons.mark_email_unread_rounded,
                          size: 42,
                          color: themeCtrl.primaryColor,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 20),
                const Text(
                  'Verify Defense Email',
                  style: TextStyle(
                    fontSize: 26,
                    fontWeight: FontWeight.w900,
                    color: AppColors.textPrimary,
                    letterSpacing: -0.5,
                  ),
                ),
                const SizedBox(height: 6),
                const Text(
                  'Zero-Trust Identity Authentication Required',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 14),
                const CyberBadge(
                  label: 'STATUS: EMAIL VERIFICATION PENDING',
                  type: BadgeType.warning,
                  fontSize: 10,
                ),
                const SizedBox(height: 24),

                CyberShieldCard(
                  padding: const EdgeInsets.all(22),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(
                            Icons.verified_user_outlined,
                            color: AppColors.warning,
                            size: 22,
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Confirmation Link Dispatched',
                                  style: TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 14,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                                const SizedBox(height: 4),
                                const Text(
                                  'To safeguard your threat telemetry, cloud history, and incident response data, all accounts must verify email ownership before entering the CyberShield SOC.',
                                  style: TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 12,
                                    height: 1.4,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),

                      // Display Target Email Address
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 10,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.surfaceLight,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: AppColors.cardBorder),
                        ),
                        child: Row(
                          children: [
                            const Icon(
                              Icons.email_outlined,
                              size: 18,
                              color: AppColors.primary,
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                email,
                                style: const TextStyle(
                                  color: AppColors.textPrimary,
                                  fontWeight: FontWeight.w700,
                                  fontSize: 13,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 20),

                      // Status Feedback Banner
                      if (_statusFeedback != null) ...[
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: (_isSuccessFeedback
                                    ? AppColors.safe
                                    : AppColors.warning)
                                .withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(
                              color: (_isSuccessFeedback
                                      ? AppColors.safe
                                      : AppColors.warning)
                                  .withValues(alpha: 0.4),
                            ),
                          ),
                          child: Row(
                            children: [
                              Icon(
                                _isSuccessFeedback
                                    ? Icons.check_circle_outline_rounded
                                    : Icons.info_outline_rounded,
                                size: 18,
                                color: _isSuccessFeedback
                                    ? AppColors.safe
                                    : AppColors.warning,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  _statusFeedback!,
                                  style: TextStyle(
                                    color: _isSuccessFeedback
                                        ? AppColors.safe
                                        : AppColors.warning,
                                    fontSize: 12,
                                    height: 1.35,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(height: 18),
                      ],

                      // Primary Action: Check Verification Status
                      SizedBox(
                        height: 48,
                        child: ElevatedButton.icon(
                          onPressed:
                              _isChecking ? null : () => _checkVerificationStatus(),
                          icon: _isChecking
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: AppColors.background,
                                  ),
                                )
                              : const Icon(Icons.refresh_rounded, size: 20),
                          label: Text(
                            _isChecking
                                ? 'Checking Verification...'
                                : 'I Have Verified / Check Status',
                            style: const TextStyle(fontWeight: FontWeight.w700),
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),

                      // Secondary Action: Resend Verification Email
                      SizedBox(
                        height: 44,
                        child: OutlinedButton.icon(
                          onPressed: (_resendCooldown > 0 || _isResending)
                              ? null
                              : _resendVerificationEmail,
                          icon: _isResending
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: AppColors.primary,
                                  ),
                                )
                              : const Icon(Icons.send_rounded, size: 16),
                          label: Text(
                            _resendCooldown > 0
                                ? 'Resend Available in ${_resendCooldown}s'
                                : 'Resend Verification Email',
                            style: const TextStyle(fontSize: 13),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Helpful Security Tip Card
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.surface,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppColors.cardBorder),
                  ),
                  child: const Row(
                    children: [
                      Icon(
                        Icons.lightbulb_outline_rounded,
                        color: AppColors.textMuted,
                        size: 18,
                      ),
                      SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'Tip: If you do not see the email in your inbox within 2 minutes, check your spam or junk folder.',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                            height: 1.35,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Sign Out / Switch Account
                TextButton.icon(
                  onPressed: _signOut,
                  icon: const Icon(
                    Icons.logout_rounded,
                    size: 16,
                    color: AppColors.danger,
                  ),
                  label: const Text(
                    'Sign In with a Different Account',
                    style: TextStyle(
                      color: AppColors.danger,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
