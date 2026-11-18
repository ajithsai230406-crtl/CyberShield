import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class CyberLoadingState extends StatefulWidget {
  final String title;
  final String subtitle;

  const CyberLoadingState({
    super.key,
    this.title = 'Analyzing Target...',
    this.subtitle = 'Inspecting protocol, host legitimacy, and heuristic indicators',
  });

  @override
  State<CyberLoadingState> createState() => _CyberLoadingStateState();
}

class _CyberLoadingStateState extends State<CyberLoadingState>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _animation = CurvedAnimation(parent: _controller, curve: Curves.easeInOut);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 40, horizontal: 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            AnimatedBuilder(
              animation: _animation,
              builder: (context, child) {
                return Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: AppColors.primary
                            .withValues(alpha: 0.15 + (_animation.value * 0.25)),
                        blurRadius: 20 + (_animation.value * 15),
                        spreadRadius: 2 + (_animation.value * 6),
                      ),
                    ],
                  ),
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      SizedBox(
                        width: 72,
                        height: 72,
                        child: CircularProgressIndicator(
                          strokeWidth: 3,
                          valueColor: const AlwaysStoppedAnimation<Color>(
                              AppColors.primary),
                          backgroundColor:
                              AppColors.primary.withValues(alpha: 0.15),
                        ),
                      ),
                      const Icon(
                        Icons.shield_outlined,
                        size: 32,
                        color: AppColors.primary,
                      ),
                    ],
                  ),
                );
              },
            ),
            const SizedBox(height: 24),
            Text(
              widget.title,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.w700,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              widget.subtitle,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.4,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

