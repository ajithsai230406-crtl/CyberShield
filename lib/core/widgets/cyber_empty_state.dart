import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class CyberEmptyState extends StatelessWidget {
  final IconData icon;
  final String title;
  final String description;
  final Widget? action;
  final String? actionLabel;
  final VoidCallback? onAction;

  const CyberEmptyState({
    super.key,
    required this.icon,
    required this.title,
    required this.description,
    this.action,
    this.actionLabel,
    this.onAction,
  });

  @override
  Widget build(BuildContext context) {
    Widget? effectiveAction = action;
    if (effectiveAction == null && actionLabel != null && onAction != null) {
      effectiveAction = ElevatedButton(
        onPressed: onAction,
        child: Text(actionLabel!),
      );
    }

    return CyberShieldCard(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppColors.primary.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                icon,
                color: AppColors.primary,
                size: 36,
              ),
            ),
            const SizedBox(height: 16),
            Text(
              title,
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.w700,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              description,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.4,
              ),
              textAlign: TextAlign.center,
            ),
            if (effectiveAction != null) ...[
              const SizedBox(height: 18),
              effectiveAction,
            ],
          ],
        ),
      ),
    );
  }
}
