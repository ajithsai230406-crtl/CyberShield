import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';

class CyberErrorState extends StatelessWidget {
  final String title;
  final String message;
  final VoidCallback? onRetry;

  const CyberErrorState({
    super.key,
    this.title = 'Scan Request Failed',
    required this.message,
    this.onRetry,
  });

  @override
  Widget build(BuildContext context) {
    return CyberShieldCard(
      borderColor: AppColors.danger.withValues(alpha: 0.4),
      backgroundColor: AppColors.surface,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.danger.withValues(alpha: 0.15),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.error_outline_rounded,
                color: AppColors.danger,
                size: 32,
              ),
            ),
            const SizedBox(height: 14),
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
              message,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.4,
              ),
              textAlign: TextAlign.center,
            ),
            if (onRetry != null) ...[
              const SizedBox(height: 18),
              OutlinedButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh_rounded, size: 18),
                label: const Text('Retry Scan'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppColors.primary,
                  side: const BorderSide(color: AppColors.primary),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

