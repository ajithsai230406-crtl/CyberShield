import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class StatusIndicator extends StatelessWidget {
  final String label;
  final Color color;
  final bool isActive;

  const StatusIndicator({
    super.key,
    required this.label,
    required this.color,
    this.isActive = true,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: isActive ? color : AppColors.textMuted,
            shape: BoxShape.circle,
            boxShadow: isActive
                ? [BoxShadow(color: color.withValues(alpha: 0.5), blurRadius: 6)]
                : null,
          ),
        ),
        const SizedBox(width: 8),
        Text(
          label,
          style: TextStyle(
            color: isActive ? AppColors.textPrimary : AppColors.textMuted,
            fontSize: 13,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}

