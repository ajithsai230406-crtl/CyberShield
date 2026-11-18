import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class StatusIndicator extends StatelessWidget {
  final String? status;
  final String label;
  final Color? color;
  final bool isActive;

  const StatusIndicator({
    super.key,
    this.status,
    required this.label,
    this.color,
    this.isActive = true,
  });

  Color get _statusColor {
    if (color != null) return color!;
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'active':
      case 'online':
        return AppColors.safe;
      case 'degraded':
      case 'warning':
      case 'checking':
        return AppColors.warning;
      case 'offline':
      case 'error':
      default:
        return AppColors.danger;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: isActive ? _statusColor : AppColors.textMuted,
            shape: BoxShape.circle,
            boxShadow: isActive
                ? [
                    BoxShadow(
                      color: _statusColor.withValues(alpha: 0.5),
                      blurRadius: 6,
                      spreadRadius: 1,
                    ),
                  ]
                : null,
          ),
        ),
        const SizedBox(width: 8),
        Flexible(
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: isActive ? _statusColor : AppColors.textMuted,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ],
    );
  }
}
