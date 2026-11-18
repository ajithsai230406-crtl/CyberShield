import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

enum BadgeType { safe, warning, danger, info, neutral }

class CyberBadge extends StatelessWidget {
  final String label;
  final BadgeType type;
  final IconData? icon;
  final double fontSize;

  const CyberBadge({
    super.key,
    required this.label,
    this.type = BadgeType.info,
    this.icon,
    this.fontSize = 11,
  });

  Color get _color {
    switch (type) {
      case BadgeType.safe:
        return AppColors.safe;
      case BadgeType.warning:
        return AppColors.warning;
      case BadgeType.danger:
        return AppColors.danger;
      case BadgeType.info:
        return AppColors.primary;
      case BadgeType.neutral:
        return AppColors.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: _color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: _color.withValues(alpha: 0.4),
          width: 1,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: fontSize + 1, color: _color),
            const SizedBox(width: 4),
          ],
          Text(
            label,
            style: TextStyle(
              color: _color,
              fontSize: fontSize,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}

