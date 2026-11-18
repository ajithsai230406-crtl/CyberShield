import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';

class CyberShieldCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  final Color? backgroundColor;
  final List<Color>? gradientColors;
  final Color? borderColor;
  final VoidCallback? onTap;
  final double borderRadius;
  final bool hasGlow;

  const CyberShieldCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(16),
    this.backgroundColor,
    this.gradientColors,
    this.borderColor,
    this.onTap,
    this.borderRadius = 16,
    this.hasGlow = false,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final defaultBorder = isDark ? AppColors.cardBorder : AppColors.lightCardBorder;
    final defaultBg = isDark ? AppColors.surface : AppColors.lightSurface;
    final effectiveBorderColor = borderColor ?? defaultBorder;
    final effectiveBgColor = backgroundColor ?? defaultBg;
    final radius = BorderRadius.circular(borderRadius);
    final cardShape = RoundedRectangleBorder(
      borderRadius: radius,
      side: BorderSide(
        color: effectiveBorderColor,
        width: 1.2,
      ),
    );

    Widget content = Padding(
      padding: padding,
      child: child,
    );

    if (onTap != null) {
      content = InkWell(
        borderRadius: radius,
        onTap: onTap,
        splashColor: ThemeController.instance.primaryColor.withValues(alpha: 0.1),
        highlightColor: ThemeController.instance.primaryColor.withValues(alpha: 0.05),
        child: content,
      );
    }

    Widget cardWidget;
    if (gradientColors != null) {
      cardWidget = Material(
        color: Colors.transparent,
        shape: cardShape,
        clipBehavior: Clip.antiAlias,
        child: Ink(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: gradientColors!,
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: radius,
          ),
          child: content,
        ),
      );
    } else {
      cardWidget = Material(
        color: effectiveBgColor,
        shape: cardShape,
        clipBehavior: Clip.antiAlias,
        child: content,
      );
    }

    if (hasGlow) {
      return DecoratedBox(
        decoration: BoxDecoration(
          borderRadius: radius,
          boxShadow: [
            BoxShadow(
              color: effectiveBorderColor.withValues(alpha: 0.15),
              blurRadius: 12,
              spreadRadius: 2,
            ),
          ],
        ),
        child: cardWidget,
      );
    }

    return cardWidget;
  }
}

typedef CyberCard = CyberShieldCard;
