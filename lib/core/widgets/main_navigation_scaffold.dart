// CyberShield Main Navigation Scaffold
// Provides unified 5-tab Bottom Navigation and hosts the CYBOR Floating AI Assistant

import 'package:flutter/material.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cybor_floating_widget.dart';
import 'package:cybershield/features/dashboard/screens/dashboard_screen.dart';
import 'package:cybershield/features/scan_hub/screens/scan_hub_screen.dart';
import 'package:cybershield/features/protection/screens/protection_dashboard_screen.dart';
import 'package:cybershield/features/history/screens/history_screen.dart';
import 'package:cybershield/features/settings/screens/settings_screen.dart';

class MainNavigationScaffold extends StatefulWidget {
  final int initialIndex;

  const MainNavigationScaffold({
    super.key,
    this.initialIndex = 0,
  });

  @override
  State<MainNavigationScaffold> createState() => _MainNavigationScaffoldState();
}

class _MainNavigationScaffoldState extends State<MainNavigationScaffold> {
  late int _currentIndex;
  Offset? _cyborOffset;

  final List<Widget> _pages = const [
    DashboardScreen(),
    ScanHubScreen(),
    ProtectionDashboardScreen(),
    HistoryScreen(),
    SettingsScreen(),
  ];

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialIndex;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: LayoutBuilder(
        builder: (context, constraints) {
          const buttonWidth = 128.0;
          const buttonHeight = 46.0;
          const margin = 12.0;

          final maxX = (constraints.maxWidth - buttonWidth - margin).clamp(margin, double.infinity);
          final maxY = (constraints.maxHeight - buttonHeight - margin).clamp(margin, double.infinity);

          final currentOffset = _cyborOffset ?? Offset(maxX, (maxY - 8).clamp(margin, maxY));
          final clampedX = currentOffset.dx.clamp(margin, maxX);
          final clampedY = currentOffset.dy.clamp(margin + 48, maxY);

          return Stack(
            children: [
              IndexedStack(
                index: _currentIndex,
                children: _pages,
              ),
              // Movable CYBOR AI floating button — drag anywhere so it never covers content or navigation
              Positioned(
                left: clampedX,
                top: clampedY,
                child: GestureDetector(
                  onPanUpdate: (details) {
                    setState(() {
                      _cyborOffset = Offset(
                        (clampedX + details.delta.dx).clamp(margin, maxX),
                        (clampedY + details.delta.dy).clamp(margin + 48, maxY),
                      );
                    });
                  },
                  child: const CyborFloatingWidget(),
                ),
              ),
            ],
          );
        },
      ),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          color: AppColors.surface,
          border: Border(
            top: BorderSide(color: AppColors.cardBorder, width: 1),
          ),
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (index) {
            setState(() {
              _currentIndex = index;
            });
          },
          type: BottomNavigationBarType.fixed,
          backgroundColor: AppColors.surface,
          selectedItemColor: AppColors.primary,
          unselectedItemColor: AppColors.textMuted,
          selectedFontSize: 11,
          unselectedFontSize: 10,
          elevation: 0,
          items: const [
            BottomNavigationBarItem(
              icon: Icon(Icons.dashboard_rounded, size: 20),
              activeIcon: Icon(Icons.dashboard_rounded, size: 22),
              label: 'Home',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.radar_rounded, size: 20),
              activeIcon: Icon(Icons.radar_rounded, size: 22),
              label: 'Scanners',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.shield_outlined, size: 20),
              activeIcon: Icon(Icons.shield_rounded, size: 22),
              label: 'Protection',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.history_rounded, size: 20),
              activeIcon: Icon(Icons.history_rounded, size: 22),
              label: 'History',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.tune_rounded, size: 20),
              activeIcon: Icon(Icons.tune_rounded, size: 22),
              label: 'Settings',
            ),
          ],
        ),
      ),
    );
  }
}

