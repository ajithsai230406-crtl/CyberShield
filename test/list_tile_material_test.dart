// Widget tests verifying ListTile, SwitchListTile, CheckboxListTile, ExpansionTile,
// NavDrawer, and CyberShieldCard render without any Material / ink splash assertions.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/navigation/app_router.dart';
import 'package:cybershield/core/theme/app_theme.dart';
import 'package:cybershield/core/widgets/cyber_card.dart';
import 'package:cybershield/core/widgets/nav_drawer.dart';

void main() {
  group('ListTile & Material Ink Splash Hierarchy Tests', () {
    testWidgets('NavDrawer renders all ListTiles with proper Material ancestors and no assertions',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: Scaffold(
            drawer: const NavDrawer(currentRoute: AppRouter.dashboard),
            body: Builder(
              builder: (context) => ElevatedButton(
                onPressed: () => Scaffold.of(context).openDrawer(),
                child: const Text('Open Drawer'),
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Open Drawer'));
      await tester.pumpAndSettle();

      // Verify nav items rendered
      expect(find.text('Dashboard'), findsOneWidget);
      expect(find.text('Communication History'), findsOneWidget);
      expect(find.text('Logout / Switch Account'), findsOneWidget);

      // Tap selected Dashboard tile to trigger ink splash without throwing
      await tester.tap(find.text('Dashboard'));
      await tester.pumpAndSettle();

      expect(tester.takeException(), isNull);
    });

    testWidgets('CyberShieldCard supports ListTile, SwitchListTile, CheckboxListTile, and ExpansionTile cleanly',
        (WidgetTester tester) async {
      bool switchVal = true;
      bool checkVal = false;
      bool tapped = false;

      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme(),
          home: Scaffold(
            body: StatefulBuilder(
              builder: (context, setState) => ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  CyberShieldCard(
                    hasGlow: true,
                    child: Column(
                      children: [
                        ListTile(
                          title: const Text('Privacy Policy'),
                          onTap: () => tapped = true,
                        ),
                        SwitchListTile(
                          title: const Text('Threat Alerts'),
                          value: switchVal,
                          onChanged: (v) => setState(() => switchVal = v),
                        ),
                        CheckboxListTile(
                          title: const Text('READ_SMS'),
                          value: checkVal,
                          onChanged: (v) => setState(() => checkVal = v ?? false),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  const CyberShieldCard(
                    gradientColors: [Color(0xFF131F3B), Color(0xFF0C1326)],
                    child: ExpansionTile(
                      title: Text('Installed App Details'),
                      children: [
                        Padding(
                          padding: EdgeInsets.all(8),
                          child: Text('Expanded content'),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Privacy Policy'));
      await tester.pumpAndSettle();
      expect(tapped, isTrue);

      await tester.tap(find.text('Threat Alerts'));
      await tester.pumpAndSettle();
      expect(switchVal, isFalse);

      await tester.tap(find.text('READ_SMS'));
      await tester.pumpAndSettle();
      expect(checkVal, isTrue);

      await tester.tap(find.text('Installed App Details'));
      await tester.pumpAndSettle();
      expect(find.text('Expanded content'), findsOneWidget);

      expect(tester.takeException(), isNull);
    });
  });
}
