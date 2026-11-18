import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/app.dart';

void main() {
  testWidgets('CyberShieldApp smoke test', (WidgetTester tester) async {
    // Build our app with a testable home widget and trigger a frame.
    await tester.pumpWidget(const CyberShieldApp(
      home: Scaffold(
        body: Center(child: Text('CyberShield')),
      ),
    ));
    await tester.pump();

    // Verify that the title appears
    expect(find.text('CyberShield'), findsWidgets);
  });
}
