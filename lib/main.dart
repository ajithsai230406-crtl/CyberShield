
import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:cybershield/app.dart';
import 'package:cybershield/core/services/api_service.dart';
import 'firebase_options.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  await ApiService.init();

  runApp(const CyberShieldApp());
}
