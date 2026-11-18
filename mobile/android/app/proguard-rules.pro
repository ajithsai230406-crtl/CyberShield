# Flutter ProGuard Rules
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Google Play Services & Firebase
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.android.gms.**
-keep class com.google.firebase.** { *; }
-dontwarn com.google.firebase.**
-dontwarn com.google.android.play.core.**

# Preserve Firebase Auth and Firestore reflection attributes
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-keep class com.google.firebase.auth.** { *; }
-keep class com.google.firebase.firestore.** { *; }

# CyberShield Native Services
-keep class com.example.mobile.services.** { *; }
-keep class com.example.mobile.MainActivity { *; }

