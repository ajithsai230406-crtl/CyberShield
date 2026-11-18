package com.example.mobile.services

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.mobile.MainActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Module 4: Automatic Newly Installed APK / Package Analysis.
 *
 * Listens for ACTION_PACKAGE_ADDED broadcasts fired by Android when an app
 * is newly installed or updated.
 *
 * Inspects package metadata, installer source, requested permissions,
 * dangerous permission combinations, and signing certificates.
 *
 * NOTE (Platform Limitation): A package-added broadcast occurs after installation.
 * It cannot block an APK before installation, but provides instant post-install
 * threat intelligence and forensics.
 */
class CyberShieldPackageReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "CyberShieldPkgRecv"
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_API_BASE_URL = "api_base_url"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_PENDING_COMM_EVENTS = "pending_comm_events"
        const val CHANNEL_ID = "cybershield_threat_alerts"
        const val CHANNEL_NAME = "CyberShield Threat Alerts"
        private const val BACKEND_TIMEOUT_MS = 4000
        private const val MAX_PENDING_EVENTS = 100

        // Dangerous permission weights for on-device heuristic evaluation
        private val DANGEROUS_PERMS = mapOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to 25,
            "android.permission.SYSTEM_ALERT_WINDOW" to 20,
            "android.permission.RECEIVE_SMS" to 20,
            "android.permission.READ_SMS" to 20,
            "android.permission.SEND_SMS" to 20,
            "android.permission.REQUEST_INSTALL_PACKAGES" to 20,
            "android.permission.RECORD_AUDIO" to 15,
            "android.permission.CAMERA" to 15,
            "android.permission.ACCESS_FINE_LOCATION" to 15,
            "android.permission.READ_CONTACTS" to 15,
            "android.permission.READ_CALL_LOG" to 15,
            "android.permission.WRITE_SETTINGS" to 15
        )
    }

    private val executor = Executors.newSingleThreadExecutor()

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) return

        val uri = intent.data ?: return
        val packageName = uri.schemeSpecificPart ?: return

        // Ignore updates if not replacing or if self
        if (packageName == context.packageName) return

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_PROTECTION_ENABLED, true)) return

        executor.execute {
            analyzeInstalledPackage(context.applicationContext, prefs, packageName)
        }
    }

    private fun analyzeInstalledPackage(context: Context, prefs: SharedPreferences, packageName: String) {
        val pm = context.packageManager
        val pkgInfo: PackageInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(
                        (PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve PackageInfo for $packageName: ${e.message}")
            return
        }

        val appInfo = pkgInfo.applicationInfo ?: return
        val appName = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            packageName
        }

        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        if (isSystem) return // Skip pre-installed system apps

        val installerPackage = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }

        val requestedPermissions = pkgInfo.requestedPermissions?.toList() ?: emptyList()
        val permSet = requestedPermissions.toSet()

        // 1. Calculate Local Static Heuristic Risk Score
        var riskScore = 0
        val suspiciousIndicators = mutableListOf<String>()
        val permissionsOfConcern = mutableListOf<String>()

        for ((perm, weight) in DANGEROUS_PERMS) {
            if (permSet.contains(perm)) {
                riskScore += weight
                val simpleName = perm.substringAfterLast(".")
                permissionsOfConcern.add(simpleName)
            }
        }

        // Dangerous combo detection
        val hasSms = permSet.contains("android.permission.READ_SMS") || permSet.contains("android.permission.RECEIVE_SMS")
        val hasAccessibility = permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasOverlay = permSet.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasInstall = permSet.contains("android.permission.REQUEST_INSTALL_PACKAGES")

        if (hasSms && hasAccessibility) {
            suspiciousIndicators.add("Banking Trojan Pattern: SMS access combined with Accessibility Service.")
            riskScore += 30
        }
        if (hasSms && hasOverlay) {
            suspiciousIndicators.add("Credential Harvesting: SMS access combined with Overlay / System Alert Window.")
            riskScore += 25
        }
        if (hasInstall && hasAccessibility) {
            suspiciousIndicators.add("Silent Dropper: Request Install Packages combined with Accessibility Service.")
            riskScore += 25
        }

        val isSideloaded = installerPackage == null || installerPackage !in listOf(
            "com.android.vending",
            "com.google.android.feedback"
        )
        if (isSideloaded && permissionsOfConcern.isNotEmpty()) {
            suspiciousIndicators.add("Sideloaded app: Installed outside Google Play Store ($installerPackage).")
            riskScore += 10
        }

        // Extract signing certificate SHA-256 fingerprint if available
        val certFingerprint = getCertSha256(pkgInfo)

        riskScore = riskScore.coerceIn(0, 100)
        val safetyScore = 100 - riskScore

        val classification = when {
            riskScore >= 70 -> "Critical"
            riskScore >= 45 -> "High Risk"
            riskScore >= 20 -> "Suspicious"
            else -> "Safe"
        }

        val explanation = when {
            riskScore == 0 -> "No suspicious indicators detected. Package metadata and declared permissions within normal boundaries."
            suspiciousIndicators.isNotEmpty() -> suspiciousIndicators.joinToString(" ")
            else -> "Declared ${permissionsOfConcern.size} sensitive permissions: ${permissionsOfConcern.joinToString(", ")}."
        }

        val recommendedActions = when (classification) {
            "Critical" -> listOf("Uninstall this application immediately.", "Do not grant Accessibility or Overlay permissions.")
            "High Risk" -> listOf("Review application permissions in Android Settings.", "Disable unnecessary SMS or background permissions.")
            "Suspicious" -> listOf("Monitor application activity.", "Verify that the app source is trustworthy.")
            else -> listOf("No action required. Application appears clean.")
        }

        val eventMap = hashMapOf<String, Any?>(
            "type" to "installed_apk",
            "packageName" to packageName,
            "appName" to appName,
            "versionName" to (pkgInfo.versionName ?: "1.0"),
            "installerPackage" to (installerPackage ?: "Unknown/Sideload"),
            "riskScore" to riskScore,
            "safetyScore" to safetyScore,
            "classification" to classification,
            "explanation" to explanation,
            "permissionsOfConcern" to permissionsOfConcern,
            "suspiciousIndicators" to suspiciousIndicators,
            "certFingerprint" to certFingerprint,
            "recommendedActions" to recommendedActions,
            "timestamp" to System.currentTimeMillis()
        )

        // Emit to Flutter live if running
        ProtectionEventBus.emitEvent(eventMap)
        enqueuePendingEvent(prefs, eventMap)

        // Post Android notification based on threat level
        // Clean scan (riskScore == 0 / Safe): No notification per prompt requirements
        // Suspicious: Warning notification
        // High-risk / Critical: Critical security notification
        if (classification != "Safe") {
            postApkAlert(
                context = context,
                packageName = packageName,
                appName = appName,
                classification = classification,
                riskScore = riskScore,
                safetyScore = safetyScore,
                explanation = explanation,
                permissionsOfConcern = permissionsOfConcern,
                recommendedAction = recommendedActions.firstOrNull() ?: "Review app"
            )
        }

        // Also query cloud backend if online for threat intelligence sync
        val apiBaseUrl = prefs.getString(KEY_API_BASE_URL, null)?.trim()?.trimEnd('/')
        val authToken = prefs.getString(KEY_AUTH_TOKEN, null)?.trim()
        if (!apiBaseUrl.isNullOrEmpty() && !authToken.isNullOrEmpty()) {
            syncApkWithBackend(apiBaseUrl, authToken, eventMap)
        }
    }

    private fun postApkAlert(
        context: Context,
        packageName: String,
        appName: String,
        classification: String,
        riskScore: Int,
        safetyScore: Int,
        explanation: String,
        permissionsOfConcern: List<String>,
        recommendedAction: String
    ) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "CyberShield Threat Alerts"
                enableLights(true)
                enableVibration(true)
            }
            manager.createNotificationChannel(channel)
        }

        // PendingIntent to launch CyberShield and open APK Detector / Permission Analyzer
        val launchIntent = Intent(context, MainActivity::class.java).apply {
            action = "com.example.mobile.ACTION_VIEW_THREAT"
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("extra_screen", "apk_analysis")
            putExtra("extra_type", "apk")
            putExtra("extra_package_name", packageName)
            putExtra("extra_app_name", appName)
            putExtra("extra_risk_score", riskScore)
            putExtra("extra_safety_score", safetyScore)
            putExtra("extra_classification", classification)
            putExtra("extra_explanation", explanation)
            putExtra("extra_event_id", "pkg-${System.currentTimeMillis()}-$packageName")
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            launchIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
        )

        val title = "CyberShield Alert: $classification APK ($appName)"
        val body = "$appName ($packageName) flagged with $riskScore% risk ($safetyScore/100 safety). $explanation $recommendedAction"

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        try {
            manager.notify(packageName.hashCode() + 200000, builder.build())
        } catch (_: SecurityException) {
            // Android 13+ POST_NOTIFICATIONS may not yet be granted
        }
    }

    private fun syncApkWithBackend(apiBaseUrl: String, authToken: String, eventMap: Map<String, Any?>) {
        var conn: HttpURLConnection? = null
        try {
            val endpoint = URL("$apiBaseUrl/api/v1/permissions/analyze-batch")
            conn = (endpoint.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = BACKEND_TIMEOUT_MS
                readTimeout = BACKEND_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Authorization", "Bearer $authToken")
            }

            val appObj = JSONObject().apply {
                put("packageName", eventMap["packageName"])
                put("appName", eventMap["appName"])
                put("versionName", eventMap["versionName"])
                put("permissions", JSONArray(eventMap["permissionsOfConcern"] as? List<*> ?: emptyList<String>()))
            }
            val payload = JSONObject().apply {
                put("apps", JSONArray().put(appObj))
            }

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(payload.toString())
                writer.flush()
            }
            conn.responseCode // Read to finish request
        } catch (_: Exception) {
            // Backend sync fail-safe
        } finally {
            conn?.disconnect()
        }
    }

    private fun getCertSha256(pkgInfo: PackageInfo): String? {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures
            }
            val cert = signatures?.firstOrNull() ?: return null
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert.toByteArray())
            digest.joinToString(":") { String.format(Locale.US, "%02X", it) }
        } catch (_: Exception) {
            null
        }
    }

    private fun enqueuePendingEvent(prefs: SharedPreferences, eventMap: Map<String, Any?>) {
        try {
            val existing = prefs.getString(KEY_PENDING_COMM_EVENTS, null)
            val oldArr = if (existing != null) JSONArray(existing) else JSONArray()
            val newArr = JSONArray()
            newArr.put(JSONObject(eventMap))
            val limit = minOf(oldArr.length(), MAX_PENDING_EVENTS - 1)
            for (i in 0 until limit) {
                newArr.put(oldArr.get(i))
            }
            prefs.edit().putString(KEY_PENDING_COMM_EVENTS, newArr.toString()).apply()
        } catch (_: Exception) {
            // Non-fatal queue write
        }
    }
}
