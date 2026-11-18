package com.example.mobile

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Settings
import android.provider.Telephony
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.example.mobile.services.CyberShieldNotificationListenerService
import com.example.mobile.services.ProtectionEventBus
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray

class MainActivity : FlutterActivity() {

    companion object {
        const val METHOD_CHANNEL = "com.example.mobile/protection"
        const val EVENT_CHANNEL = "com.example.mobile/protection_events"
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_SILENCE_SPAM = "call_screening_silence_spam"
        const val KEY_API_BASE_URL = "api_base_url"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_SCREENED_CALL_HISTORY = "screened_call_history"
        const val KEY_PENDING_COMM_EVENTS = "pending_comm_events"
        const val CHANNEL_ID = "cybershield_threat_alerts"
        const val CHANNEL_NAME = "CyberShield Threat Alerts"
        const val CRITICAL_CHANNEL_ID = "cybershield_critical_alerts"
        const val CRITICAL_CHANNEL_NAME = "CyberShield Critical & High-Risk Alerts"
        const val DIGEST_CHANNEL_ID = "cybershield_system_digest"
        const val DIGEST_CHANNEL_NAME = "CyberShield Protection Status & Daily Reports"
        const val REQUEST_CODE_CALL_SCREENING = 1001
        const val REQUEST_CODE_COMM_PERMISSIONS = 1003
    }

    private lateinit var prefs: SharedPreferences
    private var pendingCallScreeningResult: MethodChannel.Result? = null
    private var pendingCommPermissionResult: MethodChannel.Result? = null
    private var pendingCommPermissionType: String? = null
    private var launchNotificationPayload: Map<String, Any?>? = null

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        handleNotificationIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleNotificationIntent(intent)
    }

    private fun handleNotificationIntent(intent: Intent?) {
        if (intent == null) return
        if (intent.action == "com.example.mobile.ACTION_VIEW_THREAT" || intent.hasExtra("extra_screen")) {
            val payload = hashMapOf<String, Any?>(
                "action" to (intent.action ?: ""),
                "screen" to (intent.getStringExtra("extra_screen") ?: ""),
                "type" to (intent.getStringExtra("extra_type") ?: ""),
                "sender" to (intent.getStringExtra("extra_sender") ?: ""),
                "phoneNumber" to (intent.getStringExtra("extra_phone_number") ?: ""),
                "packageName" to (intent.getStringExtra("extra_package_name") ?: ""),
                "appName" to (intent.getStringExtra("extra_app_name") ?: ""),
                "content" to (intent.getStringExtra("extra_content") ?: ""),
                "title" to (intent.getStringExtra("extra_title") ?: ""),
                "riskScore" to intent.getIntExtra("extra_risk_score", 0),
                "safetyScore" to intent.getIntExtra("extra_safety_score", 100),
                "classification" to (intent.getStringExtra("extra_classification") ?: "Warning"),
                "explanation" to (intent.getStringExtra("extra_explanation") ?: ""),
                "eventId" to (intent.getStringExtra("extra_event_id") ?: "")
            )
            launchNotificationPayload = payload
            val eventMap = HashMap(payload)
            eventMap["type"] = "notification_tap"
            ProtectionEventBus.emitEvent(eventMap)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        createNotificationChannel()

        // 1. Method Channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "isProtectionMasterEnabled" -> {
                        val enabled = prefs.getBoolean(KEY_PROTECTION_ENABLED, true)
                        result.success(enabled)
                    }
                    "setProtectionMasterEnabled" -> {
                        val enabled = call.argument<Boolean>("enabled") ?: true
                        prefs.edit().putBoolean(KEY_PROTECTION_ENABLED, enabled).apply()
                        result.success(true)
                    }
                    "isCallScreeningSilenceSpamEnabled" -> {
                        val enabled = prefs.getBoolean(KEY_SILENCE_SPAM, false)
                        result.success(enabled)
                    }
                    "setCallScreeningSilenceSpamEnabled" -> {
                        val enabled = call.argument<Boolean>("enabled") ?: false
                        prefs.edit().putBoolean(KEY_SILENCE_SPAM, enabled).apply()
                        result.success(true)
                    }
                    "isNotificationListenerEnabled" -> {
                        result.success(isNotificationListenerGranted())
                    }
                    "openNotificationListenerSettings" -> {
                        openNotificationListenerSettings()
                        result.success(true)
                    }
                    "isCallScreeningSupported" -> {
                        result.success(isCallScreeningSupported())
                    }
                    "isCallScreeningRoleHeld" -> {
                        result.success(isCallScreeningRoleHeld())
                    }
                    "requestCallScreeningRole" -> {
                        requestCallScreeningRole(result)
                    }
                    "syncBackendConfig" -> {
                        val apiBaseUrl = call.argument<String>("apiBaseUrl")
                        val authToken = call.argument<String>("authToken")
                        val editor = prefs.edit()
                        if (!apiBaseUrl.isNullOrBlank()) {
                            editor.putString(KEY_API_BASE_URL, apiBaseUrl.trim().trimEnd('/'))
                        }
                        if (!authToken.isNullOrBlank()) {
                            editor.putString(KEY_AUTH_TOKEN, authToken)
                        }
                        editor.apply()
                        result.success(true)
                    }
                    "getScreenedCallHistory" -> {
                        result.success(getScreenedCallHistory())
                    }
                    "getCommunicationPermissionsStatus" -> {
                        result.success(getCommunicationPermissionsStatus())
                    }
                    "requestCommunicationPermission" -> {
                        val permType = call.argument<String>("permissionType") ?: ""
                        requestCommunicationPermission(permType, result)
                    }
                    "syncCommunicationPreferences" -> {
                        val editor = prefs.edit()
                        call.argument<Boolean>("monitoringPaused")?.let { editor.putBoolean("comm_monitoring_paused", it) }
                        call.argument<Boolean>("monitorSms")?.let { editor.putBoolean("comm_monitor_sms", it) }
                        call.argument<Boolean>("monitorNotifications")?.let { editor.putBoolean("comm_monitor_notifications", it) }
                        call.argument<Boolean>("monitorCalls")?.let { editor.putBoolean("comm_monitor_calls", it) }
                        call.argument<Boolean>("monitorEmail")?.let { editor.putBoolean("comm_monitor_email", it) }
                        call.argument<Boolean>("monitorWhatsapp")?.let { editor.putBoolean("comm_monitor_whatsapp", it) }
                        call.argument<Boolean>("storeMessagePreview")?.let { editor.putBoolean("comm_store_preview", it) }
                        editor.apply()
                        result.success(true)
                    }
                    "drainPendingCommunicationEvents" -> {
                        result.success(drainPendingCommunicationEvents())
                    }
                    "readRecentSmsMessages" -> {
                        val limit = call.argument<Int>("limit") ?: 40
                        result.success(readRecentSmsMessages(limit))
                    }
                    "readRecentIncomingCalls" -> {
                        val limit = call.argument<Int>("limit") ?: 40
                        result.success(readRecentIncomingCalls(limit))
                    }
                    "getInstalledApplications" -> {
                        val includeSystem = call.argument<Boolean>("includeSystemApps") ?: false
                        try {
                            val apps = getInstalledApps(includeSystem)
                            result.success(apps)
                        } catch (e: Exception) {
                            result.error("PACKAGE_ERROR", e.message, null)
                        }
                    }
                    "showLocalNotification" -> {
                        val title = call.argument<String>("title") ?: "CyberShield Alert"
                        val body = call.argument<String>("body") ?: ""
                        val severity = call.argument<String>("severity") ?: "medium"
                        val moduleName = call.argument<String>("moduleName")
                        val hideOnLockScreen = call.argument<Boolean>("hideOnLockScreen") ?: true
                        val notificationId = call.argument<Int>("notificationId")
                        showLocalAlertNotification(
                            title = title,
                            body = body,
                            severity = severity,
                            moduleName = moduleName,
                            hideOnLockScreen = hideOnLockScreen,
                            notificationId = notificationId
                        )
                        result.success(true)
                    }
                    "isNotificationPermissionGranted" -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            result.success(checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
                        } else {
                            result.success(NotificationManagerCompat.from(this).areNotificationsEnabled())
                        }
                    }
                    "requestNotificationPermission" -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1002)
                        }
                        result.success(true)
                    }
                    "getProtectionStatus" -> {
                        val supported = isCallScreeningSupported()
                        val held = isCallScreeningRoleHeld()
                        val status = hashMapOf<String, Any?>(
                            "isMasterEnabled" to prefs.getBoolean(KEY_PROTECTION_ENABLED, true),
                            "isNotificationAccessGranted" to isNotificationListenerGranted(),
                            "isCallScreeningRoleHeld" to held,
                            "isCallScreeningSupported" to supported,
                            "callScreeningUnavailableReason" to getCallScreeningUnavailableReason(),
                            "androidSdk" to Build.VERSION.SDK_INT,
                            "androidRelease" to Build.VERSION.RELEASE,
                            "silenceSpamCalls" to prefs.getBoolean(KEY_SILENCE_SPAM, false)
                        )
                        result.success(status)
                    }
                    "markSpamNumber" -> {
                        val number = call.argument<String>("phoneNumber")
                        val isSpam = call.argument<Boolean>("isSpam") ?: true
                        if (number != null) {
                            val clean = number.replace(Regex("[^0-9+]"), "")
                            prefs.edit()
                                .putBoolean("spam_number_$number", isSpam)
                                .putBoolean("spam_number_$clean", isSpam)
                                .apply()
                        }
                        result.success(true)
                    }
                    "getInitialNotificationPayload" -> {
                        result.success(launchNotificationPayload)
                    }
                    "clearInitialNotificationPayload" -> {
                        launchNotificationPayload = null
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }

        // 2. Event Channel
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    ProtectionEventBus.setEventSink(events)
                }

                override fun onCancel(arguments: Any?) {
                    ProtectionEventBus.setEventSink(null)
                }
            })
    }

    private fun isNotificationListenerGranted(): Boolean {
        val pkgName = packageName
        val fromCompat = NotificationManagerCompat.getEnabledListenerPackages(this).contains(pkgName)
        if (fromCompat) return true
        val flat = Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        return flat != null && flat.contains(pkgName)
    }

    private fun openNotificationListenerSettings() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    private fun isCallScreeningSupported(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        val roleManager = getSystemService(Context.ROLE_SERVICE) as? RoleManager ?: return false
        return try {
            roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)
        } catch (e: Exception) {
            false
        }
    }

    private fun getCallScreeningUnavailableReason(): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "Native Call Screening Unsupported on This Device. " +
                "Automatic CallScreeningService requires Android 10 (API 29) or higher; " +
                "detected Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}). " +
                "Calls are not automatically blocked or screened on Android 9, but manual phone-number checks remain available."
        }
        val roleManager = getSystemService(Context.ROLE_SERVICE) as? RoleManager
            ?: return "Android RoleManager service is unavailable on this device."
        return try {
            if (!roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                "The Call Screening role is not supported by this device or Android build."
            } else {
                null
            }
        } catch (e: Exception) {
            "Unable to verify Call Screening role availability: ${e.message}"
        }
    }

    private fun isCallScreeningRoleHeld(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        val roleManager = getSystemService(Context.ROLE_SERVICE) as? RoleManager ?: return false
        return try {
            roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) &&
                roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
        } catch (e: Exception) {
            false
        }
    }

    private fun requestCallScreeningRole(result: MethodChannel.Result) {
        if (pendingCallScreeningResult != null) {
            result.success(
                hashMapOf<String, Any?>(
                    "status" to "in_progress",
                    "granted" to false,
                    "supported" to isCallScreeningSupported(),
                    "androidSdk" to Build.VERSION.SDK_INT,
                    "message" to "Call screening role request is already in progress."
                )
            )
            return
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            result.success(
                hashMapOf<String, Any?>(
                    "status" to "unsupported",
                    "granted" to false,
                    "supported" to false,
                    "androidSdk" to Build.VERSION.SDK_INT,
                    "message" to (getCallScreeningUnavailableReason()
                        ?: "Android Call Screening requires Android 10 (API 29) or higher.")
                )
            )
            return
        }

        val roleManager = getSystemService(Context.ROLE_SERVICE) as? RoleManager
        if (roleManager == null || !isCallScreeningSupported()) {
            result.success(
                hashMapOf<String, Any?>(
                    "status" to "unsupported",
                    "granted" to false,
                    "supported" to false,
                    "androidSdk" to Build.VERSION.SDK_INT,
                    "message" to (getCallScreeningUnavailableReason()
                        ?: "Call Screening role is not available on this device.")
                )
            )
            return
        }

        if (roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
            result.success(
                hashMapOf<String, Any?>(
                    "status" to "already_granted",
                    "granted" to true,
                    "supported" to true,
                    "androidSdk" to Build.VERSION.SDK_INT,
                    "message" to "CyberShield already holds the Call Screening role."
                )
            )
            return
        }

        try {
            val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
            if (intent.resolveActivity(packageManager) == null) {
                result.success(
                    hashMapOf<String, Any?>(
                        "status" to "unsupported",
                        "granted" to false,
                        "supported" to false,
                        "androidSdk" to Build.VERSION.SDK_INT,
                        "message" to "No system Call Screening role settings screen is available on this device."
                    )
                )
                return
            }

            pendingCallScreeningResult = result
            @Suppress("DEPRECATION")
            startActivityForResult(intent, REQUEST_CODE_CALL_SCREENING)
        } catch (e: Exception) {
            pendingCallScreeningResult = null
            result.success(
                hashMapOf<String, Any?>(
                    "status" to "error",
                    "granted" to false,
                    "supported" to isCallScreeningSupported(),
                    "androidSdk" to Build.VERSION.SDK_INT,
                    "message" to "Failed to launch Call Screening role selector: ${e.message}"
                )
            )
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CODE_CALL_SCREENING) {
            val pending = pendingCallScreeningResult
            pendingCallScreeningResult = null

            // Always verify actual system state rather than trusting resultCode alone
            val isHeld = isCallScreeningRoleHeld()
            val response = hashMapOf<String, Any?>(
                "status" to if (isHeld) "granted" else "denied",
                "granted" to isHeld,
                "supported" to isCallScreeningSupported(),
                "resultCode" to resultCode,
                "resultOk" to (resultCode == Activity.RESULT_OK),
                "androidSdk" to Build.VERSION.SDK_INT,
                "message" to if (isHeld) {
                    "Call Screening role granted. CyberShield will now screen incoming calls."
                } else {
                    "Call Screening role was not granted. You can enable it anytime by tapping Set Role."
                }
            )
            pending?.success(response)
        }
    }

    private fun getScreenedCallHistory(): List<Map<String, Any?>> {
        val raw = prefs.getString(KEY_SCREENED_CALL_HISTORY, null) ?: return emptyList()
        val list = mutableListOf<Map<String, Any?>>()
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val tagsList = mutableListOf<String>()
                val tagsArr = obj.optJSONArray("evidenceTags")
                if (tagsArr != null) {
                    for (j in 0 until tagsArr.length()) {
                        tagsList.add(tagsArr.optString(j))
                    }
                }
                list.add(
                    hashMapOf(
                        "phoneNumber" to obj.optString("phoneNumber", "Unknown"),
                        "classification" to obj.optString("classification", "Safe"),
                        "spamScore" to obj.optInt("spamScore", 0),
                        "confidence" to obj.optString("confidence", "Low"),
                        "recommendedAction" to obj.optString("recommendedAction", "allow"),
                        "explanation" to obj.optString("explanation", ""),
                        "evidenceTags" to tagsList,
                        "wasSilenced" to obj.optBoolean("wasSilenced", false),
                        "backendEvaluated" to obj.optBoolean("backendEvaluated", false),
                        "timestamp" to obj.optLong("timestamp", System.currentTimeMillis())
                    )
                )
            }
        } catch (_: Exception) {
            // Return whatever parsed safely
        }
        return list
    }

    private fun getInstalledApps(includeSystem: Boolean): List<Map<String, Any?>> {
        val pm = packageManager
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val appList = mutableListOf<Map<String, Any?>>()
        for (pkg in packages) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (!includeSystem && isSystem) continue

            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                pkg.packageName
            }

            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
            val minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) appInfo.minSdkVersion else 0
            val targetSdk = appInfo.targetSdkVersion

            val appMap = hashMapOf<String, Any?>(
                "packageName" to pkg.packageName,
                "appName" to appName,
                "versionName" to (pkg.versionName ?: "1.0"),
                "versionCode" to if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pkg.longVersionCode.toString() else @Suppress("DEPRECATION") pkg.versionCode.toString(),
                "isSystemApp" to isSystem,
                "permissions" to perms,
                "minSdk" to minSdk,
                "targetSdk" to targetSdk,
                "firstInstallTime" to pkg.firstInstallTime,
                "lastUpdateTime" to pkg.lastUpdateTime
            )
            appList.add(appMap)
        }
        return appList
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            val threatChannel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Suspicious and real-time threat alerts from CyberShield modules"
                enableLights(true)
                enableVibration(true)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            }
            val criticalChannel = NotificationChannel(CRITICAL_CHANNEL_ID, CRITICAL_CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Immediate critical and high-risk alerts from CyberShield modules"
                enableLights(true)
                enableVibration(true)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            }
            val digestChannel = NotificationChannel(DIGEST_CHANNEL_ID, DIGEST_CHANNEL_NAME, NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "Protection activation, permission status, and daily security reports"
                enableLights(false)
                enableVibration(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            }

            manager.createNotificationChannel(threatChannel)
            manager.createNotificationChannel(criticalChannel)
            manager.createNotificationChannel(digestChannel)
        }
    }

    private fun showLocalAlertNotification(
        title: String,
        body: String,
        severity: String,
        moduleName: String? = null,
        hideOnLockScreen: Boolean = true,
        notificationId: Int? = null
    ) {
        val sev = severity.lowercase()
        val targetChannel = when (sev) {
            "critical", "high" -> CRITICAL_CHANNEL_ID
            "info", "low" -> DIGEST_CHANNEL_ID
            else -> CHANNEL_ID
        }
        val priority = when (sev) {
            "critical", "high" -> NotificationCompat.PRIORITY_MAX
            "info", "low" -> NotificationCompat.PRIORITY_DEFAULT
            else -> NotificationCompat.PRIORITY_HIGH
        }

        val cleanModule = moduleName?.trim()?.takeIf { it.isNotEmpty() }
        val finalTitle = if (cleanModule != null && !title.contains(cleanModule, ignoreCase = true)) {
            "[$cleanModule] $title"
        } else {
            title
        }

        val builder = NotificationCompat.Builder(this, targetChannel)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(finalTitle)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(priority)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)

        if (hideOnLockScreen) {
            // Never expose raw message contents, OTPs, or sensitive targets on lock screens
            val publicTitle = if (cleanModule != null) {
                "CyberShield Security Alert ($cleanModule)"
            } else {
                "CyberShield Security Alert"
            }
            val publicNotification = NotificationCompat.Builder(this, targetChannel)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(publicTitle)
                .setContentText("Unlock device to inspect security alert details.")
                .setPriority(priority)
                .setAutoCancel(true)
                .build()

            builder
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(publicNotification)
        }

        val notificationManager = NotificationManagerCompat.from(this)
        try {
            val id = notificationId ?: (System.currentTimeMillis() and 0x7FFFFFFF).toInt()
            notificationManager.notify(id, builder.build())
        } catch (e: SecurityException) {
            // Android 13+ POST_NOTIFICATIONS permission might not yet be granted
        }
    }

    // -------------------------------------------------------------------------
    // Communication History Permissions, SMS Inbox & Call Log Native Readers
    // -------------------------------------------------------------------------

    private fun hasPerm(permission: String): Boolean {
        return ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun getCommunicationPermissionsStatus(): Map<String, Any?> {
        return hashMapOf(
            "notificationAccess" to isNotificationListenerGranted(),
            "callScreeningSupported" to isCallScreeningSupported(),
            "callScreeningRole" to isCallScreeningRoleHeld(),
            "callScreeningUnavailableReason" to getCallScreeningUnavailableReason(),
            "readSms" to hasPerm(Manifest.permission.READ_SMS),
            "receiveSms" to hasPerm(Manifest.permission.RECEIVE_SMS),
            "readCallLog" to hasPerm(Manifest.permission.READ_CALL_LOG),
            "readPhoneState" to hasPerm(Manifest.permission.READ_PHONE_STATE),
            "readContacts" to hasPerm(Manifest.permission.READ_CONTACTS),
            "androidSdk" to Build.VERSION.SDK_INT,
            "androidRelease" to Build.VERSION.RELEASE
        )
    }

    private fun requestCommunicationPermission(permType: String, result: MethodChannel.Result) {
        val perms: Array<String> = when (permType.lowercase()) {
            "sms" -> arrayOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS)
            "call_log", "calls" -> arrayOf(
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.READ_PHONE_STATE
            )
            "contacts" -> arrayOf(Manifest.permission.READ_CONTACTS)
            "phone_state" -> arrayOf(Manifest.permission.READ_PHONE_STATE)
            else -> {
                result.success(hashMapOf("granted" to false, "status" to "invalid_type", "message" to "Unknown permission type: $permType"))
                return
            }
        }

        if (perms.all { hasPerm(it) }) {
            result.success(hashMapOf("granted" to true, "status" to "already_granted", "permissions" to getCommunicationPermissionsStatus()))
            return
        }

        if (pendingCommPermissionResult != null) {
            result.success(hashMapOf("granted" to false, "status" to "in_progress", "message" to "Another permission request is already in progress."))
            return
        }

        pendingCommPermissionResult = result
        pendingCommPermissionType = permType
        ActivityCompat.requestPermissions(this, perms, REQUEST_CODE_COMM_PERMISSIONS)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CODE_COMM_PERMISSIONS) {
            val pending = pendingCommPermissionResult
            pendingCommPermissionResult = null
            pendingCommPermissionType = null

            val allGranted = grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            pending?.success(
                hashMapOf(
                    "granted" to allGranted,
                    "status" to if (allGranted) "granted" else "denied",
                    "permissions" to getCommunicationPermissionsStatus(),
                    "message" to if (allGranted) "Permission granted." else "Permission was not granted."
                )
            )
        }
    }

    private fun drainPendingCommunicationEvents(): List<Map<String, Any?>> {
        val raw = prefs.getString(KEY_PENDING_COMM_EVENTS, null) ?: return emptyList()
        prefs.edit().remove(KEY_PENDING_COMM_EVENTS).apply()
        val list = mutableListOf<Map<String, Any?>>()
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val map = hashMapOf<String, Any?>()
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = obj.opt(k)
                    if (v is JSONArray) {
                        val sub = mutableListOf<String>()
                        for (j in 0 until v.length()) sub.add(v.optString(j))
                        map[k] = sub
                    } else if (v != org.json.JSONObject.NULL) {
                        map[k] = v
                    }
                }
                list.add(map)
            }
        } catch (_: Exception) {
            // Return parsed items safely
        }
        return list
    }

    private fun readRecentSmsMessages(limit: Int): Map<String, Any?> {
        if (!hasPerm(Manifest.permission.READ_SMS)) {
            return hashMapOf(
                "status" to "permission_denied",
                "granted" to false,
                "messages" to emptyList<Map<String, Any?>>(),
                "message" to "READ_SMS permission is required to inspect incoming SMS messages."
            )
        }

        val safeLimit = limit.coerceIn(1, 100)
        val items = mutableListOf<Map<String, Any?>>()
        try {
            val cursor = contentResolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                arrayOf(
                    Telephony.Sms._ID,
                    Telephony.Sms.ADDRESS,
                    Telephony.Sms.BODY,
                    Telephony.Sms.DATE
                ),
                null,
                null,
                "${Telephony.Sms.DATE} DESC"
            )
            cursor?.use { c ->
                val idIdx = c.getColumnIndex(Telephony.Sms._ID)
                val addrIdx = c.getColumnIndex(Telephony.Sms.ADDRESS)
                val bodyIdx = c.getColumnIndex(Telephony.Sms.BODY)
                val dateIdx = c.getColumnIndex(Telephony.Sms.DATE)

                while (c.moveToNext() && items.size < safeLimit) {
                    val smsId = if (idIdx >= 0) c.getString(idIdx) else null
                    val sender = if (addrIdx >= 0) c.getString(addrIdx) ?: "Unknown Sender" else "Unknown Sender"
                    val rawBody = if (bodyIdx >= 0) c.getString(bodyIdx) ?: "" else ""
                    val dateMs = if (dateIdx >= 0) c.getLong(dateIdx) else System.currentTimeMillis()

                    val (sanitized, wasRedacted) = CyberShieldNotificationListenerService.redactSensitiveText(rawBody)
                    items.add(
                        hashMapOf(
                            "externalId" to (smsId?.let { "sms_$it" }),
                            "sender" to sender,
                            "content" to sanitized,
                            "wasRedacted" to wasRedacted,
                            "timestamp" to dateMs,
                            "sourceApp" to "SMS"
                        )
                    )
                }
            }
            return hashMapOf(
                "status" to "ok",
                "granted" to true,
                "messages" to items
            )
        } catch (e: Exception) {
            return hashMapOf(
                "status" to "error",
                "granted" to true,
                "messages" to emptyList<Map<String, Any?>>(),
                "message" to "Failed to read SMS inbox: ${e.message}"
            )
        }
    }

    private fun readRecentIncomingCalls(limit: Int): Map<String, Any?> {
        if (!hasPerm(Manifest.permission.READ_CALL_LOG)) {
            return hashMapOf(
                "status" to "permission_denied",
                "granted" to false,
                "calls" to emptyList<Map<String, Any?>>(),
                "message" to "READ_CALL_LOG permission is required to read incoming call metadata."
            )
        }

        val safeLimit = limit.coerceIn(1, 100)
        val canCheckContacts = hasPerm(Manifest.permission.READ_CONTACTS)
        val items = mutableListOf<Map<String, Any?>>()

        try {
            val selection = "${CallLog.Calls.TYPE} IN (${CallLog.Calls.INCOMING_TYPE}, ${CallLog.Calls.MISSED_TYPE}, ${CallLog.Calls.REJECTED_TYPE}, ${CallLog.Calls.BLOCKED_TYPE})"
            val cursor = contentResolver.query(
                CallLog.Calls.CONTENT_URI,
                arrayOf(
                    CallLog.Calls._ID,
                    CallLog.Calls.NUMBER,
                    CallLog.Calls.CACHED_NAME,
                    CallLog.Calls.DATE,
                    CallLog.Calls.TYPE,
                    CallLog.Calls.DURATION
                ),
                selection,
                null,
                "${CallLog.Calls.DATE} DESC"
            )
            cursor?.use { c ->
                val idIdx = c.getColumnIndex(CallLog.Calls._ID)
                val numIdx = c.getColumnIndex(CallLog.Calls.NUMBER)
                val nameIdx = c.getColumnIndex(CallLog.Calls.CACHED_NAME)
                val dateIdx = c.getColumnIndex(CallLog.Calls.DATE)
                val typeIdx = c.getColumnIndex(CallLog.Calls.TYPE)
                val durIdx = c.getColumnIndex(CallLog.Calls.DURATION)

                while (c.moveToNext() && items.size < safeLimit) {
                    val callId = if (idIdx >= 0) c.getString(idIdx) else null
                    val number = (if (numIdx >= 0) c.getString(numIdx) else null)?.trim() ?: ""
                    if (number.isEmpty()) continue

                    var callerName = if (nameIdx >= 0) c.getString(nameIdx)?.trim() else null
                    var isKnownContact: Boolean? = null
                    if (canCheckContacts) {
                        val lookedUp = lookupContactDisplayName(number)
                        if (!lookedUp.isNullOrEmpty()) {
                            callerName = lookedUp
                            isKnownContact = true
                        } else {
                            isKnownContact = !callerName.isNullOrEmpty()
                        }
                    } else if (!callerName.isNullOrEmpty()) {
                        isKnownContact = true
                    }

                    val dateMs = if (dateIdx >= 0) c.getLong(dateIdx) else System.currentTimeMillis()
                    val callTypeInt = if (typeIdx >= 0) c.getInt(typeIdx) else CallLog.Calls.INCOMING_TYPE
                    val durationSec = if (durIdx >= 0) c.getLong(durIdx) else 0L

                    val callStatus = when (callTypeInt) {
                        CallLog.Calls.MISSED_TYPE -> "missed"
                        CallLog.Calls.REJECTED_TYPE -> "rejected"
                        CallLog.Calls.BLOCKED_TYPE -> "blocked"
                        else -> if (durationSec > 0) "answered" else "incoming"
                    }

                    items.add(
                        hashMapOf(
                            "externalId" to (callId?.let { "call_$it" }),
                            "phoneNumber" to number,
                            "callerName" to (if (callerName.isNullOrEmpty()) null else callerName),
                            "isKnownContact" to isKnownContact,
                            "callStatus" to callStatus,
                            "durationSeconds" to durationSec,
                            "timestamp" to dateMs
                        )
                    )
                }
            }
            return hashMapOf(
                "status" to "ok",
                "granted" to true,
                "calls" to items
            )
        } catch (e: Exception) {
            return hashMapOf(
                "status" to "error",
                "granted" to true,
                "calls" to emptyList<Map<String, Any?>>(),
                "message" to "Failed to read call log: ${e.message}"
            )
        }
    }

    private fun lookupContactDisplayName(phoneNumber: String): String? {
        return try {
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                Uri.encode(phoneNumber)
            )
            contentResolver.query(
                uri,
                arrayOf(ContactsContract.PhoneLookup.DISPLAY_NAME),
                null,
                null,
                null
            )?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
        } catch (_: Exception) {
            null
        }
    }
}
