package com.example.mobile.services

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.LinkedHashMap
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.regex.Pattern

class CyberShieldNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "CyberShieldNotifSvc"
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_API_BASE_URL = "api_base_url"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_LISTENER_CONNECTED = "notification_listener_connected"
        const val KEY_COMM_PAUSED = "comm_monitoring_paused"
        const val KEY_MONITOR_NOTIFICATIONS = "comm_monitor_notifications"
        const val KEY_MONITOR_WHATSAPP = "comm_monitor_whatsapp"
        const val KEY_MONITOR_GMAIL_NOTIF = "comm_monitor_email"
        const val KEY_MONITOR_SMS_NOTIF = "comm_monitor_sms"
        const val KEY_STORE_PREVIEW = "comm_store_preview"
        const val KEY_PENDING_COMM_EVENTS = "pending_comm_events"
        const val CHANNEL_ID = "cybershield_threat_alerts"
        const val CHANNEL_NAME = "CyberShield Threat Alerts"
        private const val DEDUP_WINDOW_MS = 30_000L
        private const val MAX_DEDUP_CACHE = 200
        private const val MAX_PENDING_EVENTS = 100
        private const val BACKEND_TIMEOUT_MS = 3500

        // Sensitive regex patterns for privacy redaction
        private val CARD_PATTERN = Pattern.compile("\\b(?:\\d{4}[ -]?){3}\\d{1,4}\\b")
        private val OTP_PATTERN = Pattern.compile("(?i)\\b(?:code|otp|pin|password|secret|verification code|auth code|passcode)[\\s:=#\\-]+(\\d{4,8})\\b")
        private val CVV_PATTERN = Pattern.compile("(?i)\\bcvv[\\s:=]+(\\d{3,4})\\b")
        private val SECRET_KV_PATTERN = Pattern.compile("(?i)\\b(password|passwd|pwd|token|bearer)[\\s:=]+([^\\s,;]+)")
        private val URL_PATTERN = Pattern.compile("(https?://[^\\s<>\"]+|www\\.[^\\s<>\"]+)")

        private val SMS_PACKAGES = setOf(
            "com.google.android.apps.messaging",
            "com.android.mms",
            "com.samsung.android.messaging",
            "com.miui.mms",
            "com.oneplus.mms",
            "com.sonyericsson.conversations",
            "com.truecaller",
            "org.thoughtcrime.securesms",
            "org.telegram.messenger",
            "com.facebook.orca"
        )
        private val WHATSAPP_PACKAGES = setOf("com.whatsapp", "com.whatsapp.w4b")
        private val EMAIL_PACKAGES = setOf(
            "com.google.android.gm",
            "com.microsoft.office.outlook",
            "com.yahoo.mobile.client.android.mail",
            "com.samsung.android.email.provider",
            "ch.protonmail.android",
            "com.fsck.k9",
            "com.zoho.mail",
            "com.readdle.spark",
            "com.trtf.blue",
            "org.kman.AquaMail"
        )

        // Known high-risk phishing keywords
        private val PHISHING_KEYWORDS = listOf(
            "account suspended", "verify login", "urgent action", "wire transfer",
            "claim reward", "tax refund", "card blocked", "unauthorized transaction",
            "immediate verification", "account compromised"
        )

        fun redactSensitiveText(input: String): Pair<String, Boolean> {
            var text = input
            var redacted = false

            if (CARD_PATTERN.matcher(text).find()) {
                text = CARD_PATTERN.matcher(text).replaceAll("[REDACTED_CARD]")
                redacted = true
            }

            val otpMatcher = OTP_PATTERN.matcher(text)
            if (otpMatcher.find()) {
                val sb = StringBuffer()
                otpMatcher.reset()
                while (otpMatcher.find()) {
                    val full = otpMatcher.group(0) ?: ""
                    val code = otpMatcher.group(1) ?: "****"
                    val masked = "[REDACTED_OTP]"
                    otpMatcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(full.replace(code, masked)))
                }
                otpMatcher.appendTail(sb)
                text = sb.toString()
                redacted = true
            }

            if (CVV_PATTERN.matcher(text).find()) {
                text = CVV_PATTERN.matcher(text).replaceAll("cvv: ***")
                redacted = true
            }

            if (SECRET_KV_PATTERN.matcher(text).find()) {
                text = SECRET_KV_PATTERN.matcher(text).replaceAll("$1=[REDACTED]")
                redacted = true
            }

            return Pair(text, redacted)
        }
    }

    private lateinit var prefs: SharedPreferences
    private val networkExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val recentFingerprints = object : LinkedHashMap<String, Long>(MAX_DEDUP_CACHE, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > MAX_DEDUP_CACHE
        }
    }

    override fun onCreate() {
        super.onCreate()
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        createNotificationChannel()
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        if (::prefs.isInitialized) {
            prefs.edit().putBoolean(KEY_LISTENER_CONNECTED, true).apply()
        }
        Log.i(TAG, "CyberShield NotificationListenerService connected")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        if (::prefs.isInitialized) {
            prefs.edit().putBoolean(KEY_LISTENER_CONNECTED, false).apply()
        }
        Log.w(TAG, "CyberShield NotificationListenerService disconnected")
    }

    override fun onDestroy() {
        networkExecutor.shutdownNow()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val pkgName = sbn.packageName ?: return

        // 1. Check master protection & monitoring pause state
        if (!prefs.getBoolean(KEY_PROTECTION_ENABLED, true)) return
        if (prefs.getBoolean(KEY_COMM_PAUSED, false)) return

        // 2. Ignore self-notifications, ongoing system indicators, and system UI noise
        if (pkgName == packageName) return
        if (pkgName in listOf("android", "com.android.systemui", "com.android.phone")) return
        if (sbn.isOngoing) return

        // 3. Determine communication source & verify per-channel user consent
        val (commType, sourceAppLabel) = classifyNotificationSource(pkgName)
        val channelAllowed = when (commType) {
            "whatsapp" -> prefs.getBoolean(KEY_MONITOR_WHATSAPP, true) && prefs.getBoolean(KEY_MONITOR_NOTIFICATIONS, true)
            "email" -> prefs.getBoolean(KEY_MONITOR_GMAIL_NOTIF, true) && prefs.getBoolean(KEY_MONITOR_NOTIFICATIONS, true)
            "sms" -> prefs.getBoolean(KEY_MONITOR_SMS_NOTIF, true) || prefs.getBoolean(KEY_MONITOR_NOTIFICATIONS, true)
            else -> prefs.getBoolean(KEY_MONITOR_NOTIFICATIONS, true)
        }
        if (!channelAllowed) return

        val extras = sbn.notification.extras ?: return
        val rawTitle = extras.getCharSequence("android.title")?.toString()?.trim() ?: ""
        val rawText = extras.getCharSequence("android.bigText")?.toString()?.trim()
            ?: extras.getCharSequence("android.text")?.toString()?.trim() ?: ""
        val subText = extras.getCharSequence("android.subText")?.toString()?.trim() ?: ""

        if (rawTitle.isEmpty() && rawText.isEmpty()) return

        // 4. Deduplicate rapid/re-posted notifications within 30-second window
        val now = System.currentTimeMillis()
        val fingerprint = "$pkgName|${rawTitle.lowercase()}|${rawText.lowercase().take(120)}"
        synchronized(recentFingerprints) {
            val prev = recentFingerprints[fingerprint]
            if (prev != null && (now - prev) < DEDUP_WINDOW_MS) {
                return
            }
            recentFingerprints[fingerprint] = now
        }

        // 5. Privacy Redaction: Never leak raw OTPs, Credit Cards, CVVs, or passwords
        val (sanitizedText, textRedacted) = redactSensitiveText(rawText)
        val (sanitizedTitle, titleRedacted) = redactSensitiveText(rawTitle)
        val wasRedacted = textRedacted || titleRedacted

        // 6. Extract URLs
        val combinedRaw = "$rawTitle $rawText"
        val matcher = URL_PATTERN.matcher(combinedRaw)
        val urls = mutableListOf<String>()
        while (matcher.find()) {
            val u = matcher.group(1)
            if (u != null && !urls.contains(u)) {
                urls.add(u)
            }
        }

        // 7. Quick local threat heuristic (only alerts on high-confidence phishing, never on normal messages)
        val lowerText = combinedRaw.lowercase()
        val hasPhishingKeywords = PHISHING_KEYWORDS.any { lowerText.contains(it) }
        val hasSuspiciousUrl = urls.any { u ->
            u.contains("192.168.") || u.contains("10.") || u.contains(".ru") ||
                u.contains(".xyz") || u.contains(".top") || u.contains("bit.ly")
        }

        val storePreview = prefs.getBoolean(KEY_STORE_PREVIEW, true)
        val eventMap = hashMapOf<String, Any?>(
            "type" to "notification",
            "communicationType" to commType,
            "sourceApp" to sourceAppLabel,
            "packageName" to pkgName,
            "sender" to (if (sanitizedTitle.isNotEmpty()) sanitizedTitle else sourceAppLabel),
            "title" to sanitizedTitle,
            "text" to sanitizedText,
            "content" to sanitizedText,
            "subText" to subText,
            "postTime" to sbn.postTime,
            "timestamp" to sbn.postTime,
            "detectedUrls" to urls,
            "wasRedacted" to wasRedacted,
            "storePreview" to storePreview,
            "isLikelySuspicious" to (hasPhishingKeywords || hasSuspiciousUrl)
        )

        // Emit event to Flutter app if running AND persist to queue for offline/background capture
        ProtectionEventBus.emitEvent(eventMap)
        enqueuePendingEvent(eventMap)

        val targetScreen = if (commType == "email") "email_scanner" else "sms_scanner"

        // 8. Analyze asynchronously with FastAPI backend when configured; fail-safe to local heuristic offline
        val localHighConfidenceThreat = hasSuspiciousUrl || (hasPhishingKeywords && urls.isNotEmpty())
        val apiBaseUrl = prefs.getString(KEY_API_BASE_URL, null)?.trim()?.trimEnd('/')
        if (!apiBaseUrl.isNullOrEmpty()) {
            val authToken = prefs.getString(KEY_AUTH_TOKEN, null)?.trim()
            analyzeWithBackendAsync(
                apiBaseUrl = apiBaseUrl,
                authToken = authToken,
                pkgName = pkgName,
                commType = commType,
                targetScreen = targetScreen,
                sourceAppLabel = sourceAppLabel,
                sanitizedTitle = sanitizedTitle,
                sanitizedText = sanitizedText,
                subText = subText,
                postTime = sbn.postTime,
                notificationId = sbn.id + 100000,
                localFallbackThreat = localHighConfidenceThreat
            )
        } else if (localHighConfidenceThreat) {
            postLocalAlert(
                title = "CyberShield Warning [Notification Monitor]",
                message = "Suspicious link detected in $sourceAppLabel notification. Do not tap or submit credentials.",
                notificationId = sbn.id + 100000,
                screen = targetScreen,
                commType = commType,
                sender = sanitizedTitle.ifEmpty { sourceAppLabel },
                content = sanitizedText,
                riskScore = 65,
                classification = "Warning",
                explanation = "Suspicious link detected in $sourceAppLabel notification."
            )
        }
    }

    private fun analyzeWithBackendAsync(
        apiBaseUrl: String,
        authToken: String?,
        pkgName: String,
        commType: String,
        targetScreen: String,
        sourceAppLabel: String,
        sanitizedTitle: String,
        sanitizedText: String,
        subText: String,
        postTime: Long,
        notificationId: Int,
        localFallbackThreat: Boolean
    ) {
        try {
            networkExecutor.execute {
                var conn: HttpURLConnection? = null
                try {
                    val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                        timeZone = TimeZone.getTimeZone("UTC")
                    }
                    val payload = JSONObject().apply {
                        put("package_name", pkgName)
                        put("title", sanitizedTitle)
                        put("text", sanitizedText)
                        put("sub_text", subText)
                        put("posted_timestamp", isoFormat.format(Date(postTime)))
                    }

                    val endpoint = URL("$apiBaseUrl/api/v1/notifications/analyze")
                    conn = (endpoint.openConnection() as HttpURLConnection).apply {
                        requestMethod = "POST"
                        connectTimeout = BACKEND_TIMEOUT_MS
                        readTimeout = BACKEND_TIMEOUT_MS
                        doOutput = true
                        setRequestProperty("Content-Type", "application/json; charset=utf-8")
                        if (!authToken.isNullOrEmpty()) {
                            setRequestProperty("Authorization", "Bearer $authToken")
                        }
                    }

                    OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                        writer.write(payload.toString())
                        writer.flush()
                    }

                    if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                        val responseBody = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                        val json = JSONObject(responseBody)
                        val riskScore = json.optInt("risk_score", 0)
                        val classification = json.optString("classification", "Safe")
                        val explanation = json.optString(
                            "explanation",
                            "Suspicious content detected in $sourceAppLabel notification."
                        )

                        if (riskScore >= 55 || classification.equals("High Risk", true) ||
                            classification.equals("Critical", true) ||
                            classification.equals("Malicious", true)
                        ) {
                            postLocalAlert(
                                title = "CyberShield $classification [Notification Monitor]",
                                message = "$sourceAppLabel ($riskScore% risk): $explanation",
                                notificationId = notificationId,
                                screen = targetScreen,
                                commType = commType,
                                sender = sanitizedTitle.ifEmpty { sourceAppLabel },
                                content = sanitizedText,
                                riskScore = riskScore,
                                classification = classification,
                                explanation = explanation
                            )
                        }
                    } else if (localFallbackThreat) {
                        postLocalAlert(
                            title = "CyberShield Warning [Notification Monitor]",
                            message = "Suspicious link detected in $sourceAppLabel notification. Do not tap or submit credentials.",
                            notificationId = notificationId,
                            screen = targetScreen,
                            commType = commType,
                            sender = sanitizedTitle.ifEmpty { sourceAppLabel },
                            content = sanitizedText,
                            riskScore = 65,
                            classification = "Warning",
                            explanation = "Suspicious link detected in $sourceAppLabel notification."
                        )
                    }
                } catch (e: Exception) {
                    Log.d(TAG, "Backend notification analysis skipped/offline: ${e.message}")
                    if (localFallbackThreat) {
                        postLocalAlert(
                            title = "CyberShield Warning [Notification Monitor]",
                            message = "Suspicious link detected in $sourceAppLabel notification (offline check). Do not tap or submit credentials.",
                            notificationId = notificationId,
                            screen = targetScreen,
                            commType = commType,
                            sender = sanitizedTitle.ifEmpty { sourceAppLabel },
                            content = sanitizedText,
                            riskScore = 65,
                            classification = "Warning",
                            explanation = "Suspicious link detected in $sourceAppLabel notification (offline check)."
                        )
                    }
                } finally {
                    conn?.disconnect()
                }
            }
        } catch (_: Exception) {
            // Executor shutting down
        }
    }

    private fun classifyNotificationSource(pkgName: String): Pair<String, String> {
        if (pkgName in WHATSAPP_PACKAGES) return Pair("whatsapp", "WhatsApp")
        if (pkgName in EMAIL_PACKAGES) {
            val appLabel = try {
                val appInfo = packageManager.getApplicationInfo(pkgName, 0)
                packageManager.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                if (pkgName == "com.google.android.gm") "Gmail" else "Email"
            }
            return Pair("email", appLabel)
        }
        if (pkgName in SMS_PACKAGES) return Pair("sms", "SMS")

        val appLabel = try {
            val appInfo = packageManager.getApplicationInfo(pkgName, 0)
            packageManager.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            pkgName
        }
        return Pair("notification", appLabel)
    }

    private fun enqueuePendingEvent(eventMap: Map<String, Any?>) {
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
            // Non-fatal
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = "Real-time threat alerts from CyberShield protection engine"
                enableLights(true)
                enableVibration(true)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun postLocalAlert(
        title: String,
        message: String,
        notificationId: Int,
        screen: String = "sms_scanner",
        commType: String = "sms",
        sender: String = "",
        content: String = "",
        riskScore: Int = 0,
        classification: String = "Warning",
        explanation: String = ""
    ) {
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            val launchIntent = Intent(this, MainActivity::class.java).apply {
                action = "com.example.mobile.ACTION_VIEW_THREAT"
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("extra_screen", screen)
                putExtra("extra_type", commType)
                putExtra("extra_sender", sender)
                putExtra("extra_content", content)
                putExtra("extra_title", title)
                putExtra("extra_risk_score", riskScore)
                putExtra("extra_classification", classification)
                putExtra("extra_explanation", explanation)
                putExtra("extra_event_id", "notif-${System.currentTimeMillis()}-$notificationId")
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                notificationId,
                launchIntent,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                } else {
                    PendingIntent.FLAG_UPDATE_CURRENT
                }
            )

            val publicVersion = NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("CyberShield Security Alert")
                .setContentText("Unlock device to view redacted security details.")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            val builder = NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(NotificationCompat.BigTextStyle().bigText(message))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(publicVersion)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)

            manager.notify(notificationId, builder.build())
        } catch (_: SecurityException) {
            // Android 13+ POST_NOTIFICATIONS might not yet be granted
        }
    }
}
