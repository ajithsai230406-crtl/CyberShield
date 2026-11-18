package com.example.mobile.services

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import android.telephony.TelephonyManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.mobile.MainActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Permission-based incoming call metadata receiver (Android 9+ compatible).
 * Complements Android 10+ CallScreeningService so Android 9 devices (e.g. Redmi Y2)
 * can still record, screen against TRAI spam heuristics, and alert on fraudulent callers
 * when the user grants READ_PHONE_STATE + READ_CALL_LOG and enables call monitoring.
 *
 * Strictly metadata only — NEVER records or accesses call audio.
 */
class CyberShieldCallStateReceiver : BroadcastReceiver() {

    companion object {
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_COMM_PAUSED = "comm_monitoring_paused"
        const val KEY_MONITOR_CALLS = "comm_monitor_calls"
        const val KEY_API_BASE_URL = "api_base_url"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_PENDING_COMM_EVENTS = "pending_comm_events"
        const val CHANNEL_ID = "cybershield_threat_alerts"
        const val CHANNEL_NAME = "CyberShield Threat Alerts"
        private const val MAX_PENDING_EVENTS = 100
        private const val BACKEND_TIMEOUT_MS = 3000

        @Volatile
        private var lastNumber: String? = null
        @Volatile
        private var lastTimestamp: Long = 0L

        /**
         * Quick local heuristic check for known spam caller patterns
         * (TRAI 140 / 1600 telemarketing series, toll-free outbound spoofing).
         */
        fun evaluatePhoneHeuristic(rawNumber: String): Pair<Int, String?> {
            val digits = rawNumber.replace(Regex("[^0-9]"), "")
            var national = digits
            if (digits.startsWith("91") && digits.length >= 11) {
                national = digits.substring(2)
            } else if (digits.startsWith("0") && digits.length >= 10) {
                national = digits.substring(1)
            }

            if (national.startsWith("140") && national.length in 9..11) {
                return Pair(75, "Matches Indian TRAI 140 telemarketing spam series.")
            }
            if (national.startsWith("160") && national.length in 9..11) {
                return Pair(65, "Matches Indian TRAI 160/1600 automated tele-calling/commercial series.")
            }
            if ((national.startsWith("1800") || national.startsWith("1860")) && national.length >= 10) {
                return Pair(45, "Toll-free prefix appearing as outbound caller ID (vishing/spoof risk).")
            }
            return Pair(0, null)
        }
    }

    private val executor = Executors.newSingleThreadExecutor()

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != TelephonyManager.ACTION_PHONE_STATE_CHANGED) return

        val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
        if (state != TelephonyManager.EXTRA_STATE_RINGING) return

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_PROTECTION_ENABLED, true)) return
        if (prefs.getBoolean(KEY_COMM_PAUSED, false)) return
        if (!prefs.getBoolean(KEY_MONITOR_CALLS, false)) return

        @Suppress("DEPRECATION")
        val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER)?.trim()
        if (incomingNumber.isNullOrEmpty()) return

        // Deduplicate duplicate RINGING broadcasts fired by Android for the same call
        val now = System.currentTimeMillis()
        if (incomingNumber == lastNumber && (now - lastTimestamp) < 15_000L) {
            return
        }
        lastNumber = incomingNumber
        lastTimestamp = now

        val contactName = lookupContactName(context, incomingNumber)
        val isKnownContact = if (hasContactsPermission(context)) contactName != null else null

        // If it's a known saved contact, allow without spam alert
        if (isKnownContact == true) {
            val eventMap = hashMapOf<String, Any?>(
                "type" to "comm_call",
                "communicationType" to "call",
                "sourceApp" to "Phone Call",
                "sender" to incomingNumber,
                "phoneNumber" to incomingNumber,
                "callerName" to contactName,
                "isKnownContact" to true,
                "callStatus" to "incoming",
                "timestamp" to now
            )
            ProtectionEventBus.emitEvent(eventMap)
            enqueuePendingEvent(prefs, eventMap)
            return
        }

        // Screen caller for Android 9 fallback
        executor.execute {
            screenAndAlertCaller(context.applicationContext, prefs, incomingNumber, contactName, now)
        }
    }

    private fun screenAndAlertCaller(
        context: Context,
        prefs: SharedPreferences,
        incomingNumber: String,
        contactName: String?,
        timestamp: Long
    ) {
        val cleanNumber = incomingNumber.replace(Regex("[^0-9+]"), "")
        val isLocalKnownSpam = prefs.getBoolean("spam_number_$incomingNumber", false) ||
            prefs.getBoolean("spam_number_$cleanNumber", false)

        val (heuristicScore, heuristicReason) = evaluatePhoneHeuristic(incomingNumber)
        var spamScore = if (isLocalKnownSpam) 80 else heuristicScore
        var explanation = if (isLocalKnownSpam) {
            "Matched locally cached verified spam caller."
        } else {
            heuristicReason ?: "Incoming call screened."
        }
        var classification = when {
            spamScore >= 70 -> "High Risk"
            spamScore >= 40 -> "Suspicious"
            else -> "Safe"
        }

        // Try live backend check if configured
        val apiBaseUrl = prefs.getString(KEY_API_BASE_URL, null)?.trim()?.trimEnd('/')
        val authToken = prefs.getString(KEY_AUTH_TOKEN, null)?.trim()
        if (!apiBaseUrl.isNullOrEmpty() && !authToken.isNullOrEmpty()) {
            var conn: HttpURLConnection? = null
            try {
                val url = URL("$apiBaseUrl/api/v1/calls/screen")
                conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = BACKEND_TIMEOUT_MS
                    readTimeout = BACKEND_TIMEOUT_MS
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Authorization", "Bearer $authToken")
                }
                val payload = JSONObject().apply {
                    put("phone_number", incomingNumber)
                }
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(payload.toString()); it.flush() }
                if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                    val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                    val json = JSONObject(body)
                    val remoteScore = json.optInt("spam_score", 0)
                    val remoteClass = json.optString("classification", classification)
                    val remoteExpl = json.optString("explanation", explanation)
                    if (remoteScore > spamScore) {
                        spamScore = remoteScore
                        classification = remoteClass
                        explanation = remoteExpl
                    }
                }
            } catch (_: Exception) {
                // Fail-safe to local heuristics
            } finally {
                conn?.disconnect()
            }
        }

        val isSpam = spamScore >= 25 || isLocalKnownSpam
        val eventMap = hashMapOf<String, Any?>(
            "type" to "comm_call",
            "communicationType" to "call",
            "sourceApp" to "Phone Call",
            "sender" to incomingNumber,
            "phoneNumber" to incomingNumber,
            "callerName" to contactName,
            "isKnownContact" to false,
            "isKnownSpam" to isSpam,
            "spamScore" to spamScore,
            "classification" to classification,
            "explanation" to explanation,
            "callStatus" to "incoming",
            "timestamp" to timestamp
        )

        ProtectionEventBus.emitEvent(eventMap)
        enqueuePendingEvent(prefs, eventMap)

        if (isSpam) {
            postCallWarningAlert(context, incomingNumber, classification, spamScore, explanation)
        }
    }

    private fun postCallWarningAlert(
        context: Context,
        phoneNumber: String,
        classification: String,
        spamScore: Int,
        explanation: String
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

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            action = "com.example.mobile.ACTION_VIEW_THREAT"
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("extra_screen", "call_screening")
            putExtra("extra_type", "call")
            putExtra("extra_phone_number", phoneNumber)
            putExtra("extra_risk_score", spamScore)
            putExtra("extra_classification", classification)
            putExtra("extra_explanation", explanation)
            putExtra("extra_event_id", "call-${System.currentTimeMillis()}-$phoneNumber")
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            phoneNumber.hashCode(),
            launchIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
        )

        val title = "CyberShield: $classification Caller ($phoneNumber)"
        val body = "Incoming caller $phoneNumber flagged with $spamScore% spam risk. $explanation Decline or do not share OTPs."

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        try {
            manager.notify(phoneNumber.hashCode() + 300000, builder.build())
        } catch (_: SecurityException) {
            // Permission catch
        }
    }

    private fun hasContactsPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.READ_CONTACTS
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun lookupContactName(context: Context, phoneNumber: String): String? {
        if (!hasContactsPermission(context)) return null
        return try {
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                Uri.encode(phoneNumber)
            )
            context.contentResolver.query(
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
            // Non-fatal queue write error
        }
    }
}
