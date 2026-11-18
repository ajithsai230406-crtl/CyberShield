package com.example.mobile.services

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.telecom.Call
import android.telecom.CallScreeningService
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import com.example.mobile.MainActivity
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

@RequiresApi(Build.VERSION_CODES.Q)
class CyberShieldCallScreeningService : CallScreeningService() {

    companion object {
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_SILENCE_SPAM = "call_screening_silence_spam"
        const val KEY_API_BASE_URL = "api_base_url"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_SCREENED_CALL_HISTORY = "screened_call_history"
        const val CHANNEL_ID = "cybershield_threat_alerts"
        private const val CONNECT_TIMEOUT_MS = 2000
        private const val READ_TIMEOUT_MS = 2500
        private const val MAX_HISTORY_ENTRIES = 25
    }

    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private data class ScreeningDecision(
        val isKnownSpam: Boolean,
        val spamScore: Int,
        val classification: String,
        val confidence: String,
        val recommendedAction: String,
        val explanation: String,
        val evidenceTags: List<String>,
        val backendEvaluated: Boolean
    )

    override fun onScreenCall(callDetails: Call.Details) {
        // Only evaluate incoming calls; allow outgoing calls immediately
        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val isEnabled = prefs.getBoolean(KEY_PROTECTION_ENABLED, true)
        val autoSilenceSpam = prefs.getBoolean(KEY_SILENCE_SPAM, false)

        if (!isEnabled) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        val phoneNumber = callDetails.handle?.schemeSpecificPart?.trim()
        if (phoneNumber.isNullOrEmpty()) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        executor.execute {
            val responseBuilder = CallResponse.Builder()
            var wasSilenced = false
            val decision: ScreeningDecision = try {
                evaluateCaller(prefs, phoneNumber)
            } catch (_: Exception) {
                // Fail-safe: never block legitimate callers on unexpected error
                ScreeningDecision(
                    isKnownSpam = false,
                    spamScore = 0,
                    classification = "Safe",
                    confidence = "Low",
                    recommendedAction = "allow",
                    explanation = "Call screening fallback: unable to reach threat service; allowed safely.",
                    evidenceTags = emptyList(),
                    backendEvaluated = false
                )
            }

            val shouldSilence = autoSilenceSpam && (
                decision.recommendedAction == "silence" ||
                    decision.recommendedAction == "block" ||
                    (decision.isKnownSpam && decision.spamScore >= 70)
                )

            if (shouldSilence) {
                responseBuilder.setSilenceCall(true)
                responseBuilder.setSkipCallLog(false)
                responseBuilder.setSkipNotification(false)
                wasSilenced = true
            }

            // Always respond to Telecom within the permitted window
            try {
                respondToCall(callDetails, responseBuilder.build())
            } catch (_: Exception) {
                // Telecom call may have already ended
            }

            // Persist for user review and notify if flagged
            val timestamp = System.currentTimeMillis()
            persistScreenedCall(prefs, phoneNumber, decision, wasSilenced, timestamp)

            if (wasSilenced) {
                postCallAlert(
                    phoneNumber = phoneNumber,
                    title = "CyberShield: Spam Caller Silenced",
                    body = "Incoming call from $phoneNumber (${decision.classification}, score ${decision.spamScore}/100) was silenced. ${decision.explanation}"
                )
            } else if (decision.isKnownSpam || decision.recommendedAction == "warn" || decision.spamScore >= 25) {
                postCallAlert(
                    phoneNumber = phoneNumber,
                    title = "CyberShield: Suspicious Caller Warning",
                    body = "Caller $phoneNumber flagged as ${decision.classification} (score ${decision.spamScore}/100). ${decision.explanation}"
                )
            }

            // Emit enriched event to Flutter if active
            val eventMap = hashMapOf<String, Any?>(
                "type" to "call",
                "phoneNumber" to phoneNumber,
                "callDirection" to "incoming",
                "isKnownSpam" to decision.isKnownSpam,
                "spamScore" to decision.spamScore,
                "classification" to decision.classification,
                "confidence" to decision.confidence,
                "recommendedAction" to decision.recommendedAction,
                "explanation" to decision.explanation,
                "evidenceTags" to decision.evidenceTags,
                "wasSilenced" to wasSilenced,
                "backendEvaluated" to decision.backendEvaluated,
                "timestamp" to timestamp
            )
            mainHandler.post {
                ProtectionEventBus.emitEvent(eventMap)
            }
        }
    }

    private fun evaluateCaller(prefs: SharedPreferences, phoneNumber: String): ScreeningDecision {
        val cleanNumber = phoneNumber.replace(Regex("[^0-9+]"), "")
        val isLocalKnownSpam = prefs.getBoolean("spam_number_$phoneNumber", false) ||
            prefs.getBoolean("spam_number_$cleanNumber", false)

        val apiBaseUrl = prefs.getString(KEY_API_BASE_URL, null)?.trim()?.trimEnd('/')
        val authToken = prefs.getString(KEY_AUTH_TOKEN, null)?.trim()

        // Try live CyberShield backend call-screening API with strict short timeout
        if (!apiBaseUrl.isNullOrEmpty() && !authToken.isNullOrEmpty()) {
            val remote = queryBackendScreeningApi(apiBaseUrl, authToken, phoneNumber)
            if (remote != null) {
                if (remote.isKnownSpam && remote.spamScore >= 70) {
                    prefs.edit()
                        .putBoolean("spam_number_$phoneNumber", true)
                        .putBoolean("spam_number_$cleanNumber", true)
                        .apply()
                }
                return remote
            }
        }

        // Safe offline fallback: ONLY flag if explicitly cached as verified spam previously
        return if (isLocalKnownSpam) {
            ScreeningDecision(
                isKnownSpam = true,
                spamScore = 80,
                classification = "High Risk",
                confidence = "Medium",
                recommendedAction = "silence",
                explanation = "Matched locally cached verified spam number while offline.",
                evidenceTags = listOf("local_spam_cache"),
                backendEvaluated = false
            )
        } else {
            ScreeningDecision(
                isKnownSpam = false,
                spamScore = 0,
                classification = "Safe",
                confidence = "Low",
                recommendedAction = "allow",
                explanation = "No spam reputation found (backend offline or not configured); call allowed safely.",
                evidenceTags = emptyList(),
                backendEvaluated = false
            )
        }
    }

    private fun queryBackendScreeningApi(
        apiBaseUrl: String,
        authToken: String,
        phoneNumber: String
    ): ScreeningDecision? {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL("$apiBaseUrl/api/v1/calls/screen")
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Authorization", "Bearer $authToken")
            }

            val payload = JSONObject().apply {
                put("phone_number", phoneNumber)
            }
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(payload.toString())
                writer.flush()
            }

            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                return null
            }

            val body = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use {
                it.readText()
            }
            val json = JSONObject(body)
            val tags = mutableListOf<String>()
            val tagsArr = json.optJSONArray("evidence_tags")
            if (tagsArr != null) {
                for (i in 0 until tagsArr.length()) {
                    tags.add(tagsArr.optString(i))
                }
            }

            ScreeningDecision(
                isKnownSpam = json.optBoolean("is_known_spam", false),
                spamScore = json.optInt("spam_score", 0),
                classification = json.optString("classification", "Safe"),
                confidence = json.optString("confidence", "Low"),
                recommendedAction = json.optString("recommended_action", "allow"),
                explanation = json.optString("explanation", ""),
                evidenceTags = tags,
                backendEvaluated = true
            )
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun persistScreenedCall(
        prefs: SharedPreferences,
        phoneNumber: String,
        decision: ScreeningDecision,
        wasSilenced: Boolean,
        timestamp: Long
    ) {
        try {
            val existing = prefs.getString(KEY_SCREENED_CALL_HISTORY, null)
            val oldArray = if (existing != null) JSONArray(existing) else JSONArray()
            val newArray = JSONArray()

            val entry = JSONObject().apply {
                put("phoneNumber", phoneNumber)
                put("isKnownSpam", decision.isKnownSpam)
                put("spamScore", decision.spamScore)
                put("classification", decision.classification)
                put("confidence", decision.confidence)
                put("recommendedAction", decision.recommendedAction)
                put("explanation", decision.explanation)
                put("evidenceTags", JSONArray(decision.evidenceTags))
                put("wasSilenced", wasSilenced)
                put("backendEvaluated", decision.backendEvaluated)
                put("timestamp", timestamp)
            }
            newArray.put(entry)

            val limit = minOf(oldArray.length(), MAX_HISTORY_ENTRIES - 1)
            for (i in 0 until limit) {
                newArray.put(oldArray.get(i))
            }

            prefs.edit().putString(KEY_SCREENED_CALL_HISTORY, newArray.toString()).apply()
        } catch (_: Exception) {
            // Non-fatal persistence error
        }
    }

    private fun postCallAlert(phoneNumber: String, title: String, body: String) {
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "CyberShield Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                )
                manager.createNotificationChannel(channel)
            }

            val launchIntent = Intent(this, MainActivity::class.java).apply {
                action = "com.example.mobile.ACTION_VIEW_THREAT"
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("extra_screen", "call_screening")
                putExtra("extra_type", "call")
                putExtra("extra_phone_number", phoneNumber)
                putExtra("extra_title", title)
                putExtra("extra_content", body)
                putExtra("extra_event_id", "call-${System.currentTimeMillis()}-$phoneNumber")
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                phoneNumber.hashCode(),
                launchIntent,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                } else {
                    PendingIntent.FLAG_UPDATE_CURRENT
                }
            )

            val builder = NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)

            manager.notify(phoneNumber.hashCode(), builder.build())
        } catch (_: SecurityException) {
            // Android 13+ POST_NOTIFICATIONS might not yet be granted
        }
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
