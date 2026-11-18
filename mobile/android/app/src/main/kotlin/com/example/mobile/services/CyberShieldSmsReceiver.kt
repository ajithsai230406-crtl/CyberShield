package com.example.mobile.services

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import org.json.JSONArray
import org.json.JSONObject

/**
 * Permission-based incoming SMS BroadcastReceiver.
 * Only operates when master protection is enabled, monitoring is not paused,
 * and the user has explicitly consented to SMS monitoring + granted RECEIVE_SMS.
 * Never logs raw OTPs, cards, or passwords.
 */
class CyberShieldSmsReceiver : BroadcastReceiver() {

    companion object {
        const val PREFS_NAME = "cybershield_protection_prefs"
        const val KEY_PROTECTION_ENABLED = "protection_master_enabled"
        const val KEY_COMM_PAUSED = "comm_monitoring_paused"
        const val KEY_MONITOR_SMS = "comm_monitor_sms"
        const val KEY_STORE_PREVIEW = "comm_store_preview"
        const val KEY_PENDING_COMM_EVENTS = "pending_comm_events"
        private const val MAX_PENDING_EVENTS = 100
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_PROTECTION_ENABLED, true)) return
        if (prefs.getBoolean(KEY_COMM_PAUSED, false)) return
        if (!prefs.getBoolean(KEY_MONITOR_SMS, false)) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        // Group multipart SMS by originating address
        val grouped = LinkedHashMap<String, StringBuilder>()
        var latestTimestamp = System.currentTimeMillis()
        for (msg in messages) {
            val sender = msg.displayOriginatingAddress ?: msg.originatingAddress ?: "Unknown Sender"
            val body = msg.messageBody ?: ""
            grouped.getOrPut(sender) { StringBuilder() }.append(body)
            if (msg.timestampMillis > 0) {
                latestTimestamp = msg.timestampMillis
            }
        }

        val storePreview = prefs.getBoolean(KEY_STORE_PREVIEW, true)

        for ((sender, bodyBuilder) in grouped) {
            val rawBody = bodyBuilder.toString().trim()
            if (rawBody.isEmpty()) continue

            val (sanitizedBody, wasRedacted) = CyberShieldNotificationListenerService.redactSensitiveText(rawBody)
            val eventMap = hashMapOf<String, Any?>(
                "type" to "comm_sms",
                "communicationType" to "sms",
                "sourceApp" to "SMS",
                "sender" to sender,
                "content" to sanitizedBody,
                "storePreview" to storePreview,
                "wasRedacted" to wasRedacted,
                "timestamp" to latestTimestamp
            )

            ProtectionEventBus.emitEvent(eventMap)
            enqueuePendingEvent(prefs, eventMap)
        }
    }

    private fun enqueuePendingEvent(prefs: android.content.SharedPreferences, eventMap: Map<String, Any?>) {
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
