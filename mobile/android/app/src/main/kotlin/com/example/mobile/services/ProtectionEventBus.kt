package com.example.mobile.services

import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.EventChannel

object ProtectionEventBus {
    private var eventSink: EventChannel.EventSink? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    fun setEventSink(sink: EventChannel.EventSink?) {
        this.eventSink = sink
    }

    fun emitEvent(event: Map<String, Any?>) {
        mainHandler.post {
            try {
                eventSink?.success(event)
            } catch (e: Exception) {
                // Flutter engine may not be attached or sink is cancelled
            }
        }
    }
}

