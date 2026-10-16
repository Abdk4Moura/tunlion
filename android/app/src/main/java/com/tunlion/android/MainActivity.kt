package com.tunlion.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*

class MainActivity : ComponentActivity() {
    private var feedbackEnabled by mutableStateOf(true)
    private var feedbackImage by mutableStateOf<android.graphics.Bitmap?>(null)
    private var capturing = false
    private var resumed = false
    private var sensitiveScreen = false
    private lateinit var shake: FeedbackShake

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        feedbackEnabled = getPreferences(MODE_PRIVATE).getBoolean("shake_feedback", true)
        shake = FeedbackShake(this) { openFeedback() }
        setContent {
            val core = remember { NativeTunlionCore(this) }
            TunlionTheme {
                TunlionApp(core, feedbackEnabled,
                    onFeedbackEnabled = { enabled ->
                        feedbackEnabled = enabled
                        getPreferences(MODE_PRIVATE).edit().putBoolean("shake_feedback", enabled).apply()
                        shake.stop()
                        if (enabled && resumed) shake.start()
                    }, onFeedback = { openFeedback() }, onSensitiveScreen = { sensitiveScreen = it })
                feedbackImage?.let { image ->
                    FeedbackEditor(image, onDismiss = { feedbackImage = null },
                        onShare = { crop, comment -> shareFeedback(this, crop, comment) })
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if (feedbackEnabled) shake.start()
    }

    override fun onPause() {
        resumed = false
        shake.stop()
        super.onPause()
    }

    private fun openFeedback() {
        if (sensitiveScreen) {
            android.widget.Toast.makeText(this, "Feedback capture is paused while recovery words are visible.", android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        if (!resumed || capturing || feedbackImage != null) return
        capturing = true
        captureFeedback(this) { image ->
            capturing = false
            if (resumed && !isDestroyed) feedbackImage = image else image?.recycle()
            if (image == null && resumed) android.widget.Toast.makeText(this,
                "Could not capture this screen. Try again.", android.widget.Toast.LENGTH_SHORT).show()
        }
    }
}
