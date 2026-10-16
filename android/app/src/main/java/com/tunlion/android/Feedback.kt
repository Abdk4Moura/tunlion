package com.tunlion.android

import android.app.Activity
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Rect
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import android.view.PixelCopy
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import java.io.File
import kotlin.math.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Registered only while this Activity is resumed. Two deliberate peaks, then cooldown. */
class FeedbackShake(private val context: Context, private val onShake: () -> Unit) : SensorEventListener {
    private val manager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private var previousPeak = 0L
    private var cooldownUntil = 0L

    fun start() {
        previousPeak = 0L
        manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)?.let {
            manager.registerListener(this, it, SensorManager.SENSOR_DELAY_UI)
        }
    }

    fun stop() { manager.unregisterListener(this); previousPeak = 0L }
    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
    override fun onSensorChanged(event: SensorEvent) {
        val now = SystemClock.elapsedRealtime()
        if (now < cooldownUntil) return
        val g = sqrt(event.values.sumOf { (it * it).toDouble() }) / SensorManager.GRAVITY_EARTH
        if (g < 2.7) return
        val elapsed = now - previousPeak
        if (previousPeak != 0L && elapsed in 180..900) {
            previousPeak = 0L
            cooldownUntil = now + 10_000
            onShake()
        } else if (elapsed > 900) previousPeak = now
    }
}

fun captureFeedback(activity: Activity, done: (Bitmap?) -> Unit) {
    val view = activity.findViewById<android.view.View>(android.R.id.content)
    if (view.width <= 0 || view.height <= 0) { done(null); return }
    val position = IntArray(2)
    view.getLocationInWindow(position)
    val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
    try {
        PixelCopy.request(activity.window,
            Rect(position[0], position[1], position[0] + view.width, position[1] + view.height),
            bitmap, { result ->
                if (result == PixelCopy.SUCCESS) done(bitmap)
                else { bitmap.recycle(); done(null) }
            }, Handler(Looper.getMainLooper()))
    } catch (_: IllegalArgumentException) { bitmap.recycle(); done(null) }
}

@Composable
fun FeedbackEditor(source: Bitmap, onDismiss: () -> Unit, onShare: suspend (Bitmap, String) -> Unit) {
    var selection by remember { mutableStateOf<androidx.compose.ui.geometry.Rect?>(null) }
    var cropped by remember { mutableStateOf<Bitmap?>(null) }
    var comment by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var sharing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Dialog(onDismissRequest = { if (!sharing) onDismiss() }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).padding(16.dp)) {
                Text(if (cropped == null) "Select a part of the app" else "Comment on this section",
                    style = MaterialTheme.typography.titleLarge)
                Text(if (cropped == null) "Drag around the part you want to change. Nothing is sent yet."
                    else "Only this crop and your comment will be shared.",
                    style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 8.dp))
                val shown = cropped ?: source
                val image = remember(shown) { shown.asImageBitmap() }
                var canvasSize by remember { mutableStateOf(IntSize.Zero) }
                val scale = if (canvasSize.width == 0) 1f else min(canvasSize.width.toFloat() / shown.width, canvasSize.height.toFloat() / shown.height)
                val origin = Offset((canvasSize.width - shown.width * scale) / 2f, (canvasSize.height - shown.height * scale) / 2f)
                fun imagePoint(point: Offset) = Offset(
                    ((point.x - origin.x) / scale).coerceIn(0f, shown.width.toFloat()),
                    ((point.y - origin.y) / scale).coerceIn(0f, shown.height.toFloat()))
                Canvas(Modifier.fillMaxWidth().weight(1f).background(Color(0xFF26251F))
                    .onSizeChanged { canvasSize = it }
                    .pointerInput(cropped, canvasSize) {
                        if (cropped != null) return@pointerInput
                        var start = Offset.Zero
                        detectDragGestures(onDragStart = { start = imagePoint(it); selection = null },
                            onDrag = { change, _ ->
                                change.consume()
                                val end = imagePoint(change.position)
                                selection = androidx.compose.ui.geometry.Rect(min(start.x, end.x), min(start.y, end.y), max(start.x, end.x), max(start.y, end.y))
                            })
                    }) {
                    drawImage(image, dstOffset = IntOffset(origin.x.roundToInt(), origin.y.roundToInt()),
                        dstSize = IntSize((shown.width * scale).roundToInt().coerceAtLeast(1), (shown.height * scale).roundToInt().coerceAtLeast(1)))
                    if (cropped == null) selection?.let { rect ->
                        drawRect(Color(0xFFD55C13).copy(alpha = .2f), origin + rect.topLeft * scale, Size(rect.width * scale, rect.height * scale))
                        drawRect(Color(0xFFFFC857), origin + rect.topLeft * scale, Size(rect.width * scale, rect.height * scale), style = Stroke(3.dp.toPx()))
                    }
                }
                if (cropped != null) {
                    OutlinedTextField(value = comment, onValueChange = { comment = it.take(2000) },
                        label = { Text("What should change?") }, minLines = 2, maxLines = 4,
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp), enabled = !sharing)
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = onDismiss, enabled = !sharing) { Text("Cancel") }
                    if (cropped != null) TextButton(onClick = { cropped = null }, enabled = !sharing) { Text("Reselect") }
                    Button(enabled = !sharing && if (cropped == null) (selection?.width ?: 0f) >= 24 && (selection?.height ?: 0f) >= 24 else comment.isNotBlank(),
                        onClick = {
                            val current = cropped
                            if (current == null) selection?.let { rect ->
                                val left = floor(rect.left).toInt().coerceIn(0, source.width - 1)
                                val top = floor(rect.top).toInt().coerceIn(0, source.height - 1)
                                cropped = Bitmap.createBitmap(source, left, top,
                                    ceil(rect.right).toInt().coerceIn(left + 1, source.width) - left,
                                    ceil(rect.bottom).toInt().coerceIn(top + 1, source.height) - top)
                            } else scope.launch {
                                sharing = true
                                try { onShare(current, comment.trim()); onDismiss() }
                                catch (_: Exception) { error = "Could not open sharing. Try again." }
                                finally { sharing = false }
                            }
                        }) { Text(if (cropped == null) "Use this section" else if (sharing) "Preparing…" else "Share feedback") }
                }
            }
        }
    }
}

/** Comment is also rendered into the PNG because some share targets drop EXTRA_TEXT. */
suspend fun shareFeedback(context: Context, crop: Bitmap, comment: String) {
    val file = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "feedback").apply { mkdirs() }
        dir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 86_400_000 }?.forEach { it.delete() }
        val width = max(crop.width, 720)
        val textPaint = TextPaint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply { color = android.graphics.Color.rgb(29, 28, 26); textSize = 28f }
        val text = "Tunlion Android preview · UI feedback\n\n$comment"
        val layout = StaticLayout.Builder.obtain(text, 0, text.length, textPaint, width - 64)
            .setAlignment(Layout.Alignment.ALIGN_NORMAL).setIncludePad(false).build()
        val report = Bitmap.createBitmap(width, crop.height + layout.height + 64, Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(report)
        canvas.drawColor(android.graphics.Color.rgb(247, 246, 242))
        canvas.drawBitmap(crop, (width - crop.width) / 2f, 0f, null)
        canvas.save(); canvas.translate(32f, crop.height + 32f); layout.draw(canvas); canvas.restore()
        val target = File(dir, "feedback-${java.util.UUID.randomUUID()}.png")
        try { target.outputStream().use { check(report.compress(Bitmap.CompressFormat.PNG, 100, it)) } }
        finally { report.recycle() }
        target
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.feedback", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "image/png"
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_TEXT, "Tunlion Android UI feedback\n\n$comment")
        clipData = ClipData.newRawUri("UI feedback", uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, "Share feedback"))
}
