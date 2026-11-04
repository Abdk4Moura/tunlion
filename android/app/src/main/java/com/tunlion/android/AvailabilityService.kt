package com.tunlion.android

import android.app.*
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import uniffi.tunlion_core.EngineState as NativeEngineState

internal enum class EnginePhase { OFF, STARTING, AVAILABLE, STOPPING, FAILED }
internal object EngineState {
    val phase = MutableStateFlow(EnginePhase.OFF)
    @Volatile var error: String? = null
}

/** The process owns one native session, shared by the Activity and this foreground service. */
class AvailabilityService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var core: NativeTunlionCore
    private var receiver: Job? = null
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onCreate() {
        super.onCreate()
        core = NativeTunlionCore.get(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("availability", "Availability", NotificationManager.IMPORTANCE_LOW).apply { setSound(null, null) })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1001, notification("Starting Tunlion…"))
        if (intent?.action == "stop") {
            EngineState.phase.value = EnginePhase.STOPPING
            scope.launch {
                try {
                    receiver?.cancel()
                    core.stopReceiver()
                    receiver?.join()
                    EngineState.phase.value = EnginePhase.OFF
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                } catch (_: Exception) {
                    EngineState.error = "The native receiver has not confirmed stopping. Try turning it off again."
                    EngineState.phase.value = EnginePhase.FAILED
                }
            }
            return START_NOT_STICKY
        }
        if (receiver?.isActive == true) return START_NOT_STICKY
        receiver = scope.launch {
            try {
                EngineState.phase.value = EnginePhase.STARTING
                EngineState.error = null
                core.startReceiver()
                EngineState.phase.value = EnginePhase.AVAILABLE
                getSystemService(NotificationManager::class.java).notify(1001, notification("Available for inbox transfers"))
                while (isActive) {
                    check(core.receiverState() == NativeEngineState.RUNNING)
                    try { core.receivedFiles().publish() }
                    catch (_: Exception) { EngineState.error = "A verified file remains in the private inbox. Check storage and receiving-folder access, then retry from Files." }
                    delay(2_000)
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                EngineState.error = "The native receiver stopped or could not start. Turn it off to join it before retrying."
                EngineState.phase.value = EnginePhase.FAILED
                getSystemService(NotificationManager::class.java).notify(1001, notification("Receiver needs attention. Open Tunlion."))
            } finally {
                withContext(NonCancellable) {
                    try { core.stopReceiver() }
                    catch (_: Exception) {
                        EngineState.phase.value = EnginePhase.FAILED
                        EngineState.error = "The native receiver has not confirmed stopping. Turn availability off again."
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, AvailabilityService::class.java).setAction("stop"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(this, "availability").setSmallIcon(R.drawable.ic_tunlion)
            .setContentTitle("Tunlion").setContentText(message).setContentIntent(open).setOngoing(true)
            .addAction(0, "Turn off", stop).setOnlyAlertOnce(true).build()
    }

    override fun onDestroy() {
        scope.cancel()
        // The receiver's finally block joins the native engine. Destruction itself is not an acknowledgment.
        super.onDestroy()
    }
}
