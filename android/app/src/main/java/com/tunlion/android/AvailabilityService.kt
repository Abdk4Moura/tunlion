package com.tunlion.android

import android.app.*
import android.content.Intent
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.concurrent.TimeUnit

internal enum class EnginePhase { OFF, STARTING, AVAILABLE, STOPPING, FAILED }
internal object EngineState {
    val phase = MutableStateFlow(EnginePhase.OFF)
    var error: String? = null
}

class AvailabilityService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var receiver: Job? = null
    private var process: Process? = null
    private var observer: FileObserver? = null
    private lateinit var cli: CliProcess
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onCreate() {
        super.onCreate()
        cli = CliProcess(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("availability", "Availability", NotificationManager.IMPORTANCE_LOW).apply { setSound(null, null) })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") {
            EngineState.phase.value = EnginePhase.STOPPING
            scope.launch {
                receiver?.cancelAndJoin()
                receiver = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                EngineState.phase.value = EnginePhase.OFF
                stopSelf()
            }
            return START_NOT_STICKY
        }
        startForeground(1001, notification("Starting Tunlion…"))
        if (receiver?.isActive != true) receiver = scope.launch {
            var attempts = 0
            try {
                while (isActive && attempts < 5) {
                    EngineState.phase.value = EnginePhase.STARTING
                    EngineState.error = null
                    val drains = CoroutineScope(SupervisorJob() + Dispatchers.IO +
                        CoroutineExceptionHandler { _, _ -> /* closing the child interrupts these readers */ })
                    try {
                        process = cli.builder(listOf("up", "--userspace", "--no-proxy-fallback", "--dir", cli.paths.inbox.absolutePath)).start()
                        val child = process!!
                        child.outputStream.close()
                            val sink = object : java.io.OutputStream() { override fun write(value: Int) = Unit; override fun write(bytes: ByteArray, offset: Int, length: Int) = Unit }
                            // Drain only. Reaping closes these streams, which interrupts a blocked read;
                            // that is expected shutdown, never a reason to fail the process.
                            val out = drains.launch { try { child.inputStream.use { it.copyTo(sink) } } catch (_: Exception) {} }
                            val err = drains.launch { try { child.errorStream.use { it.copyTo(sink) } } catch (_: Exception) {} }
                            var ready = false
                            repeat(40) {
                                ensureActive()
                                if (!ready && child.isAlive) {
                                    val status = cli.run(listOf("status"), 5_000)
                                    val snapshot = status.json
                                    if (status.exit == 0 && snapshot?.optBoolean("running") == true &&
                                        snapshot.opt("responding") != false) ready = true
                                    else delay(250)
                                }
                            }
                            check(ready) { "Receiver did not become ready" }
                            EngineState.phase.value = EnginePhase.AVAILABLE
                            getSystemService(NotificationManager::class.java).notify(1001, notification("Available to your devices"))
                            observeTransfers()
                            while (child.isAlive) { delay(500); ensureActive() }
                            out.join(); err.join()
                            error("Receiver exited (${child.exitValue()})")
                    } catch (cancelled: CancellationException) { throw cancelled }
                    catch (error: Exception) {
                        attempts++
                        if (attempts >= 5) throw error
                    } finally {
                        observer?.stopWatching(); observer = null
                        withContext(NonCancellable) {
                            process?.let { child ->
                                child.destroy()
                                if (!child.waitFor(2, TimeUnit.SECONDS)) { child.destroyForcibly(); child.waitFor(2, TimeUnit.SECONDS) }
                            }
                            process = null
                            // Cancel the readers first; closing their streams under a
                            // blocked read is what used to throw on another thread.
                            drains.cancel()
                            withTimeoutOrNull(2_000) { drains.coroutineContext[Job]?.join() }
                        }
                    }
                    delay((1L shl attempts).coerceAtMost(30) * 1000)
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                EngineState.error = "The receiver stopped. Turn availability on to retry."
                EngineState.phase.value = EnginePhase.FAILED
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, AvailabilityService::class.java).setAction("stop"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(this, "availability").setSmallIcon(com.tunlion.android.R.drawable.ic_tunlion)
            .setContentTitle("Tunlion").setContentText(message).setContentIntent(open).setOngoing(true)
            .addAction(0, "Turn off", stop).setOnlyAlertOnce(true).build()
    }

    @Suppress("DEPRECATION")
    private fun observeTransfers() {
        suspend fun publish() {
            try {
                val names = ReceivedFiles(this@AvailabilityService).publish()
                if (names.isNotEmpty()) getSystemService(NotificationManager::class.java).notify(1002,
                    NotificationCompat.Builder(this@AvailabilityService, "availability").setSmallIcon(R.drawable.ic_tunlion)
                        .setContentTitle("File received and verified").setContentText(names.joinToString()).setAutoCancel(true).build())
            } catch (_: Exception) { EngineState.error = "A verified file is safe in the inbox but could not be saved to Downloads. Free some space and reopen Files." }
        }
        observer?.stopWatching()
        observer = object : FileObserver(cli.paths.config.absolutePath, FileObserver.MOVED_TO or FileObserver.CLOSE_WRITE) {
            override fun onEvent(event: Int, path: String?) { if (path == "transfers.json") scope.launch { publish() } }
        }.also { it.startWatching() }
        scope.launch { publish() }
    }

    override fun onDestroy() {
        observer?.stopWatching()
        process?.destroy()
        scope.cancel()
        if (EngineState.phase.value != EnginePhase.FAILED) EngineState.phase.value = EnginePhase.OFF
        super.onDestroy()
    }
}
