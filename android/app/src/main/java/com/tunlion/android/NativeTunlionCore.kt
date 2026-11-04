package com.tunlion.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import java.io.File
import java.util.UUID
import kotlin.coroutines.resume
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import uniffi.tunlion_core.AccessState as NativeAccessState
import uniffi.tunlion_core.CoreException
import uniffi.tunlion_core.CoreSession
import uniffi.tunlion_core.DeviceAccess as NativeDeviceAccess
import uniffi.tunlion_core.DevicePresence as NativeDevicePresence
import uniffi.tunlion_core.DeviceRelationship as NativeDeviceRelationship
import uniffi.tunlion_core.EngineState as NativeEngineState
import uniffi.tunlion_core.PendingIdentity

/** Android resource adapter only. No subprocess, enrollment policy or key parsing. */
class NativeTunlionCore private constructor(private val context: Context) : TunlionCore {
    companion object {
        @Volatile private var instance: NativeTunlionCore? = null
        fun get(context: Context): NativeTunlionCore = instance ?: synchronized(this) {
            instance ?: NativeTunlionCore(context.applicationContext).also { instance = it }
        }
    }

    // Keep the preview's existing identity directory. Never migrate or replace keys.
    private val root = File(context.filesDir, "tunlion")
    private val config = if (File(root, "identity.ed25519").exists() || File(root, "identity/device-cert.json").exists()) root else File(root, "state")
    private val inbox = File(config, "inbox").apply { mkdirs() }
    private val session by lazy { CoreSession.open(config.absolutePath) }
    private val worker = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transfer = Mutex()
    private var pending: PendingIdentity? = null
    @Volatile private var publicationError: String? = null
    @Volatile private var lastSend: CoreSendReport? = null
    @Volatile private var cached = CoreStatus(deviceName = Build.MODEL)
    override fun status() = cached

    internal fun receivedFiles() = ReceivedFiles(context, config, inbox)
    internal suspend fun publishInbox(): List<String> {
        val published = try {
            receivedFiles().publish().also { publicationError = null }
        } catch (error: Exception) {
            publicationError = "A received file remains in the private inbox. Check free space and receiving-folder access, then reopen Files to retry."
            throw java.io.IOException("Could not publish verified inbox files", error)
        }
        if (published.isNotEmpty() && androidx.core.app.NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            val manager = context.getSystemService(android.app.NotificationManager::class.java)
            manager.createNotificationChannel(android.app.NotificationChannel("received", "Received files", android.app.NotificationManager.IMPORTANCE_DEFAULT))
            val open = android.app.PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java),
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT)
            manager.notify(1002, androidx.core.app.NotificationCompat.Builder(context, "received")
                .setSmallIcon(R.drawable.ic_tunlion).setContentTitle("Files received and verified")
                .setContentText(published.joinToString()).setContentIntent(open).setAutoCancel(true).build())
        }
        return published
    }

    override suspend fun refresh(): CoreStatus = withContext(Dispatchers.IO) {
        val snapshot = session.status()
        val devices = session.devices().map(::coreDevice)
        val history = receivedFiles()
        try { publishInbox() } catch (_: java.io.IOException) { /* The publication error is included in this snapshot. */ }
        cached = CoreStatus(identityLoaded = true, deviceName = Build.MODEL,
            fingerprint = snapshot.fingerprint, engineLinked = true,
            engineRunning = EngineState.phase.value == EnginePhase.AVAILABLE && snapshot.engine == NativeEngineState.RUNNING,
            engineError = EngineState.error ?: publicationError,
            devices = devices, lastSend = lastSend,
            transfers = history.records().takeLast(20).reversed().map {
                CoreTransfer(it.optString("file"), it.optString("direction") == "in", it.optBoolean("ok"), history.saved(it))
            })
        cached
    }

    override suspend fun prepareIdentity(): String = withContext(Dispatchers.IO) {
        check(pending == null) { "Setup is already open" }
        session.beginIdentity().also { pending = it }.phrase()
    }

    override suspend fun confirmIdentity(phrase: String): CoreResult = guarded {
        withContext(Dispatchers.IO) {
            val draft = pending ?: return@withContext CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Open identity setup again.")
            session.commitIdentity(draft, phrase)
            discardIdentity()
            CoreResult.Success
        }
    }

    override fun discardIdentity() { pending?.close(); pending = null }

    override suspend fun start(): CoreResult = guarded {
        if (transfer.isLocked) return@guarded CoreResult.Failure(CoreErrorKind.DENIED, "Wait for the transfer to finish before turning availability on.")
        if (EngineState.phase.value == EnginePhase.AVAILABLE) return@guarded CoreResult.Success
        if (EngineState.phase.value != EnginePhase.OFF) return@guarded CoreResult.Failure(CoreErrorKind.DENIED,
            "Confirm the receiver is off before restarting it.")
        EngineState.phase.value = EnginePhase.STARTING
        try {
            ContextCompat.startForegroundService(context, Intent(context, AvailabilityService::class.java))
            EngineState.phase.first { it == EnginePhase.AVAILABLE || it == EnginePhase.FAILED || it == EnginePhase.OFF }
        } catch (cancelled: CancellationException) {
            withContext(NonCancellable) { stop() }
            throw cancelled
        } catch (error: Exception) {
            EngineState.phase.value = EnginePhase.FAILED
            throw error
        }
        if (EngineState.phase.value == EnginePhase.AVAILABLE) CoreResult.Success
        else CoreResult.Failure(CoreErrorKind.INTERNAL, EngineState.error ?: "The receiver could not start.")
    }

    override suspend fun stop(): CoreResult = guarded {
        if (EngineState.phase.value == EnginePhase.OFF) {
            withContext(Dispatchers.IO) { session.stop() }
            EngineState.error = null
            return@guarded CoreResult.Success
        }
        EngineState.phase.value = EnginePhase.STOPPING
        context.startService(Intent(context, AvailabilityService::class.java).setAction("stop"))
        EngineState.phase.first { it == EnginePhase.OFF || it == EnginePhase.FAILED }
        if (EngineState.phase.value == EnginePhase.OFF) CoreResult.Success
        else CoreResult.Failure(CoreErrorKind.INTERNAL, EngineState.error ?: "The receiver has not confirmed stopping.")
    }

    internal fun startReceiver() = session.start()
    internal fun stopReceiver() = session.stop()
    internal fun receiverState() = session.status().engine

    override suspend fun joinCode(code: String, remember: Boolean) = enrollmentUnavailable()
    override suspend fun joinInvitation(bytes: ByteArray) = enrollmentUnavailable()
    private fun enrollmentUnavailable() = CoreResult.Failure(CoreErrorKind.FEATURE_NOT_LINKED,
        "Native pairing and fleet enrollment are not connected yet. No device or permission has been changed.")

    override suspend fun receiveCode(code: String): CoreResult = runTransfer {
        val summary = session.receiveCode(code, inbox.absolutePath, true, 300uL)
        val receipts = receivedFiles().records()
        if (summary.stored.any { stored -> receipts.none { record ->
                record.optString("stored") == File(inbox, stored.storedName).absolutePath &&
                    record.optString("sha256").equals(stored.sha256, ignoreCase = true) && record.optBoolean("ok")
            } }) return@runTransfer CoreResult.Failure(CoreErrorKind.LOCAL_RESOURCE,
            "Files arrived in the private inbox, but their durable receipt is unavailable. They have not been exported. Do not clear app storage.")
        publishInbox()
        if (summary.refused.isNotEmpty()) CoreResult.Failure(CoreErrorKind.PARTIAL,
            "${summary.stored.size} received; ${summary.refused.size} refused. " + summary.refused.joinToString { it.message })
        else CoreResult.Success
    }

    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult {
        val device = deviceId?.let { id -> cached.devices.firstOrNull { it.id == id } }
        if (deviceId != null && device == null) return CoreResult.Failure(CoreErrorKind.UNKNOWN_DEVICE, "The device is not in the current core snapshot. Return to Devices and refresh.")
        if (files.isEmpty()) return CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Choose files first.")
        return runTransfer {
            lastSend = null
            val staging = File(context.cacheDir, "send-${UUID.randomUUID()}")
            check(staging.mkdirs())
            try {
                val paths = files.mapIndexed { index, uri ->
                    val raw = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                        if (it.moveToFirst()) it.getString(0) else null
                    }
                    val name = raw?.let { File(it).name }?.takeUnless { it.isBlank() || it == "." || it == ".." } ?: "file-$index"
                    val folder = File(staging, index.toString()).apply { check(mkdir()) }
                    File(folder, name).also { target ->
                        context.contentResolver.openInputStream(uri).use { input ->
                            checkNotNull(input) { "The selected file is no longer readable" }
                            target.outputStream().use { output ->
                                val bytes = ByteArray(64 * 1024)
                                while (true) {
                                    currentCoroutineContext().ensureActive()
                                    val count = input.read(bytes)
                                    if (count < 0) break
                                    output.write(bytes, 0, count)
                                }
                            }
                        }
                    }.absolutePath
                }
                currentCoroutineContext().ensureActive()
                val sent = if (device == null) {
                    val created = session.createCode(paths, 300uL)
                    withContext(Dispatchers.Main) { onCode(created.code) }
                    session.waitSend()
                } else session.sendToDevice(paths, device.name, 300uL)
                lastSend = CoreSendReport(sent.files.map { CoreSentFile(it.name, it.delivered, it.storedName) }, device?.name)
                val missing = sent.files.filterNot { it.delivered }
                if (sent.files.size != paths.size || missing.isNotEmpty())
                    CoreResult.Failure(CoreErrorKind.PARTIAL,
                        "${sent.files.count { it.delivered }} of ${paths.size} files were acknowledged as delivered by the receiver." +
                            missing.joinToString(prefix = " Not acknowledged: ", separator = ", ") { it.name })
                else CoreResult.Success
            } finally { staging.deleteRecursively() }
        }
    }

    /**
     * Project the core's read-only device facts. Relationship and stored
     * records are never promoted to remote authority; presence is unknown
     * because the snapshot does not probe peers.
     */
    private fun coreDevice(access: NativeDeviceAccess): CoreDevice {
        val actions = access.actions.map { action ->
            CoreAction(action.action, when (action.state) {
                NativeAccessState.AVAILABLE -> CoreAccessState.AVAILABLE
                NativeAccessState.BLOCKED -> CoreAccessState.BLOCKED
                NativeAccessState.UNSUPPORTED -> CoreAccessState.UNSUPPORTED
                NativeAccessState.UNKNOWN -> CoreAccessState.UNKNOWN
            }, action.reason)
        }
        return CoreDevice(
            id = access.deviceKey ?: "name:${access.name}",
            name = access.name,
            online = when (access.presence) { NativeDevicePresence.UNKNOWN -> null },
            route = null,
            plainLine = "Stored device record from the shared core. Remote grants, reachability and delivered files are not observed.",
            canSendFiles = actions.any { it.action == "send" && it.state == CoreAccessState.AVAILABLE },
            canOpenShell = actions.any { it.action == "terminal" && it.state == CoreAccessState.AVAILABLE },
            relationship = when (access.relationship) {
                NativeDeviceRelationship.PAIRED -> CoreRelationship.PAIRED
                NativeDeviceRelationship.FLEET -> CoreRelationship.FLEET
                NativeDeviceRelationship.TEMPORARY -> CoreRelationship.TEMPORARY
                NativeDeviceRelationship.UNKNOWN -> CoreRelationship.UNKNOWN
            },
            expiry = access.expiresAt?.let { java.time.Instant.ofEpochSecond(it.toLong()).toString() },
            revoked = access.revoked,
            actions = actions,
        )
    }

    /** Blocking FFI owns its files until it returns. Cancellation calls core.stop on another thread. */
    private suspend fun runTransfer(action: suspend () -> CoreResult): CoreResult {
        if (!transfer.tryLock()) return CoreResult.Failure(CoreErrorKind.DENIED, "A transfer is still running or stopping.")
        if (EngineState.phase.value != EnginePhase.OFF) {
            transfer.unlock()
            return CoreResult.Failure(CoreErrorKind.DENIED, "Turn availability off before a code transfer. The core currently supports one engine at a time.")
        }
        return suspendCancellableCoroutine { continuation ->
            val lifecycle = Any()
            var completed = false
            var cancelling = false
            val task = worker.launch(start = CoroutineStart.LAZY) {
                val result = guarded {
                    ContextCompat.startForegroundService(context, Intent(context, TransferService::class.java))
                    action()
                }
                if (continuation.isActive) continuation.resume(result)
            }
            task.invokeOnCompletion {
                synchronized(lifecycle) {
                    completed = true
                    if (!cancelling) {
                        context.stopService(Intent(context, TransferService::class.java))
                        transfer.unlock()
                    }
                }
            }
            continuation.invokeOnCancellation {
                val needsStop = synchronized(lifecycle) {
                    if (completed) false else { cancelling = true; true }
                }
                if (needsStop) {
                    task.cancel()
                    worker.launch {
                        try {
                            // Stop can race allocation. Keep the operation lease through cancellation and join.
                            while (!task.isCompleted) {
                                try { session.stop() }
                                catch (_: Exception) { EngineState.error = "The transfer could not be joined. Turn availability off before retrying." }
                                delay(100)
                            }
                        } finally {
                            context.stopService(Intent(context, TransferService::class.java))
                            transfer.unlock()
                        }
                    }
                }
            }
            task.start()
        }
    }

    private suspend fun guarded(action: suspend () -> CoreResult): CoreResult = try { action() }
    catch (cancelled: CancellationException) { throw cancelled }
    catch (_: CoreException.Usage) { CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Check the complete file code and selected files.") }
    catch (_: CoreException.Unreachable) { CoreResult.Failure(CoreErrorKind.UNREACHABLE, "The other device did not answer. Keep Tunlion open there and retry.") }
    catch (_: CoreException.Refused) { CoreResult.Failure(CoreErrorKind.DENIED, "The receiver refused the transfer.") }
    catch (_: CoreException.Partial) { CoreResult.Failure(CoreErrorKind.PARTIAL, "Not all files were acknowledged. The core did not return per-file delivery facts; check the receiver before retrying.") }
    catch (_: CoreException.Cancelled) { CoreResult.Failure(CoreErrorKind.CANCELLED, "Transfer cancelled.") }
    catch (_: CoreException.PhraseMismatch) { CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "The recovery words did not match. Nothing was saved.") }
    catch (_: CoreException.Io) { CoreResult.Failure(CoreErrorKind.LOCAL_RESOURCE, "The native core could not read or save local data. Check free space and reopen Files. Private inbox files have been kept.") }
    catch (_: CoreException.Stop) { CoreResult.Failure(CoreErrorKind.INTERNAL, "The native engine has not confirmed stopping. Turn availability off again before retrying.") }
    catch (_: java.io.IOException) { CoreResult.Failure(CoreErrorKind.LOCAL_RESOURCE, "Could not read or save a file. Check free space and folder access. Private inbox files have been kept.") }
    catch (_: Exception) { CoreResult.Failure(CoreErrorKind.INTERNAL, "The native core could not finish. Your identity has not been replaced. Check storage and availability before retrying.") }
}
