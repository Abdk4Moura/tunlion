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
import uniffi.tunlion_core.CoreException
import uniffi.tunlion_core.CoreSession
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
    @Volatile private var cached = CoreStatus(deviceName = Build.MODEL)
    override fun status() = cached

    internal fun receivedFiles() = ReceivedFiles(context, config, inbox)

    override suspend fun refresh(): CoreStatus = withContext(Dispatchers.IO) {
        val snapshot = session.status()
        val history = receivedFiles()
        try { history.publish() }
        catch (_: Exception) { EngineState.error = "A verified file remains in the private inbox. Check free space and receiving-folder access, then reopen Files to retry." }
        cached = CoreStatus(identityLoaded = true, deviceName = Build.MODEL,
            fingerprint = snapshot.fingerprint, engineLinked = true,
            engineRunning = EngineState.phase.value == EnginePhase.AVAILABLE && snapshot.engine == NativeEngineState.RUNNING,
            engineError = EngineState.error,
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
        EngineState.phase.value = EnginePhase.STARTING
        ContextCompat.startForegroundService(context, Intent(context, AvailabilityService::class.java))
        EngineState.phase.first { it == EnginePhase.AVAILABLE || it == EnginePhase.FAILED }
        if (EngineState.phase.value == EnginePhase.AVAILABLE) CoreResult.Success
        else CoreResult.Failure(CoreErrorKind.INTERNAL, EngineState.error ?: "The receiver could not start.")
    }

    override suspend fun stop(): CoreResult = guarded {
        if (EngineState.phase.value == EnginePhase.OFF) {
            withContext(Dispatchers.IO) { session.stop() }
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
        receivedFiles().publish()
        if (summary.refused.isNotEmpty()) CoreResult.Failure(CoreErrorKind.PARTIAL,
            "${summary.stored.size} saved privately; ${summary.refused.size} refused. " + summary.refused.joinToString { it.message })
        else CoreResult.Success
    }

    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult {
        if (deviceId != null) return CoreResult.Failure(CoreErrorKind.FEATURE_NOT_LINKED, "Native device discovery is not connected. Use a file code instead.")
        if (files.isEmpty()) return CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Choose files first.")
        return runTransfer {
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
                val created = session.createCode(paths, 300uL)
                withContext(Dispatchers.Main) { onCode(created.code) }
                val sent = session.waitSend()
                if (sent.files.any { !it.delivered }) CoreResult.Failure(CoreErrorKind.PARTIAL, "Some files were not acknowledged by the receiver.")
                else CoreResult.Success
            } finally { staging.deleteRecursively() }
        }
    }

    /** Blocking FFI owns its files until it returns. Cancellation calls core.stop on another thread. */
    private suspend fun runTransfer(action: suspend () -> CoreResult): CoreResult {
        if (!transfer.tryLock()) return CoreResult.Failure(CoreErrorKind.DENIED, "A transfer is still running or stopping.")
        if (EngineState.phase.value != EnginePhase.OFF && EngineState.phase.value != EnginePhase.FAILED) {
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
    catch (_: CoreException.Partial) { CoreResult.Failure(CoreErrorKind.PARTIAL, "Not all files were acknowledged. Check Files before retrying.") }
    catch (_: CoreException.Cancelled) { CoreResult.Failure(CoreErrorKind.CANCELLED, "Transfer cancelled.") }
    catch (_: CoreException.PhraseMismatch) { CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "The recovery words did not match. Nothing was saved.") }
    catch (_: CoreException.Io) { CoreResult.Failure(CoreErrorKind.LOCAL_RESOURCE, "The native core could not read or save local data. Check free space and reopen Files. Private inbox files have been kept.") }
    catch (_: CoreException.Stop) { CoreResult.Failure(CoreErrorKind.INTERNAL, "The native engine has not confirmed stopping. Turn availability off again before retrying.") }
    catch (_: java.io.IOException) { CoreResult.Failure(CoreErrorKind.LOCAL_RESOURCE, "Could not read or save a file. Check free space and folder access. Private inbox files have been kept.") }
    catch (_: Exception) { CoreResult.Failure(CoreErrorKind.INTERNAL, "The native core could not finish. Your identity has not been replaced. Check storage and availability before retrying.") }
}
