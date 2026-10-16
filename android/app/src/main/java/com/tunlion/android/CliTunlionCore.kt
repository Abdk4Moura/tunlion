package com.tunlion.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Temporary, CLI-only backend. All protocol decisions stay in the packaged Rust executable. */
class CliTunlionCore(private val context: Context) : TunlionCore {
    private val cli = CliProcess(context)
    private val operations = Mutex()
    private var cached = CoreStatus(deviceName = Build.MODEL)
    private var draft: File? = null
    private var draftPhrase: String? = null
    override fun status() = cached

    override suspend fun refresh(): CoreStatus = operations.withLock { withContext(Dispatchers.IO) {
        val status = cli.run(listOf("status"), 8_000)
        val snapshot = status.json ?: error("The CLI did not return a status snapshot")
        val result = cli.run(listOf("devices"), 10_000)
        check(result.exit == 0 || result.exit == 9) { "Could not load devices" }
        val rows = result.json?.optJSONObject("data")?.optJSONArray("devices") ?: JSONArray()
        val devices = (0 until rows.length()).map { index ->
            val row = rows.getJSONObject(index)
            val caps = row.optJSONArray("caps") ?: JSONArray()
            val active = row.optString("state", "active") == "active"
            CoreDevice(
                id = row.optString("channel").ifBlank { row.getString("name") },
                name = row.getString("name"),
                online = if (row.isNull("online")) null else row.getBoolean("online"),
                route = null, // devices --json has no authoritative route field. Never infer one.
                plainLine = "Access on this phone: " + (0 until caps.length()).joinToString { caps.getString(it) }.ifBlank { "none" },
                canSendFiles = active,
                canOpenShell = false, // Local caps describe THEIR access here, not our shell rights there.
            )
        }
        val publisher = ReceivedFiles(context)
        val transfers = publisher.records().takeLast(20).reversed().map { record ->
            CoreTransfer(record.optString("file"), record.optString("direction") == "in", record.optBoolean("ok"), publisher.saved(record))
        }
        cached = CoreStatus(identityLoaded = true, deviceName = Build.MODEL,
            fingerprint = snapshot.optString("identity").takeUnless { it.isBlank() || it == "null" },
            engineRunning = snapshot.optBoolean("running") && snapshot.optBoolean("responding"),
            engineLinked = cli.paths.binary.canExecute(), devices = devices, transfers = transfers,
            engineError = EngineState.error)
        cached
    } }

    override suspend fun prepareIdentity(): String = operations.withLock { withContext(Dispatchers.IO) {
        check(draft == null) { "Setup is already open" }
        val current = cli.run(listOf("status"), 8_000).json ?: error("Could not inspect identity")
        check(current.isNull("identity") && current.optInt("devices") == 0) { "This phone already has an identity or paired devices" }
        val folder = File(cli.paths.root, ".draft-${UUID.randomUUID()}").apply { mkdir(); android.system.Os.chmod(absolutePath, 448) }
        draft = folder
        try {
            val recovery = File(folder, "recovery.txt")
            val result = cli.run(listOf("init", "--name", Build.MODEL, "--no-background", "--recovery-file", recovery.absolutePath, "--yes"), 30_000, folder)
            check(result.exit == 0) { "Could not prepare identity" }
            val phrase = recovery.readText().trim()
            check(phrase.split(Regex("\\s+")).size == 12) { "Invalid recovery phrase" }
            recovery.delete()
            draftPhrase = phrase
            phrase
        } catch (error: Exception) { discardIdentity(); throw error }
    } }

    override suspend fun confirmIdentity(phrase: String): CoreResult = guarded {
        operations.withLock { withContext(Dispatchers.IO) {
            val pending = draft ?: return@withContext failure("Open identity setup again.")
            if (phrase.trim().split(Regex("\\s+")) != draftPhrase?.split(Regex("\\s+"))) return@withContext failure("The recovery words did not match.")
            val current = cli.run(listOf("status"), 8_000).json ?: error("Could not inspect identity")
            check(current.isNull("identity") && current.optInt("devices") == 0) { "An identity or pairing already exists; it has not been replaced" }
            val active = File(cli.paths.root, "state")
            // Status may have created an unused overlay key before setup. Move
            // that uninitialised directory aside; promote the complete CLI state.
            val previous = File(cli.paths.root, ".uninitialised-${UUID.randomUUID()}")
            if (active.exists()) Files.move(active.toPath(), previous.toPath(), StandardCopyOption.ATOMIC_MOVE)
            try { Files.move(pending.toPath(), active.toPath(), StandardCopyOption.ATOMIC_MOVE) }
            catch (error: Exception) { if (previous.exists()) Files.move(previous.toPath(), active.toPath(), StandardCopyOption.ATOMIC_MOVE); throw error }
            previous.deleteRecursively()
            draft = null; draftPhrase = null
            CoreResult.Success
        } }
    }

    override fun discardIdentity() { draft?.deleteRecursively(); draft = null; draftPhrase = null }

    override suspend fun start(): CoreResult = guarded {
        if (EngineState.phase.value == EnginePhase.AVAILABLE) return@guarded CoreResult.Success
        EngineState.phase.value = EnginePhase.STARTING
        ContextCompat.startForegroundService(context, Intent(context, AvailabilityService::class.java))
        try {
            withTimeout(25_000) { EngineState.phase.first { it == EnginePhase.AVAILABLE || it == EnginePhase.FAILED } }
            if (EngineState.phase.value == EnginePhase.AVAILABLE) CoreResult.Success else failure(EngineState.error ?: "Could not start the receiver.")
        } catch (error: CancellationException) {
            context.startService(Intent(context, AvailabilityService::class.java).setAction("stop"))
            throw error
        }
    }

    override suspend fun stop(): CoreResult = guarded {
        if (EngineState.phase.value == EnginePhase.OFF) return@guarded CoreResult.Success
        context.startService(Intent(context, AvailabilityService::class.java).setAction("stop"))
        withTimeout(10_000) { EngineState.phase.first { it == EnginePhase.OFF } }
        CoreResult.Success
    }

    override suspend fun joinCode(code: String, remember: Boolean): CoreResult = guarded {
        if (!Regex("[a-zA-Z]+(?:-[a-zA-Z]+){1,3}-[0-9]{4}").matches(code)) return@guarded failure("Enter the complete device code, including its four-digit number.")
        transferForeground {
        val result = operations.withLock { cli.run(listOf("join", code), 120_000).result() }
        if (result == CoreResult.Success) start() else result
        }
    }

    override suspend fun joinInvitation(bytes: ByteArray): CoreResult = guarded {
        require(bytes.size in 1..65536) { "Invitation is empty or too large" }
        transferForeground {
        val result = operations.withLock {
            withContext(Dispatchers.IO) {
                val invitation = File(cli.paths.root, ".invitation-${UUID.randomUUID()}")
                try {
                    Files.createFile(invitation.toPath(), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")))
                    invitation.writeBytes(bytes)
                    cli.run(listOf("join", "--invite-file", invitation.absolutePath, "--name", Build.MODEL, "--yes"), 120_000).result()
                } finally { invitation.delete() }
            }
        }
        if (result == CoreResult.Success) start() else result
        }
    }

    override suspend fun receiveCode(code: String): CoreResult = guarded {
        if (!Regex("[a-zA-Z]+(?:-[a-zA-Z]+){1,3}-[0-9]{2,4}").matches(code)) return@guarded failure("Enter the complete file code.")
        transferForeground {
        operations.withLock {
            val result = cli.run(listOf("receive", code, "--dir", cli.paths.inbox.absolutePath), 600_000).result()
            if (result == CoreResult.Success) withContext(Dispatchers.IO) { ReceivedFiles(context).publish() }
            result
        }
        }
    }

    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult = guarded {
        require(files.isNotEmpty()) { "Choose a file first" }
        transferForeground {
        operations.withLock {
            withContext(Dispatchers.IO) {
                val staging = File(context.cacheDir, "send-${UUID.randomUUID()}").apply { mkdirs() }
                try {
                    val paths = files.mapIndexed { index, uri ->
                        val rawName = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                            if (it.moveToFirst()) it.getString(0) else null
                        } ?: "file-$index"
                        val name = File(rawName).name.takeIf { it.isNotBlank() && it != "." && it != ".." } ?: "file-$index"
                        val folder = File(staging, index.toString()).apply { mkdir() }
                        val target = File(folder, name)
                        context.contentResolver.openInputStream(uri).use { input ->
                            checkNotNull(input) { "Could not open selected file" }
                            target.outputStream().use { output ->
                                val buffer = ByteArray(64 * 1024)
                                while (true) { ensureActive(); val n = input.read(buffer); if (n < 0) break; output.write(buffer, 0, n) }
                            }
                        }
                        target.absolutePath
                    }
                    val deviceName = deviceId?.let { id -> cached.devices.firstOrNull { it.id == id }?.name ?: error("Unknown device") }
                    val args = listOf("send") + paths + if (deviceName == null) listOf("--code", "--timeout", "300") else listOf("--to", deviceName)
                    cli.run(args, 600_000) { frame ->
                        if (frame.optString("event") == "code") withContext(Dispatchers.Main) { onCode(frame.getString("code")) }
                    }.result()
                } finally { staging.deleteRecursively() }
            }
        }
        }
    }

    private suspend fun transferForeground(block: suspend () -> CoreResult): CoreResult {
        ContextCompat.startForegroundService(context, Intent(context, TransferService::class.java))
        return try { block() } finally { context.stopService(Intent(context, TransferService::class.java)) }
    }

    private fun failure(message: String) = CoreResult.Failure(CoreErrorKind.INVALID_INPUT, message)
    private suspend fun guarded(block: suspend () -> CoreResult): CoreResult = try { block() }
        catch (_: TimeoutCancellationException) { CoreResult.Failure(CoreErrorKind.UNREACHABLE, "This action timed out. Check the other device and try again.") }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { CoreResult.Failure(CoreErrorKind.INTERNAL, "Tunlion could not complete this action. Your existing identity has not been replaced.") }
}
