package com.tunlion.android

import android.content.Context
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

internal class CliPaths(context: Context) {
    val root = File(context.filesDir, "tunlion").apply { mkdirs(); android.system.Os.chmod(absolutePath, 448) }
    // Preserve an identity created by an earlier preview rather than replacing it.
    // An owner holds identity.ed25519; a joined device holds identity/device-cert.json.
    val config: File get() = if (File(root, "identity.ed25519").exists() || File(root, "identity/device-cert.json").exists()) root else File(root, "state")
    val inbox = File(context.filesDir, "inbox").apply { mkdirs() }
    val binary = File(context.applicationInfo.nativeLibraryDir, "libtunlion_cli.so")
    val home = context.filesDir
}

internal data class CliOutcome(val exit: Int, val json: JSONObject?) {
    fun result(): CoreResult = if (exit == 0) CoreResult.Success else CoreResult.Failure(
        when (exit) {
            2 -> CoreErrorKind.INVALID_INPUT
            3 -> CoreErrorKind.UNKNOWN_DEVICE
            4 -> CoreErrorKind.DENIED
            6 -> CoreErrorKind.UNREACHABLE
            7 -> CoreErrorKind.NETWORK
            8 -> CoreErrorKind.PARTIAL
            9 -> CoreErrorKind.NO_IDENTITY
            12 -> CoreErrorKind.LOCAL_RESOURCE
            130, 143 -> CoreErrorKind.CANCELLED
            else -> CoreErrorKind.INTERNAL
        }, json?.optJSONObject("error")?.optString("message")?.takeIf { it.isNotBlank() }
            ?: when (exit) {
                4 -> "The other device refused access."
                6 -> "The other device did not answer. Keep Tunlion open there and try again."
                7 -> "Could not reach Tunlion. Check your connection."
                9 -> "Set up this phone or join a device first."
                12 -> "This phone ran out of a local resource."
                130, 143 -> "Cancelled."
                else -> "Tunlion could not finish this action (exit $exit)."
            })
}

/** Framing only, never a second protocol: handles pretty JSON and NDJSON events. */
internal class JsonObjectFrames {
    private val buffer = StringBuilder()
    private var depth = 0
    private var quoted = false
    private var escaped = false
    fun feed(chunk: String): List<JSONObject> {
        val ready = mutableListOf<JSONObject>()
        for (char in chunk) {
            if (depth == 0 && char != '{') continue
            buffer.append(char)
            check(buffer.length <= 512 * 1024) { "CLI JSON frame is too large" }
            if (quoted) {
                if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) { ready += JSONObject(buffer.toString()); buffer.clear() }
                }
            }
        }
        return ready
    }
}

internal class CliProcess(context: Context) {
    val paths = CliPaths(context)
    fun builder(args: List<String>, config: File = paths.config): ProcessBuilder {
        check(paths.binary.canExecute()) { "The packaged Android CLI is missing or not executable" }
        return ProcessBuilder(listOf(paths.binary.absolutePath, "--no-interactive", "--color", "never") + args).apply {
            directory(paths.home)
            environment().putAll(mapOf(
                "HOME" to paths.home.absolutePath,
                "TUNLION_CONFIG_DIR" to config.absolutePath,
                "TUNLION_NAME" to android.os.Build.MODEL,
                "TUNLION_NO_IMPLICIT_INIT" to "1",
                "TUNLION_NONINTERACTIVE" to "1",
            ))
        }
    }

    suspend fun run(args: List<String>, timeoutMs: Long = 30_000, config: File = paths.config,
        onFrame: suspend (JSONObject) -> Unit = {}): CliOutcome = withContext(Dispatchers.IO) {
        val process = builder(listOf("--quiet", "--json") + args, config).start()
        process.outputStream.close()
        var answer: JSONObject? = null
        // Reader failures on shutdown (a closed pipe) must not escape as a crash.
        val readers = CoroutineScope(SupervisorJob() + Dispatchers.IO +
            CoroutineExceptionHandler { _, _ -> })
        try {
                val stdout = readers.async {
                    val decoder = JsonObjectFrames()
                    val chars = CharArray(4096)
                    try {
                        process.inputStream.bufferedReader().use { reader ->
                            while (true) {
                                val count = runInterruptible { reader.read(chars) }
                                if (count < 0) break
                                for (frame in decoder.feed(String(chars, 0, count))) {
                                    if (frame.has("ok")) answer = frame
                                    onFrame(frame)
                                }
                            }
                        }
                    } catch (cancelled: CancellationException) { throw cancelled }
                    // A closed pipe on shutdown is expected, not a failure.
                    catch (_: Exception) { }
                }
                val stderr = readers.async {
                    // Drain only. Never log stderr: it can carry a code or invitation material.
                    try {
                        process.errorStream.use { input ->
                            val scratch = ByteArray(4096)
                            while (input.read(scratch) >= 0) { }
                        }
                    } catch (_: Exception) { }
                }
                val exit = withTimeout(timeoutMs) {
                    while (!process.waitFor(100, TimeUnit.MILLISECONDS)) {
                        ensureActive()
                        if (stdout.isCompleted) stdout.await()
                    }
                    process.exitValue()
                }
                stdout.await(); stderr.await()
                CliOutcome(exit, answer)
        } finally {
            withContext(NonCancellable) {
                readers.cancel()
                process.destroy()
                if (!process.waitFor(2, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(2, TimeUnit.SECONDS) }
                process.inputStream.close(); process.errorStream.close()
                withTimeoutOrNull(2_000) { readers.coroutineContext[Job]?.join() }
            }
        }
    }
}
