package com.tunlion.android

import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.tunlion_core.CoreSession
import uniffi.tunlion_core.PendingIdentity

/** Real identity binding; connection operations wait for the shared peer loop. */
class NativeTunlionCore(context: Context) : TunlionCore {
    private val directory = File(context.filesDir, "tunlion")
    private var session: CoreSession? = null
    private var pending: PendingIdentity? = null
    private var cached = CoreStatus(deviceName = android.os.Build.MODEL)
    private fun session(): CoreSession = session ?: CoreSession.open(directory.absolutePath).also { session = it }

    override fun status() = cached
    override suspend fun refresh(): CoreStatus = withContext(Dispatchers.IO) {
        val native = session().status()
        cached = cached.copy(fingerprint = native.fingerprint, identityLoaded = true)
        cached
    }

    override suspend fun prepareIdentity(): String = withContext(Dispatchers.IO) {
        check(pending == null) { "Identity setup is already open" }
        session().beginIdentity().also { pending = it }.phrase()
    }

    override suspend fun confirmIdentity(phrase: String): CoreResult = withContext(Dispatchers.IO) {
        val identity = pending ?: return@withContext CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Open identity setup again.")
        try {
            val fingerprint = session().commitIdentity(identity, phrase)
            cached = cached.copy(fingerprint = fingerprint)
            pending = null
            identity.destroy()
            CoreResult.Success
        } catch (error: Exception) {
            CoreResult.Failure(CoreErrorKind.INVALID_INPUT, error.message ?: "Could not confirm identity. Check your recovery words.")
        }
    }

    override fun discardIdentity() { pending?.destroy(); pending = null }
    override suspend fun start() = CoreResult.Failure(CoreErrorKind.ENGINE_NOT_LINKED,
        "This phone is set up. Device connections are not available in this preview yet.")
    override suspend fun stop() = CoreResult.Success
    override suspend fun joinCode(code: String, remember: Boolean) = CoreResult.Failure(CoreErrorKind.FEATURE_NOT_LINKED,
        "The code has not been used. Device connections are still being added to this preview.")
    override suspend fun receiveCode(code: String) = CoreResult.Failure(CoreErrorKind.FEATURE_NOT_LINKED,
        "Nothing has been received. File receiving is still being added to this preview.")
}
