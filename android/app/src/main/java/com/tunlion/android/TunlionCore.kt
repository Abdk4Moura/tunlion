package com.tunlion.android

/**
 * The UI depends on this boundary. The temporary Android CLI backend can be
 * replaced by UniFFI without moving protocol logic into Kotlin.
 */
interface TunlionCore {
    fun status(): CoreStatus
    suspend fun refresh(): CoreStatus
    suspend fun prepareIdentity(): String
    suspend fun confirmIdentity(phrase: String): CoreResult
    fun discardIdentity()
    suspend fun start(): CoreResult
    suspend fun stop(): CoreResult
    suspend fun joinCode(code: String, remember: Boolean): CoreResult
    suspend fun receiveCode(code: String): CoreResult
    suspend fun joinInvitation(bytes: ByteArray): CoreResult
    suspend fun sendFiles(deviceId: String?, files: List<android.net.Uri>, onCode: (String) -> Unit): CoreResult
}

data class CoreStatus(
    val identityLoaded: Boolean = false,
    val deviceName: String? = null,
    val fingerprint: String? = null,
    val engineRunning: Boolean = false,
    val engineLinked: Boolean = false,
    val devices: List<CoreDevice> = emptyList(),
    val transfers: List<CoreTransfer> = emptyList(),
    val engineError: String? = null,
)

data class CoreTransfer(val name: String, val incoming: Boolean, val verified: Boolean, val saved: Boolean)

data class CoreDevice(
    val id: String,
    val name: String,
    val online: Boolean?,
    val route: String?,
    val plainLine: String,
    val canSendFiles: Boolean,
    val canOpenShell: Boolean,
) : java.io.Serializable

sealed interface CoreResult {
    data object Success : CoreResult
    data class Failure(val kind: CoreErrorKind, val message: String) : CoreResult
}

enum class CoreErrorKind {
    ENGINE_NOT_LINKED,
    FEATURE_NOT_LINKED,
    INVALID_INPUT,
    INTERNAL,
    UNKNOWN_DEVICE, DENIED, UNREACHABLE, NETWORK, PARTIAL, NO_IDENTITY, LOCAL_RESOURCE, CANCELLED,
}
