package com.tunlion.android

/**
 * The UI depends on this boundary. Protocol and authority decisions belong to
 * the shared core, not the Android adapter.
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
    val lastSend: CoreSendReport? = null,
    val engineError: String? = null,
    val enrollmentSupported: Boolean = false,
)

data class CoreTransfer(val name: String, val incoming: Boolean, val verified: Boolean, val saved: Boolean)

/** Per-file receiver acknowledgment from the most recent send in this process. */
data class CoreSendReport(val files: List<CoreSentFile>, val target: String? = null) : java.io.Serializable
data class CoreSentFile(val name: String, val delivered: Boolean, val storedName: String?) : java.io.Serializable

data class CoreDevice(
    val id: String,
    val name: String,
    val online: Boolean?,
    val route: String?,
    val plainLine: String,
    val canSendFiles: Boolean,
    val canOpenShell: Boolean,
    val relationship: CoreRelationship = CoreRelationship.UNKNOWN,
    val expiry: String? = null,
    val revoked: Boolean = false,
    val actions: List<CoreAction> = emptyList(),
) : java.io.Serializable {
    // An explicit attempt is not a claim that the remote receiver authorized us.
    val canAttemptSend: Boolean get() = actions.any { it.action == "send" && it.state == CoreAccessState.UNKNOWN }
}

enum class CoreRelationship { PAIRED, FLEET, TEMPORARY, UNKNOWN }
enum class CoreAccessState { AVAILABLE, PENDING, BLOCKED, UNSUPPORTED, UNKNOWN }
data class CoreAction(val action: String, val state: CoreAccessState, val reason: String) : java.io.Serializable

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
