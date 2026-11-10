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
    /** Ask the shared core to read an invitation. Kotlin never parses or validates the bytes. */
    suspend fun previewInvitation(bytes: ByteArray): InvitationPreviewResult
    /** Join with the exact bytes the core previewed. Blocking work runs off the main thread. */
    suspend fun joinInvitation(bytes: ByteArray, name: String): CoreResult
    suspend fun sendFiles(deviceId: String?, files: List<android.net.Uri>, onCode: (String) -> Unit): CoreResult
}

data class CoreStatus(
    val statusLoaded: Boolean = false,
    val identityLoaded: Boolean = false,
    val deviceName: String? = null,
    val fingerprint: String? = null,
    val engineRunning: Boolean = false,
    val engineLinked: Boolean = false,
    val devices: List<CoreDevice> = emptyList(),
    val transfers: List<CoreTransfer> = emptyList(),
    val lastSend: CoreSendReport? = null,
    val engineError: String? = null,
    /**
     * Invitation preview and join are linked. Set only from a typed core
     * enrollment surface; never inferred from devices or pairing.
     */
    val enrollmentSupported: Boolean = false,
    /** Spoken-code enrollment is linked. Separate from invitations: the core has no code-enrollment surface yet. */
    val codeEnrollmentSupported: Boolean = false,
) {
    val identityState: CoreIdentityState get() = when {
        !statusLoaded -> CoreIdentityState.LOADING
        fingerprint != null -> CoreIdentityState.LOCAL
        devices.isNotEmpty() -> CoreIdentityState.JOINED
        else -> CoreIdentityState.BLANK
    }
}

enum class CoreIdentityState { LOADING, BLANK, LOCAL, JOINED }

data class CoreTransfer(val name: String, val incoming: Boolean, val verified: Boolean, val saved: Boolean)

/** Per-file receiver acknowledgment from the most recent send in this process. */
data class CoreSendReport(val files: List<CoreSentFile>, val target: String? = null) : java.io.Serializable
data class CoreSentFile(val name: String, val delivered: Boolean, val storedName: String?) : java.io.Serializable

/** Rendering projection of one core `DeviceAccess` record. It evaluates no authority. */
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
    val canAttemptSend: Boolean get() = actions.any { it.kind == CoreActionKind.SEND && it.state == CoreAccessState.UNKNOWN }
}

enum class CoreRelationship { PAIRED, FLEET, TEMPORARY, UNKNOWN }
enum class CoreAccessState { AVAILABLE, PENDING, BLOCKED, UNSUPPORTED, UNKNOWN }
enum class CoreActionKind { SEND, RECEIVE_INBOX, TERMINAL, FOLDER }
/** One direction-named core action fact, preserved for rendering. */
data class CoreAction(val kind: CoreActionKind, val state: CoreAccessState, val reason: String) : java.io.Serializable

/** Rendering mirror of the core's `CoreInvitationPreview`. Every field is the core's value, unmodified. */
data class InvitationPreview(
    val ownerName: String,
    val relationship: InvitationRelationship,
    val requestedCapabilities: List<String>,
    /** Unix seconds, as signed. */
    val expires: Long,
    /** Seconds, as signed. */
    val maxOffline: Long,
    val maxUses: Long?,
    val reusable: Boolean,
    val ephemeral: Boolean,
    /** The core's expiry verdict. Kotlin never compares clocks. */
    val expired: Boolean,
)

/** Mirror of the core's `EnrollmentRelationship`. */
enum class InvitationRelationship { ORDINARY_PAIR, OWN_DEVICE, OTHER_PERSON, TEMPORARY_WORKER, UNKNOWN }

sealed interface InvitationPreviewResult {
    data class Previewed(val preview: InvitationPreview) : InvitationPreviewResult
    data class Failed(val failure: CoreResult.Failure) : InvitationPreviewResult
}

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
