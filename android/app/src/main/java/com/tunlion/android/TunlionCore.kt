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
    /** One device's typed local policy. Local read only; no network work. */
    suspend fun devicePolicy(name: String): CoreDevicePolicyResult
    /** Remove one device record on this phone. The core writes the key block first. Local only. */
    suspend fun forgetDevice(name: String): CoreRemovalResult
    /** Keep the record and mark it revoked. The peer is told on its next open. Local only. */
    suspend fun cutOffDevice(name: String): CoreRemovalResult
    /** Lift this phone's refusal for a name. A forgotten record is not recreated. */
    suspend fun restoreDevice(name: String): CoreRemovalResult
    /** Grant one action's enforcing capability. No screen calls this yet; the core decides the outcome. */
    suspend fun grantCapability(device: String, action: CoreActionKind): CoreCapabilityResult
    /** Revoke one action's enforcing capability. A ceiling-held capability is refused, not reported as success. */
    suspend fun revokeCapability(device: String, action: CoreActionKind): CoreCapabilityResult
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
     * Invitation preview and join are linked. Set only from the core's typed
     * `enrollmentStatus().state`; never inferred from devices, pairing or the
     * fact that the binding exposes a method.
     */
    val enrollmentSupported: Boolean = false,
    /** The core's own reason when invitations are not linked. Never re-worded. */
    val enrollmentReason: String? = null,
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

/**
 * Rendering mirror of the core's `DevicePolicy`. Every field is the core's
 * value, unmodified: relationship, expiry, revocation, admission, delivery and
 * one row per action with the source of its state and the core's reason.
 */
data class CoreDevicePolicy(
    val name: String,
    val deviceKey: String?,
    val relationship: CoreRelationship,
    val expires: Long?,
    val revoked: Boolean,
    val enrollment: CoreEnrollment,
    val delivery: CoreDelivery,
    val actions: List<CoreActionPolicy>,
) : java.io.Serializable

/** Which stored fact says how this device was admitted. */
data class CoreEnrollment(
    val kind: CoreEnrollmentKind,
    val ceiling: List<String>,
    /** The core's own reason when it cannot read the admission shape. */
    val reason: String?,
) : java.io.Serializable

enum class CoreEnrollmentKind { NOT_RECORDED, OWNER_DEVICE, DELEGATED, TEMPORARY, PAIRED, UNSUPPORTED }

/** Whether a local policy change has reached the peer. */
data class CoreDelivery(val kind: CoreDeliveryKind, val at: Long?) : java.io.Serializable
enum class CoreDeliveryKind { NOT_TRACKED, PENDING, DELIVERED }

/** Where an action's state came from. A fact about the local store, never a remote claim. */
enum class CorePolicySource { RECORD, GRANT_STORE, ENROLLMENT_CEILING, DENIED, PROFILE, LINK_FACTS, KEY_BLOCK }

/** One action with the source of its state and the core's reason verbatim. */
data class CoreActionPolicy(
    val kind: CoreActionKind,
    val state: CoreAccessState,
    val source: CorePolicySource,
    val reason: String,
) : java.io.Serializable

/** What a removal request did to this phone's stores. */
enum class CoreRemovalMode { FORGET, CUT_OFF, RESTORE }

/** Whether a removal touched a live session. It never claims to have ended one. */
enum class CoreSessionsSummary { NOT_TOUCHED, ENDS_ON_RECHECK }

data class CoreLiftedKeyBlock(val name: String, val revokedAt: Long, val deviceKey: String) : java.io.Serializable

/** The facts the core reports after writing its stores. Local only by construction. */
data class CoreRemovalReceipt(
    val mode: CoreRemovalMode,
    val name: String,
    val deviceKey: String?,
    val refusedUntil: Long?,
    val grantsRevoked: Long,
    val recordRemoved: Boolean,
    val sessions: CoreSessionsSummary,
    val localOnly: Boolean,
    val keyBlockWritten: Boolean,
    val keyBlocksLifted: List<CoreLiftedKeyBlock>,
) : java.io.Serializable

/** What one capability edit did. Ceiling outcomes are refusals, not success. */
enum class CoreCapabilityOutcome {
    APPLIED,
    ALREADY_HELD_BY_CEILING,
    NOT_GRANTABLE_BECAUSE_CEILING,
    NOT_REVOCABLE_BECAUSE_CEILING,
    NOT_HELD,
}

data class CoreCapabilityReceipt(
    val action: CoreActionKind,
    val capability: String,
    val outcome: CoreCapabilityOutcome,
    /** True only when an owner-signed op was written to the capability store. */
    val signed: Boolean,
    /** The signed grant's horizon, when one was written. */
    val expiresAt: Long?,
    /** The delegated ceiling when the outcome is about one; empty otherwise. */
    val ceiling: List<String>,
) : java.io.Serializable

/** One typed policy read. A failure is the core's own text, never a client paraphrase. */
sealed interface CoreDevicePolicyResult {
    data class Loaded(val policy: CoreDevicePolicy) : CoreDevicePolicyResult
    data class Failed(val failure: CoreResult.Failure) : CoreDevicePolicyResult
}

/** One typed removal. Only `Removed` carries a receipt the core actually wrote. */
sealed interface CoreRemovalResult {
    data class Removed(val receipt: CoreRemovalReceipt) : CoreRemovalResult
    data class Failed(val failure: CoreResult.Failure) : CoreRemovalResult
}

/** One typed capability edit. `Edited` carries the core's own outcome, including a ceiling refusal. */
sealed interface CoreCapabilityResult {
    data class Edited(val receipt: CoreCapabilityReceipt) : CoreCapabilityResult
    data class Failed(val failure: CoreResult.Failure) : CoreCapabilityResult
}

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
