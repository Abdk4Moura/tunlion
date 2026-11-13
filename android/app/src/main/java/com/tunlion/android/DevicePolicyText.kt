package com.tunlion.android

/**
 * Pure rendering of the core's typed device policy. Nothing here decides a
 * permission: every state, source and reason comes from the core, and the
 * removal/capability notices only restate the receipt the core returned.
 */

/** Lowercase label used in compact summaries. */
internal fun accessStateLabel(state: CoreAccessState) = when (state) {
    CoreAccessState.AVAILABLE -> "available"
    CoreAccessState.PENDING -> "pending"
    CoreAccessState.BLOCKED -> "blocked"
    CoreAccessState.UNSUPPORTED -> "unsupported"
    CoreAccessState.UNKNOWN -> "unknown"
}

/** Standalone chip label. `Pending` is its own word so it can never read as available. */
internal fun accessStateChip(state: CoreAccessState) = when (state) {
    CoreAccessState.AVAILABLE -> "Available"
    CoreAccessState.PENDING -> "Pending"
    CoreAccessState.BLOCKED -> "Blocked"
    CoreAccessState.UNSUPPORTED -> "Unsupported"
    CoreAccessState.UNKNOWN -> "Unknown"
}

/**
 * Only an authenticated observation is effective. `PENDING` is a local record
 * whose delivery or live access is unconfirmed, so it is never effective.
 */
internal fun isEffective(state: CoreAccessState) = state == CoreAccessState.AVAILABLE

internal const val PENDING_GROUP_NOTE =
    "Waiting for delivery: a grant or invitation ceiling is recorded on this phone, but delivery and live access are not confirmed. Pending is never working access."

internal const val EFFECTIVE_GROUP_NOTE =
    "No action is confirmed effective by this snapshot."

internal fun actionShortLabel(kind: CoreActionKind) = when (kind) {
    CoreActionKind.SEND -> "Send"
    CoreActionKind.RECEIVE_INBOX -> "Receive inbox"
    CoreActionKind.TERMINAL -> "Terminal"
    CoreActionKind.FOLDER -> "Folders"
}

internal fun actionLabel(kind: CoreActionKind) = when (kind) {
    CoreActionKind.SEND -> "Send files to this device"
    CoreActionKind.RECEIVE_INBOX -> "This device sending to this phone's inbox"
    CoreActionKind.TERMINAL -> "This phone serving a terminal"
    CoreActionKind.FOLDER -> "This phone exposing folders"
}

internal fun relationshipLabel(relationship: CoreRelationship) = when (relationship) {
    CoreRelationship.PAIRED -> "Paired device"
    CoreRelationship.FLEET -> "Fleet device"
    CoreRelationship.TEMPORARY -> "Temporary worker"
    CoreRelationship.UNKNOWN -> "Relationship unknown"
}

/** State summary for the device list: every action, in the core's stable order. */
internal fun actionSummary(actions: List<CoreAction>): String =
    actions.joinToString(" · ") { "${actionShortLabel(it.kind)}: ${accessStateLabel(it.state)}" }

internal fun actionPolicySummary(actions: List<CoreActionPolicy>): String =
    actions.joinToString(" · ") { "${actionShortLabel(it.kind)}: ${accessStateLabel(it.state)}" }

/** The stored fact that produced an action's state. */
internal fun policySourceLabel(source: CorePolicySource) = when (source) {
    CorePolicySource.RECORD -> "From the stored device record"
    CorePolicySource.GRANT_STORE -> "From a capability recorded on this phone"
    CorePolicySource.ENROLLMENT_CEILING -> "From the invitation ceiling"
    CorePolicySource.DENIED -> "From an explicit deny on this phone"
    CorePolicySource.PROFILE -> "From this core profile"
    CorePolicySource.LINK_FACTS -> "Needs authenticated link facts"
    CorePolicySource.KEY_BLOCK -> "From a key block on this phone"
}

internal fun enrollmentKindLabel(kind: CoreEnrollmentKind) = when (kind) {
    CoreEnrollmentKind.NOT_RECORDED -> "Not recorded"
    CoreEnrollmentKind.OWNER_DEVICE -> "This owner's device"
    CoreEnrollmentKind.DELEGATED -> "Admitted by an invitation"
    CoreEnrollmentKind.TEMPORARY -> "Temporary access"
    CoreEnrollmentKind.PAIRED -> "Paired device"
    CoreEnrollmentKind.UNSUPPORTED -> "Admission shape not understood"
}

/**
 * One line for the admission fact. An `Unsupported` shape shows the core's own
 * reason instead of guessing what the record meant.
 */
internal fun enrollmentSummary(enrollment: CoreEnrollment): String {
    enrollment.reason?.let { return it }
    if (enrollment.kind == CoreEnrollmentKind.NOT_RECORDED) return enrollmentKindLabel(enrollment.kind)
    val ceiling = if (enrollment.ceiling.isEmpty()) "" else " · ceiling: ${enrollment.ceiling.joinToString(", ")}"
    return enrollmentKindLabel(enrollment.kind) + ceiling
}

/** Whether a local policy change has reached the peer. */
internal fun deliverySummary(delivery: CoreDelivery): String = when (delivery.kind) {
    CoreDeliveryKind.NOT_TRACKED -> "Not tracked by this build; no delivery acknowledgment is recorded"
    CoreDeliveryKind.PENDING -> "Waiting for delivery to the device"
    CoreDeliveryKind.DELIVERED -> delivery.at?.let { "Delivered at ${instantText(it)}" } ?: "Delivered"
}

internal fun instantText(seconds: Long) = java.time.Instant.ofEpochSecond(seconds).toString()

/** One removal result in the person's words. Nothing here claims a remote effect. */
data class CoreRemovalNotice(
    val title: String,
    val lines: List<String>,
    /** A forgotten name whose key block this phone can still lift. */
    val forgottenName: String? = null,
)

internal fun removalNotice(receipt: CoreRemovalReceipt): CoreRemovalNotice {
    val lines = mutableListOf<String>()
    val title = when (receipt.mode) {
        CoreRemovalMode.FORGET -> "Forgotten on this phone."
        CoreRemovalMode.CUT_OFF -> "Cut off on this phone."
        CoreRemovalMode.RESTORE -> "Local refusal lifted."
    }
    when (receipt.mode) {
        CoreRemovalMode.FORGET -> {
            if (receipt.recordRemoved) lines += "The device record was removed from this phone."
            else lines += "The device record was already gone; no record was removed."
            if (receipt.keyBlockWritten) {
                val horizon = receipt.refusedUntil?.let { " until ${instantText(it)}" }.orEmpty()
                lines += "A key block now refuses the old device key$horizon."
            }
            if (receipt.grantsRevoked > 0) lines += "${receipt.grantsRevoked} owner-signed grant(s) were revoked."
        }
        CoreRemovalMode.CUT_OFF -> {
            lines += "The device record was kept on this phone and marked revoked."
            if (receipt.keyBlockWritten) lines += "A key block was also written."
            if (receipt.grantsRevoked > 0) lines += "${receipt.grantsRevoked} grant(s) were revoked."
        }
        CoreRemovalMode.RESTORE -> {
            if (receipt.keyBlocksLifted.isEmpty()) {
                lines += "No key block was stored under this name."
            } else {
                lines += "${receipt.keyBlocksLifted.size} key block(s) were lifted; this phone no longer refuses the old key."
                lines += "A record removed by a forget is not recreated by a restore."
            }
        }
    }
    lines += when (receipt.sessions) {
        CoreSessionsSummary.ENDS_ON_RECHECK -> "No live session was ended by this call. The device is refused when it next rechecks."
        CoreSessionsSummary.NOT_TOUCHED -> "No session was examined or changed."
    }
    lines += "This phone wrote its own stores only. The device was not contacted and has not acknowledged anything."
    val forgotten = if (receipt.mode == CoreRemovalMode.FORGET && receipt.keyBlockWritten) receipt.name else null
    return CoreRemovalNotice(title, lines, forgotten)
}

enum class CoreCapabilityIntent { GRANT, REVOKE }

/**
 * One capability edit in the person's words. `applied` is true only for the
 * core's `Applied` outcome: a ceiling refusal is reported as a refusal.
 */
data class CoreCapabilityNotice(
    val applied: Boolean,
    val title: String,
    val lines: List<String>,
    /** The ceiling holds the access, so only cutting the device off can end it. */
    val offerCutOff: Boolean = false,
)

internal fun capabilityNotice(
    device: String,
    intent: CoreCapabilityIntent,
    receipt: CoreCapabilityReceipt,
): CoreCapabilityNotice {
    val action = actionShortLabel(receipt.action).lowercase()
    val ceiling = if (receipt.ceiling.isEmpty()) "the invitation ceiling" else
        "the invitation ceiling (${receipt.ceiling.joinToString(", ")})"
    return when (receipt.outcome) {
        CoreCapabilityOutcome.APPLIED -> when (intent) {
            CoreCapabilityIntent.REVOKE -> CoreCapabilityNotice(true, "Revoked.", buildList {
                add("This phone recorded an explicit deny for $action on $device.")
                add(if (receipt.signed) "An owner-signed revocation was written to the capability store."
                else "A local deny was written; this pair has no certificate for an owner-signed revocation.")
                add("The change is local. The device has not acknowledged it.")
            })
            CoreCapabilityIntent.GRANT -> CoreCapabilityNotice(true, "Granted.", buildList {
                add("This phone recorded $action for $device.")
                add(if (receipt.signed) "An owner-signed grant was written" +
                    (receipt.expiresAt?.let { " and expires at ${instantText(it)}" } ?: "") + "."
                else "Stored locally; this pair has no certificate, so no owner-signed grant was written.")
                add("A recorded grant is not delivery. The device has not acknowledged it.")
            })
        }
        CoreCapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING -> CoreCapabilityNotice(false, "Not revoked.", listOf(
            "This access comes from $ceiling, not from a grant on this phone.",
            "A grant edit cannot narrow the ceiling, so the action is unchanged.",
            "Cutting the device off ends the whole relationship instead.",
        ), offerCutOff = true)
        CoreCapabilityOutcome.NOT_HELD -> CoreCapabilityNotice(false, "Nothing to revoke.", listOf(
            "$ceiling for this device does not include $action, and this phone holds no grant that covers it.",
            "No store was changed.",
        ))
        CoreCapabilityOutcome.ALREADY_HELD_BY_CEILING -> CoreCapabilityNotice(false, "Already allowed by the ceiling.", listOf(
            "$ceiling already includes $action.",
            "A grant cannot widen or restate it. Nothing was written.",
        ))
        CoreCapabilityOutcome.NOT_GRANTABLE_BECAUSE_CEILING -> CoreCapabilityNotice(false, "Not granted.", listOf(
            "$ceiling for this device does not include $action, and a grant cannot widen it.",
            "The action is unchanged.",
        ))
    }
}
