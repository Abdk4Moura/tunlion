package com.tunlion.android

import uniffi.tunlion_core.AccessState as NativeAccessState
import uniffi.tunlion_core.ActionKind as NativeActionKind
import uniffi.tunlion_core.ActionPolicy as NativeActionPolicy
import uniffi.tunlion_core.CapabilityOutcome as NativeCapabilityOutcome
import uniffi.tunlion_core.CapabilityReceipt as NativeCapabilityReceipt
import uniffi.tunlion_core.DeliveryKind as NativeDeliveryKind
import uniffi.tunlion_core.DeliveryState as NativeDeliveryState
import uniffi.tunlion_core.DevicePolicy as NativeDevicePolicy
import uniffi.tunlion_core.DevicePresence as NativeDevicePresence
import uniffi.tunlion_core.DeviceRelationship as NativeDeviceRelationship
import uniffi.tunlion_core.EnrollmentKind as NativeEnrollmentKind
import uniffi.tunlion_core.EnrollmentState as NativeEnrollmentState
import uniffi.tunlion_core.LiftedKeyBlock as NativeLiftedKeyBlock
import uniffi.tunlion_core.PolicySource as NativePolicySource
import uniffi.tunlion_core.RemovalMode as NativeRemovalMode
import uniffi.tunlion_core.RemovalReceipt as NativeRemovalReceipt
import uniffi.tunlion_core.SessionsSummary as NativeSessionsSummary

/**
 * Typed projections of the core's UniFFI records. Each `when` is exhaustive
 * over the generated enum, so a new native variant cannot be dropped silently:
 * the Kotlin build fails instead of inventing a default.
 */

internal fun mapAccessState(state: NativeAccessState): CoreAccessState = when (state) {
    NativeAccessState.AVAILABLE -> CoreAccessState.AVAILABLE
    NativeAccessState.PENDING -> CoreAccessState.PENDING
    NativeAccessState.BLOCKED -> CoreAccessState.BLOCKED
    NativeAccessState.UNSUPPORTED -> CoreAccessState.UNSUPPORTED
    NativeAccessState.UNKNOWN -> CoreAccessState.UNKNOWN
}

internal fun mapActionKind(kind: NativeActionKind): CoreActionKind = when (kind) {
    NativeActionKind.SEND -> CoreActionKind.SEND
    NativeActionKind.RECEIVE_INBOX -> CoreActionKind.RECEIVE_INBOX
    NativeActionKind.TERMINAL -> CoreActionKind.TERMINAL
    NativeActionKind.FOLDER -> CoreActionKind.FOLDER
}

internal fun mapRelationship(relationship: NativeDeviceRelationship): CoreRelationship = when (relationship) {
    NativeDeviceRelationship.PAIRED -> CoreRelationship.PAIRED
    NativeDeviceRelationship.FLEET -> CoreRelationship.FLEET
    NativeDeviceRelationship.TEMPORARY -> CoreRelationship.TEMPORARY
    NativeDeviceRelationship.UNKNOWN -> CoreRelationship.UNKNOWN
}

/** Presence is projected only from the core enum; the client never probes. */
internal fun mapPresence(presence: NativeDevicePresence): Boolean? = when (presence) {
    NativeDevicePresence.UNKNOWN -> null
    NativeDevicePresence.LIVE -> true
}

internal fun mapPolicySource(source: NativePolicySource): CorePolicySource = when (source) {
    NativePolicySource.RECORD -> CorePolicySource.RECORD
    NativePolicySource.GRANT_STORE -> CorePolicySource.GRANT_STORE
    NativePolicySource.ENROLLMENT_CEILING -> CorePolicySource.ENROLLMENT_CEILING
    NativePolicySource.DENIED -> CorePolicySource.DENIED
    NativePolicySource.PROFILE -> CorePolicySource.PROFILE
    NativePolicySource.LINK_FACTS -> CorePolicySource.LINK_FACTS
    NativePolicySource.KEY_BLOCK -> CorePolicySource.KEY_BLOCK
}

internal fun mapEnrollmentKind(kind: NativeEnrollmentKind): CoreEnrollmentKind = when (kind) {
    NativeEnrollmentKind.NOT_RECORDED -> CoreEnrollmentKind.NOT_RECORDED
    NativeEnrollmentKind.OWNER_DEVICE -> CoreEnrollmentKind.OWNER_DEVICE
    NativeEnrollmentKind.DELEGATED -> CoreEnrollmentKind.DELEGATED
    NativeEnrollmentKind.TEMPORARY -> CoreEnrollmentKind.TEMPORARY
    NativeEnrollmentKind.PAIRED -> CoreEnrollmentKind.PAIRED
    NativeEnrollmentKind.UNSUPPORTED -> CoreEnrollmentKind.UNSUPPORTED
}

internal fun mapDeliveryKind(kind: NativeDeliveryKind): CoreDeliveryKind = when (kind) {
    NativeDeliveryKind.NOT_TRACKED -> CoreDeliveryKind.NOT_TRACKED
    NativeDeliveryKind.PENDING -> CoreDeliveryKind.PENDING
    NativeDeliveryKind.DELIVERED -> CoreDeliveryKind.DELIVERED
}

internal fun mapRemovalMode(mode: NativeRemovalMode): CoreRemovalMode = when (mode) {
    NativeRemovalMode.FORGET -> CoreRemovalMode.FORGET
    NativeRemovalMode.CUT_OFF -> CoreRemovalMode.CUT_OFF
    NativeRemovalMode.RESTORE -> CoreRemovalMode.RESTORE
}

internal fun mapSessions(summary: NativeSessionsSummary): CoreSessionsSummary = when (summary) {
    NativeSessionsSummary.NOT_TOUCHED -> CoreSessionsSummary.NOT_TOUCHED
    NativeSessionsSummary.ENDS_ON_RECHECK -> CoreSessionsSummary.ENDS_ON_RECHECK
}

internal fun mapCapabilityOutcome(outcome: NativeCapabilityOutcome): CoreCapabilityOutcome = when (outcome) {
    NativeCapabilityOutcome.APPLIED -> CoreCapabilityOutcome.APPLIED
    NativeCapabilityOutcome.ALREADY_HELD_BY_CEILING -> CoreCapabilityOutcome.ALREADY_HELD_BY_CEILING
    NativeCapabilityOutcome.NOT_GRANTABLE_BECAUSE_CEILING -> CoreCapabilityOutcome.NOT_GRANTABLE_BECAUSE_CEILING
    NativeCapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING -> CoreCapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING
    NativeCapabilityOutcome.NOT_HELD -> CoreCapabilityOutcome.NOT_HELD
}

private fun mapEnrollment(enrollment: NativeEnrollmentState) = CoreEnrollment(
    kind = mapEnrollmentKind(enrollment.kind),
    ceiling = enrollment.ceiling.toList(),
    reason = enrollment.reason,
)

private fun mapDelivery(delivery: NativeDeliveryState) = CoreDelivery(
    kind = mapDeliveryKind(delivery.kind),
    at = delivery.at?.toLong(),
)

private fun mapActionPolicy(action: NativeActionPolicy) = CoreActionPolicy(
    kind = mapActionKind(action.action),
    state = mapAccessState(action.state),
    source = mapPolicySource(action.source),
    // The core's reason is the authority. Never re-worded here.
    reason = action.reason,
)

internal fun mapDevicePolicy(policy: NativeDevicePolicy) = CoreDevicePolicy(
    name = policy.name,
    deviceKey = policy.deviceKey,
    relationship = mapRelationship(policy.relationship),
    expires = policy.expiresAt?.toLong(),
    revoked = policy.revoked,
    enrollment = mapEnrollment(policy.enrollment),
    delivery = mapDelivery(policy.delivery),
    actions = policy.actions.map(::mapActionPolicy),
)

private fun mapLiftedBlock(block: NativeLiftedKeyBlock) = CoreLiftedKeyBlock(
    name = block.name,
    revokedAt = block.revokedAt.toLong(),
    deviceKey = block.deviceKey,
)

internal fun mapRemovalReceipt(receipt: NativeRemovalReceipt) = CoreRemovalReceipt(
    mode = mapRemovalMode(receipt.mode),
    name = receipt.name,
    deviceKey = receipt.deviceKey,
    refusedUntil = receipt.refusedUntil?.toLong(),
    grantsRevoked = receipt.grantsRevoked.toLong(),
    recordRemoved = receipt.recordRemoved,
    sessions = mapSessions(receipt.sessions),
    localOnly = receipt.localOnly,
    keyBlockWritten = receipt.keyBlockWritten,
    keyBlocksLifted = receipt.keyBlocksLifted.map(::mapLiftedBlock),
)

internal fun mapCapabilityReceipt(receipt: NativeCapabilityReceipt) = CoreCapabilityReceipt(
    action = mapActionKind(receipt.action),
    capability = receipt.capability,
    outcome = mapCapabilityOutcome(receipt.outcome),
    signed = receipt.signed,
    expiresAt = receipt.expiresAt?.toLong(),
    ceiling = receipt.ceiling.toList(),
)
