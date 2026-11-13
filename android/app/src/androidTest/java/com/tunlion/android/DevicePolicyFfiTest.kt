package com.tunlion.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.tunlion_core.AccessState
import uniffi.tunlion_core.ActionKind
import uniffi.tunlion_core.CapabilityOutcome
import uniffi.tunlion_core.CoreException
import uniffi.tunlion_core.CoreSession
import uniffi.tunlion_core.DeliveryKind
import uniffi.tunlion_core.DeviceRelationship
import uniffi.tunlion_core.EnrollmentKind
import uniffi.tunlion_core.EnrollmentSupport
import uniffi.tunlion_core.PolicySource
import uniffi.tunlion_core.RemovalMode
import uniffi.tunlion_core.SessionsSummary

/**
 * The typed lifecycle surface against the library actually packaged in the app.
 * Every fact asserted here is the core's; the adapter may only project it.
 */
@RunWith(AndroidJUnit4::class)
class DevicePolicyFfiTest {
    private fun config(): File = File(
        InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
        "native-policy-${UUID.randomUUID()}",
    )

    private fun writeDelegated(root: File) {
        root.mkdirs()
        File(root, "devices.json").writeText(
            """[{"name":"guest","secret":"${"s".repeat(64)}",""" +
                """"principalKind":"delegated","principalCeiling":["shell"],"principalExpires":4102444800}]""",
        )
    }

    @Test fun everyNativeAccessStateMapsToItsOwnCoreState() {
        assertEquals(CoreAccessState.AVAILABLE, mapAccessState(AccessState.AVAILABLE))
        assertEquals(CoreAccessState.PENDING, mapAccessState(AccessState.PENDING))
        assertEquals(CoreAccessState.BLOCKED, mapAccessState(AccessState.BLOCKED))
        assertEquals(CoreAccessState.UNSUPPORTED, mapAccessState(AccessState.UNSUPPORTED))
        assertEquals(CoreAccessState.UNKNOWN, mapAccessState(AccessState.UNKNOWN))
        // Pending is a local record, never working access.
        assertFalse(isEffective(mapAccessState(AccessState.PENDING)))
        assertEquals("Pending", accessStateChip(mapAccessState(AccessState.PENDING)))
        assertTrue(isEffective(mapAccessState(AccessState.AVAILABLE)))
    }

    @Test fun theMergedCoreReportsTheInvitationSurfaceItCarries() {
        val root = config()
        try {
            CoreSession.open(root.absolutePath).use { core ->
                val status = core.enrollmentStatus()
                assertEquals(EnrollmentSupport.SUPPORTED, status.state)
                assertNull(status.reason)
            }
        } finally { root.deleteRecursively() }
    }

    @Test fun delegatedPolicyKeepsCeilingSourceOrderAndReasonVerbatim() {
        val root = config()
        try {
            writeDelegated(root)
            CoreSession.open(root.absolutePath).use { core ->
                val policy = core.devicePolicy("guest")
                assertEquals(DeviceRelationship.PAIRED, policy.relationship)
                assertEquals(EnrollmentKind.DELEGATED, policy.enrollment.kind)
                assertEquals(listOf("shell"), policy.enrollment.ceiling)
                assertNull(policy.enrollment.reason)
                assertEquals(DeliveryKind.NOT_TRACKED, policy.delivery.kind)
                assertNull(policy.delivery.at)
                // Stable order: Send, ReceiveInbox, Terminal, Folder.
                assertEquals(
                    listOf(ActionKind.SEND, ActionKind.RECEIVE_INBOX, ActionKind.TERMINAL, ActionKind.FOLDER),
                    policy.actions.map { it.action },
                )
                assertEquals(AccessState.UNKNOWN, policy.actions[0].state)
                assertEquals(PolicySource.LINK_FACTS, policy.actions[0].source)
                assertTrue(policy.actions[0].reason.isNotEmpty())
                // This profile serves neither terminal nor a folder mount, and
                // the core names that as the source instead of inventing one.
                assertEquals(AccessState.UNSUPPORTED, policy.actions[2].state)
                assertEquals(PolicySource.PROFILE, policy.actions[2].source)
                assertEquals("This core profile does not serve terminals", policy.actions[2].reason)

                val mapped = mapDevicePolicy(policy)
                assertEquals("guest", mapped.name)
                assertEquals(CoreEnrollmentKind.DELEGATED, mapped.enrollment.kind)
                assertEquals(listOf("shell"), mapped.enrollment.ceiling)
                assertEquals(CoreDeliveryKind.NOT_TRACKED, mapped.delivery.kind)
                assertEquals(CorePolicySource.PROFILE, mapped.actions[2].source)
                assertEquals("This core profile does not serve terminals", mapped.actions[2].reason)
                assertEquals(CoreActionKind.FOLDER, mapped.actions[3].kind)
            }
        } finally { root.deleteRecursively() }
    }

    @Test fun ceilingHeldCapabilityIsRefusedInsteadOfReportedAsSuccess() {
        val root = config()
        try {
            writeDelegated(root)
            CoreSession.open(root.absolutePath).use { core ->
                val revoke = core.revokeCapability("guest", ActionKind.TERMINAL)
                assertEquals(CapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING, revoke.outcome)
                assertFalse(revoke.signed)
                assertNull(revoke.expiresAt)
                assertEquals(listOf("shell"), revoke.ceiling)

                val grant = core.grantCapability("guest", ActionKind.FOLDER)
                assertEquals(CapabilityOutcome.NOT_GRANTABLE_BECAUSE_CEILING, grant.outcome)
                assertFalse(grant.signed)

                val mapped = mapCapabilityReceipt(revoke)
                assertEquals(CoreCapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING, mapped.outcome)
                val notice = capabilityNotice("guest", CoreCapabilityIntent.REVOKE, mapped)
                assertFalse("A ceiling refusal must never read as success", notice.applied)
                assertTrue("The person is offered cut off instead", notice.offerCutOff)
                assertTrue(notice.lines.any { it.contains("invitation ceiling") })
            }
        } finally { root.deleteRecursively() }
    }

    @Test fun forgetRemovesTheRecordAndReportsALocalOnlyReceipt() {
        val root = config()
        try {
            writeDelegated(root)
            CoreSession.open(root.absolutePath).use { core ->
                val receipt = core.forgetDevice("guest")
                assertEquals(RemovalMode.FORGET, receipt.mode)
                assertEquals("guest", receipt.name)
                assertTrue(receipt.localOnly)
                assertTrue(receipt.recordRemoved)
                assertFalse(receipt.keyBlockWritten)
                assertEquals(0L, receipt.grantsRevoked.toLong())
                assertEquals(SessionsSummary.ENDS_ON_RECHECK, receipt.sessions)
                assertTrue(core.devices().isEmpty())
                val mapped = mapRemovalReceipt(receipt)
                assertEquals(CoreRemovalMode.FORGET, mapped.mode)
                assertTrue(removalNotice(mapped).lines.any { it.contains("removed from this phone") })
                // A restore of a name with no record and no key block is refused,
                // and the refusal is the core's own text.
                val refused = assertThrows(CoreException.Usage::class.java) { core.restoreDevice("guest") }
                assertEquals("no known device named 'guest'", refused.v1)
            }
        } finally { root.deleteRecursively() }
    }

    @Test fun cutOffKeepsTheRecordAndRestoreLiftsTheMarker() {
        val root = config()
        try {
            writeDelegated(root)
            CoreSession.open(root.absolutePath).use { core ->
                val cut = core.cutOffDevice("guest")
                assertEquals(RemovalMode.CUT_OFF, cut.mode)
                assertFalse(cut.recordRemoved)
                assertFalse(cut.keyBlockWritten)
                assertEquals(SessionsSummary.ENDS_ON_RECHECK, cut.sessions)
                assertTrue(core.devices().single().revoked)

                val restored = core.restoreDevice("guest")
                assertEquals(RemovalMode.RESTORE, restored.mode)
                assertEquals(SessionsSummary.NOT_TOUCHED, restored.sessions)
                assertTrue(restored.keyBlocksLifted.isEmpty())
                val record = core.devices().single()
                assertFalse("Restore clears the local revocation marker", record.revoked)
                assertEquals("guest", record.name)
            }
        } finally { root.deleteRecursively() }
    }
}
