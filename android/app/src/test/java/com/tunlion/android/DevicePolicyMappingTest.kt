package com.tunlion.android

import org.junit.Assert.*
import org.junit.Test
import uniffi.tunlion_core.AccessState

/**
 * Pure JVM tests for the typed device-policy projection. No Android, no native
 * library: these pin the mapping the UI depends on, including the state the
 * adapter must never render as working access.
 */
class DevicePolicyMappingTest {

    @Test fun pendingIsItsOwnStateAndIsNeverEffective() {
        assertEquals("Pending", accessStateChip(CoreAccessState.PENDING))
        assertEquals("pending", accessStateLabel(CoreAccessState.PENDING))
        assertNotEquals("Available", accessStateChip(CoreAccessState.PENDING))
        assertFalse(isEffective(CoreAccessState.PENDING))
        // Only an authenticated observation is effective.
        assertTrue(isEffective(CoreAccessState.AVAILABLE))
        CoreAccessState.values().filter { it != CoreAccessState.AVAILABLE }.forEach {
            assertFalse("${accessStateChip(it)} must not be effective", isEffective(it))
        }
        // Every state has its own chip word: a pending row cannot borrow
        // "Available" by falling through a default branch.
        assertEquals(
            CoreAccessState.values().size,
            CoreAccessState.values().map { accessStateChip(it) }.toSet().size,
        )
    }

    @Test fun everyNativeAccessStateMapsOneToOne() {
        assertEquals(CoreAccessState.AVAILABLE, mapAccessState(AccessState.AVAILABLE))
        assertEquals(CoreAccessState.PENDING, mapAccessState(AccessState.PENDING))
        assertEquals(CoreAccessState.BLOCKED, mapAccessState(AccessState.BLOCKED))
        assertEquals(CoreAccessState.UNSUPPORTED, mapAccessState(AccessState.UNSUPPORTED))
        assertEquals(CoreAccessState.UNKNOWN, mapAccessState(AccessState.UNKNOWN))
        assertEquals(CoreAccessState.values().size,
            AccessState.values().map { mapAccessState(it) }.toSet().size)
    }

    @Test fun actionRowsKeepOrderSourceAndTheCoreReasonVerbatim() {
        val policy = CoreDevicePolicy(
            name = "guest",
            deviceKey = "ab".repeat(32),
            relationship = CoreRelationship.PAIRED,
            expires = 1_900_000_000L,
            revoked = true,
            enrollment = CoreEnrollment(CoreEnrollmentKind.DELEGATED, listOf("shell", "transfer"), null),
            delivery = CoreDelivery(CoreDeliveryKind.PENDING, null),
            actions = listOf(
                CoreActionPolicy(CoreActionKind.SEND, CoreAccessState.UNKNOWN, CorePolicySource.LINK_FACTS,
                    "Remote receiver authorization and reachability are not observed"),
                CoreActionPolicy(CoreActionKind.RECEIVE_INBOX, CoreAccessState.BLOCKED, CorePolicySource.ENROLLMENT_CEILING,
                    "The enrollment ceiling for this device does not include transfer"),
                CoreActionPolicy(CoreActionKind.TERMINAL, CoreAccessState.PENDING, CorePolicySource.GRANT_STORE,
                    "Granted on this phone; the peer has not acknowledged delivery"),
                CoreActionPolicy(CoreActionKind.FOLDER, CoreAccessState.UNSUPPORTED, CorePolicySource.PROFILE,
                    "This core profile does not serve folder mounts"),
            ),
        )
        assertEquals(
            "Send: unknown · Receive inbox: blocked · Terminal: pending · Folders: unsupported",
            actionPolicySummary(policy.actions),
        )
        // The stable order the core documents: Send, ReceiveInbox, Terminal, Folder.
        assertEquals(
            listOf(CoreActionKind.SEND, CoreActionKind.RECEIVE_INBOX, CoreActionKind.TERMINAL, CoreActionKind.FOLDER),
            policy.actions.map { it.kind },
        )
        assertEquals("Needs authenticated link facts", policySourceLabel(policy.actions[0].source))
        assertEquals("From the invitation ceiling", policySourceLabel(policy.actions[1].source))
        assertEquals("From a capability recorded on this phone", policySourceLabel(policy.actions[2].source))
        assertEquals("From this core profile", policySourceLabel(policy.actions[3].source))
        // Reasons are the core's own sentences, unchanged.
        assertEquals("Granted on this phone; the peer has not acknowledged delivery", policy.actions[2].reason)
        assertEquals("This core profile does not serve folder mounts", policy.actions[3].reason)
        assertEquals("Admitted by an invitation · ceiling: shell, transfer", enrollmentSummary(policy.enrollment))
        assertEquals("Waiting for delivery to the device", deliverySummary(policy.delivery))
        assertEquals("Paired device", relationshipLabel(policy.relationship))
        assertTrue(policy.revoked)
        assertEquals(1_900_000_000L, policy.expires)
        assertEquals("2030-03-17T17:46:40Z", instantText(policy.expires!!))
    }

    @Test fun anUnsupportedAdmissionShapeShowsTheCoreReasonInstead() {
        val enrollment = CoreEnrollment(CoreEnrollmentKind.UNSUPPORTED, emptyList(),
            "principalKind 'guest-link' is not understood by this core version")
        assertEquals("principalKind 'guest-link' is not understood by this core version", enrollmentSummary(enrollment))
        assertEquals("Not tracked by this build; no delivery acknowledgment is recorded",
            deliverySummary(CoreDelivery(CoreDeliveryKind.NOT_TRACKED, null)))
    }

    @Test fun forgetReceiptNamesExactlyWhatTheLocalStoresDid() {
        val notice = removalNotice(CoreRemovalReceipt(
            mode = CoreRemovalMode.FORGET, name = "laptop", deviceKey = "ab".repeat(32),
            refusedUntil = 1_900_000_000L, grantsRevoked = 3, recordRemoved = true,
            sessions = CoreSessionsSummary.ENDS_ON_RECHECK, localOnly = true,
            keyBlockWritten = true, keyBlocksLifted = emptyList(),
        ))
        assertEquals("Forgotten on this phone.", notice.title)
        assertEquals("laptop", notice.forgottenName)
        assertTrue(notice.lines.any { it == "The device record was removed from this phone." })
        assertTrue(notice.lines.any { it == "A key block now refuses the old device key until 2030-03-17T17:46:40Z." })
        assertTrue(notice.lines.any { it == "3 owner-signed grant(s) were revoked." })
        assertTrue(notice.lines.any { it.contains("No live session was ended by this call") })
        assertTrue(notice.lines.any { it == "This phone wrote its own stores only. The device was not contacted and has not acknowledged anything." })
        // Nothing claims the device removed its own record.
        assertFalse(notice.lines.any { it.contains("was removed on the device") })
    }

    @Test fun cutOffAndRestoreReceiptsReadTheirOwnMode() {
        val cut = removalNotice(CoreRemovalReceipt(
            mode = CoreRemovalMode.CUT_OFF, name = "guest", deviceKey = null, refusedUntil = null,
            grantsRevoked = 0, recordRemoved = false, sessions = CoreSessionsSummary.ENDS_ON_RECHECK,
            localOnly = true, keyBlockWritten = false, keyBlocksLifted = emptyList(),
        ))
        assertEquals("Cut off on this phone.", cut.title)
        assertNull("A cut off keeps the record; no restore is offered for it", cut.forgottenName)
        assertTrue(cut.lines.any { it == "The device record was kept on this phone and marked revoked." })
        assertTrue(cut.lines.any { it.contains("refused when it next rechecks") })

        val restore = removalNotice(CoreRemovalReceipt(
            mode = CoreRemovalMode.RESTORE, name = "laptop", deviceKey = "ab".repeat(32), refusedUntil = null,
            grantsRevoked = 0, recordRemoved = false, sessions = CoreSessionsSummary.NOT_TOUCHED,
            localOnly = true, keyBlockWritten = false,
            keyBlocksLifted = listOf(CoreLiftedKeyBlock("laptop", 1_700_000_000L, "ab".repeat(32))),
        ))
        assertEquals("Local refusal lifted.", restore.title)
        assertNull(restore.forgottenName)
        assertTrue(restore.lines.any { it.contains("1 key block(s) were lifted") })
        assertTrue(restore.lines.any { it.contains("is not recreated") })
        assertTrue(restore.lines.any { it == "No session was examined or changed." })
    }

    @Test fun aCeilingHeldCapabilityIsRefusedAndOffersCutOff() {
        val receipt = CoreCapabilityReceipt(
            action = CoreActionKind.TERMINAL,
            capability = "shell",
            outcome = CoreCapabilityOutcome.NOT_REVOCABLE_BECAUSE_CEILING,
            signed = false,
            expiresAt = null,
            ceiling = listOf("shell", "transfer"),
        )
        val notice = capabilityNotice("guest", CoreCapabilityIntent.REVOKE, receipt)
        assertFalse("A ceiling refusal is never reported as success", notice.applied)
        assertEquals("Not revoked.", notice.title)
        assertTrue(notice.offerCutOff)
        assertTrue(notice.lines.any { it.contains("invitation ceiling (shell, transfer)") })
        assertTrue(notice.lines.any { it.contains("Cutting the device off ends the whole relationship") })

        // The other ceiling outcomes are refusals too, and none offer success.
        listOf(
            CoreCapabilityOutcome.NOT_GRANTABLE_BECAUSE_CEILING,
            CoreCapabilityOutcome.ALREADY_HELD_BY_CEILING,
            CoreCapabilityOutcome.NOT_HELD,
        ).forEach { outcome ->
            val refused = capabilityNotice("guest", CoreCapabilityIntent.GRANT, receipt.copy(outcome = outcome))
            assertFalse("${outcome} must not report success", refused.applied)
            assertFalse(refused.offerCutOff)
        }
    }

    @Test fun anAppliedEditShowsWhetherTheCoreSignedIt() {
        val signed = capabilityNotice("laptop", CoreCapabilityIntent.GRANT, CoreCapabilityReceipt(
            action = CoreActionKind.TERMINAL, capability = "shell", outcome = CoreCapabilityOutcome.APPLIED,
            signed = true, expiresAt = 1_900_000_000L, ceiling = emptyList(),
        ))
        assertTrue(signed.applied)
        assertEquals("Granted.", signed.title)
        assertTrue(signed.lines.any { it.contains("An owner-signed grant was written and expires at 2030-03-17T17:46:40Z.") })
        assertTrue(signed.lines.any { it.contains("not delivery") })

        val plain = capabilityNotice("browser", CoreCapabilityIntent.GRANT, CoreCapabilityReceipt(
            action = CoreActionKind.FOLDER, capability = "mount", outcome = CoreCapabilityOutcome.APPLIED,
            signed = false, expiresAt = null, ceiling = emptyList(),
        ))
        assertTrue(plain.applied)
        assertTrue(plain.lines.any { it.contains("no owner-signed grant was written") })

        val revoked = capabilityNotice("laptop", CoreCapabilityIntent.REVOKE, CoreCapabilityReceipt(
            action = CoreActionKind.TERMINAL, capability = "shell", outcome = CoreCapabilityOutcome.APPLIED,
            signed = true, expiresAt = null, ceiling = emptyList(),
        ))
        assertTrue(revoked.applied)
        assertEquals("Revoked.", revoked.title)
    }

    @Test fun theDeviceListSummaryKeepsEveryActionState() {
        val summary = actionSummary(listOf(
            CoreAction(CoreActionKind.SEND, CoreAccessState.UNKNOWN, ""),
            CoreAction(CoreActionKind.RECEIVE_INBOX, CoreAccessState.PENDING, ""),
            CoreAction(CoreActionKind.TERMINAL, CoreAccessState.BLOCKED, ""),
            CoreAction(CoreActionKind.FOLDER, CoreAccessState.UNSUPPORTED, ""),
        ))
        assertEquals("Send: unknown · Receive inbox: pending · Terminal: blocked · Folders: unsupported", summary)
    }
}
