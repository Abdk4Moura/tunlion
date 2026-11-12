package com.tunlion.android

import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test

/** UI contract tests only. Native transport proof lives in NativePeerAcceptanceTest. */
class DeviceAuthorityUiTest {
    @get:Rule val compose = createComposeRule()

    private fun open(snapshot: CoreStatus) {
        compose.setContent {
            TunlionTheme {
                TunlionApp(SnapshotCore(snapshot.copy(statusLoaded = true)), false, {}, {}, {})
            }
        }
    }

    /** The same entry point, but the caller supplies the fake core (policies, receipts). */
    private fun open(core: TunlionCore) {
        compose.setContent { TunlionTheme { TunlionApp(core, false, {}, {}, {}) } }
    }

    /** A loaded device list: an unloaded snapshot shows the opening spinner instead. */
    private fun deviceStatus(vararg devices: CoreDevice) = CoreStatus(
        statusLoaded = true, identityLoaded = true, fingerprint = "12345678",
        engineLinked = true, devices = devices.toList(),
    )

    @Test fun enrollmentCannotSilentlyUseLegacyPairing() {
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true))
        compose.onNodeWithText("Add device").performClick()
        compose.onNodeWithText("Spoken code").assertExists()
        compose.onNodeWithText("Temporary worker").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Invitation file").performScrollTo().performClick()
        compose.onNodeWithText("Invitation preview is not linked in this build. No file is read and nothing is joined.").assertExists()
        compose.onNodeWithText("Temporary worker").performScrollTo().performClick()
        compose.onNodeWithText("Temporary access must have a bounded expiry confirmed by the core. Invitation file only.").assertExists()
        compose.onNodeWithText("Choose invitation file").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Join with this invitation").assertDoesNotExist()
        compose.onNodeWithText("Someone else's").performScrollTo().performClick()
        compose.onNodeWithText("External pair with explicitly confirmed permissions, not fleet membership.").assertExists()
        compose.onNodeWithText("Spoken code").performScrollTo().performClick()
        compose.onNodeWithText("Review enrollment").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Enrollment review is unavailable until the shared core exposes enrollment facts. These choices do not record a relationship or grant permission. Use Files for a one-time transfer code.").assertExists()
    }

    @Test fun linkedInvitationSurfaceOffersPickerButNotSpokenCodeEnrollment() {
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true, enrollmentSupported = true))
        compose.onNodeWithText("Add device").performClick()
        compose.onNodeWithText("Review enrollment").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Spoken-code enrollment is not linked in this build. Use an invitation file, or Files for a one-time transfer code.").assertExists()
        compose.onNodeWithText("Invitation file").performScrollTo().performClick()
        compose.onNodeWithText("The shared core reads and verifies the invitation file. You see its signed facts before anything is joined.").assertExists()
        compose.onNodeWithText("Choose invitation file").performScrollTo().assertIsEnabled()
        // No bytes have been previewed, so nothing can be joined.
        compose.onNodeWithText("Join with this invitation").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("INVITATION PREVIEW").assertDoesNotExist()
    }

    private fun review(core: InvitationCore, invitation: ByteArray, onJoin: (ByteArray, String) -> Unit) {
        compose.setContent {
            TunlionTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    InvitationReview(core, invitation, "Pixel test", busy = false, enabled = true,
                        onChooseFile = {}, onJoin = onJoin)
                }
            }
        }
    }

    private fun preview(expired: Boolean) = InvitationPreview(
        ownerName = "Ada's laptop",
        relationship = InvitationRelationship.TEMPORARY_WORKER,
        requestedCapabilities = listOf("inbox", "route:10.0.0.0/8"),
        expires = 1_893_456_000L,
        maxOffline = 86_400L,
        maxUses = 1L,
        reusable = false,
        ephemeral = true,
        expired = expired,
    )

    @Test fun previewShowsCoreFieldsAndJoinReceivesExactlyThePreviewedBytes() {
        val invitation = "filament-invite:v2:opaque-to-kotlin".toByteArray()
        val core = InvitationCore(InvitationPreviewResult.Previewed(preview(expired = false)))
        review(core, invitation) { bytes, name -> runBlocking { core.joinInvitation(bytes, name) } }
        compose.onNodeWithText("INVITATION PREVIEW").performScrollTo().assertExists()
        compose.onNodeWithText("Ada's laptop").performScrollTo().assertExists()
        compose.onNodeWithText("Temporary worker").performScrollTo().assertExists()
        compose.onNodeWithText("inbox\nroute:10.0.0.0/8").performScrollTo().assertExists()
        compose.onNodeWithText("2030-01-01T00:00:00Z").performScrollTo().assertExists()
        compose.onNodeWithText("86400 seconds").performScrollTo().assertExists()
        compose.onNodeWithText("The core reports temporary-worker access. It is bounded by the signed expiry above.").performScrollTo().assertExists()
        compose.onNodeWithText("The core reports this invitation has expired. It cannot be joined.").assertDoesNotExist()
        assertEquals(1, core.previewCalls)
        assertSame(invitation, core.previewed)
        assertNull(core.joined)
        compose.onNodeWithText("Join with this invitation").performScrollTo().assertIsEnabled().performClick()
        compose.waitForIdle()
        val joined = checkNotNull(core.joined) { "Join did not reach the core" }
        // The same array instance the core previewed: never re-read, copied or rebuilt.
        assertSame(invitation, joined.first)
        assertSame(core.previewed, joined.first)
        assertEquals("Pixel test", joined.second)
        assertEquals(1, core.joinCalls)
        assertEquals(1, core.previewCalls)
    }

    @Test fun coreExpiredFlagDisablesJoin() {
        val invitation = "filament-invite:v2:expired".toByteArray()
        val core = InvitationCore(InvitationPreviewResult.Previewed(preview(expired = true)))
        review(core, invitation) { bytes, name -> runBlocking { core.joinInvitation(bytes, name) } }
        compose.onNodeWithText("INVITATION PREVIEW").performScrollTo().assertExists()
        compose.onNodeWithText("The core reports this invitation has expired. It cannot be joined.").performScrollTo().assertExists()
        compose.onNodeWithText("Join with this invitation").performScrollTo().assertIsNotEnabled().performClick()
        compose.waitForIdle()
        assertSame(invitation, core.previewed)
        assertNull(core.joined)
        assertEquals(0, core.joinCalls)
    }

    @Test fun corePreviewErrorIsShownVerbatimAndJoinStaysDisabled() {
        val invitation = "not an invitation".toByteArray()
        val core = InvitationCore(InvitationPreviewResult.Failed(
            CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "invitation: unrecognised prefix")))
        review(core, invitation) { bytes, name -> runBlocking { core.joinInvitation(bytes, name) } }
        compose.onNodeWithText("CORE COULD NOT PREVIEW").performScrollTo().assertExists()
        compose.onNodeWithText("invitation: unrecognised prefix").performScrollTo().assertExists()
        compose.onNodeWithText("INVITATION PREVIEW").assertDoesNotExist()
        compose.onNodeWithText("Join with this invitation").performScrollTo().assertIsNotEnabled().performClick()
        compose.waitForIdle()
        assertSame(invitation, core.previewed)
        assertNull(core.joined)
        assertEquals(0, core.joinCalls)
    }

    @Test fun blankIdentityOffersSetupInsteadOfDevices() {
        open(CoreStatus(identityLoaded = false))
        compose.onNodeWithText("Your files,\ndirect to this phone.").assertExists()
        compose.onNodeWithText("Set up my first device").assertExists()
        compose.onNodeWithText("DEVICES").assertDoesNotExist()
    }

    @Test fun joinedDeviceWithoutOwnerFingerprintIsDistinct() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.PAIRED)
        open(CoreStatus(identityLoaded = true, fingerprint = null, engineLinked = true, devices = listOf(peer)))
        compose.onNodeWithText("This phone is joined through stored device records. No local owner identity fingerprint is present.").assertExists()
        compose.onNodeWithContentDescription("Settings").performClick()
        compose.onNodeWithText("Joined device; no local owner fingerprint").assertExists()
    }

    @Test fun unknownRemotePermissionDoesNotBecomeSendAuthority() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.PAIRED,
            actions = listOf(CoreAction(CoreActionKind.SEND, CoreAccessState.UNKNOWN, "Remote receiver authorization is not observed")))
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true, devices = listOf(peer)))
        compose.onNodeWithText("Stored laptop").performClick()
        compose.onNodeWithText("No action is confirmed effective by this snapshot.").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("UNKNOWN").assertExists()
        // The action row is tagged: the same label also appears in the revoke
        // list, and a text-only selector would be ambiguous.
        compose.onNodeWithTag("policy-SEND").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Send files to this device").assertExists()
        compose.onNodeWithText("Send a file").assertDoesNotExist()
        compose.onNodeWithText("Availability unknown").assertExists()
        compose.onNodeWithText("Try sending a file").performScrollTo().performClick()
        compose.onNodeWithText("Try sending to Stored laptop").assertExists()
        compose.onNodeWithText("Remote permission is unknown, not granted. The receiver will decide whether to accept this attempt.").assertExists()
        compose.onNodeWithText("Try sending files").performScrollTo().assertIsNotEnabled()
    }

    @Test fun deviceListShowsRelationshipAndEveryActionState() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.FLEET,
            revoked = true,
            actions = listOf(
                CoreAction(CoreActionKind.SEND, CoreAccessState.UNKNOWN, "Remote receiver authorization is not observed"),
                CoreAction(CoreActionKind.RECEIVE_INBOX, CoreAccessState.BLOCKED, "Device access is revoked on this receiver"),
                CoreAction(CoreActionKind.TERMINAL, CoreAccessState.UNSUPPORTED, "This core profile does not serve terminals"),
                CoreAction(CoreActionKind.FOLDER, CoreAccessState.PENDING, "Waiting for a core fact"),
            ))
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true, devices = listOf(peer)))
        compose.onNodeWithText("Fleet device · revoked locally").assertExists()
        compose.onNodeWithText("Send: unknown · Receive inbox: blocked · Terminal: unsupported · Folders: pending").assertExists()
        compose.onNodeWithText("Stored laptop").performClick()
        compose.onNodeWithText("A stored relationship or recorded grant is not proof that an action currently works. This snapshot does not probe the remote device.").performScrollTo().assertExists()
        compose.onNodeWithText("PENDING").performScrollTo().assertExists()
        compose.onNodeWithText("BLOCKED").performScrollTo().assertExists()
        compose.onNodeWithText("UNKNOWN").performScrollTo().assertExists()
        compose.onNodeWithText("UNAVAILABLE").performScrollTo().assertExists()
        // The removal actions are wired to the core now: both are offered.
        compose.onNodeWithText("Cut this device off").performScrollTo().assertIsEnabled()
        compose.onNodeWithText("Forget this device").performScrollTo().assertIsEnabled()
    }

    @Test fun pendingChipIsItsOwnStateAndNeverRenderedAsAvailable() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.PAIRED,
            actions = listOf(
                CoreAction(CoreActionKind.SEND, CoreAccessState.PENDING, "Granted on this phone; the peer has not acknowledged delivery"),
            ))
        val policy = CoreDevicePolicy(
            name = peer.name, deviceKey = peer.id, relationship = CoreRelationship.PAIRED,
            expires = null, revoked = false,
            enrollment = CoreEnrollment(CoreEnrollmentKind.PAIRED, emptyList(), null),
            delivery = CoreDelivery(CoreDeliveryKind.PENDING, null),
            actions = listOf(CoreActionPolicy(CoreActionKind.SEND, CoreAccessState.PENDING,
                CorePolicySource.GRANT_STORE, "Granted on this phone; the peer has not acknowledged delivery")),
        )
        open(DeviceCore(deviceStatus(peer), mapOf("Stored laptop" to policy)))
        compose.onNodeWithText("Stored laptop").performScrollTo().performClick()
        compose.onNodeWithText("PENDING").performScrollTo().assertExists()
        compose.onNodeWithText("Waiting for delivery: a grant or invitation ceiling is recorded on this phone, but delivery and live access are not confirmed. Pending is never working access.").performScrollTo().assertExists()
        // The core's reason is the authority and is shown verbatim.
        compose.onNodeWithText("Granted on this phone; the peer has not acknowledged delivery").performScrollTo().assertExists()
        compose.onNodeWithText("From a capability recorded on this phone").performScrollTo().assertExists()
        // Pending is exactly one chip, and it is not the effective chip.
        compose.onAllNodesWithText("Pending").assertCountEquals(1)
        compose.onNodeWithText("Available").assertDoesNotExist()
        compose.onNodeWithText("EFFECTIVE").assertDoesNotExist()
        // A pending send is not a working send: no send button, no attempt copy.
        compose.onNodeWithText("Send a file").assertDoesNotExist()
        compose.onNodeWithText("Sending is not available for this device in the current core snapshot. The reason above is the core's own fact, not a client guess.").performScrollTo().assertExists()
    }

    @Test fun forgetAsksForConfirmationAndShowsTheCoreReceipt() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.PAIRED)
        val core = DeviceCore(deviceStatus(peer), mapOf("Stored laptop" to policyOf(peer)))
        open(core)
        compose.onNodeWithText("Stored laptop").performScrollTo().performClick()
        compose.onNodeWithText("Forget this device").performScrollTo().performClick()
        // Nothing is called before the person confirms.
        assertNull("Forget must not run before confirmation", core.forgotten)
        compose.onNodeWithText("Forget Stored laptop?").assertExists()
        compose.onNodeWithText("This phone removes the stored device record and writes a key block that refuses the old device key. The device is not contacted and nothing is removed on it. This cannot be undone from this phone.").assertExists()
        compose.onNodeWithText("Forget").performClick()
        compose.waitForIdle()
        assertEquals("Stored laptop", core.forgotten)
        compose.onNodeWithText("Forgotten on this phone.").performScrollTo().assertExists()
        compose.onNodeWithText("The device record was removed from this phone.").performScrollTo().assertExists()
        compose.onNodeWithText("This phone wrote its own stores only. The device was not contacted and has not acknowledged anything.").performScrollTo().assertExists()
        compose.onNodeWithText("Lift the key block for Stored laptop").performScrollTo().assertExists()
    }

    @Test fun cutOffConfirmationNamesTheKeptRecordAndDoesNotCallForget() {
        val peer = CoreDevice("peer-key", "Rented phone", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.FLEET)
        val core = DeviceCore(deviceStatus(peer), mapOf("Rented phone" to policyOf(peer)))
        open(core)
        compose.onNodeWithText("Rented phone").performScrollTo().performClick()
        compose.onNodeWithText("Cut this device off").performScrollTo().performClick()
        assertNull(core.forgotten)
        compose.onNodeWithText("Cut off Rented phone?").assertExists()
        compose.onNodeWithText("This phone keeps the record and marks the device revoked. The device is refused when it next checks in. An active session is not ended by this call.").assertExists()
        compose.onNodeWithText("Cut off").performClick()
        compose.waitForIdle()
        assertEquals("Rented phone", core.cutOff)
        assertNull("Cut off must not use the forget call", core.forgotten)
        compose.onNodeWithText("Cut off on this phone.").performScrollTo().assertExists()
        compose.onNodeWithText("The device record was kept on this phone and marked revoked.").performScrollTo().assertExists()
    }

    @Test fun effectiveCoreActionIsRenderedOnlyWhenCoreReportsIt() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", true, false,
            relationship = CoreRelationship.FLEET,
            actions = listOf(
                CoreAction(CoreActionKind.SEND, CoreAccessState.AVAILABLE, "Authenticated link and receiver grant"),
                CoreAction(CoreActionKind.RECEIVE_INBOX, CoreAccessState.UNKNOWN, "Authenticated link facts are not available here"),
            ))
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true, devices = listOf(peer)))
        compose.onNodeWithText("Send: available · Receive inbox: unknown").assertExists()
        compose.onNodeWithText("Stored laptop").performClick()
        compose.onNodeWithText("EFFECTIVE").performScrollTo().assertExists()
        compose.onNodeWithText("Send a file").assertExists()
        compose.onNodeWithText("Try sending a file").assertDoesNotExist()
    }

    @Test fun sendResultShowsOnlyReceiverAcknowledgedDelivery() {
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true,
            lastSend = CoreSendReport(listOf(
                CoreSentFile("sent.txt", true, "sent.1.txt"),
                CoreSentFile("lost.txt", false, null),
            ))))
        compose.onAllNodesWithText("Files")[0].performClick()
        compose.onNodeWithText("LAST SEND RESULT").performScrollTo().assertExists()
        compose.onNodeWithText("Code transfer").performScrollTo().assertExists()
        compose.onNodeWithText("Receiver acknowledged delivery · stored as sent.1.txt").performScrollTo().assertExists()
        compose.onNodeWithText("Receiver did not acknowledge delivery").performScrollTo().assertExists()
    }
}

/**
 * The UI tests never invent core facts: every operation they do not exercise
 * fails loudly. Policy and receipts come from the test fixture below.
 */
private abstract class FakeCore : TunlionCore {
    abstract override fun status(): CoreStatus
    override suspend fun refresh() = status()
    protected fun unsupported(): Nothing = error("This UI test must not call a core operation")
    override suspend fun prepareIdentity(): String = unsupported()
    override suspend fun confirmIdentity(phrase: String): CoreResult = unsupported()
    override fun discardIdentity() = Unit
    override suspend fun start(): CoreResult = unsupported()
    override suspend fun stop(): CoreResult = unsupported()
    override suspend fun joinCode(code: String, remember: Boolean): CoreResult = unsupported()
    override suspend fun receiveCode(code: String): CoreResult = unsupported()
    override suspend fun previewInvitation(bytes: ByteArray): InvitationPreviewResult = unsupported()
    override suspend fun joinInvitation(bytes: ByteArray, name: String): CoreResult = unsupported()
    override suspend fun devicePolicy(name: String): CoreDevicePolicyResult = unsupported()
    override suspend fun forgetDevice(name: String): CoreRemovalResult = unsupported()
    override suspend fun cutOffDevice(name: String): CoreRemovalResult = unsupported()
    override suspend fun restoreDevice(name: String): CoreRemovalResult = unsupported()
    override suspend fun grantCapability(device: String, action: CoreActionKind): CoreCapabilityResult = unsupported()
    override suspend fun revokeCapability(device: String, action: CoreActionKind): CoreCapabilityResult = unsupported()
    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult = unsupported()
}

private class SnapshotCore(private val snapshot: CoreStatus) : FakeCore() {
    override fun status() = snapshot
    override suspend fun refresh() = snapshot
    override suspend fun devicePolicy(name: String): CoreDevicePolicyResult {
        val device = snapshot.devices.firstOrNull { it.name == name }
            ?: return CoreDevicePolicyResult.Failed(CoreResult.Failure(CoreErrorKind.UNKNOWN_DEVICE, "no known device named '$name'"))
        return CoreDevicePolicyResult.Loaded(policyOf(device))
    }
}

/** A device screen backed by one policy snapshot, recording the typed calls it receives. */
private class DeviceCore(private val snapshot: CoreStatus, private val policies: Map<String, CoreDevicePolicy>) : FakeCore() {
    var forgotten: String? = null
    var cutOff: String? = null
    var restored: String? = null
    var revoked: Pair<String, CoreActionKind>? = null
    var revokeResult: CoreCapabilityResult? = null
    override fun status() = snapshot
    override suspend fun refresh() = snapshot
    override suspend fun devicePolicy(name: String): CoreDevicePolicyResult =
        policies[name]?.let { CoreDevicePolicyResult.Loaded(it) }
            ?: CoreDevicePolicyResult.Failed(CoreResult.Failure(CoreErrorKind.UNKNOWN_DEVICE, "no known device named '$name'"))
    override suspend fun forgetDevice(name: String): CoreRemovalResult {
        forgotten = name
        return CoreRemovalResult.Removed(receipt(CoreRemovalMode.FORGET, name))
    }
    override suspend fun cutOffDevice(name: String): CoreRemovalResult {
        cutOff = name
        return CoreRemovalResult.Removed(receipt(CoreRemovalMode.CUT_OFF, name))
    }
    override suspend fun restoreDevice(name: String): CoreRemovalResult {
        restored = name
        return CoreRemovalResult.Removed(receipt(CoreRemovalMode.RESTORE, name))
    }
    override suspend fun revokeCapability(device: String, action: CoreActionKind): CoreCapabilityResult {
        revoked = device to action
        return revokeResult ?: CoreCapabilityResult.Edited(CoreCapabilityReceipt(action, "transfer",
            CoreCapabilityOutcome.APPLIED, false, null, emptyList()))
    }
}

/** The projection the adapter builds from one device's core policy. */
internal fun policyOf(device: CoreDevice) = CoreDevicePolicy(
    name = device.name,
    deviceKey = device.id.takeUnless { it.startsWith("name:") },
    relationship = device.relationship,
    expires = null,
    revoked = device.revoked,
    enrollment = CoreEnrollment(CoreEnrollmentKind.PAIRED, emptyList(), null),
    delivery = CoreDelivery(CoreDeliveryKind.NOT_TRACKED, null),
    actions = device.actions.map {
        CoreActionPolicy(it.kind, it.state, CorePolicySource.RECORD, it.reason)
    },
)

private fun receipt(mode: CoreRemovalMode, name: String) = when (mode) {
    CoreRemovalMode.FORGET -> CoreRemovalReceipt(mode, name, "device-key", 1_900_000_000L, 2, true,
        CoreSessionsSummary.ENDS_ON_RECHECK, true, true, emptyList())
    CoreRemovalMode.CUT_OFF -> CoreRemovalReceipt(mode, name, "device-key", null, 0, false,
        CoreSessionsSummary.ENDS_ON_RECHECK, true, false, emptyList())
    CoreRemovalMode.RESTORE -> CoreRemovalReceipt(mode, name, "device-key", null, 0, false,
        CoreSessionsSummary.NOT_TOUCHED, true, false, emptyList())
}

/** Returns a fixed core preview and records the exact arrays it is handed. */
private class InvitationCore(private val result: InvitationPreviewResult) : FakeCore() {
    var previewCalls = 0
    var previewed: ByteArray? = null
    var joinCalls = 0
    var joined: Pair<ByteArray, String>? = null
    override fun status() = CoreStatus(statusLoaded = true, enrollmentSupported = true)
    override suspend fun refresh() = status()
    override suspend fun previewInvitation(bytes: ByteArray): InvitationPreviewResult {
        previewCalls += 1
        previewed = bytes
        return result
    }
    override suspend fun joinInvitation(bytes: ByteArray, name: String): CoreResult {
        joinCalls += 1
        joined = bytes to name
        return CoreResult.Success
    }
}
