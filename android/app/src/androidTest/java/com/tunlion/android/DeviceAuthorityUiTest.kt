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
        compose.onNodeWithText("Send files to this device").performScrollTo().assertIsDisplayed()
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
        compose.onNodeWithText("Revoke a capability · unavailable").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Cut device off · unavailable").performScrollTo().assertIsNotEnabled()
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

private class SnapshotCore(private val snapshot: CoreStatus) : TunlionCore {
    override fun status() = snapshot
    override suspend fun refresh() = snapshot
    private fun unsupported(): Nothing = error("This UI test must not call a core operation")
    override suspend fun prepareIdentity(): String = unsupported()
    override suspend fun confirmIdentity(phrase: String): CoreResult = unsupported()
    override fun discardIdentity() = Unit
    override suspend fun start(): CoreResult = unsupported()
    override suspend fun stop(): CoreResult = unsupported()
    override suspend fun joinCode(code: String, remember: Boolean): CoreResult = unsupported()
    override suspend fun receiveCode(code: String): CoreResult = unsupported()
    override suspend fun previewInvitation(bytes: ByteArray): InvitationPreviewResult = unsupported()
    override suspend fun joinInvitation(bytes: ByteArray, name: String): CoreResult = unsupported()
    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult = unsupported()
}

/** Returns a fixed core preview and records the exact arrays it is handed. */
private class InvitationCore(private val result: InvitationPreviewResult) : TunlionCore {
    var previewCalls = 0
    var previewed: ByteArray? = null
    var joinCalls = 0
    var joined: Pair<ByteArray, String>? = null
    override fun status() = CoreStatus(statusLoaded = true, enrollmentSupported = true)
    override suspend fun refresh() = status()
    private fun unsupported(): Nothing = error("This UI test must not call a core operation")
    override suspend fun prepareIdentity(): String = unsupported()
    override suspend fun confirmIdentity(phrase: String): CoreResult = unsupported()
    override fun discardIdentity() = Unit
    override suspend fun start(): CoreResult = unsupported()
    override suspend fun stop(): CoreResult = unsupported()
    override suspend fun joinCode(code: String, remember: Boolean): CoreResult = unsupported()
    override suspend fun receiveCode(code: String): CoreResult = unsupported()
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
    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult = unsupported()
}
