package com.tunlion.android

import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
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
        compose.onNodeWithText("Invitation file").performClick()
        compose.onNodeWithText("Temporary worker").performScrollTo().performClick()
        compose.onNodeWithText("Temporary access must have a bounded expiry confirmed by the core. Invitation file only.").assertExists()
        compose.onNodeWithText("Preview invitation · unavailable").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Someone else's").performScrollTo().performClick()
        compose.onNodeWithText("External pair with explicitly confirmed permissions, not fleet membership.").assertExists()
        compose.onNodeWithText("Spoken code").performScrollTo().performClick()
        compose.onNodeWithText("Review enrollment").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Enrollment review is unavailable until the shared core exposes enrollment facts. These choices do not record a relationship or grant permission. Use Files for a one-time transfer code.").assertExists()
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
            actions = listOf(CoreAction("send", CoreAccessState.UNKNOWN, "Remote receiver authorization is not observed")))
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
                CoreAction("send", CoreAccessState.UNKNOWN, "Remote receiver authorization is not observed"),
                CoreAction("receive-inbox", CoreAccessState.BLOCKED, "Device access is revoked on this receiver"),
                CoreAction("terminal", CoreAccessState.UNSUPPORTED, "This core profile does not serve terminals"),
                CoreAction("folder", CoreAccessState.PENDING, "Waiting for a core fact"),
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
                CoreAction("send", CoreAccessState.AVAILABLE, "Authenticated link and receiver grant"),
                CoreAction("receive-inbox", CoreAccessState.UNKNOWN, "Authenticated link facts are not available here"),
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
    override suspend fun joinInvitation(bytes: ByteArray): CoreResult = unsupported()
    override suspend fun sendFiles(deviceId: String?, files: List<Uri>, onCode: (String) -> Unit): CoreResult = unsupported()
}
