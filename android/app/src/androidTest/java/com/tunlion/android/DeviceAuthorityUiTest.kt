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
                TunlionApp(SnapshotCore(snapshot), false, {}, {}, {})
            }
        }
    }

    @Test fun enrollmentCannotSilentlyUseLegacyPairing() {
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true))
        compose.onNodeWithText("Add device").performClick()
        compose.onNodeWithText("Someone else's").performScrollTo().performClick()
        compose.onNodeWithText("External pair with explicitly confirmed permissions, not fleet membership.").assertExists()
        compose.onNodeWithText("Review enrollment").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Open an invitation file").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Temporary worker").performScrollTo().performClick()
        compose.onNodeWithText("Temporary access must have a bounded expiry confirmed by the core.").assertExists()
        compose.onNodeWithText("Review enrollment").performScrollTo().assertIsNotEnabled()
    }

    @Test fun unknownRemotePermissionDoesNotBecomeSendAuthority() {
        val peer = CoreDevice("peer-key", "Stored laptop", null, null,
            "Stored facts only, not remote acknowledgment.", false, false,
            relationship = CoreRelationship.PAIRED,
            actions = listOf(CoreAction("send", CoreAccessState.UNKNOWN, "Remote receiver authorization is not observed")))
        open(CoreStatus(identityLoaded = true, fingerprint = "12345678", engineLinked = true, devices = listOf(peer)))
        compose.onNodeWithText("Stored laptop").performClick()
        compose.onNodeWithText("No action is confirmed effective by this snapshot.").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Send files to this device · Unknown").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Send a file").assertDoesNotExist()
        compose.onNodeWithText("Availability unknown").assertExists()
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
