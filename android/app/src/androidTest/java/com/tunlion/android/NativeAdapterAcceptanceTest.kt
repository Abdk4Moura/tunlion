package com.tunlion.android

import android.app.NotificationManager
import android.content.ContentUris
import android.provider.MediaStore
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Full receive slice through the app adapter, foreground service and real public storage. */
@RunWith(AndroidJUnit4::class)
class NativeAdapterAcceptanceTest {
    @Test fun desktopCodePublishesOnlyVerifiedBytesAndStopsForegroundTransfer() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val code = requireNotNull(args.getString("code"))
        val expectedSha = requireNotNull(args.getString("sha256"))
        val expectedBytes = requireNotNull(args.getString("bytes")).toLong()
        val expectedName = args.getString("filename", "android-core-payload.bin")
        val context = instrumentation.targetContext
        val root = File(context.filesDir, "tunlion/state").apply { mkdirs() }
        check(!File(root, "identity.ed25519").exists()) { "Run on a fresh test install; never replace an identity" }
        File(root, "config").writeText("server ${args.getString("server", "http://10.0.2.2:8188")}\nname android-adapter-proof\n")
        val core = NativeTunlionCore.get(context)
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            val phrase = core.prepareIdentity()
            assertEquals(CoreResult.Success, core.confirmIdentity(phrase))
            assertNotNull(core.refresh().fingerprint)
            assertEquals(CoreResult.Success, core.receiveCode(code))
            val record = core.refresh().transfers.single { it.incoming && it.name == expectedName }
            assertTrue("Core receipt must establish verification", record.verified)
            assertTrue("Verified bytes must be published, not merely left in private storage", record.saved)
            context.contentResolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.MediaColumns._ID),
                "${MediaStore.MediaColumns.DISPLAY_NAME} = ? AND ${MediaStore.MediaColumns.RELATIVE_PATH} = ?",
                arrayOf(expectedName, "Download/Tunlion/"), null)!!.use { cursor ->
                assertTrue(cursor.moveToFirst())
                val uri = ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cursor.getLong(0))
                val bytes = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                assertEquals(expectedBytes, bytes.size.toLong())
                val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
                assertEquals(expectedSha, sha)
                assertFalse("A fresh fixture must produce exactly one public copy", cursor.moveToNext())
            }
            assertEquals(CoreResult.Success, core.stop())
            assertFalse(core.refresh().engineRunning)
            withTimeout(10_000) {
                while (context.getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == 1003 }) delay(100)
            }
        } finally {
            withContext(NonCancellable) { core.stop() }
            scenario.close()
        }
    }
}
