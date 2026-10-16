package com.tunlion.android

import android.app.NotificationManager
import android.os.Bundle
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Manual real-device acceptance with a desktop peer, not a mocked transport. */
@RunWith(AndroidJUnit4::class)
class CliAndroidAcceptanceTest {
    @Test fun pairTransferBackgroundReceiveAndStop() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val code = args.getString("deviceCode")
        assumeTrue("Supply a desktop deviceCode to run real peer acceptance", code != null)
        val context = instrumentation.targetContext
        val backgroundFile = args.getString("backgroundFile", "desktop-proof.txt")
        val core = CliTunlionCore(context)
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            assertEquals(CoreResult.Success, core.joinCode(code!!, true))
            val snapshot = core.refresh()
            assertTrue(snapshot.engineRunning)
            val peer = snapshot.devices.firstOrNull { it.name == args.getString("desktopName", "acceptance-desktop") }
            assertNotNull("The actual desktop must be listed", peer)

            val staged = File(context.cacheDir, "feedback/phone-proof.txt").apply {
                parentFile!!.mkdirs()
                writeText("phone-to-desktop verified proof\n")
            }
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.feedback", staged)
            assertEquals(CoreResult.Success, core.sendFiles(peer!!.id, listOf(uri)) { })
            staged.delete()
            assertTrue(core.refresh().transfers.any { !it.incoming && it.verified && it.name.endsWith("phone-proof.txt") })

            args.getString("fileCode")?.let { fileCode ->
                assertEquals(CoreResult.Success, core.receiveCode(fileCode))
                assertTrue(core.refresh().transfers.any { it.incoming && it.verified && it.saved })
            }

            val pid = CliProcess(context).run(listOf("status")).json!!.getInt("pid")
            scenario.moveToState(Lifecycle.State.CREATED)
            instrumentation.sendStatus(0, Bundle().apply { putString("phase", "BACKGROUND_READY") })
            withTimeout(120_000) {
                while (true) {
                    val received = ReceivedFiles(context)
                    val record = withContext(Dispatchers.IO) { received.records().lastOrNull { it.optString("file") == backgroundFile && it.optString("direction") == "in" && it.optBoolean("ok") } }
                    if (record != null && received.saved(record)) break
                    delay(500)
                }
            }
            val resolver = context.contentResolver
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                resolver.query(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    arrayOf(android.provider.MediaStore.MediaColumns._ID),
                    "${android.provider.MediaStore.MediaColumns.DISPLAY_NAME} = ? AND ${android.provider.MediaStore.MediaColumns.RELATIVE_PATH} = ?",
                    arrayOf(backgroundFile, "Download/Tunlion/"), null)!!.use { cursor ->
                    assertTrue("A real public Download/Tunlion file must exist", cursor.moveToFirst())
                    val savedUri = android.content.ContentUris.withAppendedId(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cursor.getLong(0))
                    assertEquals("desktop-to-phone verified proof\n", resolver.openInputStream(savedUri)!!.bufferedReader().use { it.readText() })
                }
            }

            assertEquals(CoreResult.Success, core.stop())
            assertFalse(core.refresh().engineRunning)
            val dead = try { Os.kill(pid, 0); false } catch (error: ErrnoException) { error.errno == OsConstants.ESRCH }
            assertTrue("Availability off must reap the actual daemon", dead)
            assertFalse(context.getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == 1001 || it.id == 1003 })
            instrumentation.sendStatus(0, Bundle().apply { putString("phase", "CLI_ACCEPTANCE_PASSED") })
        } finally {
            withContext(NonCancellable) { core.stop() }
            scenario.close()
        }
    }
}
