package com.tunlion.coresmoke

import android.os.Looper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.tunlion_core.CoreException
import uniffi.tunlion_core.CoreSession
import uniffi.tunlion_core.EngineState

/** Calls the generated Kotlin bindings and shipped Android .so, never a CLI. */
@RunWith(AndroidJUnit4::class)
class CoreAcceptanceTest {
    @Test(timeout = 240_000)
    fun libraryStartsStopsAndReceivesVerifiedBytes() {
        assertNotEquals("blocking FFI must stay off the UI thread", Looper.getMainLooper(), Looper.myLooper())
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val code = requireNotNull(args.getString("code")) { "missing sender code" }
        val expectedSha = requireNotNull(args.getString("sha256"))
        val expectedBytes = requireNotNull(args.getString("bytes")).toULong()
        val root = File(instrumentation.targetContext.filesDir, "core-${UUID.randomUUID()}")
        val config = File(root, "config").apply { mkdirs() }
        val inbox = File(root, "inbox").apply { mkdirs() }
        File(config, "config").writeText("server http://10.0.2.2:8188\nname android-core\n")

        try {
            CoreSession.open(config.absolutePath).use { core ->
                core.beginIdentity().use { pending ->
                    val fingerprint = core.commitIdentity(pending, pending.phrase())
                    assertEquals(fingerprint, core.fingerprint())
                }
                core.start()
                try {
                    assertEquals(EngineState.RUNNING, core.status().engine)
                    CoreSession.open(config.absolutePath).use { competitor ->
                        // A second instance may not acquire the same-root engine lease.
                        assertThrows(CoreException.EngineLease::class.java) { competitor.start() }
                    }
                    assertThrows(CoreException.EngineAlreadyRunning::class.java) {
                        core.receiveCode(code, inbox.absolutePath, true, 90uL)
                    }
                } finally {
                    core.stop()
                }
                assertEquals(EngineState.STOPPED, core.status().engine)
                // Prove that stop released the OS lease, not merely a status flag.
                CoreSession.open(config.absolutePath).use { successor ->
                    successor.start()
                    successor.stop()
                    assertEquals(EngineState.STOPPED, successor.status().engine)
                }

                val summary = core.receiveCode(code, inbox.absolutePath, true, 90uL)
                assertTrue(summary.refused.isEmpty())
                assertEquals(expectedBytes, summary.bytes)
                val stored = summary.stored.single()
                assertEquals("android-core-payload.bin", stored.name)
                assertEquals(expectedSha, stored.sha256)
                assertEquals(expectedBytes, stored.bytes)
                val received = File(inbox, stored.storedName).readBytes()
                assertEquals(expectedBytes, received.size.toULong())
                val sha = MessageDigest.getInstance("SHA-256").digest(received)
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) }
                assertEquals(expectedSha, sha)
                assertEquals(EngineState.STOPPED, core.status().engine)
            }
        } finally {
            root.deleteRecursively()
        }
    }
}
