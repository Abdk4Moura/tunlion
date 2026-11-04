package com.tunlion.android

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

/** Exercises the exact bindings and library shipped inside the Compose application. */
@RunWith(AndroidJUnit4::class)
class NativeCoreAcceptanceTest {
    @Test fun identityConfirmationAndMalformedCodeUseNativeCore() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val config = File(context.cacheDir, "native-proof-${UUID.randomUUID()}")
        try {
            CoreSession.open(config.absolutePath).use { core ->
                assertNull(core.fingerprint())
                core.beginIdentity().use { pending ->
                    assertThrows(CoreException.PhraseMismatch::class.java) { core.commitIdentity(pending, "not the phrase") }
                    assertNull(core.fingerprint())
                    val fingerprint = core.commitIdentity(pending, pending.phrase())
                    assertEquals(fingerprint, core.fingerprint())
                    assertThrows(CoreException.AlreadyExists::class.java) { core.beginIdentity() }
                }
                assertThrows(CoreException.Usage::class.java) {
                    core.receiveCode("not-a-code", File(config, "inbox").absolutePath, true, 1uL)
                }
                core.stop()
                assertNotEquals(EngineState.RUNNING, core.status().engine)
            }
        } finally { config.deleteRecursively() }
    }
}

/** Run explicitly with a live desktop sender, code, sha256 and bytes instrumentation arguments. */
@RunWith(AndroidJUnit4::class)
class NativePeerAcceptanceTest {
    @Test fun receiveVerifiesActualDesktopBytes() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val code = requireNotNull(args.getString("code")) { "Supply a live desktop sender code" }
        val expectedSha = requireNotNull(args.getString("sha256"))
        val expectedBytes = requireNotNull(args.getString("bytes")).toULong()
        val root = File(instrumentation.targetContext.cacheDir, "native-peer-${UUID.randomUUID()}")
        val inbox = File(root, "inbox").apply { mkdirs() }
        val config = File(root, "config").apply { mkdirs() }
        File(config, "config").writeText("server ${args.getString("server", "http://10.0.2.2:8188")}\nname android-native-proof\n")
        try {
            CoreSession.open(config.absolutePath).use { core ->
                core.beginIdentity().use { core.commitIdentity(it, it.phrase()) }
                try {
                    val summary = core.receiveCode(code, inbox.absolutePath, true, 90uL)
                    assertTrue(summary.refused.isEmpty())
                    assertEquals(expectedBytes, summary.bytes)
                    val stored = summary.stored.single()
                    assertEquals(expectedSha, stored.sha256)
                    val file = File(inbox, stored.storedName)
                    assertEquals(expectedBytes, file.length().toULong())
                    val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
                        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
                    assertEquals(expectedSha, digest)
                    assertEquals(EngineState.STOPPED, core.status().engine)
                } finally { core.stop() }
            }
        } finally { root.deleteRecursively() }
    }
}
