package com.tunlion.android

import org.junit.Assert.*
import org.junit.Test

class CliProcessTest {
    @Test fun prettyStatusAndChunkedEventsAreNotConfused() {
        val frames = JsonObjectFrames()
        assertTrue(frames.feed("{\"event\":\"code\",\"code\":\"brave-").isEmpty())
        val code = frames.feed("otter-123\"}\n").single()
        assertEquals("brave-otter-123", code.getString("code"))
        val result = frames.feed("{\n \"ok\":true,\n \"data\":{\"name\":\"a}b{c\\\"\"}\n}\n").single()
        assertTrue(result.getBoolean("ok"))
        assertEquals("a}b{c\"", result.getJSONObject("data").getString("name"))
    }

    @Test fun failuresUseExitMeaningAndStructuredMessages() {
        val result = CliOutcome(4, org.json.JSONObject("""{"ok":false,"error":{"message":"Shell is not granted"}}""")).result()
        assertEquals(CoreResult.Failure(CoreErrorKind.DENIED, "Shell is not granted"), result)
        assertEquals(CoreErrorKind.NETWORK, (CliOutcome(7, null).result() as CoreResult.Failure).kind)
    }

    @Test(expected = IllegalStateException::class)
    fun unboundedOutputCannotGrowMemoryForever() {
        JsonObjectFrames().feed("{\"text\":\"" + "x".repeat(512 * 1024))
    }
}
