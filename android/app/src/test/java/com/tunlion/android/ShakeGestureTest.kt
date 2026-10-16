package com.tunlion.android

import org.junit.Assert.*
import org.junit.Test

class ShakeGestureTest {
    @Test fun oneBumpAndOrdinaryMovementDoNotOpenFeedback() {
        val gesture = ShakeGesture()
        for (time in 1_000L..2_000L step 50) assertFalse(gesture.sample(1.2, time))
        for (time in 3_000L..3_500L step 50) assertFalse(gesture.sample(3.0, time))
    }

    @Test fun deliberateShakeTriggersOnceAndRespectsCooldown() {
        val gesture = ShakeGesture()
        assertFalse(gesture.sample(3.0, 1_000))
        assertFalse(gesture.sample(1.0, 1_100))
        assertTrue(gesture.sample(3.0, 1_300))
        assertFalse(gesture.sample(1.0, 1_400))
        assertFalse(gesture.sample(3.0, 1_600))
        assertFalse(gesture.sample(1.0, 11_400))
        assertFalse(gesture.sample(3.0, 11_500))
        assertFalse(gesture.sample(1.0, 11_600))
        assertTrue(gesture.sample(3.0, 11_800))
    }

    @Test fun backgroundResetDoesNotCarryHalfAShakeIntoNextSession() {
        val gesture = ShakeGesture()
        assertFalse(gesture.sample(3.0, 1_000))
        gesture.reset()
        assertFalse(gesture.sample(3.0, 1_300))
    }
}
