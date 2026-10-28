package com.tunlion.android

/** Two separate acceleration peaks, not repeated samples from a single bump. */
internal class ShakeGesture {
    private var previousPeak: Long? = null
    private var cooldownUntil = 0L
    private var armed = true

    fun reset() { previousPeak = null; armed = true }

    fun sample(g: Double, now: Long): Boolean {
        if (g < 1.5) armed = true
        if (now < cooldownUntil || g < 2.7 || !armed) return false
        armed = false
        val previous = previousPeak
        if (previous != null && now - previous in 180..900) {
            previousPeak = null
            cooldownUntil = now + 10_000
            return true
        }
        if (previous == null || now - previous > 900) previousPeak = now
        return false
    }
}
