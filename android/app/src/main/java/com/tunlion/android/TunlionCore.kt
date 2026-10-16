package com.tunlion.android

/**
 * The UI depends on this boundary. NativeTunlionCore uses generated UniFFI
 * bindings; presentation does not depend on how the engine is reached.
 */
interface TunlionCore {
    fun status(): CoreStatus
    suspend fun refresh(): CoreStatus
    suspend fun prepareIdentity(): String
    suspend fun confirmIdentity(phrase: String): CoreResult
    fun discardIdentity()
    suspend fun start(): CoreResult
    suspend fun stop(): CoreResult
    suspend fun joinCode(code: String, remember: Boolean): CoreResult
    suspend fun receiveCode(code: String): CoreResult
}

data class CoreStatus(
    val deviceName: String? = null,
    val fingerprint: String? = null,
    val engineRunning: Boolean = false,
    val engineLinked: Boolean = false,
    val devices: List<CoreDevice> = emptyList(),
)

data class CoreDevice(
    val id: String,
    val name: String,
    val online: Boolean,
    val route: String?,
    val plainLine: String,
    val canSendFiles: Boolean,
    val canOpenShell: Boolean,
)

sealed interface CoreResult {
    data object Success : CoreResult
    data class Failure(val kind: CoreErrorKind, val message: String) : CoreResult
}

enum class CoreErrorKind {
    ENGINE_NOT_LINKED,
    FEATURE_NOT_LINKED,
    INVALID_INPUT,
    INTERNAL,
}
