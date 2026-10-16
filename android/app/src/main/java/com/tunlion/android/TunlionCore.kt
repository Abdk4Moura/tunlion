package com.tunlion.android

/**
 * The UI depends on this boundary, never on a CLI process. The UniFFI adapter
 * will replace UnlinkedTunlionCore when the native bindings land.
 */
interface TunlionCore {
    fun status(): CoreStatus
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

/**
 * This build intentionally does not claim availability or pairing success.
 * No UniFFI bindings or peer-loop implementation are present in the base core
 * yet. All operations fail closed until the real adapter is connected.
 */
class UnlinkedTunlionCore : TunlionCore {
    override fun status() = CoreStatus(engineLinked = false)

    override suspend fun start() = CoreResult.Failure(
        CoreErrorKind.ENGINE_NOT_LINKED,
        "The native engine is not linked yet. This phone is still off.",
    )

    override suspend fun stop() = CoreResult.Success

    override suspend fun joinCode(code: String, remember: Boolean): CoreResult =
        if (code.isBlank()) {
            CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Enter a code first.")
        } else {
            CoreResult.Failure(
                CoreErrorKind.FEATURE_NOT_LINKED,
                "Pairing will work when the native core binding is connected.",
            )
        }

    override suspend fun receiveCode(code: String): CoreResult =
        if (code.isBlank()) {
            CoreResult.Failure(CoreErrorKind.INVALID_INPUT, "Enter a code first.")
        } else {
            CoreResult.Failure(
                CoreErrorKind.FEATURE_NOT_LINKED,
                "Receiving files will work when the native core binding is connected.",
            )
        }
}
