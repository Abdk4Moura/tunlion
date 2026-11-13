package com.tunlion.android

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun TunlionTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val scheme = if (dark) darkColorScheme(
        primary = Color(0xFFE36927), onPrimary = Color(0xFF141412),
        background = Color(0xFF141412), onBackground = Color(0xFFF2EFE6),
        surface = Color(0xFF1D1C1A), onSurface = Color(0xFFF2EFE6),
        surfaceVariant = Color(0xFF26251F), onSurfaceVariant = Color(0xFFA29E94),
        outline = Color(0xFF33312D), error = Color(0xFFF58A8B),
    ) else lightColorScheme(
        primary = Color(0xFFD55C13), onPrimary = Color.White,
        background = Color(0xFFF7F6F2), onBackground = Color(0xFF1D1C1A),
        surface = Color.White, onSurface = Color(0xFF1D1C1A),
        surfaceVariant = Color(0xFFEFEDE6), onSurfaceVariant = Color(0xFF5D5A53),
        outline = Color(0xFFDEDAD0), error = Color(0xFFAF3B43),
    )
    MaterialTheme(colorScheme = scheme, content = content)
}

private enum class Screen { HOME, PAIR, FILES, SETTINGS, DEVICE, SEND, SETUP, RECOVERY }

@Composable
fun TunlionApp(core: TunlionCore, feedbackEnabled: Boolean,
    onFeedbackEnabled: (Boolean) -> Unit, onFeedback: () -> Unit, onSensitiveScreen: (Boolean) -> Unit) {
    val navigation = rememberNavController()
    val currentEntry by navigation.currentBackStackEntryAsState()
    var status by remember { mutableStateOf(core.status()) }
    var busy by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<String?>(null) }
    var selectedDevice by rememberSaveable { mutableStateOf<CoreDevice?>(null) }
    var recoveryWords by remember { mutableStateOf<String?>(null) }
    var loadFailed by remember { mutableStateOf(false) }
    var removalOutcome by remember { mutableStateOf<CoreRemovalNotice?>(null) }
    var capabilityOutcome by remember { mutableStateOf<CoreCapabilityNotice?>(null) }
    val scope = rememberCoroutineScope()
    val colors = MaterialTheme.colorScheme
    val context = androidx.compose.ui.platform.LocalContext.current
    var notificationsEnabled by remember { mutableStateOf(androidx.core.app.NotificationManagerCompat.from(context).areNotificationsEnabled()) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val enginePhase by EngineState.phase.collectAsState()
    var operation by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationsEnabled = granted
        if (!granted) notice = "Notifications are off. Foreground work can still run, but Android 13+ shows its notice in Task Manager rather than the notification drawer."
    }
    fun requestNotifications() {
        if (android.os.Build.VERSION.SDK_INT >= 33 && androidx.core.content.ContextCompat.checkSelfPermission(context,
                android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
    }
    LaunchedEffect(currentEntry?.id) { notice = null }

    fun navigate(to: Screen) {
        if (to == Screen.HOME) {
            navigation.popBackStack(Screen.HOME.name, inclusive = false)
        } else {
            navigation.navigate(to.name) { launchSingleTop = true }
        }
        notice = null
    }
    LaunchedEffect(core, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                notificationsEnabled = androidx.core.app.NotificationManagerCompat.from(context).areNotificationsEnabled()
                if (!busy) try { status = core.refresh(); loadFailed = false }
                catch (cancelled: CancellationException) { throw cancelled }
                catch (error: Exception) {
                    loadFailed = true
                    notice = "Could not read Tunlion's state. Your identity has not been changed."
                }
                delay(2_000)
            }
        }
    }
    val activity = androidx.compose.ui.platform.LocalContext.current as? android.app.Activity
    fun perform(action: suspend () -> CoreResult, success: () -> Unit = {}) {
        if (busy) return
        busy = true
        notice = null
        operation = scope.launch {
            try {
                when (val result = action()) {
                    CoreResult.Success -> { status = core.refresh(); success() }
                    is CoreResult.Failure -> { status = core.refresh(); notice = result.message }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                notice = "That action could not finish. Your existing devices have not been changed."
            } finally { busy = false }
        }
    }

    // A typed write. The screen shows the core's receipt, or the core's refusal
    // text; a refusal never reaches `removalNotice`/`capabilityNotice` as success.
    fun performRemoval(action: suspend () -> CoreRemovalResult) {
        if (busy) return
        busy = true
        notice = null
        operation = scope.launch {
            try {
                when (val result = action()) {
                    is CoreRemovalResult.Removed -> {
                        removalOutcome = removalNotice(result.receipt)
                        capabilityOutcome = null
                        status = core.refresh()
                    }
                    is CoreRemovalResult.Failed -> { notice = result.failure.message; status = core.refresh() }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                notice = "That removal could not finish. The core did not report a change."
            } finally { busy = false }
        }
    }

    fun performCapability(intent: CoreCapabilityIntent, deviceName: String, action: suspend () -> CoreCapabilityResult) {
        if (busy) return
        busy = true
        notice = null
        operation = scope.launch {
            try {
                when (val result = action()) {
                    is CoreCapabilityResult.Edited -> {
                        capabilityOutcome = capabilityNotice(deviceName, intent, result.receipt)
                        removalOutcome = null
                        status = core.refresh()
                    }
                    is CoreCapabilityResult.Failed -> { notice = result.failure.message; status = core.refresh() }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                notice = "That capability change could not finish. The core did not report success."
            } finally { busy = false }
        }
    }

    // NavHost owns gesture progress, cancellation, state restoration and the
    // actual back stack. Animate the whole destination, including its header.
    NavHost(navigation, startDestination = Screen.HOME.name, modifier = Modifier.fillMaxSize(),
        enterTransition = { slideInHorizontally(tween(220)) { it } },
        exitTransition = { slideOutHorizontally(tween(220)) { -it / 4 } },
        popEnterTransition = { slideInHorizontally(tween(220)) { -it / 4 } },
        popExitTransition = { slideOutHorizontally(tween(220)) { it } }) {
    Screen.entries.forEach { destination ->
    composable(destination.name) {
    if (destination == Screen.RECOVERY) {
        // Keep protection and the pending identity until this destination is
        // actually disposed. A cancelled back gesture must not discard either.
        DisposableEffect(Unit) {
            onSensitiveScreen(true)
            activity?.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            onDispose {
                core.discardIdentity()
                recoveryWords = null
                onSensitiveScreen(false)
                activity?.window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }
    Scaffold(containerColor = colors.background, topBar = {
        Column {
        Row(Modifier.fillMaxWidth().windowInsetsPadding(WindowInsets.statusBars)
            .padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (destination == Screen.HOME) {
                TunlionMark(Modifier.size(25.dp))
                Spacer(Modifier.width(9.dp))
                Text("tunlion", fontSize = 20.sp, fontWeight = FontWeight.SemiBold,
                    letterSpacing = (-.5).sp, modifier = Modifier.weight(1f))
                IconButton(onClick = { navigate(Screen.SETTINGS) }) {
                    Icon(Icons.Outlined.Settings, "Settings")
                }
            } else {
                IconButton(onClick = { if (!busy) { notice = null; navigation.popBackStack() } }, enabled = !busy) {
                    Icon(Icons.Outlined.ArrowBack, "Back")
                }
                Text(when (destination) {
                    Screen.PAIR -> "Connect a device"
                    Screen.FILES -> "Files"
                    Screen.SETTINGS -> "Settings"
                    Screen.DEVICE -> selectedDevice?.name ?: "Device"
                    Screen.SEND -> "Send a file"
                    Screen.SETUP -> "Set up this phone"
                    Screen.RECOVERY -> "Recovery words"
                    else -> "Tunlion"
                }, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
            }
        }
        HorizontalDivider(color = colors.outline)
        }
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            AnimatedVisibility(notice != null, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
                Row(Modifier.fillMaxWidth().background(colors.surfaceVariant).padding(start = 20.dp, end = 8.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text(notice.orEmpty(), style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f).padding(vertical = 12.dp).semantics { liveRegion = LiveRegionMode.Polite })
                    IconButton(onClick = { notice = null }) { Icon(Icons.Outlined.Close, "Dismiss message") }
                }
            }
            if (busy && operation?.isActive == true) TextButton(onClick = {
                operation?.cancel()
                notice = "Cancelled."
            }) { Text("Cancel action") }
                Column(Modifier.fillMaxWidth().weight(1f).verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp).padding(top = 24.dp, bottom = 32.dp),
                    verticalArrangement = Arrangement.spacedBy(24.dp)) {
                    when (destination) {
                        Screen.HOME -> {
                            if (!status.statusLoaded) {
                                if (loadFailed) {
                                    SecondaryText("Your identity could not be opened. You can retry without replacing it.")
                                    PrimaryButton("Try again", busy) {
                                        scope.launch {
                                            busy = true
                                            try { status = core.refresh(); loadFailed = false; notice = null }
                                            catch (_: Exception) { notice = "Could not open the identity. Nothing was changed." }
                                            finally { busy = false }
                                        }
                                    }
                                } else if (delayedBusy(true)) {
                                    Row(verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                                        SecondaryText("Opening this phone…")
                                    }
                                }
                            } else if (!status.identityLoaded) {
                                FirstConnection(onJoin = { navigate(Screen.PAIR) }, onSetup = { navigate(Screen.SETUP) })
                            } else {
                            Availability(status, busy, onChange = { turnOn ->
                                if (turnOn) requestNotifications()
                                perform({ if (turnOn) core.start() else core.stop() })
                            })
                            status.engineError?.let { SecondaryText(it) }
                            if (enginePhase == EnginePhase.FAILED) {
                                OutlinedButton(onClick = { perform({ core.stop() }) }, enabled = !busy) { Text("Confirm receiver is off") }
                            }
                            if (status.identityState == CoreIdentityState.JOINED)
                                SecondaryText("This phone is joined through stored device records. No local owner identity fingerprint is present.")
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Eyebrow("DEVICES", Modifier.weight(1f))
                                TextButton(onClick = { navigate(Screen.PAIR) }) { Text("Add device") }
                            }
                            if (status.devices.isEmpty()) {
                                Text("No other devices yet.", style = MaterialTheme.typography.titleMedium)
                                SecondaryText("No stored device relationships. Fleet discovery and enrollment are not connected yet. File codes work without adding a device.")
                            }
                            status.devices.forEach { device ->
                                key(device.id) { DeviceRow(device) {
                                    selectedDevice = device
                                    removalOutcome = null
                                    capabilityOutcome = null
                                    navigate(Screen.DEVICE)
                                } }
                            }
                            HorizontalDivider(color = colors.outline)
                            ActionRow(Icons.Outlined.FolderOpen, "Files", "Send a file or receive with a code") { navigate(Screen.FILES) }
                            }
                        }
                        Screen.PAIR -> PairScreen(core, busy, status.enrollmentSupported, status.enrollmentReason, status.codeEnrollmentSupported,
                            status.deviceName, onJoin = { code, remember ->
                                requestNotifications()
                                perform({ core.joinCode(code, remember) }) { navigate(Screen.HOME) }
                            }, onJoinInvitation = { bytes, name ->
                                requestNotifications()
                                // The exact array the core previewed. Never re-read or rebuilt.
                                perform({ core.joinInvitation(bytes, name) }) { navigate(Screen.HOME) }
                            })
                        Screen.SETUP -> {
                            Title("Make this phone yours.", "Your identity lives on this phone. No account or sign-in.")
                            Step("01", "Keep your recovery words", "Confirm them before the identity is saved.")
                            Step("02", "Your identity stays here", "Stored privately on this phone, not on a server.")
                            PrimaryButton("Create identity", busy = busy, onClick = {
                                if (!busy) scope.launch {
                                    busy = true
                                    try {
                                        recoveryWords = core.prepareIdentity()
                                        navigate(Screen.RECOVERY)
                                    } catch (error: Exception) {
                                        core.discardIdentity()
                                        notice = "Could not prepare an identity. Nothing has been saved."
                                    } finally { busy = false }
                                }
                            })
                            TextButton(onClick = { navigate(Screen.PAIR) }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                                Text("I already have a code")
                            }
                        }
                        Screen.RECOVERY -> {
                            val phrase = recoveryWords
                            if (phrase == null) {
                                SecondaryText("Setup was interrupted. No identity has been saved.")
                                PrimaryButton("Start again", onClick = { navigate(Screen.SETUP) })
                            } else RecoveryScreen(phrase, busy) {
                                perform({ core.confirmIdentity(phrase) }) { navigate(Screen.HOME) }
                            }
                        }
                        Screen.FILES -> FilesScreen(status, busy, onReceive = { code -> requestNotifications(); perform({ core.receiveCode(code) }) },
                            onMakeCode = { selectedDevice = null; navigate(Screen.SEND) },
                            onConnect = { navigate(Screen.PAIR) }, onPickDevice = { device ->
                                selectedDevice = device; navigate(Screen.SEND)
                            })
                        Screen.DEVICE -> {
                            val device = selectedDevice?.let { selected ->
                                status.devices.firstOrNull { it.id == selected.id }
                            }
                            var pendingRemoval by remember { mutableStateOf<CoreRemovalMode?>(null) }
                            removalOutcome?.let { notice ->
                                RemovalOutcome(notice, busy,
                                    onRestore = { name -> performRemoval { core.restoreDevice(name) } },
                                    onDismiss = { removalOutcome = null })
                            }
                            capabilityOutcome?.let { notice ->
                                CapabilityOutcomeCard(notice, busy,
                                    onCutOff = { pendingRemoval = CoreRemovalMode.CUT_OFF },
                                    onDismiss = { capabilityOutcome = null })
                            }
                            if (device == null) SecondaryText("This device is no longer in the current core snapshot. Return to Devices and refresh.")
                            else DeviceDetails(core, device, busy,
                                onSend = { navigate(Screen.SEND) },
                                onRequestForget = { pendingRemoval = CoreRemovalMode.FORGET },
                                onRequestCutOff = { pendingRemoval = CoreRemovalMode.CUT_OFF },
                                onRevoke = { action ->
                                    performCapability(CoreCapabilityIntent.REVOKE, device.name) {
                                        core.revokeCapability(device.name, action)
                                    }
                                })
                            pendingRemoval?.let { mode ->
                                RemovalConfirmDialog(mode, device?.name ?: selectedDevice?.name.orEmpty(), busy,
                                    onDismiss = { pendingRemoval = null },
                                    onConfirm = {
                                        pendingRemoval = null
                                        when (mode) {
                                            CoreRemovalMode.FORGET -> performRemoval { core.forgetDevice(device?.name ?: selectedDevice?.name.orEmpty()) }
                                            else -> performRemoval { core.cutOffDevice(device?.name ?: selectedDevice?.name.orEmpty()) }
                                        }
                                    })
                            }
                        }
                        Screen.SEND -> SendScreen(selectedDevice, busy) { files, onCode ->
                            requestNotifications()
                            perform({ core.sendFiles(selectedDevice?.id, files, onCode) }) { navigate(Screen.FILES) }
                        }
                        Screen.SETTINGS -> {
                            Eyebrow("THIS PHONE")
                            DetailRow("Name", status.deviceName ?: android.os.Build.MODEL)
                            DetailRow("Identity", when (status.identityState) {
                                CoreIdentityState.LOCAL -> status.fingerprint ?: "Local identity"
                                CoreIdentityState.JOINED -> "Joined device; no local owner fingerprint"
                                CoreIdentityState.BLANK -> "Not set up"
                                CoreIdentityState.LOADING -> "Not read yet"
                            })
                            DetailRow("Notifications", if (notificationsEnabled) "Allowed" else "Off in Android settings")
                            if (!notificationsEnabled) SecondaryText("Transfer and availability notices may not appear in the notification drawer. Android 13+ still lists foreground services in Task Manager.")
                            OutlinedButton(onClick = {
                                context.startActivity(android.content.Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                    .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, context.packageName))
                            }) { Text("Notification settings") }
                            if (android.os.Build.VERSION.SDK_INT < 29) ReceiveFolderSetting()
                            HorizontalDivider(color = colors.outline)
                            Eyebrow("EXPERIMENTAL")
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text("Shake to give feedback", fontWeight = FontWeight.Medium)
                                    SecondaryText("Select a section and tell us what should change.")
                                }
                                Switch(feedbackEnabled, onFeedbackEnabled,
                                    colors = tunlionSwitchColors(),
                                    modifier = Modifier.semantics { contentDescription = "Shake to give feedback" })
                            }
                            OutlinedButton(onClick = onFeedback, shape = RoundedCornerShape(7.dp)) { Text("Give feedback") }
                            HorizontalDivider(color = colors.outline)
                            Eyebrow("ABOUT")
                            SecondaryText("Tunlion for Android · Preview\nNo account. Your devices, your permissions.")
                            SecondaryText(if (status.engineLinked) "Backend: shared native core (UniFFI). No CLI subprocess." else "Native core has not been opened yet.")
                            SecondaryText("Availability uses a foreground notification. Android can still stop the app or enforce background limits. Transfers do not resume automatically after process death. Reopen Tunlion, inspect Files, then retry any unacknowledged transfer.")
                            SecondaryText("Recovery phrase import is not connected yet. Do not uninstall or clear app storage to troubleshoot an existing identity.")
                        }
                    }
                }
        }
    }
    }
    }
    }
    // Block back only while an operation owns the destination. Otherwise the
    // NavHost's predictive handler, or Android's root back-to-home, handles it.
    BackHandler(enabled = busy) { }
}

@Composable
private fun Availability(status: CoreStatus, busy: Boolean, onChange: (Boolean) -> Unit) {
    val colors = MaterialTheme.colorScheme
    val phase by EngineState.phase.collectAsState()
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(42.dp).background(colors.surfaceVariant, RoundedCornerShape(9.dp)), contentAlignment = Alignment.Center) {
            Icon(Icons.Outlined.Smartphone, null, Modifier.size(22.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(status.deviceName ?: android.os.Build.MODEL, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            val label = when (phase) {
                EnginePhase.STARTING -> "Starting…"
                EnginePhase.STOPPING -> "Stopping…"
                EnginePhase.FAILED -> "Needs attention"
                else -> if (status.engineRunning) "Available" else "Off"
            }
            AnimatedContent(label, label = "availability") { text ->
                Text(text, color = if (status.engineRunning) colors.primary else colors.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
        Switch(status.engineRunning, onChange, enabled = !busy,
            colors = tunlionSwitchColors(),
            modifier = Modifier.semantics { contentDescription = "Make this phone available" })
    }
    SecondaryText("Availability accepts inbox transfers only. This phone does not serve a terminal or expose folders. Turn it off before using a file code; the native core currently runs one engine at a time.")
}

@Composable
private fun FirstConnection(onJoin: () -> Unit, onSetup: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Column(Modifier.fillMaxWidth().padding(top = 20.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Title("Your files,\ndirect to this phone.", "Create an identity, then send or receive files with a transfer code. Native device enrollment is still being connected.")
        PrimaryButton("Device enrollment options", onClick = onJoin)
        OutlinedButton(onClick = onSetup, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(7.dp), border = BorderStroke(1.dp, colors.outline)) { Text("Set up my first device", color = colors.onBackground) }
        SecondaryText("No account. Nothing uploaded to a cloud drive.")
    }
}

@Composable
private fun PairScreen(core: TunlionCore, busy: Boolean, supported: Boolean, unsupportedReason: String?, codeSupported: Boolean, deviceName: String?,
    onJoin: (String, Boolean) -> Unit, onJoinInvitation: (ByteArray, String) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var code by rememberSaveable { mutableStateOf("") }
    // Read once per pick. This same instance goes to preview and to join.
    var invitation by remember { mutableStateOf<ByteArray?>(null) }
    var readError by remember { mutableStateOf<String?>(null) }
    val invitationPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            invitation = null
            readError = null
            scope.launch {
                try {
                    invitation = withContext(Dispatchers.IO) { readInvitationFile(context, uri) }
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { readError = "Could not read that file. Nothing was previewed or joined." }
            }
        }
    }
    var carrier by rememberSaveable { mutableStateOf("Spoken code") }
    var relationship by rememberSaveable { mutableStateOf("My device") }
    fun selectCarrier(next: String) {
        carrier = next
        if (next != "Invitation file" && relationship == "Temporary worker") relationship = "My device"
    }
    Title("How are you\nconnecting?", "Carrier first. A spoken code, invitation file or nearby discovery carries the request; only a signed invitation or core acknowledgment can establish a relationship.")
    Eyebrow("CARRIER")
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(carrier == "Spoken code", { selectCarrier("Spoken code") },
            label = { Text("Spoken code") }, enabled = !busy)
        FilterChip(carrier == "Invitation file", { selectCarrier("Invitation file") },
            label = { Text("Invitation file") }, enabled = !busy)
    }
    SecondaryText(when (carrier) {
        "Spoken code" -> "A spoken code is a carrier fact only. It cannot select or prove a relationship."
        else -> if (supported) "The shared core reads and verifies the invitation file. You see its signed facts before anything is joined."
            else "Invitation preview is not linked in this build. No file is read and nothing is joined."
    })
    if (carrier == "Spoken code") {
        OutlinedTextField(code, { code = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
            label = { Text("Device code") }, placeholder = { Text("brave-otter-3141") },
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
            shape = RoundedCornerShape(7.dp), enabled = codeSupported && !busy,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false))
        SecondaryText("A spoken code never selects or proves a relationship. Temporary worker requires a signed invitation file.")
        if (!codeSupported) SecondaryText("Spoken-code enrollment is not linked in this build. Use an invitation file, or Files for a one-time transfer code.")
    } else {
        InvitationReview(core, invitation, deviceName, busy, enabled = supported,
            onChooseFile = { invitationPicker.launch(arrayOf("*/*")) }, onJoin = onJoinInvitation)
        readError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
    Eyebrow("INTENDED RELATIONSHIP")
    SecondaryText("This choice is an intent only, not a signed fact. It records no relationship and grants no permission.")
    listOf("My device", "Someone else's", "Temporary worker").forEach { choice ->
        val optionEnabled = !busy && (choice != "Temporary worker" || carrier == "Invitation file")
        Row(Modifier.fillMaxWidth().clickable(enabled = optionEnabled) { relationship = choice }.padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically) {
            RadioButton(relationship == choice, onClick = { relationship = choice }, enabled = optionEnabled)
            Text(choice, color = if (optionEnabled) MaterialTheme.colorScheme.onBackground else MaterialTheme.colorScheme.onSurfaceVariant)
            if (choice == "Temporary worker" && carrier != "Invitation file") {
                Spacer(Modifier.width(8.dp))
                SecondaryText("invitation file only")
            }
        }
    }
    SecondaryText(when (relationship) {
        "My device" -> "Fleet discovery and inbox transfers by default. No terminal or folder authority."
        "Someone else's" -> "External pair with explicitly confirmed permissions, not fleet membership."
        else -> "Temporary access must have a bounded expiry confirmed by the core. Invitation file only."
    })
    if (!supported) {
        SecondaryText("Enrollment review is unavailable until the shared core exposes enrollment facts. These choices do not record a relationship or grant permission. Use Files for a one-time transfer code.")
        // The core's own reason. Not a client guess about why invitations are off.
        unsupportedReason?.let { SecondaryText("The core reports: $it") }
    }
    SecondaryText("The actual relationship is shown only after the core verifies signed enrollment facts. Nearby enrollment is not supported in this build.")
    if (carrier == "Spoken code") PrimaryButton("Review enrollment", busy, enabled = codeSupported && code.isNotBlank(),
        onClick = { onJoin(code.trim(), true) })
}

/** Memory guard for the picker only. The core alone decides whether the bytes are an invitation. */
private const val INVITATION_READ_LIMIT = 1 shl 20

private fun readInvitationFile(context: android.content.Context, uri: android.net.Uri): ByteArray {
    val input = checkNotNull(context.contentResolver.openInputStream(uri)) { "The selected file is not readable" }
    return input.use { stream ->
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            out.write(buffer, 0, count)
            check(out.size() <= INVITATION_READ_LIMIT) { "The selected file is too large to read" }
        }
        out.toByteArray()
    }
}

/**
 * Preview, then confirm. Renders only the fields the core returned. Join is
 * offered only after a successful core preview whose `expired` flag is false,
 * and it hands back the very array that was previewed.
 */
@Composable
internal fun InvitationReview(core: TunlionCore, invitation: ByteArray?, defaultName: String?, busy: Boolean,
    enabled: Boolean, onChooseFile: () -> Unit, onJoin: (ByteArray, String) -> Unit) {
    var result by remember(invitation) { mutableStateOf<InvitationPreviewResult?>(null) }
    var name by rememberSaveable { mutableStateOf(defaultName.orEmpty()) }
    LaunchedEffect(invitation) {
        result = null
        val bytes = invitation ?: return@LaunchedEffect
        result = try { core.previewInvitation(bytes) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { InvitationPreviewResult.Failed(CoreResult.Failure(CoreErrorKind.INTERNAL,
            "The invitation could not be previewed. Nothing was joined.")) }
    }
    OutlinedButton(onClick = onChooseFile, enabled = enabled && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RoundedCornerShape(7.dp)) { Text(if (invitation == null) "Choose invitation file" else "Choose another invitation file") }
    // The carrier text above already explains an unlinked build.
    if (!enabled) return
    val preview = (result as? InvitationPreviewResult.Previewed)?.preview
    when (val current = result) {
        null -> SecondaryText(if (invitation == null) "Nothing is joined until the core shows the invitation and you confirm."
            else "The core is reading the invitation…")
        is InvitationPreviewResult.Failed -> {
            Eyebrow("CORE COULD NOT PREVIEW")
            Text(current.failure.message, color = MaterialTheme.colorScheme.error)
        }
        is InvitationPreviewResult.Previewed -> {
            val facts = current.preview
            Eyebrow("INVITATION PREVIEW")
            DetailRow("Owner", facts.ownerName)
            DetailRow("Relationship", invitationRelationshipLabel(facts.relationship))
            DetailRow("Requested capabilities",
                if (facts.requestedCapabilities.isEmpty()) "None listed" else facts.requestedCapabilities.joinToString("\n"))
            DetailRow("Expires", java.time.Instant.ofEpochSecond(facts.expires).toString())
            DetailRow("Max offline", "${facts.maxOffline} seconds")
            DetailRow("Uses", if (facts.reusable) "Reusable" else facts.maxUses?.toString() ?: "Not stated")
            DetailRow("Ephemeral", if (facts.ephemeral) "Yes" else "No")
            DetailRow("Expired", if (facts.expired) "Yes" else "No")
            if (facts.relationship == InvitationRelationship.TEMPORARY_WORKER)
                SecondaryText("The core reports temporary-worker access. It is bounded by the signed expiry above.")
            if (facts.expired) Text("The core reports this invitation has expired. It cannot be joined.",
                color = MaterialTheme.colorScheme.error)
            SecondaryText("These are the requested capabilities as signed, not a confirmation that any action will work. The intended relationship on this screen records nothing.")
        }
    }
    OutlinedTextField(name, { name = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        label = { Text("This device's name") }, shape = RoundedCornerShape(7.dp), enabled = !busy,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false))
    val joinable = preview != null && !preview.expired
    PrimaryButton("Join with this invitation", busy, enabled = joinable, onClick = {
        val bytes = invitation
        if (bytes != null && preview != null && !preview.expired) onJoin(bytes, name)
    })
}

private fun invitationRelationshipLabel(relationship: InvitationRelationship) = when (relationship) {
    InvitationRelationship.ORDINARY_PAIR -> "Ordinary pair"
    InvitationRelationship.OWN_DEVICE -> "Own device"
    InvitationRelationship.OTHER_PERSON -> "Other person"
    InvitationRelationship.TEMPORARY_WORKER -> "Temporary worker"
    InvitationRelationship.UNKNOWN -> "Not stated in the invitation"
}

private fun Modifier.toggleableForRemember(checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) =
    this.then(Modifier.clickable(enabled = enabled, role = Role.Checkbox) { onChange(!checked) }
        .semantics { stateDescription = if (checked) "Remember on" else "Remember off" }.padding(vertical = 8.dp))

@Composable
private fun RecoveryScreen(phrase: String, busy: Boolean, onConfirm: () -> Unit) {
    var saved by remember { mutableStateOf(false) }
    Title("Keep these words\nsomewhere safe.", "They recover your identity. They are shown only during setup and are never included in feedback captures.")
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(9.dp))
        .padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        phrase.split(" ").chunked(2).forEachIndexed { row, pair ->
            Row(Modifier.fillMaxWidth()) {
                pair.forEachIndexed { column, word ->
                    Text("${row * 2 + column + 1}. $word", fontFamily = FontFamily.Monospace,
                        modifier = Modifier.weight(1f), fontSize = 15.sp)
                }
            }
        }
    }
    Row(Modifier.fillMaxWidth().toggleableForRemember(saved, !busy) { saved = it }, verticalAlignment = Alignment.CenterVertically) {
        Checkbox(saved, null)
        Text("I have saved my recovery words", modifier = Modifier.padding(start = 8.dp))
    }
    PrimaryButton("Finish setup", busy, saved, onConfirm)
    SecondaryText("Your identity is saved on this phone only after you confirm. Going back discards these words.")
}

@Composable
private fun FilesScreen(status: CoreStatus, busy: Boolean, onReceive: (String) -> Unit, onMakeCode: () -> Unit,
    onConnect: () -> Unit, onPickDevice: (CoreDevice) -> Unit) {
    var receiveExpanded by rememberSaveable { mutableStateOf(false) }
    var code by rememberSaveable { mutableStateOf("") }
    Title("Files, straight\nto your device.", "Choose a stored device to attempt a send, or use a file code. The real receiver checks permission and reachability.")
    Eyebrow("SEND TO")
    val recipients = status.devices.filter { it.canSendFiles || it.canAttemptSend }
    if (recipients.isEmpty()) {
        SecondaryText("Connect another device to send your first file.")
        OutlinedButton(onClick = onConnect, shape = RoundedCornerShape(7.dp)) { Text("Connect a device") }
    } else recipients.forEach { device -> DeviceRow(device) { onPickDevice(device) } }
    OutlinedButton(onClick = onMakeCode, enabled = !busy, shape = RoundedCornerShape(7.dp)) { Text("Send with a code") }
    HorizontalDivider(color = MaterialTheme.colorScheme.outline)
    ActionRow(Icons.Outlined.Download, "Receive with a code", "Someone shared a file with you") { receiveExpanded = !receiveExpanded }
    AnimatedVisibility(receiveExpanded, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            OutlinedTextField(code, { code = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("File code") }, shape = RoundedCornerShape(7.dp), enabled = !busy)
            PrimaryButton("Receive file", busy, code.isNotBlank()) { onReceive(code.trim()) }
        }
    }
    SecondaryText(if (android.os.Build.VERSION.SDK_INT >= 29) "Received files are saved to Download/Tunlion after verification." else "Choose a receiving folder in Settings. Files remain in the private inbox until a folder is chosen.")
    status.lastSend?.let { report ->
        Eyebrow("LAST SEND RESULT")
        SecondaryText(report.target?.let { "To $it" } ?: "Code transfer")
        report.files.forEach { file ->
            Column {
                Text(file.name, fontWeight = FontWeight.Medium)
                SecondaryText(
                    if (!file.delivered) "Receiver did not acknowledge delivery"
                    else (file.storedName?.let { "Receiver acknowledged delivery · stored as $it" }
                        ?: "Receiver acknowledged delivery"))
            }
        }
        SecondaryText("Only receiver acknowledgments from the completed send appear here. A recorded device grant is not a delivery.")
    }
    if (status.transfers.isNotEmpty()) {
        Eyebrow("RECENT FILES")
        status.transfers.forEach { transfer ->
            Column {
                Text(transfer.name, fontWeight = FontWeight.Medium)
                SecondaryText(if (!transfer.verified) "Not completed" else if (!transfer.incoming) "Sent · verified" else if (transfer.saved) "Received · saved" else "Received · verified · private inbox")
            }
        }
    }
}

@Composable
private fun ReceiveFolderSetting() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                check(androidx.documentfile.provider.DocumentFile.fromTreeUri(context, uri)?.canWrite() == true)
                context.getSharedPreferences("received_files", android.content.Context.MODE_PRIVATE).edit().putString("folder", uri.toString()).apply()
                scope.launch {
                    try { withContext(Dispatchers.IO) { NativeTunlionCore.get(context).publishInbox() }; message = "Receiving folder saved." }
                    catch (_: Exception) { message = "The folder is saved, but an inbox file could not be published yet." }
                }
            } catch (_: Exception) { message = "Choose a folder this app can write to." }
        }
    }
    OutlinedButton(onClick = { picker.launch(null) }) { Text("Choose receiving folder") }
    message?.let { SecondaryText(it) }
}

@Composable
private fun DeviceRow(device: CoreDevice, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth().clipForRow().clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.size(8.dp).background(if (device.online == true) Color(0xFF137738) else colors.onSurfaceVariant,
            androidx.compose.foundation.shape.CircleShape))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(device.name, fontWeight = FontWeight.Medium,
                color = if (device.online == true) colors.onBackground else colors.onSurfaceVariant)
            SecondaryText(when (device.online) { true -> "Online"; false -> "Offline"; null -> "Availability unknown" })
            SecondaryText(relationshipLabel(device.relationship) + if (device.revoked) " · revoked locally" else "")
            if (device.actions.isNotEmpty()) SecondaryText(actionSummary(device.actions))
        }
        if (device.online == true && device.route != null) {
            Text(if (device.route == "relayed") "RELAYED" else if (device.route == "direct") "DIRECT" else "",
                fontSize = 10.sp, fontFamily = FontFamily.Monospace,
                color = if (device.route == "relayed") {
                    if (isSystemInDarkTheme()) Color(0xFFFFC857) else Color(0xFF9A6B00)
                } else colors.onSurfaceVariant)
        }
        Icon(Icons.Outlined.ChevronRight, null, tint = colors.onSurfaceVariant)
    }
}

@Composable
private fun DeviceDetails(
    core: TunlionCore,
    device: CoreDevice,
    busy: Boolean,
    onSend: () -> Unit,
    onRequestForget: () -> Unit,
    onRequestCutOff: () -> Unit,
    onRevoke: (CoreActionKind) -> Unit,
) {
    var policyResult by remember(device.name) { mutableStateOf<CoreDevicePolicyResult?>(null) }
    var pendingRevoke by remember(device.name) { mutableStateOf<CoreActionKind?>(null) }
    // Reload after every core call this screen can start (busy falls back to
    // false), so the rows always show the stores as they are now.
    LaunchedEffect(device.name, busy) {
        if (busy) return@LaunchedEffect
        policyResult = try { core.devicePolicy(device.name) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { CoreDevicePolicyResult.Failed(CoreResult.Failure(CoreErrorKind.INTERNAL,
            "The native core could not read this device's local policy. Nothing was changed.")) }
    }
    SecondaryText(when (device.online) { true -> "Online"; false -> "Offline"; null -> "Availability unknown" })
    DetailRow("Relationship", relationshipLabel(device.relationship))
    device.expiry?.let { DetailRow("Expiry recorded by core", it) }
    if (device.revoked) SecondaryText("Revoked on this receiver. This does not acknowledge remote removal or termination of every active session.")
    Eyebrow("ACCESS FACTS")
    SecondaryText(device.plainLine)
    SecondaryText("A stored relationship or recorded grant is not proof that an action currently works. This snapshot does not probe the remote device.")
    when (val result = policyResult) {
        null -> SecondaryText("Reading this device's local policy from the shared core…")
        is CoreDevicePolicyResult.Failed -> {
            Eyebrow("CORE COULD NOT READ THE POLICY")
            Text(result.failure.message, color = MaterialTheme.colorScheme.error)
        }
        is CoreDevicePolicyResult.Loaded -> {
            val policy = result.policy
            DetailRow("Admitted", enrollmentSummary(policy.enrollment))
            if (policy.enrollment.ceiling.isNotEmpty())
                SecondaryText("The admission ceiling bounds every action below. It is not a claim that the device is reachable now.")
            DetailRow("Local policy delivery", deliverySummary(policy.delivery))
            policy.deviceKey?.let { DetailRow("Device key", it) }
            policy.expires?.let { DetailRow("Core policy expiry", instantText(it)) }
            val actions = policy.actions
            actionGroup("EFFECTIVE", actions.filter { isEffective(it.state) }, emptyNote = EFFECTIVE_GROUP_NOTE)
            actionGroup("PENDING", actions.filter { it.state == CoreAccessState.PENDING }, groupNote = PENDING_GROUP_NOTE)
            actionGroup("BLOCKED", actions.filter { it.state == CoreAccessState.BLOCKED })
            actionGroup("UNKNOWN", actions.filter { it.state == CoreAccessState.UNKNOWN })
            actionGroup("UNAVAILABLE", actions.filter { it.state == CoreAccessState.UNSUPPORTED })
            SecondaryText("Only actions reported by the shared core appear here, with the stored fact each one comes from. Pending is a local record, not confirmed access.")
            Eyebrow("REVOKE A CAPABILITY")
            SecondaryText("Revoking one capability records a single deny on this phone. If the access comes from the invitation ceiling, the core refuses and this screen says so instead of reporting success.")
            val revocable = actions.filter { it.source != CorePolicySource.PROFILE }
            if (revocable.isEmpty()) SecondaryText("This build's profile serves none of these actions, so there is no capability to revoke here.")
            revocable.forEach { action ->
                Row(Modifier.fillMaxWidth().testTag("revoke-${action.kind}").padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        // The compact name: the access rows above carry the full action sentence.
                        Text(actionShortLabel(action.kind), fontWeight = FontWeight.Medium)
                        SecondaryText(accessStateChip(action.state) + " · " + policySourceLabel(action.source).lowercase())
                    }
                    OutlinedButton(onClick = { pendingRevoke = action.kind }, enabled = !busy,
                        shape = RoundedCornerShape(7.dp)) { Text("Revoke") }
                }
            }
        }
    }
    if (device.route == "relayed") SecondaryText("On relay, not a direct link. Still end-to-end encrypted.")
    if (device.canSendFiles) PrimaryButton("Send a file", onClick = onSend)
    else if (device.canAttemptSend) {
        SecondaryText("Remote permission and reachability have not been checked. You can attempt a transfer; the receiver may refuse it. This is not an effective permission grant.")
        OutlinedButton(onClick = onSend, shape = RoundedCornerShape(7.dp)) { Text("Try sending a file") }
    } else SecondaryText("Sending is not available for this device in the current core snapshot. The reason above is the core's own fact, not a client guess.")
    if (device.canOpenShell) SecondaryText("The core reports terminal service as effective. A terminal client is not connected in this build.")
    Eyebrow("REMOVAL")
    SecondaryText("Cutting a device off keeps its record on this phone and marks it revoked; the device is refused when it next checks in. Forget removes the record and writes a key block that refuses the old device key. Neither contacts the device, so nothing here claims a remote change or an ended session.")
    OutlinedButton(onClick = onRequestCutOff, enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RoundedCornerShape(7.dp)) { Text("Cut this device off") }
    OutlinedButton(onClick = onRequestForget, enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RoundedCornerShape(7.dp)) { Text("Forget this device") }
    SecondaryText("Pending deliveries, offline peers and active sessions cannot be resolved from this snapshot. A removal is not acknowledged by the device, and an existing session is not shown as ended.")
    pendingRevoke?.let { kind ->
        AlertDialog(onDismissRequest = { pendingRevoke = null },
            title = { Text("Revoke ${actionShortLabel(kind)}?") },
            text = { Text("This phone records an explicit deny for that capability on ${device.name}. If the access comes from the invitation ceiling, the core refuses and this screen says so instead of reporting success. The device is not contacted.") },
            confirmButton = { TextButton(onClick = { pendingRevoke = null; onRevoke(kind) }) { Text("Revoke") } },
            dismissButton = { TextButton(onClick = { pendingRevoke = null }) { Text("Cancel") } })
    }
}

/** The receipt the core returned, in the core's own terms. Never a success line for a refusal. */
@Composable
private fun RemovalOutcome(notice: CoreRemovalNotice, busy: Boolean, onRestore: (String) -> Unit, onDismiss: () -> Unit) {
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(9.dp))
        .padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Eyebrow("RESULT")
        Text(notice.title, fontWeight = FontWeight.SemiBold)
        notice.lines.forEach { SecondaryText(it) }
        notice.forgottenName?.let { name ->
            OutlinedButton(onClick = { onRestore(name) }, enabled = !busy, shape = RoundedCornerShape(7.dp)) {
                Text("Lift the key block for $name")
            }
            SecondaryText("A restore lifts this phone's refusal. It does not recreate the record that was removed.")
        }
        TextButton(onClick = onDismiss, enabled = !busy) { Text("Dismiss") }
    }
}

/** One capability edit's outcome. A ceiling refusal offers cut off instead of success. */
@Composable
private fun CapabilityOutcomeCard(notice: CoreCapabilityNotice, busy: Boolean, onCutOff: () -> Unit, onDismiss: () -> Unit) {
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(9.dp))
        .padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Eyebrow(if (notice.applied) "CAPABILITY RESULT" else "CAPABILITY REFUSED")
        Text(notice.title, fontWeight = FontWeight.SemiBold,
            color = if (notice.applied) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
        notice.lines.forEach { SecondaryText(it) }
        if (notice.offerCutOff) {
            OutlinedButton(onClick = onCutOff, enabled = !busy, shape = RoundedCornerShape(7.dp)) {
                Text("Cut this device off")
            }
        }
        TextButton(onClick = onDismiss, enabled = !busy) { Text("Dismiss") }
    }
}

@Composable
private fun RemovalConfirmDialog(mode: CoreRemovalMode, name: String, busy: Boolean,
    onDismiss: () -> Unit, onConfirm: () -> Unit) {
    val forget = mode == CoreRemovalMode.FORGET
    AlertDialog(onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(if (forget) "Forget $name?" else "Cut off $name?") },
        text = { Text(if (forget)
            "This phone removes the stored device record and writes a key block that refuses the old device key. The device is not contacted and nothing is removed on it. This cannot be undone from this phone."
            else "This phone keeps the record and marks the device revoked. The device is refused when it next checks in. An active session is not ended by this call.") },
        confirmButton = { TextButton(onClick = onConfirm, enabled = !busy) { Text(if (forget) "Forget" else "Cut off") } },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancel") } })
}

@Composable
private fun actionGroup(title: String, actions: List<CoreActionPolicy>, emptyNote: String? = null, groupNote: String? = null) {
    if (actions.isEmpty()) { emptyNote?.let { SecondaryText(it) }; return }
    Eyebrow(title)
    actions.forEach { ActionPolicyRow(it) }
    // A group explanation belongs under the rows it explains. The empty-state
    // line above is a different thing and only appears when nothing is listed.
    groupNote?.let { SecondaryText(it) }
}

@Composable
private fun ActionPolicyRow(action: CoreActionPolicy) {
    Column(Modifier.fillMaxWidth().testTag("policy-${action.kind}").padding(vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(actionLabel(action.kind), fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
            StateChip(action.state)
        }
        SecondaryText(policySourceLabel(action.source))
        // The core's reason is the authority. Shown verbatim, never re-worded.
        Text(action.reason, fontSize = 14.sp, lineHeight = 21.sp)
    }
}

@Composable
private fun StateChip(state: CoreAccessState) {
    val colors = MaterialTheme.colorScheme
    val (background, foreground) = when (state) {
        CoreAccessState.AVAILABLE -> colors.primary to colors.onPrimary
        CoreAccessState.PENDING -> colors.surfaceVariant to colors.onSurface
        CoreAccessState.BLOCKED -> colors.error.copy(alpha = .14f) to colors.error
        else -> colors.surfaceVariant to colors.onSurfaceVariant
    }
    Text(accessStateChip(state), color = foreground, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
        fontFamily = FontFamily.Monospace, modifier = Modifier
            .background(background, RoundedCornerShape(5.dp))
            .padding(horizontal = 7.dp, vertical = 2.dp)
            .semantics { contentDescription = "Access ${accessStateChip(state)}" })
}

@Composable
private fun SendScreen(device: CoreDevice?, busy: Boolean, onSend: (List<android.net.Uri>, (String) -> Unit) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var names by remember { mutableStateOf<List<String>>(emptyList()) }
    var selected by remember { mutableStateOf<List<android.net.Uri>>(emptyList()) }
    var sendCode by remember { mutableStateOf<String?>(null) }
    var reading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(busy) { if (!busy) sendCode = null }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) scope.launch {
            selected = uris
            reading = true
            error = null
            try {
                names = withContext(Dispatchers.IO) {
                    uris.map { uri ->
                        context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                            if (cursor.moveToFirst()) cursor.getString(0) else "Selected file"
                        } ?: "Selected file"
                    }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { error = "Could not read the selected files. Choose them again." }
            finally { reading = false }
        }
    }
    val sendable = device == null || device.canSendFiles || device.canAttemptSend
    Title(if (device == null) "Send with a code" else if (device.canSendFiles) "Send to ${device.name}"
        else if (device.canAttemptSend) "Try sending to ${device.name}" else "Sending unavailable",
        "Choose files with Android's file picker. They stay on this phone until you send them.")
    if (device != null && !device.canSendFiles && device.canAttemptSend) SecondaryText("Remote permission is unknown, not granted. The receiver will decide whether to accept this attempt.")
    if (!sendable) SecondaryText("The current core snapshot does not allow a send attempt to this device. Nothing will be sent.")
    sendCode?.let { code ->
        Eyebrow("YOUR FILE CODE")
        Text(code, fontFamily = FontFamily.Monospace, fontSize = 22.sp)
        SecondaryText("Enter this code on the receiving device. Waiting for it to connect…")
    }
    if (names.isNotEmpty()) {
        Eyebrow("SELECTED FILES · ${names.size}")
        names.forEach { name ->
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.InsertDriveFile, null)
                Text(name, modifier = Modifier.weight(1f))
            }
        }
    }
    OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !busy && !reading, shape = RoundedCornerShape(7.dp)) { Text(if (names.isEmpty()) "Choose files" else "Choose different files") }
    val sendLabel = when {
        !sendable -> "Sending unavailable"
        device == null -> "Make a file code"
        device?.canSendFiles == true -> "Send files"
        else -> "Try sending files"
    }
    PrimaryButton(sendLabel, busy, selected.isNotEmpty() && !reading && sendable) {
        onSend(selected) { sendCode = it }
    }
    error?.let { SecondaryText(it) }
}

@Composable private fun Step(number: String, title: String, detail: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(number, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.primary)
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            SecondaryText(detail)
        }
    }
}

@Composable private fun Title(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(title, fontSize = 28.sp, lineHeight = 34.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-.7).sp)
        SecondaryText(subtitle)
    }
}

@Composable private fun SecondaryText(text: String) {
    Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 14.sp, lineHeight = 21.sp)
}

@Composable private fun Eyebrow(text: String, modifier: Modifier = Modifier) {
    Text(text, modifier, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp,
        letterSpacing = 1.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
}

@Composable private fun DetailRow(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        SecondaryText(label)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable private fun ActionRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clipForRow().clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Icon(icon, null, Modifier.size(23.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(title, fontWeight = FontWeight.Medium)
            SecondaryText(subtitle)
        }
        Icon(Icons.Outlined.ChevronRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun Modifier.clipForRow() = this.then(Modifier.background(Color.Transparent, RoundedCornerShape(7.dp)))

@Composable private fun PrimaryButton(text: String, busy: Boolean = false, enabled: Boolean = true, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val showProgress = delayedBusy(busy)
    Button(onClick, enabled = enabled && !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
        shape = RoundedCornerShape(7.dp), colors = ButtonDefaults.buttonColors(containerColor = colors.onBackground, contentColor = colors.background)) {
        if (showProgress) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = colors.onSurfaceVariant)
            Spacer(Modifier.width(9.dp))
        }
        Text(if (showProgress) "Please wait…" else text, fontWeight = FontWeight.SemiBold)
    }
}

@Composable private fun delayedBusy(busy: Boolean): Boolean {
    var show by remember { mutableStateOf(false) }
    LaunchedEffect(busy) {
        show = false
        if (busy) { delay(300); show = true }
    }
    return busy && show
}

@Composable private fun tunlionSwitchColors() = SwitchDefaults.colors(
    checkedTrackColor = MaterialTheme.colorScheme.primary,
    checkedThumbColor = MaterialTheme.colorScheme.background,
    uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
    uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
    uncheckedBorderColor = MaterialTheme.colorScheme.outline,
)

@Composable private fun TunlionMark(modifier: Modifier) {
    val ink = MaterialTheme.colorScheme.onBackground
    val accent = MaterialTheme.colorScheme.primary
    Canvas(modifier) {
        val factor = size.minDimension / 80f
        val arch = Path().apply {
            moveTo(12f, 74f); lineTo(12f, 24f); quadraticTo(12f, 10f, 26f, 10f)
            lineTo(54f, 10f); quadraticTo(68f, 10f, 68f, 24f); lineTo(68f, 74f)
        }
        withTransform({ scale(factor, factor, pivot = androidx.compose.ui.geometry.Offset.Zero) }) {
            drawPath(arch, ink, style = Stroke(width = 10f))
            drawRect(accent, androidx.compose.ui.geometry.Offset(33f, 46f), androidx.compose.ui.geometry.Size(14f, 28f))
        }
    }
}
