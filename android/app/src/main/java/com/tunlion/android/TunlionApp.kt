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
                            if (!status.identityLoaded) {
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
                            } else {
                            Availability(status, busy, onChange = { turnOn ->
                                if (status.fingerprint == null && status.devices.isEmpty() && turnOn) navigate(Screen.SETUP)
                                else { if (turnOn) requestNotifications(); perform({ if (turnOn) core.start() else core.stop() }) }
                            })
                            status.engineError?.let { SecondaryText(it) }
                            if (enginePhase == EnginePhase.FAILED) {
                                OutlinedButton(onClick = { perform({ core.stop() }) }, enabled = !busy) { Text("Confirm receiver is off") }
                            }
                            if (status.fingerprint == null && status.devices.isEmpty()) {
                                FirstConnection(onJoin = { navigate(Screen.PAIR) }, onSetup = { navigate(Screen.SETUP) })
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Eyebrow("DEVICES", Modifier.weight(1f))
                                    TextButton(onClick = { navigate(Screen.PAIR) }) { Text("Add device") }
                                }
                                if (status.devices.isEmpty()) {
                                    Text("No other devices yet.", style = MaterialTheme.typography.titleMedium)
                                    SecondaryText("No stored device relationships. Fleet discovery and enrollment are not connected yet. File codes work without adding a device.")
                                }
                                status.devices.forEach { device ->
                                    key(device.id) { DeviceRow(device) { selectedDevice = device; navigate(Screen.DEVICE) } }
                                }
                            }
                            HorizontalDivider(color = colors.outline)
                            ActionRow(Icons.Outlined.FolderOpen, "Files", "Send a file or receive with a code") { navigate(Screen.FILES) }
                            }
                        }
                        Screen.PAIR -> PairScreen(busy, status.enrollmentSupported, onJoin = { code, remember ->
                            requestNotifications()
                            perform({ core.joinCode(code, remember) }) { navigate(Screen.HOME) }
                        }, onInvitation = { bytes ->
                            requestNotifications()
                            perform({ core.joinInvitation(bytes) }) { navigate(Screen.HOME) }
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
                        Screen.DEVICE -> selectedDevice?.let { selected ->
                            val device = status.devices.firstOrNull { it.id == selected.id }
                            if (device == null) SecondaryText("This device is no longer in the current core snapshot. Return to Devices and refresh.")
                            else
                            DeviceDetails(device, onSend = { navigate(Screen.SEND) })
                        }
                        Screen.SEND -> SendScreen(selectedDevice, busy) { files, onCode ->
                            requestNotifications()
                            perform({ core.sendFiles(selectedDevice?.id, files, onCode) }) { navigate(Screen.FILES) }
                        }
                        Screen.SETTINGS -> {
                            Eyebrow("THIS PHONE")
                            DetailRow("Name", status.deviceName ?: android.os.Build.MODEL)
                            DetailRow("Identity", status.fingerprint ?: "Not set up")
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
private fun PairScreen(busy: Boolean, supported: Boolean, onJoin: (String, Boolean) -> Unit, onInvitation: (ByteArray) -> Unit) {
    var code by rememberSaveable { mutableStateOf("") }
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    val invitation = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        val bytes = ByteArray(65537)
                        var size = 0
                        while (size < bytes.size) { val n = input.read(bytes, size, bytes.size - size); if (n < 0) break; size += n }
                        bytes.copyOf(size)
                    } ?: error("Unreadable invitation")
                }
                if (bytes.size > 65536) error = "That invitation file is too large." else onInvitation(bytes)
            } catch (_: Exception) { error = "Could not read that invitation file." }
        }
    }
    var relationship by rememberSaveable { mutableStateOf("My device") }
    Title("What are you\nconnecting?", "Choose the relationship first. A code, invitation file or nearby discovery must not change it.")
    listOf("My device", "Someone else's", "Temporary worker").forEach { choice ->
        Row(Modifier.fillMaxWidth().clickable(enabled = !busy) { relationship = choice }.padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically) {
            RadioButton(relationship == choice, onClick = { relationship = choice }, enabled = !busy)
            Text(choice)
        }
    }
    SecondaryText(when (relationship) {
        "My device" -> "Fleet discovery and inbox transfers by default. No terminal or folder authority."
        "Someone else's" -> "External pair with explicitly confirmed permissions, not fleet membership."
        else -> "Temporary access must have a bounded expiry confirmed by the core."
    })
    if (!supported) SecondaryText("Enrollment is not connected to the native core yet. These choices do not enroll a device or grant permissions. Use Files for a one-time transfer code.")
    OutlinedTextField(code, { code = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        label = { Text("Device code") }, placeholder = { Text("brave-otter-3141") },
        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        shape = RoundedCornerShape(7.dp), enabled = supported && !busy,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false))
    SecondaryText("Confirmation must show effective permissions separately from pending or blocked permissions. Default inbox access is not terminal or folder authority.")
    PrimaryButton("Review enrollment", busy, enabled = supported && code.isNotBlank(), onClick = { onJoin(code.trim(), true) })
    OutlinedButton(onClick = { invitation.launch(arrayOf("*/*")) }, enabled = supported && !busy, shape = RoundedCornerShape(7.dp)) { Text("Open an invitation file") }
    SecondaryText("Nearby enrollment is not supported in this build.")
    error?.let { SecondaryText(it) }
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
            if (device.actions.isNotEmpty()) SecondaryText(relationshipLabel(device.relationship) + if (device.revoked) " · revoked locally" else "")
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
private fun DeviceDetails(device: CoreDevice, onSend: () -> Unit) {
    SecondaryText(when (device.online) { true -> "Online"; false -> "Offline"; null -> "Availability unknown" })
    DetailRow("Relationship", relationshipLabel(device.relationship))
    device.expiry?.let { DetailRow("Expiry recorded by core", it) }
    if (device.revoked) SecondaryText("Revoked on this receiver. This does not acknowledge remote removal or termination of every active session.")
    Eyebrow("ACCESS")
    SecondaryText(device.plainLine)
    if (device.actions.isNotEmpty()) {
        val effective = device.actions.filter { it.state == CoreAccessState.AVAILABLE }
        Eyebrow("EFFECTIVE SUPPORTED ACTIONS")
        if (effective.isEmpty()) SecondaryText("No action is confirmed effective by this snapshot.")
        effective.forEach { DetailRow(actionLabel(it.action), it.reason) }
        val pending = device.actions.filter { it.state == CoreAccessState.PENDING }
        if (pending.isNotEmpty()) {
            Eyebrow("PENDING")
            pending.forEach { DetailRow(actionLabel(it.action), it.reason) }
        }
        val unavailable = device.actions.filter { it.state != CoreAccessState.AVAILABLE && it.state != CoreAccessState.PENDING }
        if (unavailable.isNotEmpty()) {
            Eyebrow("BLOCKED, UNKNOWN OR UNSUPPORTED")
            unavailable.forEach {
                DetailRow(actionLabel(it.action) + " · " + when (it.state) {
                    CoreAccessState.BLOCKED -> "Blocked"
                    CoreAccessState.UNSUPPORTED -> "Unsupported"
                    else -> "Unknown"
                }, it.reason)
            }
        }
    }
    SecondaryText("Only actions confirmed effective by the core appear here. Missing terminal, folder, permission editing and removal actions are not supported in this build.")
    SecondaryText("Revoking a capability and cutting a device are different operations. Offline acknowledgment and active-session termination are not available here. Withdrawing an owner grant must not be assumed to close an existing session.")
    if (device.route == "relayed") SecondaryText("On relay, not a direct link. Still end-to-end encrypted.")
    if (device.canSendFiles) PrimaryButton("Send a file", onClick = onSend)
    else if (device.canAttemptSend) {
        SecondaryText("Remote permission and reachability have not been checked. You can attempt a transfer; the receiver may refuse it. This is not an effective permission grant.")
        OutlinedButton(onClick = onSend) { Text("Try sending a file") }
    }
    if (device.canOpenShell) SecondaryText("Shell access granted. The terminal is not connected in this preview.")
}

private fun relationshipLabel(relationship: CoreRelationship) = when (relationship) {
    CoreRelationship.PAIRED -> "Paired device"
    CoreRelationship.FLEET -> "Fleet device"
    CoreRelationship.TEMPORARY -> "Temporary worker"
    CoreRelationship.UNKNOWN -> "Relationship unknown"
}

private fun actionLabel(action: String) = when (action) {
    "send" -> "Send files to this device"
    "receive-inbox" -> "This device sending to this phone's inbox"
    "terminal" -> "This phone serving a terminal"
    "folder" -> "This phone exposing folders"
    else -> action
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
    Title(if (device == null) "Send with a code" else if (device.canSendFiles) "Send to ${device.name}" else "Try sending to ${device.name}",
        "Choose files with Android's file picker. They stay on this phone until you send them.")
    if (device != null && !device.canSendFiles) SecondaryText("Remote permission is unknown, not granted. The receiver will decide whether to accept this attempt.")
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
    PrimaryButton(if (device == null) "Make a file code" else if (device.canSendFiles) "Send files" else "Try sending files", busy, selected.isNotEmpty() && !reading) {
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
