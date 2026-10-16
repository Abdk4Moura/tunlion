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
    var screen by rememberSaveable { mutableStateOf(Screen.HOME) }
    var status by remember { mutableStateOf(core.status()) }
    var busy by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf<String?>(null) }
    var selectedDevice by rememberSaveable { mutableStateOf<CoreDevice?>(null) }
    var recoveryWords by remember { mutableStateOf<String?>(null) }
    var loadFailed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val colors = MaterialTheme.colorScheme

    fun navigate(to: Screen) {
        if (screen == Screen.RECOVERY && to != Screen.RECOVERY) {
            core.discardIdentity()
            recoveryWords = null
        }
        screen = to
        notice = null
    }
    LaunchedEffect(core) {
        try { status = core.refresh() }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (error: Exception) {
            loadFailed = true
            notice = "Could not load this phone's identity. Nothing was changed."
        }
    }
    val activity = androidx.compose.ui.platform.LocalContext.current as? android.app.Activity
    DisposableEffect(screen == Screen.RECOVERY) {
        onSensitiveScreen(screen == Screen.RECOVERY)
        if (screen == Screen.RECOVERY) activity?.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            onSensitiveScreen(false)
            activity?.window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
    fun perform(action: suspend () -> CoreResult, success: () -> Unit = {}) {
        if (busy) return
        busy = true
        notice = null
        scope.launch {
            try {
                when (val result = action()) {
                    CoreResult.Success -> { status = core.refresh(); success() }
                    is CoreResult.Failure -> notice = result.message
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                notice = "That action could not finish. Your existing devices have not been changed."
            } finally { busy = false }
        }
    }

    BackHandler(enabled = screen != Screen.HOME && !busy) { navigate(Screen.HOME) }
    Scaffold(containerColor = colors.background, topBar = {
        Column {
        Row(Modifier.fillMaxWidth().windowInsetsPadding(WindowInsets.statusBars)
            .padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (screen == Screen.HOME) {
                TunlionMark(Modifier.size(25.dp))
                Spacer(Modifier.width(9.dp))
                Text("tunlion", fontSize = 20.sp, fontWeight = FontWeight.SemiBold,
                    letterSpacing = (-.5).sp, modifier = Modifier.weight(1f))
                IconButton(onClick = { navigate(Screen.SETTINGS) }) {
                    Icon(Icons.Outlined.Settings, "Settings")
                }
            } else {
                IconButton(onClick = { if (!busy) navigate(Screen.HOME) }, enabled = !busy) {
                    Icon(Icons.Outlined.ArrowBack, "Back to devices")
                }
                Text(when (screen) {
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
            AnimatedContent(targetState = screen, modifier = Modifier.weight(1f),
                transitionSpec = {
                    val direction = if (targetState == Screen.HOME) -1 else 1
                    (fadeIn(tween(180)) + slideInHorizontally(tween(220)) { direction * it / 14 }) togetherWith
                        (fadeOut(tween(100)) + slideOutHorizontally(tween(180)) { -direction * it / 20 })
                }, label = "screen") { destination ->
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())
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
                                if (status.fingerprint == null && turnOn) navigate(Screen.SETUP)
                                else perform({ if (turnOn) core.start() else core.stop() })
                            })
                            if (status.fingerprint == null && status.devices.isEmpty()) {
                                FirstConnection(onJoin = { navigate(Screen.PAIR) }, onSetup = { navigate(Screen.SETUP) })
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Eyebrow("MY DEVICES", Modifier.weight(1f))
                                    TextButton(onClick = { navigate(Screen.PAIR) }) { Text("Add device") }
                                }
                                if (status.devices.isEmpty()) {
                                    Text("No other devices yet.", style = MaterialTheme.typography.titleMedium)
                                    SecondaryText("Open Tunlion on your other device and enter its code here.")
                                }
                                status.devices.forEach { device ->
                                    key(device.id) { DeviceRow(device) { selectedDevice = device; navigate(Screen.DEVICE) } }
                                }
                            }
                            HorizontalDivider(color = colors.outline)
                            ActionRow(Icons.Outlined.FolderOpen, "Files", "Send a file or receive with a code") { navigate(Screen.FILES) }
                            }
                        }
                        Screen.PAIR -> PairScreen(busy, onJoin = { code, remember ->
                            perform({ core.joinCode(code, remember) }) { navigate(Screen.HOME) }
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
                                        screen = Screen.RECOVERY
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
                        Screen.FILES -> FilesScreen(status, busy, onReceive = { code -> perform({ core.receiveCode(code) }) },
                            onConnect = { navigate(Screen.PAIR) }, onPickDevice = { device ->
                                selectedDevice = device; navigate(Screen.SEND)
                            })
                        Screen.DEVICE -> selectedDevice?.let { device ->
                            DeviceDetails(device, onSend = { navigate(Screen.SEND) })
                        }
                        Screen.SEND -> selectedDevice?.let { device -> SendScreen(device) }
                        Screen.SETTINGS -> {
                            Eyebrow("THIS PHONE")
                            DetailRow("Name", status.deviceName ?: android.os.Build.MODEL)
                            DetailRow("Identity", status.fingerprint ?: "Not set up")
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
                            SecondaryText(if (status.engineLinked) "Core connected" else "Connection engine is still being connected to this preview.")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Availability(status: CoreStatus, busy: Boolean, onChange: (Boolean) -> Unit) {
    val colors = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(42.dp).background(colors.surfaceVariant, RoundedCornerShape(9.dp)), contentAlignment = Alignment.Center) {
            Icon(Icons.Outlined.Smartphone, null, Modifier.size(22.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(status.deviceName ?: android.os.Build.MODEL, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            AnimatedContent(status.engineRunning, label = "availability") { running ->
                Text(if (running) "Available" else "Off", color = if (running) colors.primary else colors.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
        Switch(status.engineRunning, onChange, enabled = !busy,
            colors = tunlionSwitchColors(),
            modifier = Modifier.semantics { contentDescription = "Make this phone available" })
    }
}

@Composable
private fun FirstConnection(onJoin: () -> Unit, onSetup: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Column(Modifier.fillMaxWidth().padding(top = 20.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Title("Your other devices,\njust a code away.", "Connect this phone to your computer. Send files directly, and keep your devices within reach.")
        PrimaryButton("I have a code", onClick = onJoin)
        OutlinedButton(onClick = onSetup, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = RoundedCornerShape(7.dp), border = BorderStroke(1.dp, colors.outline)) { Text("Set up my first device", color = colors.onBackground) }
        SecondaryText("No account. Nothing uploaded to a cloud drive.")
    }
}

@Composable
private fun PairScreen(busy: Boolean, onJoin: (String, Boolean) -> Unit) {
    var code by rememberSaveable { mutableStateOf("") }
    var remember by rememberSaveable { mutableStateOf(false) }
    Title("Enter the code\nfrom your other device.", "Open Tunlion there and choose to add a device. Keep both devices open while they connect.")
    OutlinedTextField(code, { code = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        label = { Text("Device code") }, placeholder = { Text("brave-otter-3141") },
        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        shape = RoundedCornerShape(7.dp), enabled = !busy,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false))
    Row(Modifier.fillMaxWidth().toggleableForRemember(remember, !busy) { remember = it },
        verticalAlignment = Alignment.CenterVertically) {
        Checkbox(remember, null)
        Spacer(Modifier.width(10.dp))
        Column {
            Text("Remember this device", fontWeight = FontWeight.Medium)
            SecondaryText("Reconnect next time without a code.")
        }
    }
    PrimaryButton("Connect device", busy, enabled = code.isNotBlank(), onClick = { onJoin(code.trim(), remember) })
    SecondaryText("You choose what each device may use. Connecting does not grant shell access.")
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
private fun FilesScreen(status: CoreStatus, busy: Boolean, onReceive: (String) -> Unit,
    onConnect: () -> Unit, onPickDevice: (CoreDevice) -> Unit) {
    var receiveExpanded by rememberSaveable { mutableStateOf(false) }
    var code by rememberSaveable { mutableStateOf("") }
    Title("Files, straight\nto your device.", "Choose a connected device to send a file. Received files are verified before they are saved.")
    Eyebrow("SEND TO")
    val recipients = status.devices.filter { it.canSendFiles }
    if (recipients.isEmpty()) {
        SecondaryText("Connect another device to send your first file.")
        OutlinedButton(onClick = onConnect, shape = RoundedCornerShape(7.dp)) { Text("Connect a device") }
    } else recipients.forEach { device -> DeviceRow(device) { onPickDevice(device) } }
    HorizontalDivider(color = MaterialTheme.colorScheme.outline)
    ActionRow(Icons.Outlined.Download, "Receive with a code", "Someone shared a file with you") { receiveExpanded = !receiveExpanded }
    AnimatedVisibility(receiveExpanded, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            OutlinedTextField(code, { code = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("File code") }, shape = RoundedCornerShape(7.dp), enabled = !busy)
            PrimaryButton("Receive file", busy, code.isNotBlank()) { onReceive(code.trim()) }
        }
    }
    SecondaryText("Saved to Download/Tunlion when receiving is connected in this preview.")
}

@Composable
private fun DeviceRow(device: CoreDevice, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth().clipForRow().clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.size(8.dp).background(if (device.online) Color(0xFF137738) else colors.onSurfaceVariant,
            androidx.compose.foundation.shape.CircleShape))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(device.name, fontWeight = FontWeight.Medium,
                color = if (device.online) colors.onBackground else colors.onSurfaceVariant)
            SecondaryText(if (device.online) "Online" else "Offline")
        }
        if (device.online && device.route != null) {
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
    SecondaryText(if (device.online) "Online" else "Offline")
    Eyebrow("ACCESS")
    SecondaryText(device.plainLine)
    if (device.route == "relayed") SecondaryText("On relay, not a direct link. Still end-to-end encrypted.")
    if (device.canSendFiles) PrimaryButton("Send a file", onClick = onSend)
    if (device.canOpenShell) SecondaryText("Shell access granted. The terminal is not connected in this preview.")
}

@Composable
private fun SendScreen(device: CoreDevice) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var names by remember { mutableStateOf<List<String>>(emptyList()) }
    var reading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) scope.launch {
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
    Title("Send to ${device.name}", "Choose files with Android's file picker. They stay on this phone until you send them.")
    if (names.isNotEmpty()) {
        Eyebrow("SELECTED FILES · ${names.size}")
        names.forEach { name ->
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.InsertDriveFile, null)
                Text(name, modifier = Modifier.weight(1f))
            }
        }
    }
    PrimaryButton(if (names.isEmpty()) "Choose files" else "Choose different files", reading) { picker.launch(arrayOf("*/*")) }
    error?.let { SecondaryText(it) }
    SecondaryText("File sending is not connected in this preview yet. Selecting a file does not upload or send it.")
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
