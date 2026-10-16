package com.tunlion.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DevicesOther
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private var feedbackEnabled by mutableStateOf(true)
    private var feedbackImage by mutableStateOf<android.graphics.Bitmap?>(null)
    private var capturing = false
    private var resumed = false
    private lateinit var shake: FeedbackShake

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        feedbackEnabled = getPreferences(MODE_PRIVATE).getBoolean("shake_feedback", true)
        shake = FeedbackShake(this) { openFeedback() }
        setContent {
            val core = remember { UnlinkedTunlionCore() }
            TunlionApp(core, feedbackEnabled,
                onFeedbackEnabled = { enabled ->
                    feedbackEnabled = enabled
                    getPreferences(MODE_PRIVATE).edit().putBoolean("shake_feedback", enabled).apply()
                    shake.stop()
                    if (enabled && resumed) shake.start()
                }, onFeedback = { openFeedback() })
            feedbackImage?.let { image ->
                MaterialTheme {
                    FeedbackEditor(image, onDismiss = { feedbackImage = null },
                        onShare = { crop, comment -> shareFeedback(this, crop, comment) })
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if (feedbackEnabled) shake.start()
    }

    override fun onPause() {
        resumed = false
        shake.stop()
        super.onPause()
    }

    private fun openFeedback() {
        if (!resumed || capturing || feedbackImage != null) return
        capturing = true
        captureFeedback(this) { image ->
            capturing = false
            if (resumed && !isDestroyed) feedbackImage = image
            else image?.recycle()
            if (image == null && resumed) android.widget.Toast.makeText(this,
                "Could not capture this screen. Try again.", android.widget.Toast.LENGTH_SHORT).show()
        }
    }
}

private val Paper = Color(0xFFF7F6F2)
private val Surface = Color(0xFFFFFFFF)
private val Ink = Color(0xFF1D1C1A)
private val Sub = Color(0xFF5D5A53)
private val Rule = Color(0xFFDEDAD0)
private val Soft = Color(0xFFEFEDE6)
private val Accent = Color(0xFFD55C13)
private val DarkBg = Color(0xFF141412)
private val DarkSurface = Color(0xFF1D1C1A)
private val DarkInk = Color(0xFFF2EFE6)
private val DarkSub = Color(0xFFA29E94)
private val DarkRule = Color(0xFF33312D)
private val DarkSoft = Color(0xFF26251F)
private val DarkAccent = Color(0xFFE36927)

private enum class Tab(val label: String) {
    DEVICES("Devices"), FILES("Files"), SETTINGS("Settings")
}

@Composable
private fun TunlionApp(core: TunlionCore, feedbackEnabled: Boolean,
    onFeedbackEnabled: (Boolean) -> Unit, onFeedback: () -> Unit) {
    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val colors = if (dark) AppColors(DarkBg, DarkSurface, DarkInk, DarkSub, DarkRule, DarkSoft, DarkAccent)
        else AppColors(Paper, Surface, Ink, Sub, Rule, Soft, Accent)
    val status = remember(core) { core.status() }
    val materialColors = if (dark) {
        darkColorScheme(
            primary = colors.accent,
            onPrimary = colors.bg,
            background = colors.bg,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            onSurfaceVariant = colors.sub,
            outline = colors.rule,
        )
    } else {
        lightColorScheme(
            primary = colors.accent,
            onPrimary = Color.White,
            background = colors.bg,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            onSurfaceVariant = colors.sub,
            outline = colors.rule,
        )
    }
    var selectedTab by rememberSaveable { mutableStateOf(Tab.DEVICES) }
    var available by remember { mutableStateOf(status.engineRunning) }
    var pairCode by rememberSaveable { mutableStateOf("") }
    var rememberDevice by rememberSaveable { mutableStateOf(false) }
    var receiveCode by rememberSaveable { mutableStateOf("") }
    var notice by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    MaterialTheme(colorScheme = materialColors) {
        BackHandler(enabled = selectedTab != Tab.DEVICES) { selectedTab = Tab.DEVICES }
        Scaffold(
            containerColor = colors.bg,
        ) { insets ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(insets)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 28.dp),
            ) {
                AppHeader(colors, selectedTab, onHome = { selectedTab = Tab.DEVICES },
                    onFiles = { selectedTab = Tab.FILES }, onSettings = { selectedTab = Tab.SETTINGS })
                when (selectedTab) {
                    Tab.DEVICES -> HomeScreen(
                        colors = colors,
                        status = status,
                        available = available,
                        pairCode = pairCode,
                        rememberDevice = rememberDevice,
                        onRememberDevice = { rememberDevice = it },
                        onPairCode = { pairCode = it },
                        onAvailable = { turnOn ->
                            scope.launch {
                                val result = if (turnOn) core.start() else core.stop()
                                when (result) {
                                    CoreResult.Success -> {
                                        available = turnOn
                                        notice = null
                                    }
                                    is CoreResult.Failure -> notice = result.message
                                }
                            }
                        },
                        onJoin = {
                            scope.launch {
                                when (val result = core.joinCode(pairCode.trim(), remember = rememberDevice)) {
                                    CoreResult.Success -> {
                                        pairCode = ""
                                        notice = "Code accepted."
                                    }
                                    is CoreResult.Failure -> notice = result.message
                                }
                            }
                        },
                        onScan = { notice = "Code scanning will be available with pairing." },
                    )
                    Tab.FILES -> FilesScreen(
                        colors = colors,
                        code = receiveCode,
                        onCode = { receiveCode = it },
                        onReceive = {
                            scope.launch {
                                when (val result = core.receiveCode(receiveCode.trim())) {
                                    CoreResult.Success -> {
                                        receiveCode = ""
                                        notice = "Receiving."
                                    }
                                    is CoreResult.Failure -> notice = result.message
                                }
                            }
                        },
                    )
                    Tab.SETTINGS -> SettingsScreen(colors, status, feedbackEnabled, onFeedbackEnabled, onFeedback)
                }
                notice?.let { message ->
                    Spacer(Modifier.height(16.dp))
                    NoticeCard(message, colors)
                }
            }
        }
    }
}

private data class AppColors(
    val bg: Color,
    val surface: Color,
    val ink: Color,
    val sub: Color,
    val rule: Color,
    val soft: Color,
    val accent: Color,
)

@Composable
private fun AppHeader(colors: AppColors, selected: Tab, onHome: () -> Unit,
    onFiles: () -> Unit, onSettings: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(Modifier.weight(1f).clip(RoundedCornerShape(6.dp)).clickable(onClick = onHome)
            .padding(vertical = 10.dp).semantics { contentDescription = "Tunlion home" },
            verticalAlignment = Alignment.CenterVertically) {
            TunlionMark(colors, 26)
            Spacer(Modifier.width(9.dp))
            Text("tunlion", color = colors.ink, fontSize = 20.sp, letterSpacing = (-.5).sp,
                fontWeight = FontWeight.SemiBold)
        }
        TextButton(onClick = if (selected == Tab.FILES) onHome else onFiles) {
            Text(if (selected == Tab.FILES) "Devices" else "Files", color = colors.ink)
        }
        androidx.compose.material3.IconButton(onClick = onSettings) {
            Icon(Icons.Outlined.Settings, contentDescription = "Settings", tint = colors.ink)
        }
    }
}

@Composable
private fun HomeScreen(
    colors: AppColors,
    status: CoreStatus,
    available: Boolean,
    pairCode: String,
    rememberDevice: Boolean,
    onRememberDevice: (Boolean) -> Unit,
    onPairCode: (String) -> Unit,
    onAvailable: (Boolean) -> Unit,
    onJoin: () -> Unit,
    onScan: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Card(colors = colors) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(if (available) "Available" else "Off", color = colors.ink,
                            fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                        Text("This phone", color = colors.sub, fontSize = 12.sp)
                    }
                    Switch(
                        checked = available,
                        onCheckedChange = onAvailable,
                        modifier = Modifier.semantics { contentDescription = "Availability" },
                        colors = SwitchDefaults.colors(checkedTrackColor = colors.accent,
                            checkedThumbColor = Color.White),
                    )
                }
                Text(
                    if (available) "Your remembered devices can reach you."
                    else "Your devices cannot reach this phone while it is off.",
                    color = colors.sub, fontSize = 13.sp, lineHeight = 18.sp,
                )
                if (!status.engineLinked) {
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(7.dp))
                            .background(colors.soft).padding(horizontal = 9.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(Modifier.size(7.dp).clip(CircleShape).background(colors.accent))
                        Spacer(Modifier.width(8.dp))
                        Text("Preview · native engine not linked", color = colors.sub,
                            fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }

        Card(colors = colors) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Enter a code", color = colors.ink, fontSize = 17.sp,
                            fontWeight = FontWeight.SemiBold)
                    }
                    TextButton(onClick = onScan) {
                        Text("Scan", color = colors.accent, fontWeight = FontWeight.SemiBold)
                    }
                }
                OutlinedTextField(
                    value = pairCode,
                    onValueChange = onPairCode,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Pairing code") },
                    placeholder = { Text("brave-otter-3141", color = colors.sub.copy(alpha = .72f)) },
                    shape = RoundedCornerShape(8.dp),
                    textStyle = androidx.compose.ui.text.TextStyle(
                        fontFamily = FontFamily.Monospace, fontSize = 15.sp, color = colors.ink),
                )
                Row(
                    Modifier.fillMaxWidth().clickable { onRememberDevice(!rememberDevice) },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = rememberDevice, onCheckedChange = null,
                        modifier = Modifier.semantics { contentDescription = "Remember this device" })
                    Column {
                        Text("Remember this device", color = colors.ink, fontSize = 13.sp,
                            fontWeight = FontWeight.Medium)
                        Text("Keep it in My devices on this phone.", color = colors.sub, fontSize = 11.sp)
                    }
                }
                Button(
                    onClick = onJoin,
                    enabled = pairCode.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(7.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = colors.ink,
                        contentColor = colors.bg, disabledContainerColor = colors.soft,
                        disabledContentColor = colors.sub),
                ) {
                    Text("Join with code", fontWeight = FontWeight.SemiBold)
                }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Eyebrow("MY DEVICES", colors)
            Spacer(Modifier.weight(1f))
            Text("${status.devices.size}", color = colors.sub, fontSize = 12.sp,
                fontFamily = FontFamily.Monospace)
        }
        if (status.devices.isEmpty()) {
            EmptyDevices(colors)
        } else {
            status.devices.forEach { DeviceRow(it, colors) }
        }
    }
}

@Composable
private fun EmptyDevices(colors: AppColors) {
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(9.dp),
        border = BorderStroke(1.dp, colors.rule),
    ) {
        Column(Modifier.fillMaxWidth().padding(vertical = 18.dp, horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("No devices yet", color = colors.ink, fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold)
            Text("Enter a code to connect your first device.", color = colors.sub,
                fontSize = 13.sp, lineHeight = 18.sp)
        }
    }
}

@Composable
private fun DeviceRow(device: CoreDevice, colors: AppColors) {
    Card(colors = colors) {
        Row(Modifier.fillMaxWidth().padding(15.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(38.dp).clip(RoundedCornerShape(8.dp)).background(colors.soft),
                contentAlignment = Alignment.Center) {
                Icon(Icons.Outlined.DevicesOther, contentDescription = null, tint = colors.ink)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(device.name, color = colors.ink, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                Text(device.plainLine, color = colors.sub, fontSize = 12.sp,
                    maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            StatusDot(device.online, colors)
        }
    }
}

@Composable
private fun FilesScreen(colors: AppColors, code: String, onCode: (String) -> Unit, onReceive: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        ScreenTitle("Files", "Send privately. Receive what was shared with you.", colors)
        Card(colors = colors) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
                Eyebrow("RECEIVE BY CODE", colors)
                OutlinedTextField(
                    value = code,
                    onValueChange = onCode,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Receive code") },
                    placeholder = { Text("Enter a receive code") },
                    shape = RoundedCornerShape(8.dp),
                )
                Button(
                    onClick = onReceive,
                    enabled = code.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(7.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = colors.ink,
                        contentColor = colors.bg, disabledContainerColor = colors.soft,
                        disabledContentColor = colors.sub),
                ) { Text("Receive file", fontWeight = FontWeight.SemiBold) }
            }
        }
        Card(colors = colors) {
            Row(Modifier.padding(17.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.FolderOpen, contentDescription = null, tint = colors.accent)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text("Saved files", color = colors.ink, fontWeight = FontWeight.SemiBold)
                    Text("Verified files will appear in Download/Tunlion.",
                        color = colors.sub, fontSize = 13.sp, lineHeight = 18.sp)
                }
            }
        }
        NoticeCard("File transfer becomes available when the native core is connected.", colors)
    }
}

@Composable
private fun SettingsScreen(colors: AppColors, status: CoreStatus, feedbackEnabled: Boolean,
    onFeedbackEnabled: (Boolean) -> Unit, onFeedback: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        ScreenTitle("Settings", "This phone and its Tunlion identity.", colors)
        Card(colors = colors) {
            Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Eyebrow("EXPERIMENTAL", colors)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Shake to give feedback", color = colors.ink, modifier = Modifier.weight(1f))
                    Switch(checked = feedbackEnabled, onCheckedChange = onFeedbackEnabled,
                        modifier = Modifier.semantics { contentDescription = "Shake to give feedback" })
                }
                Text("Shake twice while using this preview. Select a section, add a comment, then share it into this chat. Nothing is uploaded automatically.",
                    color = colors.sub, fontSize = 13.sp, lineHeight = 18.sp)
                OutlinedButton(onClick = onFeedback) { Text("Give feedback without shaking") }
            }
        }
        Card(colors = colors) {
            Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Eyebrow("THIS DEVICE", colors)
                SettingsLine("Name", status.deviceName ?: "Not set", colors)
                Divider(color = colors.rule)
                SettingsLine("Identity", status.fingerprint ?: "Not created", colors)
            }
        }
        Card(colors = colors) {
            Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Eyebrow("ABOUT", colors)
                Text("Tunlion for Android · Preview", color = colors.ink, fontWeight = FontWeight.SemiBold)
                Text("No account. Your devices, your permissions.", color = colors.sub,
                    fontSize = 13.sp, lineHeight = 18.sp)
                Text("Native core: ${if (status.engineLinked) "linked" else "not linked"}",
                    color = colors.sub, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun ScreenTitle(title: String, subtitle: String, colors: AppColors) {
    Column(Modifier.padding(bottom = 4.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Text(title, color = colors.ink, fontSize = 29.sp, fontWeight = FontWeight.SemiBold)
        Text(subtitle, color = colors.sub, fontSize = 14.sp, lineHeight = 20.sp)
    }
}

@Composable
private fun SettingsLine(label: String, value: String, colors: AppColors) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = colors.sub, fontSize = 13.sp, modifier = Modifier.weight(1f))
        Text(value, color = colors.ink, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun NoticeCard(message: String, colors: AppColors) {
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, colors.rule),
    ) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(colors.accent))
            Spacer(Modifier.width(10.dp))
            Text(message, color = colors.sub, fontSize = 13.sp, lineHeight = 18.sp)
        }
    }
}

@Composable
private fun Card(colors: AppColors, content: @Composable () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        shape = RoundedCornerShape(9.dp),
        border = BorderStroke(1.dp, colors.rule),
        content = { content() },
    )
}

@Composable
private fun Eyebrow(text: String, colors: AppColors) {
    Text(text, color = colors.sub, fontSize = 10.sp, letterSpacing = 1.2.sp,
        fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
}

@Composable
private fun StatusDot(online: Boolean, colors: AppColors) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(if (online) Color(0xFF137738) else colors.sub))
        Text(if (online) "online" else "offline", color = colors.sub, fontSize = 11.sp)
    }
}

@Composable
private fun TunlionMark(colors: AppColors, size: Int) {
    Canvas(Modifier.size(size.dp)) {
        val factor = this.size.minDimension / 80f
        val arch = Path().apply {
            moveTo(12f, 74f)
            lineTo(12f, 24f)
            quadraticTo(12f, 10f, 26f, 10f)
            lineTo(54f, 10f)
            quadraticTo(68f, 10f, 68f, 24f)
            lineTo(68f, 74f)
        }
        withTransform({ scale(factor, factor, pivot = androidx.compose.ui.geometry.Offset.Zero) }) {
            drawPath(arch, colors.ink, style = Stroke(width = if (size < 24) 16f else 10f))
            drawRect(colors.accent, topLeft = androidx.compose.ui.geometry.Offset(33f, 46f),
                size = androidx.compose.ui.geometry.Size(14f, 28f))
        }
    }
}
