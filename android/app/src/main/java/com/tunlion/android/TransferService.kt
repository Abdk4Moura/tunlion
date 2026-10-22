package com.tunlion.android

import android.app.*
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

/** Keeps user-started transfers foreground while the Activity is backgrounded. */
class TransferService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return START_NOT_STICKY }
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("transfers", "File transfers", NotificationManager.IMPORTANCE_LOW).apply { setSound(null, null) })
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        startForeground(1003, NotificationCompat.Builder(this, "transfers").setSmallIcon(R.drawable.ic_tunlion)
            .setContentTitle("Tunlion").setContentText("Connecting or transferring…")
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).build())
        return START_NOT_STICKY
    }
}
