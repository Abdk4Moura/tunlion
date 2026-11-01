package com.tunlion.android

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import java.io.File
import java.security.MessageDigest

/** Only checksum-verified CLI history entries may be published. Keep private originals on failure. */
internal class ReceivedFiles(private val context: Context) {
    private val paths = CliPaths(context)
    private val journal = context.getSharedPreferences("received_files", Context.MODE_PRIVATE)
    companion object { private val lock = Mutex() }
    fun records(): List<org.json.JSONObject> {
        val history = File(paths.config, "transfers.json")
        if (!history.exists()) return emptyList()
        val array = JSONArray(history.readText())
        return (0 until array.length()).map { array.getJSONObject(it) }
    }
    private fun id(record: org.json.JSONObject) = MessageDigest.getInstance("SHA-256")
        .digest("${record.optLong("time")}|${record.optString("stored")}|${record.optString("sha256")}".toByteArray())
        .joinToString("") { "%02x".format(it) }
    fun saved(record: org.json.JSONObject) = journal.getBoolean("done-${id(record)}", false)

    suspend fun publish(): List<String> = lock.withLock {
        val published = mutableListOf<String>()
        for (record in records()) {
            if (record.optString("direction") != "in" || !record.optBoolean("ok") || saved(record)) continue
            val hash = record.optString("sha256")
            if (!hash.matches(Regex("[0-9a-fA-F]{64}"))) continue
            val stored = record.optString("stored")
            val source = File(stored).canonicalFile
            if (!source.toPath().startsWith(paths.inbox.canonicalFile.toPath()) || !source.isFile) continue
            val name = File(record.optString("file")).name.takeIf { it.isNotBlank() && it != "." && it != ".." } ?: "Received file"
            val token = id(record)
            var uri = journal.getString("uri-$token", null)?.let(Uri::parse)
            if (uri == null) {
                uri = if (Build.VERSION.SDK_INT >= 29) {
                    context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                        put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, "Download/Tunlion")
                        put(MediaStore.MediaColumns.IS_PENDING, 1)
                    })
                } else {
                    val folder = journal.getString("folder", null)?.let(Uri::parse)
                        ?: continue // Android 8/9 uses a user-selected SAF folder, no storage permission.
                    DocumentFile.fromTreeUri(context, folder)?.createFile("application/octet-stream", name)?.uri
                }
                checkNotNull(uri) { "Could not create the received file" }
                check(journal.edit().putString("uri-$token", uri.toString()).commit())
            }
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                context.contentResolver.openOutputStream(uri, "wt").use { output ->
                    checkNotNull(output)
                    source.inputStream().use { input ->
                        val bytes = ByteArray(64 * 1024)
                        while (true) {
                            val count = input.read(bytes)
                            if (count < 0) break
                            digest.update(bytes, 0, count); output.write(bytes, 0, count)
                        }
                    }
                }
                check(digest.digest().joinToString("") { "%02x".format(it) }.equals(hash, true)) { "Saved file checksum did not match" }
                if (Build.VERSION.SDK_INT >= 29) context.contentResolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
                check(journal.edit().putBoolean("done-$token", true).commit())
                source.delete()
                published += name
            } catch (error: Exception) {
                context.contentResolver.delete(uri, null, null)
                journal.edit().remove("uri-$token").apply()
                throw error
            }
        }
        published
    }
}
