package dev.hinana.flow

import android.net.Uri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner

/** Holds only the user's picker result; never resumes a connection or a transfer. */
internal class ForegroundImport(
    private val lifecycle: Lifecycle,
    private val activate: () -> Unit,
    private val consume: (Uri) -> Unit,
    private val cancelled: () -> Unit,
) : LifecycleEventObserver {
    private var resumed = false
    private var pending: Uri? = null
    init { lifecycle.addObserver(this) }
    fun pause() { resumed = false }
    fun result(uri: Uri?) {
        pending = uri
        if (uri == null) cancelled() else drain()
    }
    private fun drain() {
        if (!resumed || !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        val selected = pending ?: return
        pending = null
        consume(selected)
    }
    override fun onStateChanged(source: LifecycleOwner, event: Lifecycle.Event) {
        when (event) {
            Lifecycle.Event.ON_RESUME -> { activate(); resumed = true; drain() }
            Lifecycle.Event.ON_PAUSE, Lifecycle.Event.ON_STOP -> pause()
            Lifecycle.Event.ON_DESTROY -> { pause(); pending = null; lifecycle.removeObserver(this) }
            else -> Unit
        }
    }
}
