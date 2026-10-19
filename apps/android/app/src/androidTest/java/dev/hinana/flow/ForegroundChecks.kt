package dev.hinana.flow

import android.app.Application
import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry

@RunWith(AndroidJUnit4::class)
class ForegroundChecks {
    @Test fun pickerResultWaitsForActualResumeAndIsConsumedOnce(){
        InstrumentationRegistry.getInstrumentation().runOnMainSync{
            val owner=object:LifecycleOwner{
                val registry=LifecycleRegistry(this)
                override val lifecycle:Lifecycle get()=registry
            }
            val events=mutableListOf<String>()
            val first=Uri.parse("content://test-only/first")
            val second=Uri.parse("content://test-only/second")
            val gate=ForegroundImport(owner.lifecycle,{events.add("active")},{events.add(it.lastPathSegment!!)},{events.add("cancel")})
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_CREATE)
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_START)
            gate.result(first)
            assertTrue(events.isEmpty()) // onResume/onPostResume can still see STARTED.
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_RESUME)
            assertEquals(listOf("active","first"),events)
            gate.result(second)
            assertEquals(listOf("active","first","second"),events)
            gate.pause() // MainActivity immediately stops networking in onPause.
            gate.result(first)
            assertEquals(3,events.size) // No read during the pause callback window.
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_PAUSE)
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_RESUME)
            assertEquals(listOf("active","first","second","active","first"),events)
            gate.result(null)
            assertEquals("cancel",events.last())
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_PAUSE)
            gate.result(second)
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
            owner.registry.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
            assertEquals(6,events.size) // Destroy drops pending selection.
        }
    }
    @Test fun inactiveActionsAndResumeNeverOpenIdentityOrNetwork(){
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync{
            val model=FlowModel(instrumentation.targetContext.applicationContext as Application)
            model.setActive(false);model.prepare();model.browse();model.listen();model.connect();model.connect(true,true)
            model.stageFile(Uri.parse("content://invalid-not-accessed/test"));model.sendText();model.decideText(true);model.decideFile(true)
            assertFalse(model.connected);assertFalse(model.busy);assertFalse(model.preparing);assertTrue(model.fingerprint.isEmpty())
            model.setActive(true)
            assertFalse(model.connected);assertFalse(model.busy);assertTrue(model.fingerprint.isEmpty())
            assertTrue(model.textConsent.isEmpty());assertTrue(model.fileConsent.isEmpty());assertTrue(model.receivedText.isEmpty())
            model.dispose()
        }
    }
}
