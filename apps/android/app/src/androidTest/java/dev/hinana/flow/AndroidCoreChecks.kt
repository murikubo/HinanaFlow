package dev.hinana.flow
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.runner.RunWith
/** Runs the identical vectors with Android's real JSONObject/JSONTokener and TLS provider.
 * Memory-only keys, app-owned test directories and loopback; never opens Android Keystore. */
@RunWith(AndroidJUnit4::class)
class AndroidCoreChecks:CoreChecks(){
    override fun document(name:String)=JSONObject(InstrumentationRegistry.getInstrumentation().context.assets.open(name).bufferedReader(Charsets.UTF_8).use{it.readText()})
}
