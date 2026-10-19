package dev.hinana.flow
import org.json.JSONObject
class JvmCoreChecks:CoreChecks(){
    override fun document(name:String)=JSONObject(javaClass.classLoader!!.getResourceAsStream(name)!!.bufferedReader(Charsets.UTF_8).use{it.readText()})
}
