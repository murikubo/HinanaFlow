package dev.hinana.flow.core

/** Android NSD returns a trailing dot for discovery and a leading dot for resolve.
 * Accept only these exact OS spellings; never arbitrary domains, subtypes or suffixes. */
object ServiceType {
    fun canonical(value:String):String?=when(value.lowercase(java.util.Locale.ROOT)){
        "_hinanaflow._tcp","_hinanaflow._tcp.","._hinanaflow._tcp"->"_hinanaflow._tcp"
        else->null
    }
}
