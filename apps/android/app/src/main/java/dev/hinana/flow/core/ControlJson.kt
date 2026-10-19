package dev.hinana.flow.core

import org.json.JSONTokener
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.text.Normalizer
import java.util.UUID

class ProtocolFailure(val code: String = "HF-P-INVALID") : Exception(code)
fun checkWire(value: Boolean) { if (!value) throw ProtocolFailure() }
fun strictUtf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()
fun scalarCount(value: String): Int {
    var at = 0; var count = 0
    while (at < value.length) {
        val ch = value[at++]
        if (ch.isHighSurrogate()) { checkWire(at < value.length && value[at].isLowSurrogate()); at++ }
        else checkWire(!ch.isLowSurrogate())
        count++
    }
    return count
}

data class Message(val fields: Map<String, Any>) {
    fun string(key: String) = fields[key] as? String ?: throw ProtocolFailure()
    fun number(key: String) = fields[key] as? Long ?: throw ProtocolFailure()
    fun boolean(key: String) = fields[key] as? Boolean ?: throw ProtocolFailure()
    val type: String get() = string("type")
    val id: String get() = string("id")
    fun encoded(): ByteArray {
        val json = JSONObject()
        fields.toSortedMap().forEach { (k,v) -> json.put(k,v) }
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        ControlJson.parse(bytes)
        return bytes
    }
    companion object {
        fun make(type: String, values: Map<String, Any> = emptyMap()): Message {
            val result = Message(values + mapOf("v" to 1L, "id" to UUID.randomUUID().toString(), "type" to type))
            result.encoded(); return result
        }
    }
}

object SharedFilename {
    private val forbidden = "/\\:<>\"|?*"
    private val reserved = setOf("CON","PRN","AUX","NUL","CLOCK$","CONIN$","CONOUT$") +
        (1..9).flatMap { listOf("COM$it","LPT$it") } + listOf("COM¹","COM²","COM³","LPT¹","LPT²","LPT³")
    fun normalize(name: String): String = Normalizer.normalize(name, Normalizer.Form.NFC).also { checkWire(valid(it)) }
    fun valid(name: String): Boolean = runCatching {
        checkWire(name == Normalizer.normalize(name, Normalizer.Form.NFC) && name.isNotEmpty())
        checkWire(scalarCount(name) <= 120 && name.toByteArray(Charsets.UTF_8).size <= 180)
        checkWire(!name.startsWith('.') && !name.startsWith(' ') && !name.endsWith('.') && !name.endsWith(' ') && !name.contains(".."))
        name.codePoints().forEach { cp ->
            checkWire(cp !in forbidden.map { it.code })
            checkWire(Character.getType(cp) !in listOf(Character.CONTROL.toInt(),Character.FORMAT.toInt(),
                Character.LINE_SEPARATOR.toInt(),Character.PARAGRAPH_SEPARATOR.toInt(),Character.SURROGATE.toInt(),
                Character.PRIVATE_USE.toInt(),Character.UNASSIGNED.toInt()))
            checkWire(cp == 32 || !(Character.isWhitespace(cp) || Character.isSpaceChar(cp) || cp == 0x85))
        }
        checkWire(name.substringBefore('.').trim(' ').uppercase(java.util.Locale.ROOT) !in reserved)
    }.isSuccess
}

/** Bounded flat lexer enforces canonical JSON before the platform JSON string parser.
 * JSONObject alone accepts duplicate keys/lenient tokens on some Android versions. */
object ControlJson {
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val legacyName = Regex("(?!.*\\.\\.)(?!(?:[cC][oO][nN]|[pP][rR][nN]|[aA][uU][xX]|[nN][uU][lL]|[cC][oO][mM][1-9]|[lL][pP][tT][1-9])(?:\\.|$))[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,118}[A-Za-z0-9_-])?")
    fun parse(bytes: ByteArray): Message {
        checkWire(bytes.size in 1..65536)
        val raw = strictUtf8(bytes); var at = 0
        fun space() { while (at < raw.length && raw[at] in " \t\r\n") at++ }
        fun take(c: Char) { space(); checkWire(at < raw.length && raw[at++] == c) }
        fun string(): String {
            space(); val start = at; take('"')
            while (at < raw.length) {
                val ch = raw[at++]
                checkWire(ch.code >= 32)
                if (ch == '"') {
                    val value = JSONTokener(raw.substring(start, at)).nextValue() as? String ?: throw ProtocolFailure()
                    scalarCount(value); return value
                }
                if (ch == '\\') {
                    checkWire(at < raw.length)
                    val escape = raw[at++]
                    checkWire(escape in "\"\\/bfnrtu")
                    if (escape == 'u') {
                        checkWire(at + 4 <= raw.length && raw.substring(at,at+4).all { it in "0123456789abcdefABCDEF" }); at += 4
                    }
                }
            }
            throw ProtocolFailure()
        }
        take('{'); val fields = linkedMapOf<String,Any>(); space()
        if (at < raw.length && raw[at] == '}') at++ else while (true) {
            val key = string(); checkWire(!fields.containsKey(key)); take(':'); space(); checkWire(at < raw.length)
            val value: Any = if (raw[at] == '"') string() else {
                val start = at
                while (at < raw.length && raw[at] !in " \t\r\n,}") at++
                when (val token = raw.substring(start, at)) {
                    "true" -> true; "false" -> false
                    else -> { checkWire(Regex("0|[1-9][0-9]*").matches(token)); token.toLongOrNull() ?: throw ProtocolFailure() }
                }
            }
            fields[key] = value; space(); checkWire(at < raw.length)
            if (raw[at] == '}') {at++; break}; take(',')
        }
        space(); checkWire(at == raw.length)
        val m = Message(fields); checkWire(m.number("v") == 1L && uuid.matches(m.id))
        fun offerID() { checkWire(uuid.matches(m.string("offerId"))) }
        val extras = when (m.type) {
            "hello" -> {checkWire(uuid.matches(m.string("deviceId")) && scalarCount(m.string("displayName")) in 1..64); setOf("deviceId","displayName")}
            "textOffer" -> {checkWire(m.number("byteCount") in 1..32768 && m.number("scalarCount") in 1..8192); setOf("byteCount","scalarCount")}
            "textData" -> {offerID(); checkWire(scalarCount(m.string("text")) in 1..8192); setOf("offerId","text")}
            "fileOffer", "fileOfferUnicode" -> {
                val name = m.string("name"); val unicode = m.type == "fileOfferUnicode"
                checkWire(if (unicode) SharedFilename.valid(name) else legacyName.matches(name))
                checkWire(m.number("size") in 0..(if (unicode) 10_000_000L else 1_073_741_824L))
                checkWire(Regex("[0-9a-f]{64}").matches(m.string("sha256"))); setOf("name","size","sha256")
            }
            "decision", "fileDecision" -> {offerID(); m.boolean("accept"); setOf("offerId","accept")}
            "receipt","cancel","fileEnd","fileReceipt","fileCancel" -> {offerID(); setOf("offerId")}
            "error" -> {checkWire(m.string("code") in setOf("unsupported","denied","invalid","timeout","integrity")); setOf("code")}
            else -> throw ProtocolFailure()
        }
        checkWire(fields.keys == extras + setOf("v","type","id")); return m
    }
}
