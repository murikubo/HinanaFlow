package dev.hinana.flow.core

import java.security.MessageDigest

/** Evidence is supplied by the platform adapter only after the native TLS handshake. */
class Authentication {
    enum class Phase { STOPPED, HANDSHAKING, VERIFIED, READY, CLOSED }
    var phase=Phase.STOPPED; private set
    var active=false; private set
    private var expected=byteArrayOf()
    val ready: Boolean get()=active && phase==Phase.READY
    fun setActive(value: Boolean) {active=value;if(!value)close()}
    private inline fun guarded(block:()->Unit) {try {block()} catch(e:Exception){close();throw e}}
    fun begin(local:ByteArray,peer:ByteArray,stored:ByteArray?,oob:Boolean) = guarded {
        checkWire(active && phase in setOf(Phase.STOPPED,Phase.CLOSED) && local.size==32 && peer.size==32 && !local.contentEquals(peer))
        if(stored!=null)checkWire(stored.size==32 && MessageDigest.isEqual(stored,peer)) else checkWire(oob)
        expected=peer.copyOf();phase=Phase.HANDSHAKING
    }
    fun tls(peer:ByteArray,tls13:Boolean,verified:Boolean,localPresented:Boolean) = guarded {
        checkWire(active && phase==Phase.HANDSHAKING && tls13 && verified && localPresented && MessageDigest.isEqual(peer,expected));phase=Phase.VERIFIED
    }
    fun persisted() = guarded {checkWire(active && phase==Phase.VERIFIED);phase=Phase.READY}
    fun requireReady() {checkWire(ready)}
    fun close() {phase=Phase.CLOSED;expected.fill(0);expected=byteArrayOf()}
}

sealed interface TextEvent {
    data class Send(val message:Message):TextEvent
    data class Consent(val bytes:Long,val scalars:Long):TextEvent
    data class Received(val text:String):TextEvent
    data object Delivered:TextEvent
    data object Denied:TextEvent
}
class TextProtocol(private val authenticated:Boolean) {
    private data class Incoming(val id:String,val bytes:Long,val scalars:Long,var accepted:Boolean=false,var deadline:Double)
    private data class Outgoing(val id:String,val text:String,var receipt:Boolean=false,var deadline:Double)
    private var incoming:Incoming?=null;private var outgoing:Outgoing?=null;private val seen=HashSet<String>()
    val needsConsent get()=incoming?.accepted==false
    fun expired(now:Double)=(incoming?.let{now>=it.deadline}?:false)||(outgoing?.let{now>=it.deadline}?:false)
    private fun remember(id:String){checkWire(authenticated && seen.size<1024 && seen.add(id))}
    fun offer(text:String,now:Double):Message {
        checkWire(authenticated && !expired(now) && outgoing==null && scalarCount(text) in 1..8192 && text.toByteArray(Charsets.UTF_8).size in 1..32768)
        val m=Message.make("textOffer",mapOf("byteCount" to text.toByteArray(Charsets.UTF_8).size.toLong(),"scalarCount" to scalarCount(text).toLong()))
        remember(m.id);outgoing=Outgoing(m.id,text,deadline=now+60);return m
    }
    fun decide(accept:Boolean,now:Double):Message {
        val offer=incoming?:throw ProtocolFailure();checkWire(authenticated && !expired(now) && !offer.accepted)
        val m=Message.make("decision",mapOf("offerId" to offer.id,"accept" to accept));remember(m.id)
        if(accept){offer.accepted=true;offer.deadline=now+10}else incoming=null
        return m
    }
    fun receive(m:Message,now:Double):List<TextEvent> {
        checkWire(!expired(now));remember(m.id)
        return when(m.type){
            "textOffer"->{checkWire(incoming==null);val bytes=m.number("byteCount");val scalars=m.number("scalarCount");checkWire(bytes>=scalars && bytes<=scalars*4)
                incoming=Incoming(m.id,bytes,scalars,deadline=now+60);listOf(TextEvent.Consent(bytes,scalars))}
            "decision"->{val offer=outgoing?:throw ProtocolFailure();checkWire(!offer.receipt && m.string("offerId")==offer.id)
                if(!m.boolean("accept")){outgoing=null;listOf(TextEvent.Denied)}else{
                    val body=Message.make("textData",mapOf("offerId" to offer.id,"text" to offer.text));remember(body.id);offer.receipt=true;offer.deadline=now+10;listOf(TextEvent.Send(body))}}
            "textData"->{val offer=incoming?:throw ProtocolFailure();val text=m.string("text")
                checkWire(offer.accepted && m.string("offerId")==offer.id && text.toByteArray(Charsets.UTF_8).size.toLong()==offer.bytes && scalarCount(text).toLong()==offer.scalars)
                val receipt=Message.make("receipt",mapOf("offerId" to offer.id));remember(receipt.id);incoming=null;listOf(TextEvent.Received(text),TextEvent.Send(receipt))}
            "receipt"->{val offer=outgoing?:throw ProtocolFailure();checkWire(offer.receipt && m.string("offerId")==offer.id);outgoing=null;listOf(TextEvent.Delivered)}
            "cancel"->{val id=m.string("offerId");if(incoming?.id==id)incoming=null else if(outgoing?.id==id)outgoing=null else throw ProtocolFailure();listOf(TextEvent.Denied)}
            else->throw ProtocolFailure()
        }
    }
}
