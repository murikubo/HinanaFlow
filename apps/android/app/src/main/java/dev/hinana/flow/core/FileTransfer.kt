package dev.hinana.flow.core

sealed interface FileEvent {
    data class Send(val message:Message):FileEvent
    data class Consent(val name:String,val size:Long):FileEvent
    data class Saved(val file:StoredFile):FileEvent
    data object Start:FileEvent
    data object Delivered:FileEvent
    data object Denied:FileEvent
}
sealed interface PumpItem {data class Chunk(val value:Frame.Chunk):PumpItem;data class End(val message:Message):PumpItem}
/** Same single-file, approval, deadline and replay rules as the Apple profile. */
class FileTransfer(private val authenticated:Boolean) {
    private data class Incoming(val id:String,val size:Long,val hash:String,val name:String,var accepted:Boolean=false,var deadline:Double,var end:Double)
    private data class Outgoing(val id:String,val file:FileSnapshot,var accepted:Boolean=false,var receipt:Boolean=false,var offset:Long=0,var deadline:Double,var end:Double)
    private var incoming:Incoming?=null;private var outgoing:Outgoing?=null;private var sink:IncomingFile?=null;private val seen=HashSet<String>()
    val busy get()=incoming!=null||outgoing!=null
    val needsConsent get()=incoming?.accepted==false
    val sending get()=outgoing?.let{it.accepted && !it.receipt}?:false
    fun expired(now:Double)=(incoming?.let{now>=it.deadline||now>=it.end}?:false)||(outgoing?.let{now>=it.deadline||now>=it.end}?:false)
    private fun remember(id:String,now:Double){checkWire(authenticated && !expired(now) && seen.size<1024 && seen.add(id))}
    fun cancel(){sink?.close();sink=null;incoming=null;outgoing?.file?.close();outgoing=null}
    fun offer(file:FileSnapshot,now:Double):Message {
        checkWire(authenticated && !busy && !expired(now) && file.size<=FileStorage.MAX)
        val m=Message.make("fileOfferUnicode",mapOf("name" to file.name,"size" to file.size,"sha256" to file.hash));remember(m.id,now)
        outgoing=Outgoing(m.id,file,deadline=now+60,end=now+180);return m
    }
    fun decide(accept:Boolean,store:FileStorage,now:Double):Message {
        val offer=incoming?:throw ProtocolFailure();checkWire(authenticated && !expired(now) && !offer.accepted)
        if(accept){sink=store.receive(offer.size,offer.hash);offer.accepted=true;offer.deadline=now+15;offer.end=now+120}else incoming=null
        val m=Message.make("fileDecision",mapOf("offerId" to offer.id,"accept" to accept));remember(m.id,now);return m
    }
    fun receive(m:Message,now:Double):List<FileEvent> {
        remember(m.id,now)
        return when(m.type){
            "fileOffer","fileOfferUnicode"->{checkWire(!busy);val size=m.number("size");checkWire(size in 0..FileStorage.MAX)
                incoming=Incoming(m.id,size,m.string("sha256"),SharedFilename.normalize(m.string("name")),deadline=now+60,end=now+180)
                listOf(FileEvent.Consent(m.string("name"),size))}
            "fileDecision"->{val offer=outgoing?:throw ProtocolFailure();checkWire(!offer.accepted && m.string("offerId")==offer.id)
                if(!m.boolean("accept")){offer.file.close();outgoing=null;listOf(FileEvent.Denied)}else{offer.accepted=true;offer.deadline=now+15;offer.end=now+120;listOf(FileEvent.Start)}}
            "fileEnd"->{val offer=incoming?:throw ProtocolFailure();val writer=sink?:throw ProtocolFailure();checkWire(offer.accepted && m.string("offerId")==offer.id)
                val file=writer.finish(offer.name,offer.id);sink=null;incoming=null
                val receipt=Message.make("fileReceipt",mapOf("offerId" to offer.id));remember(receipt.id,now);listOf(FileEvent.Saved(file),FileEvent.Send(receipt))}
            "fileReceipt"->{val offer=outgoing?:throw ProtocolFailure();checkWire(offer.receipt && m.string("offerId")==offer.id);offer.file.close();outgoing=null;listOf(FileEvent.Delivered)}
            "fileCancel"->{val id=m.string("offerId");checkWire(incoming?.id==id||outgoing?.id==id);cancel();listOf(FileEvent.Denied)}
            else->throw ProtocolFailure()
        }
    }
    fun receive(chunk:Frame.Chunk,now:Double){val offer=incoming?:throw ProtocolFailure();checkWire(authenticated && !expired(now) && offer.accepted && chunk.id==offer.id);sink!!.append(chunk);offer.deadline=now+15}
    fun next(now:Double):PumpItem {
        val offer=outgoing?:throw ProtocolFailure();checkWire(authenticated && !expired(now) && offer.accepted && !offer.receipt);offer.deadline=now+15
        val bytes=offer.file.next()
        if(bytes!=null){val chunk=Frame.Chunk(offer.id,offer.offset,bytes);offer.offset+=bytes.size;return PumpItem.Chunk(chunk)}
        checkWire(offer.offset==offer.file.size);offer.receipt=true
        val end=Message.make("fileEnd",mapOf("offerId" to offer.id));remember(end.id,now);return PumpItem.End(end)
    }
}
