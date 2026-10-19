package dev.hinana.flow

import dev.hinana.flow.core.*
import dev.hinana.flow.platform.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.nio.file.*
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.*
import javax.net.ssl.*

abstract class CoreChecks {
    protected abstract fun document(name:String):JSONObject
    private fun hex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun rejected(block:()->Unit){assertTrue("expected rejection",runCatching(block).isFailure)}
    @Test fun commonNativeJson(){
        for(name in listOf("vectors.json","file-sharing-vectors.json")){
            val values=document(name).getJSONArray("control")
            for(i in 0 until values.length()){
                val v=values.getJSONObject(i);val bytes=if(v.has("inputHex"))hex(v.getString("inputHex"))else v.getString("json").toByteArray(Charsets.UTF_8)
                val result=runCatching{ControlJson.parse(bytes)}
                assertEquals(v.getString("name"),v.getBoolean("valid"),result.isSuccess)
            }
        }
        val bad=document("vectors.json").getJSONArray("controlBytes")
        for(i in 0 until bad.length()){val v=bad.getJSONObject(i);assertEquals(v.getBoolean("valid"),runCatching{ControlJson.parse(hex(v.getString("inputHex")))}.isSuccess)}
        val body="한글 😀 \" escaped \\ \n"
        val m=Message.make("textData",mapOf("offerId" to UUID.randomUUID().toString(),"text" to body))
        assertEquals(body,ControlJson.parse(m.encoded()).string("text"))
    }
    @Test fun splitFrames(){
        for(name in listOf("vectors.json","file-vectors.json")){
            val values=document(name).getJSONArray("frames")
            for(i in 0 until values.length()){
                val v=values.getJSONObject(i);val bytes=hex(v.getString("hex"))
                for(split in 0..bytes.size){
                    val result=runCatching{val d=FrameDecoder(name!="vectors.json");val frames=d.feed(bytes.copyOfRange(0,split))+d.feed(bytes.copyOfRange(split,bytes.size));d.finish();frames}
                    assertEquals(v.getString("name")+" split "+split,v.getBoolean("valid"),result.isSuccess)
                    if(result.isSuccess && v.has("payloadHex"))assertArrayEquals(hex(v.getString("payloadHex")),(result.getOrThrow().single() as Frame.Control).data)
                }
            }
        }
    }
    @Test fun commonAuthenticationStates(){
        val values=document("apple-auth-vectors.json").getJSONArray("cases")
        for(i in 0 until values.length()){
            val v=values.getJSONObject(i);val auth=Authentication();var failed=false;val steps=v.getJSONArray("steps")
            for(s in 0 until steps.length()){
                val step=steps.getJSONObject(s)
                val outcome=runCatching{when(step.getString("op")){
                    "active"->auth.setActive(step.getBoolean("value"))
                    "begin"->{val local=ByteArray(32){1};val peer=when(step.optString("peer")){"self"->local;"short"->byteArrayOf(2);else->ByteArray(32){2}}
                        val stored=when(step.optString("stored")){"same"->ByteArray(32){2};"other"->ByteArray(32){3};"short"->byteArrayOf(2);else->null}
                        auth.begin(local,peer,stored,step.optBoolean("oob",false))}
                    "tls"->auth.tls(ByteArray(32){if(step.optString("peer")=="other")3 else 2},step.optBoolean("tls13",true),step.optBoolean("peerVerified",true),step.optBoolean("localPresented",true))
                    "persist"->auth.persisted()
                    "close"->auth.close()
                    else->error("unknown operation")
                }}
                if(outcome.isFailure){failed=true;break}
            }
            assertEquals(v.getString("name"),v.getBoolean("expectedError"),failed)
            assertEquals(v.getString("name"),v.getBoolean("expectedReady"),auth.ready)
            if(!auth.ready)rejected{auth.requireReady()}
        }
    }
    @Test fun twoWayTextConsent(){
        val a=TextProtocol(true);val b=TextProtocol(true)
        val ao=a.offer("hello 😀",0.0);val bo=b.offer("안녕하세요",0.0)
        assertTrue(b.receive(ao,1.0).single() is TextEvent.Consent);a.receive(bo,1.0)
        val aBody=(a.receive(b.decide(true,2.0),2.0).single() as TextEvent.Send).message
        val bBody=(b.receive(a.decide(true,2.0),2.0).single() as TextEvent.Send).message
        val fromA=b.receive(aBody,3.0);val fromB=a.receive(bBody,3.0)
        assertEquals("hello 😀",(fromA[0] as TextEvent.Received).text)
        a.receive((fromA[1] as TextEvent.Send).message,4.0);b.receive((fromB[1] as TextEvent.Send).message,4.0)
        rejected{a.receive(aBody,5.0)}
        val denied=TextProtocol(true);val offer=denied.offer("sensitive",0.0);val receiver=TextProtocol(true);receiver.receive(offer,0.0)
        assertTrue(denied.receive(receiver.decide(false,1.0),1.0).single() is TextEvent.Denied)
        val premature=TextProtocol(true);premature.receive(offer,0.0)
        rejected{premature.receive(Message.make("textData",mapOf("offerId" to offer.id,"text" to "sensitive")),1.0)}
        val unpaired=TextProtocol(false);rejected{unpaired.offer("no",0.0)}
        val timeout=TextProtocol(true);timeout.offer("no",0.0);assertTrue(timeout.expired(60.0))
    }
    private fun <T> storage(block:(Path,FileStorage)->T):T {
        val root=Files.createTempDirectory("hf-owned-test-");val store=FileStorage(root.resolve("private"))
        try{return block(root,store)}finally{Files.walk(root).use{paths->paths.sorted(Comparator.reverseOrder()).forEach{Files.deleteIfExists(it)}}}
    }
    @Test fun fileStreamingAndBoundaries()=storage{root,store->
        for(size in listOf(0,1,32768,65539,9_999_999,10_000_000,10_000_001)){
            val bytes=ByteArray(size){(it%256).toByte()};val attempt=runCatching{store.snapshot(ByteArrayInputStream(bytes),"공개 문서.bin")}
            assertEquals(size<=10_000_000,attempt.isSuccess)
            if(attempt.isFailure)continue
            val a=FileTransfer(true);val b=FileTransfer(true)
            val offered=a.offer(attempt.getOrThrow(),0.0);assertTrue(b.receive(offered,0.0).single() is FileEvent.Consent)
            rejected{a.next(0.5)}
            a.receive(b.decide(true,store,1.0),1.0)
            var record:StoredFile?=null
            while(record==null){when(val item=a.next(2.0)){
                is PumpItem.Chunk->{val decoded=FrameDecoder().feed(FrameDecoder.chunk(item.value)).single() as Frame.Chunk;b.receive(decoded,2.0)}
                is PumpItem.End->{val result=b.receive(item.message,2.0);record=(result[0] as FileEvent.Saved).file;a.receive((result[1] as FileEvent.Send).message,3.0)}
            }}
            assertArrayEquals(bytes,store.verifiedBytes(record));assertFalse(a.busy||b.busy)
        }
        val unknown=root.resolve("user.txt");Files.write(unknown,byteArrayOf(9));store.recover();assertTrue(Files.exists(unknown))
    }
    @Test fun partialCancellationHashQuotaCollisionAndCleanup()=storage{_,store->
        val bytes=byteArrayOf(1,2,3,4);val id=UUID.randomUUID().toString()
        val partial=store.receive(4,shaHex(bytes));partial.append(Frame.Chunk(id,0,bytes.copyOf(2)))
        assertTrue(store.files().isEmpty());partial.close();assertTrue(store.files().isEmpty())
        Files.newDirectoryStream(store.root).use{assertFalse(it.iterator().hasNext())}
        for(mode in listOf("hash","size","offset","quota")){
            val sink=store.receive(4,if(mode=="hash")"0".repeat(64)else shaHex(bytes),if(mode=="quota")2 else 10_000_000)
            try{rejected{sink.append(Frame.Chunk(id,if(mode=="offset")1 else 0,if(mode=="size")bytes.copyOf(2)else bytes));sink.finish("ok.bin",UUID.randomUUID().toString())}}
            finally{sink.close()}
        }
        fun save(id:String):StoredFile {val sink=store.receive(4,shaHex(bytes));try{sink.append(Frame.Chunk(id,0,bytes));return sink.finish("same.bin",id)}finally{sink.close()}}
        val saved=save(id);rejected{save(id)};assertArrayEquals(bytes,store.verifiedBytes(saved))
        val untouched=store.root.resolve("unrelated.txt");Files.write(untouched,bytes)
        val orphan=store.root.resolve(".hf-stage-${UUID.randomUUID()}.part");Files.write(orphan,bytes)
        val alias=store.root.resolve(".hf-stage-${UUID.randomUUID()}.part");Files.createSymbolicLink(alias,untouched)
        store.recover();assertFalse(Files.exists(orphan));assertTrue(Files.isSymbolicLink(alias));assertArrayEquals(bytes,Files.readAllBytes(untouched))
        assertEquals(1,store.files().size)
    }
    @Test fun onLinkFilters(){
        fun ip(s:String)=OnLink.numericV4(s)
        assertTrue(OnLink.allowed(ip("192.168.7.20"),ip("192.168.7.21"),24))
        for(s in listOf("192.168.7.20","192.168.8.21","192.168.7.0","192.168.7.255","8.8.8.8","127.0.0.1"))assertFalse(s,OnLink.allowed(ip("192.168.7.20"),ip(s),24))
        rejected{ip("example.com")};rejected{ip("192.168.1.01")}
    }
    // Standard RFC 5280 DER fixture encoding only; all test keys stay in memory.
    private fun certificate(pair:KeyPair,now:Long=System.currentTimeMillis()):X509Certificate {
        fun der(tag:Int,value:ByteArray):ByteArray {
            val length=if(value.size<128)byteArrayOf(value.size.toByte())else{
                val b=java.math.BigInteger.valueOf(value.size.toLong()).toByteArray().dropWhile{it==0.toByte()}.toByteArray();byteArrayOf((128+b.size).toByte())+b}
            return byteArrayOf(tag.toByte())+length+value
        }
        fun seq(value:ByteArray)=der(0x30,value)
        val alg=hex("300a06082a8648ce3d040302")
        val name=seq(der(0x31,seq(hex("0603550403")+der(12,"HF memory test".toByteArray()))))
        val format=SimpleDateFormat("yyyyMMddHHmmss'Z'",Locale.US).apply{timeZone=TimeZone.getTimeZone("UTC")}
        fun date(n:Long)=der(0x18,format.format(Date(n)).toByteArray(Charsets.US_ASCII))
        val extensions=der(0xa3,seq(seq(hex("0603551d130101ff")+der(4,seq(byteArrayOf())))+
            seq(hex("0603551d0f0101ff")+der(4,der(3,byteArrayOf(7,0x80.toByte()))))+
            seq(hex("0603551d25")+der(4,seq(hex("06082b0601050507030106082b06010505070302"))))))
        val tbs=seq(der(0xa0,der(2,byteArrayOf(2)))+der(2,byteArrayOf(1))+alg+name+seq(date(now-300000)+date(now+365L*86400000))+name+pair.public.encoded+extensions)
        val signature=Signature.getInstance("SHA256withECDSA").apply{initSign(pair.private);update(tbs)}.sign()
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(seq(tbs+alg+der(3,byteArrayOf(0)+signature)))) as X509Certificate
    }
    private fun identity():LocalIdentity {
        val pair=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        return LocalIdentity(pair.private,certificate(pair),PublicPin.digest(pair.public),"memory-only test")
    }
    @Test fun nativeCertificateRejection(){
        val id=identity();PinnedTrust(id.pin).checkServerTrusted(arrayOf(id.certificate),"ECDHE_ECDSA")
        rejected{PinnedTrust(ByteArray(32)).checkServerTrusted(arrayOf(id.certificate),"ECDHE_ECDSA")}
        val pair=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        for(offset in listOf(-370L*86400000,2L*86400000)){
            val cert=certificate(pair,System.currentTimeMillis()+offset)
            rejected{PinnedTrust(PublicPin.digest(pair.public)).checkServerTrusted(arrayOf(cert),"ECDHE_ECDSA")}
        }
    }
    @Test fun nativeMutualTls13Loopback(){
        val a=identity();val b=identity();val serverTls=PinnedTls(b,a.pin);val clientTls=PinnedTls(a,b.pin)
        val server=serverTls.context.serverSocketFactory.createServerSocket(0,1,InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.enabledProtocols=arrayOf("TLSv1.3");server.needClientAuth=true;server.soTimeout=5000
        val executor=Executors.newSingleThreadExecutor()
        val task=executor.submit<ByteArray>{(server.accept() as SSLSocket).use{socket->val pin=serverTls.handshake(socket,false);assertEquals(7,socket.inputStream.read());socket.outputStream.write(9);pin}}
        try{
            (clientTls.context.socketFactory.createSocket(InetAddress.getLoopbackAddress(),server.localPort) as SSLSocket).use{socket->
                assertArrayEquals(b.pin,clientTls.handshake(socket,true));socket.outputStream.write(7);assertEquals(9,socket.inputStream.read())
            }
            assertArrayEquals(a.pin,task.get(8,TimeUnit.SECONDS))
        }finally{server.close();executor.shutdownNow()}
    }
    @Test fun nativeMissingClientAndTls12Rejected(){
        for(mode in listOf("missing-client","tls12","wrong-pin")){
            val a=identity();val b=identity();val serverTls=PinnedTls(b,a.pin)
            val server=serverTls.context.serverSocketFactory.createServerSocket(0,1,InetAddress.getLoopbackAddress()) as SSLServerSocket
            server.enabledProtocols=arrayOf("TLSv1.3");server.needClientAuth=true;server.soTimeout=4000
            val executor=Executors.newSingleThreadExecutor()
            val task=executor.submit<Boolean>{runCatching{(server.accept() as SSLSocket).use{serverTls.handshake(it,false)}}.isSuccess}
            try{
                val trust=PinnedTrust(if(mode=="wrong-pin")ByteArray(32)else b.pin)
                val context=if(mode=="missing-client")SSLContext.getInstance("TLSv1.3").apply{init(emptyArray(),arrayOf(trust),SecureRandom())}
                    else PinnedTls(a,if(mode=="wrong-pin")ByteArray(32)else b.pin).context
                val failed=runCatching{
                    (context.socketFactory.createSocket(InetAddress.getLoopbackAddress(),server.localPort) as SSLSocket).use{socket->
                        socket.enabledProtocols=arrayOf(if(mode=="tls12")"TLSv1.2" else "TLSv1.3");socket.soTimeout=4000
                        socket.startHandshake();checkWire(socket.inputStream.read()>=0)
                    }
                }.isFailure
                assertTrue(mode,failed);assertFalse(mode,task.get(6,TimeUnit.SECONDS))
            }finally{server.close();executor.shutdownNow()}
        }
    }

    @Test fun nativeNsdTypeSpellings(){
        for(value in listOf("_hinanaflow._tcp","_hinanaflow._tcp.","._hinanaflow._tcp","._HINANAFLOW._TCP"))assertEquals("_hinanaflow._tcp",ServiceType.canonical(value))
        for(value in listOf("",".._hinanaflow._tcp","._hinanaflow._tcp.","_hinanaflow._tcp.local.","_hinanaflow._tcp.example.com.","_http._tcp","_hinanaflow._udp"))assertNull(ServiceType.canonical(value))
    }

}
