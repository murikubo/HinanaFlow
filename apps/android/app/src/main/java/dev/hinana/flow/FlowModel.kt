package dev.hinana.flow

import android.app.Application
import android.net.*
import android.os.SystemClock
import androidx.compose.runtime.*
import dev.hinana.flow.core.*
import dev.hinana.flow.platform.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.InputStream
import java.net.*
import java.nio.file.Paths
import javax.net.ssl.SSLSocket

/** UI/protocol mutations stay on Main. Blocking OS operations run on IO; tokens discard stale completions. */
class FlowModel(private val app:Application) {
    var status by mutableStateOf("공유할 준비가 됐어요");private set
    var fingerprint by mutableStateOf("");private set
    var hardware by mutableStateOf("");private set
    var expected by mutableStateOf("")
    var oob by mutableStateOf(false)
    var storedTrust by mutableStateOf(false);private set
    var peers by mutableStateOf<List<Discovery.Peer>>(emptyList());private set
    var selected by mutableStateOf<Discovery.Peer?>(null)
    var busy by mutableStateOf(false);private set
    var connected by mutableStateOf(false);private set
    var preparing by mutableStateOf(false);private set
    var textConsent by mutableStateOf("");private set
    var fileConsent by mutableStateOf("");private set
    var receivedText by mutableStateOf("");private set
    var draft by mutableStateOf("")
    var fileSummary by mutableStateOf("");private set
    var prepared by mutableStateOf(false);private set
    var files by mutableStateOf<List<StoredFile>>(emptyList());private set
    var manualHost by mutableStateOf("")
    var manualPort by mutableStateOf("45731")
    private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private val store=IdentityStore(app)
    private val lan=Lan(app)
    private val cm=app.getSystemService(ConnectivityManager::class.java)
    private val discovery=Discovery(app,{peers=it},{stop("HF-N-NSD — 탐색·광고 종료")})
    private var identity:LocalIdentity?=null
    private var storage:FileStorage?=null
    private var snapshot:FileSnapshot?=null
    private var snapshotID:String?=null
    private var auth=Authentication()
    private var text=TextProtocol(false)
    private var transfer=FileTransfer(false)
    @Volatile private var foreground=false
    @Volatile private var generation=0L
    private var connectionJob:Job?=null
    private var timer:Job?=null
    private var monitor:ConnectivityManager.NetworkCallback?=null
    private var raw:Socket?=null
    private var tls:SSLSocket?=null
    private var listener:ServerSocket?=null
    private val sourceLock=Any()
    private var source:InputStream?=null
    private var querySignal:android.os.CancellationSignal?=null
    private val writeLock=Mutex()
    private var end=0.0;private var last=0.0;private var handshakeEnd=0.0
    private var frameEnd:Double?=null;private var writeEnd:Double?=null
    private var decoder=FrameDecoder()
    private fun now()=SystemClock.elapsedRealtime()/1000.0
    private fun valid(token:Long)=foreground && token==generation
    private fun storage():FileStorage {
        storage?.let{return it}
        return FileStorage(Paths.get(app.noBackupFilesDir.path,"HinanaFlowTransfers")).also{it.recover();storage=it}
    }
    private fun error(e:Exception)=when(e){
        is ProtocolFailure->e.code
        is java.net.SocketTimeoutException->"HF-N-TIMEOUT"
        is java.security.cert.CertificateException->"HF-T-CERT"
        is javax.net.ssl.SSLException->"HF-T-TLS"
        is java.io.IOException->"HF-F-IO"
        else->"HF-OS-"+e.javaClass.simpleName
    }
    fun setActive(active:Boolean) {
        foreground=active;auth.setActive(active)
        if(!active)stop("앱 비활성 — 연결·요청·본문 정리됨")
    }
    fun notice(message:String){status=message}
    fun dispose(){setActive(false);scope.cancel()}
    fun prepare() {
        if(!foreground || busy || preparing)return
        val token=generation;preparing=true
        scope.launch {
            try{
                val id=withContext(Dispatchers.IO){store.loadOrCreate()}
                val pin=withContext(Dispatchers.IO){store.trusted(id.pin)}
                if(!valid(token))return@launch
                identity=id;fingerprint=PublicPin.hex(id.pin);hardware=id.security
                storedTrust=pin!=null;if(pin!=null)expected=PublicPin.hex(pin)
                status=if(storedTrust)"저장된 상대 키가 있습니다" else "양쪽 화면의 전체 지문을 직접 확인하세요"
                refreshFiles()
            }catch(e:Exception){if(valid(token)){identity=null;fingerprint="";storedTrust=false;status="신원 준비 실패 — "+error(e)}}
            finally{if(generation==token)preparing=false}
        }
    }
    private suspend fun configure(token:Long):Pair<LocalIdentity,ByteArray> {
        checkWire(valid(token))
        val id=identity?:throw ProtocolFailure("HF-S-IDENTITY")
        val pin=PublicPin.parse(expected)
        val previous=withContext(Dispatchers.IO){store.trusted(id.pin)}
        checkWire(valid(token))
        if(id.pin.contentEquals(pin))throw ProtocolFailure("HF-S-SELF")
        if(previous==null && !oob)throw ProtocolFailure("HF-S-OOB")
        if(previous!=null && !previous.contentEquals(pin))throw ProtocolFailure("HF-S-CHANGED")
        auth.begin(id.pin,pin,previous,oob)
        return id to pin
    }
    fun browse() {
        if(!foreground || busy || preparing)return
        discovery.stop();peers=emptyList();busy=true
        val token=generation
        try{
            val network=lan.wifi();monitor(network,token);discovery.browse(network);status="주변 기기 찾는 중 · 발견 이름은 미확인"
            timer=scope.launch{delay(60_000);if(valid(token))stop("탐색 시간이 끝났습니다")}
        }catch(e:Exception){stop(error(e))}
    }
    private fun monitor(network:Network,token:Long) {
        val signature=lan.signature(network)
        val callback=object:ConnectivityManager.NetworkCallback(){
            override fun onLost(n:Network){if(n==network)scope.launch{if(valid(token))stop("LAN 연결 종료 — 직접 다시 시작하세요")}}
            override fun onLinkPropertiesChanged(n:Network,p:LinkProperties){if(n==network)scope.launch{
                if(valid(token) && runCatching{lan.signature(network)!=signature}.getOrDefault(true))stop("LAN 변경 — 직접 다시 시작하세요")
            }}
        }
        monitor=callback
        cm.registerNetworkCallback(NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback)
    }
    /** Resolves the explicit untrusted selection afresh, including after a file picker interruption. */
    fun connect(sendFile:Boolean=false,manual:Boolean=false) {
        if(!foreground || preparing || connected)return
        val chosen=selected
        if(!manual && chosen==null){status="주변 기기를 먼저 선택하세요";return}
        val staged=snapshot;val selection=snapshotID
        if(sendFile && staged==null){status="파일을 먼저 선택하세요";return}
        // Preserve only the explicit staged file and candidate across this user action.
        snapshot=null;snapshotID=null;stop("상대 확인 중");snapshot=staged;snapshotID=selection;prepared=staged!=null
        val token=generation;busy=true;val approvedOob=oob
        connectionJob=scope.launch {
            var stage="CONFIG"
            try{
                val (id,pin)=configure(token);val network=lan.wifi();monitor(network,token)
                handshakeEnd=now()+10;startTimer(token);stage="RESOLVE"
                val endpoint=if(manual){checkWire(manualPort.toIntOrNull() in 1024..65535);OnLink.numericV4(manualHost) to manualPort.toInt()}
                    else discovery.resolve(chosen!!,network)
                checkWire(valid(token));val route=lan.route(endpoint.first,network);stage="TCP"
                val native=PinnedTls(id,pin);val socket=Socket();raw=socket
                val secure=withContext(Dispatchers.IO){
                    route.network.bindSocket(socket);socket.bind(InetSocketAddress(route.local,0));socket.connect(InetSocketAddress(route.peer,endpoint.second),10_000)
                    native.context.socketFactory.createSocket(socket,route.peer.hostAddress,endpoint.second,true) as SSLSocket
                }
                if(!valid(token)){secure.close();return@launch};tls=secure
                stage="TLS"
                val actual=withContext(Dispatchers.IO){native.handshake(secure,true)}
                stage="TRUST";established(token,native,actual,approvedOob)
                stage="DATA"
                if(sendFile){checkWire(snapshot===staged && snapshotID==selection);offerFile(token)}
                read(token)
            }catch(e:CancellationException){throw e}catch(e:Exception){if(valid(token))stop("연결 종료 — HF-C-$stage / "+error(e))}
        }
    }
    fun listen() {
        if(!foreground || busy || preparing)return
        stop();val token=generation;busy=true;val approvedOob=oob
        connectionJob=scope.launch {
            try{
                val (id,pin)=configure(token);val network=lan.wifi();monitor(network,token)
                val local=lan.localV4(network);val server=ServerSocket();listener=server
                withContext(Dispatchers.IO){server.reuseAddress=false;server.bind(InetSocketAddress(local,0));server.soTimeout=60_000}
                checkWire(valid(token));handshakeEnd=now()+60;startTimer(token)
                discovery.advertise(network,server.localPort);status="받기 대기 중 · 전면 60초"
                val socket=withContext(Dispatchers.IO){server.accept()}
                if(!valid(token)){socket.close();return@launch};raw=socket;handshakeEnd=now()+10
                val route=lan.route(socket.inetAddress,network);checkWire(route.local==socket.localAddress)
                val native=PinnedTls(id,pin)
                val secure=withContext(Dispatchers.IO){native.context.socketFactory.createSocket(socket,socket.inetAddress.hostAddress,socket.port,true) as SSLSocket}
                if(!valid(token)){secure.close();return@launch};tls=secure
                val actual=withContext(Dispatchers.IO){native.handshake(secure,false)}
                established(token,native,actual,approvedOob);read(token)
            }catch(e:CancellationException){throw e}catch(e:Exception){if(valid(token))stop("받기 종료 — "+error(e))}
        }
    }
    private suspend fun established(token:Long,native:PinnedTls,actual:ByteArray,approved:Boolean) {
        checkWire(valid(token));auth.tls(actual,true,native.trust.verified,true)
        withContext(Dispatchers.IO){store.confirm(native.identity.pin,actual,approved,true)}
        checkWire(valid(token));auth.persisted();connected=true;storedTrust=true
        text=TextProtocol(true);transfer=FileTransfer(true);decoder=FrameDecoder();last=now();end=last+600
        discovery.stopBrowsing();status="상호 TLS 1.3 인증됨 · 건별 수신 승인"
    }
    private fun startTimer(token:Long) {
        timer?.cancel();timer=scope.launch{while(valid(token)&&busy){delay(250);val n=now()
            if((!connected && n>=handshakeEnd)||(connected && (n>=end || n-last>=90 || text.expired(n) || transfer.expired(n)))||
                (frameEnd?.let{n>=it}?:false)||(writeEnd?.let{n>=it}?:false)){stop("시간 제한 — 연결 종료됨");return@launch}
        }}
    }
    private suspend fun read(token:Long) {
        val socket=tls?:throw ProtocolFailure();val input=socket.inputStream;val buffer=ByteArray(32768)
        while(valid(token)&&connected){
            val count=try{withContext(Dispatchers.IO){input.read(buffer)}}catch(e:SocketTimeoutException){continue}
            if(count<0){decoder.finish();stop("상대 연결 종료 — 요청·본문 정리됨");return}
            checkWire(valid(token) && count>0);auth.requireReady();last=now()
            for(frame in decoder.feed(buffer.copyOf(count))) {
                when(frame){
                    is Frame.Control->{val m=ControlJson.parse(frame.data)
                        if(m.type.startsWith("file"))fileEvents(transfer.receive(m,now()),token)else textEvents(text.receive(m,now()),token)}
                    is Frame.Chunk->transfer.receive(frame,now())
                }
            }
            frameEnd=if(decoder.partial)frameEnd?:now()+10 else null
        }
    }
    private suspend fun write(bytes:ByteArray,token:Long) = writeLock.withLock {
        checkWire(valid(token));auth.requireReady();val socket=tls?:throw ProtocolFailure();writeEnd=now()+10
        try{withContext(Dispatchers.IO){socket.outputStream.write(bytes);socket.outputStream.flush()};checkWire(valid(token));last=now()}
        finally{if(generation==token)writeEnd=null}
    }
    private suspend fun send(m:Message,token:Long)=write(FrameDecoder.control(m.encoded()),token)
    private suspend fun textEvents(events:List<TextEvent>,token:Long) {
        for(event in events)when(event){
            is TextEvent.Send->send(event.message,token)
            is TextEvent.Consent->{textConsent="텍스트 제안: ${event.bytes} bytes / ${event.scalars} scalars"}
            is TextEvent.Received->{textConsent="";receivedText=event.text;status="텍스트 수신 완료"}
            TextEvent.Delivered->status="상대 텍스트 수신 확인 완료"
            TextEvent.Denied->{textConsent="";status="텍스트 제안 거절·취소됨"}
        }
    }
    private suspend fun fileEvents(events:List<FileEvent>,token:Long) {
        for(event in events)when(event){
            is FileEvent.Send->send(event.message,token)
            is FileEvent.Consent->fileConsent="${event.name} / ${event.size} bytes"
            is FileEvent.Saved->{fileConsent="";fileSummary="크기·SHA-256 검증 및 저장 완료";refreshFiles()}
            FileEvent.Start->scope.launch{try{while(valid(token)&&transfer.sending){when(val item=transfer.next(now())){
                is PumpItem.Chunk->write(FrameDecoder.chunk(item.value),token)
                is PumpItem.End->send(item.message,token)
            }}}catch(e:CancellationException){throw e}catch(e:Exception){if(valid(token))stop("파일 전송 종료 — "+error(e))}}
            FileEvent.Delivered->{fileSummary="상대 파일 수신 확인 완료";prepared=false}
            FileEvent.Denied->{fileConsent="";fileSummary="파일 제안 거절·취소됨"}
        }
    }
    fun sendText(){action{val m=text.offer(draft,now());draft="";send(m,generation);status="텍스트 본문 전송 전 승인 대기"}}
    fun decideText(accept:Boolean){action{send(text.decide(accept,now()),generation);textConsent=""}}
    fun decideFile(accept:Boolean){action{val m=transfer.decide(accept,storage(),now());send(m,generation);fileConsent="";fileSummary=if(accept)"승인됨 — 수신·검증 중" else "파일 거절됨"}}
    private fun action(block:suspend()->Unit){if(!foreground || !connected)return;val token=generation;scope.launch{try{auth.requireReady();block()}catch(e:CancellationException){throw e}catch(e:Exception){if(valid(token))stop(error(e))}}}
    private suspend fun offerFile(token:Long){auth.requireReady();val file=snapshot?:throw ProtocolFailure();val m=transfer.offer(file,now());snapshot=null;snapshotID=null;prepared=false;send(m,token);fileSummary="파일 본문 전송 전 상대 승인 대기"}
    fun stageFile(uri:android.net.Uri) {
        if(!foreground || busy || preparing)return
        val token=generation;preparing=true
        status="선택한 파일을 안전하게 준비하는 중"
        val signal=android.os.CancellationSignal();querySignal=signal
        val deadline=scope.launch{delay(20_000);if(valid(token) && preparing)stop("파일 준비 시간 초과 — 선택을 취소했습니다")}
        scope.launch{
            try{
                checkWire(uri.scheme=="content")
                val fileStore=storage()
                val staged=withContext(Dispatchers.IO){
                    var name="selected-file"
                    app.contentResolver.query(uri,arrayOf(android.provider.OpenableColumns.DISPLAY_NAME,android.provider.OpenableColumns.SIZE),null,null,null,signal)?.use{c->
                        if(c.moveToFirst()){val ni=c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);if(ni>=0)name=c.getString(ni)?:name
                            val si=c.getColumnIndex(android.provider.OpenableColumns.SIZE);if(si>=0 && !c.isNull(si))checkWire(c.getLong(si) in 0..FileStorage.MAX)}
                    }
                    checkWire(valid(token))
                    val input=app.contentResolver.openInputStream(uri)?:throw ProtocolFailure("HF-F-SOURCE")
                    try{
                        synchronized(sourceLock){checkWire(valid(token));source=input}
                        input.use {stream->
                            fileStore.snapshot(object:java.io.FilterInputStream(stream){
                                override fun read(b:ByteArray,off:Int,len:Int):Int {checkWire(valid(token));return super.read(b,off,len)}
                            },name)
                        }
                    }finally{input.close();synchronized(sourceLock){if(source===input)source=null}}
                }
                if(!valid(token)){staged.close();return@launch}
                snapshot?.close();snapshot=staged;snapshotID=java.util.UUID.randomUUID().toString();prepared=true
                fileSummary="파일 준비됨: ${staged.name} / ${staged.size} bytes"
                status="파일 준비 완료 — 선택 기기에 직접 보내세요"
            }catch(e:Exception){if(valid(token)){prepared=false;fileSummary="파일 준비 실패 — "+error(e);status=fileSummary}}
            finally{deadline.cancel();if(generation==token){preparing=false;querySignal=null}}
        }
    }
    fun refreshFiles(){if(!foreground)return;try{files=storage().files()}catch(e:Exception){fileSummary="저장소 확인 실패 — "+error(e)}}
    fun exportBytes(file:StoredFile):ByteArray? {
        if(!foreground || busy)return null
        return try{storage().verifiedBytes(file)}catch(e:Exception){fileSummary="내보내기 검증 실패 — "+error(e);null}
    }
    fun exported(success:Boolean){fileSummary=if(success)"사용자 지정 위치로 내보내기 완료" else "내보내기 취소·실패 — 검증 원본 보존"}
    fun stop(reason:String="공유할 준비가 됐어요") {
        generation++;connectionJob?.cancel();connectionJob=null;timer?.cancel();timer=null
        raw?.run{runCatching{close()}};raw=null;tls?.run{runCatching{close()}};tls=null;listener?.run{runCatching{close()}};listener=null
        querySignal?.cancel();querySignal=null
        val reading=synchronized(sourceLock){source.also{source=null}}
        reading?.let{runCatching{it.close()}}
        monitor?.let{runCatching{cm.unregisterNetworkCallback(it)}};monitor=null;discovery.stop()
        auth.close();text=TextProtocol(false);transfer.cancel();transfer=FileTransfer(false);decoder=FrameDecoder()
        snapshot?.close();snapshot=null;snapshotID=null;prepared=false;busy=false;connected=false;preparing=false
        textConsent="";fileConsent="";receivedText="";draft="";fileSummary="";files=emptyList();frameEnd=null;writeEnd=null
        status=reason
    }
}
