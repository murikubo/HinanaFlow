package dev.hinana.flow.platform

import android.content.Context
import android.net.Network
import android.net.nsd.*
import android.os.Build
import android.os.Handler
import android.os.Looper
import dev.hinana.flow.core.*
import java.net.InetAddress
import java.util.UUID
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout

/** Names/addresses are untrusted candidates. Selection is not authentication. */
class Discovery(private val context:Context,private val changed:(List<Peer>)->Unit,private val invalid:()->Unit) {
    data class Peer(val id:String,val label:String,val info:NsdServiceInfo)
    private val nsd=context.getSystemService(NsdManager::class.java)
    private val handler=Handler(Looper.getMainLooper())
    private var generation=0
    private var browser:NsdManager.DiscoveryListener?=null
    private var advertiser:NsdManager.RegistrationListener?=null
    private val peers=linkedMapOf<String,Peer>()
    private fun key(info:NsdServiceInfo)=info.serviceName+"\u0000"+ServiceType.canonical(info.serviceType)+"\u0000"+(if(Build.VERSION.SDK_INT>=33)info.network?.toString()?:"" else "")
    private fun label(raw:String)=buildString{raw.codePoints().limit(48).forEach{cp->if(Character.getType(cp) !in listOf(Character.CONTROL.toInt(),Character.FORMAT.toInt()))appendCodePoint(cp)}}.ifBlank{"Hinana Flow"}
    fun browse(network:Network) {
        stop();val token=generation
        val listener=object:NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(type:String){}
            override fun onDiscoveryStopped(type:String){}
            override fun onStartDiscoveryFailed(type:String,code:Int){handler.post{if(generation==token)invalid()}}
            override fun onStopDiscoveryFailed(type:String,code:Int){}
            override fun onServiceFound(info:NsdServiceInfo){handler.post{
                if(generation!=token || info.serviceName.toByteArray(Charsets.UTF_8).size !in 1..63 || ServiceType.canonical(info.serviceType)==null)return@post
                if(Build.VERSION.SDK_INT>=33 && info.network!=null && info.network!=network)return@post
                val key=key(info)
                if(peers.containsKey(key)||peers.size>=64)return@post
                peers[key]=Peer(UUID.randomUUID().toString(),label(info.serviceName),info);changed(peers.values.toList())
            }}
            override fun onServiceLost(info:NsdServiceInfo){handler.post{if(generation==token){peers.remove(key(info));changed(peers.values.toList())}}}
        }
        browser=listener
        if(Build.VERSION.SDK_INT>=33)nsd.discoverServices("_hinanaflow._tcp.",NsdManager.PROTOCOL_DNS_SD,network,{r->handler.post(r)},listener)
        else nsd.discoverServices("_hinanaflow._tcp.",NsdManager.PROTOCOL_DNS_SD,listener)
    }
    @Suppress("DEPRECATION")
    suspend fun resolve(peer:Peer,network:Network):Pair<InetAddress,Int> = withTimeout(5000){
        suspendCancellableCoroutine {cont->
            val token=generation
            val info=NsdServiceInfo().apply{serviceName=peer.info.serviceName;serviceType="_hinanaflow._tcp.";if(Build.VERSION.SDK_INT>=33)setNetwork(network)}
            val listener=object:NsdManager.ResolveListener {
                override fun onResolveFailed(i:NsdServiceInfo,code:Int){if(cont.isActive)cont.resumeWith(Result.failure(ProtocolFailure("HF-N-RESOLVE")))}
                override fun onServiceResolved(i:NsdServiceInfo){handler.post{
                    if(!cont.isActive)return@post
                    try{
                        if(token!=generation)throw ProtocolFailure("HF-N-STALE")
                        if(i.port !in 1024..65535)throw ProtocolFailure("HF-N-PORT")
                        if(ServiceType.canonical(i.serviceType)==null)throw ProtocolFailure("HF-N-TYPE")
                        if(i.serviceName!=info.serviceName)throw ProtocolFailure("HF-N-NAME")
                        if(Build.VERSION.SDK_INT>=33 && i.network!=network)throw ProtocolFailure("HF-N-INTERFACE")
                        val addresses=if(Build.VERSION.SDK_INT>=34)i.hostAddresses else listOfNotNull(i.host)
                        val lan=Lan(context)
                        val address=addresses.take(16).sortedBy{if(it.address.size==4)0 else 1}.firstOrNull{runCatching{lan.route(it,network)}.isSuccess}?:throw ProtocolFailure("HF-N-ONLINK")
                        cont.resume(address to i.port)
                    }catch(e:Exception){cont.resumeWith(Result.failure(e))}
                }}
            }
            nsd.resolveService(info,listener)
            cont.invokeOnCancellation{if(Build.VERSION.SDK_INT>=34)runCatching{nsd.stopServiceResolution(listener)}}
        }
    }
    fun advertise(network:Network,port:Int) {
        val info=NsdServiceInfo().apply{serviceName="Hinana Flow-"+UUID.randomUUID().toString().take(6);serviceType="_hinanaflow._tcp.";setPort(port);if(Build.VERSION.SDK_INT>=33)setNetwork(network)}
        val token=generation
        val listener=object:NsdManager.RegistrationListener {
            override fun onServiceRegistered(info:NsdServiceInfo){}
            override fun onServiceUnregistered(info:NsdServiceInfo){}
            override fun onRegistrationFailed(info:NsdServiceInfo,code:Int){handler.post{if(token==generation)invalid()}}
            override fun onUnregistrationFailed(info:NsdServiceInfo,code:Int){}
        }
        advertiser=listener;nsd.registerService(info,NsdManager.PROTOCOL_DNS_SD,listener)
    }
    fun stopBrowsing(){browser?.let{runCatching{nsd.stopServiceDiscovery(it)}};browser=null}
    fun stop(){generation++;stopBrowsing();advertiser?.let{runCatching{nsd.unregisterService(it)}};advertiser=null;peers.clear();changed(emptyList())}
}
