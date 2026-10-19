package dev.hinana.flow.platform

import android.content.Context
import android.net.*
import dev.hinana.flow.core.*
import java.net.*

object OnLink {
    fun privateV4(a:ByteArray):Boolean {
        if(a.size!=4)return false
        val x=a.map{it.toInt() and 255}
        return x[0]==10 || (x[0]==172 && x[1] in 16..31) || (x[0]==192 && x[1]==168) || (x[0]==169 && x[1]==254)
    }
    fun samePrefix(a:ByteArray,b:ByteArray,prefix:Int):Boolean {
        if(a.size!=b.size || prefix !in 1..a.size*8)return false
        return (0 until prefix).all{bit->(a[bit/8].toInt() and (128 shr (bit%8)))==(b[bit/8].toInt() and (128 shr (bit%8)))}
    }
    fun allowed(local:InetAddress,peer:InetAddress,prefix:Int):Boolean {
        if(local==peer || peer.isAnyLocalAddress || peer.isLoopbackAddress || peer.isMulticastAddress)return false
        val a=local.address;val b=peer.address
        if(a.size!=b.size)return false
        if(a.size==4){
            if(prefix !in 16..30 || !privateV4(a) || !privateV4(b) || !samePrefix(a,b,prefix))return false
            val hostBits=32-prefix;val n=b.fold(0L){n,v->(n shl 8) or (v.toLong() and 255)}
            val host=n and ((1L shl hostBits)-1);return host!=0L && host!=(1L shl hostBits)-1
        }
        if(a.size!=16)return false
        if(local.isLinkLocalAddress && peer.isLinkLocalAddress)return true
        return prefix in 64..126 && (a[0].toInt() and 254)==252 && (b[0].toInt() and 254)==252 && samePrefix(a,b,prefix)
    }
    fun numericV4(value:String):InetAddress {
        val parts=value.split('.');checkWire(parts.size==4 && parts.all{Regex("0|[1-9][0-9]{0,2}").matches(it) && it.toInt()<=255})
        return InetAddress.getByAddress(parts.map{it.toInt().toByte()}.toByteArray())
    }
}
class Lan(private val context:Context) {
    private val cm=context.getSystemService(ConnectivityManager::class.java)
    data class Route(val network:Network,val local:InetAddress,val prefix:Int,val signature:String,val peer:InetAddress)
    fun wifi():Network=cm.allNetworks.firstOrNull{n->cm.getNetworkCapabilities(n)?.let{it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)}==true}?:throw ProtocolFailure("HF-N-WIFI")
    fun signature(network:Network):String {
        val p=cm.getLinkProperties(network)?:throw ProtocolFailure("HF-N-LOST")
        return network.toString()+":"+p.interfaceName+":"+p.linkAddresses.map{it.toString()}.sorted().joinToString(",")
    }
    fun route(peer:InetAddress,network:Network=wifi()):Route {
        checkWire(wifi()==network)
        val p=cm.getLinkProperties(network)?:throw ProtocolFailure("HF-N-LOST")
        val iface=NetworkInterface.getByName(p.interfaceName)?:throw ProtocolFailure("HF-N-INTERFACE")
        val scoped=if(peer is Inet6Address && peer.isLinkLocalAddress){
            checkWire(peer.scopeId==0 || peer.scopeId==iface.index)
            Inet6Address.getByAddress(null,peer.address,iface)
        }else peer
        val local=p.linkAddresses.firstOrNull{OnLink.allowed(it.address,peer,it.prefixLength)}?:throw ProtocolFailure("HF-N-ONLINK")
        return Route(network,local.address,local.prefixLength,signature(network),scoped)
    }
    fun localV4(network:Network=wifi()):InetAddress=cm.getLinkProperties(network)?.linkAddresses?.firstOrNull{it.address is Inet4Address && OnLink.privateV4(it.address.address)}?.address?:throw ProtocolFailure("HF-N-IPV4")
}
