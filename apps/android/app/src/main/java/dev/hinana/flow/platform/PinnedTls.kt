package dev.hinana.flow.platform

import dev.hinana.flow.core.*
import java.net.Socket
import java.security.*
import java.security.cert.X509Certificate
import javax.net.ssl.*

/** The pinned self-signed leaf is an explicit anchor, never an accept-all TrustManager. */
class PinnedTrust(private val expected:ByteArray):X509ExtendedTrustManager() {
    @Volatile var verified=false;private set
    private fun validate(chain:Array<out X509Certificate>?,auth:String?,server:Boolean) {
        try { validatePinned(chain,auth,server) }
        catch(e:Exception) {throw java.security.cert.CertificateException("HF-T-PIN-CERT",e)}
    }
    private fun validatePinned(chain:Array<out X509Certificate>?,auth:String?,server:Boolean) {
        checkWire(expected.size==32 && chain!=null && chain.size==1 && !auth.isNullOrEmpty())
        val cert=chain!![0]
        checkWire(MessageDigest.isEqual(expected,PublicPin.digest(cert.publicKey)))
        cert.checkValidity();cert.verify(cert.publicKey)
        val anchors=KeyStore.getInstance(KeyStore.getDefaultType()).apply{load(null);setCertificateEntry("approved-leaf",cert)}
        val manager=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply{init(anchors)}
            .trustManagers.filterIsInstance<X509TrustManager>().single()
        if(server)manager.checkServerTrusted(chain,auth) else manager.checkClientTrusted(chain,auth)
        verified=true
    }
    override fun getAcceptedIssuers():Array<X509Certificate> = emptyArray()
    override fun checkServerTrusted(c:Array<out X509Certificate>?,a:String?)=validate(c,a,true)
    override fun checkClientTrusted(c:Array<out X509Certificate>?,a:String?)=validate(c,a,false)
    override fun checkServerTrusted(c:Array<out X509Certificate>?,a:String?,s:Socket?)=validate(c,a,true)
    override fun checkClientTrusted(c:Array<out X509Certificate>?,a:String?,s:Socket?)=validate(c,a,false)
    override fun checkServerTrusted(c:Array<out X509Certificate>?,a:String?,s:SSLEngine?)=validate(c,a,true)
    override fun checkClientTrusted(c:Array<out X509Certificate>?,a:String?,s:SSLEngine?)=validate(c,a,false)
}
private class IdentityManager(private val identity:LocalIdentity):X509ExtendedKeyManager() {
    private val alias="own-identity"
    private fun supported(types:Array<out String>?):Boolean=types?.any{it=="EC" || it.startsWith("EC_")}==true
    override fun chooseClientAlias(t:Array<out String>?,i:Array<out Principal>?,s:Socket?):String?=if(supported(t))alias else null
    override fun chooseEngineClientAlias(t:Array<out String>?,i:Array<out Principal>?,e:SSLEngine?):String?=if(supported(t))alias else null
    override fun chooseServerAlias(t:String?,i:Array<out Principal>?,s:Socket?):String?=if(supported(arrayOf(t?:"")))alias else null
    override fun chooseEngineServerAlias(t:String?,i:Array<out Principal>?,e:SSLEngine?):String?=if(supported(arrayOf(t?:"")))alias else null
    override fun getClientAliases(t:String?,i:Array<out Principal>?):Array<String>?=if(supported(arrayOf(t?:"")))arrayOf(alias) else null
    override fun getServerAliases(t:String?,i:Array<out Principal>?):Array<String>?=getClientAliases(t,i)
    override fun getCertificateChain(a:String?):Array<X509Certificate>?=if(a==alias)arrayOf(identity.certificate)else null
    override fun getPrivateKey(a:String?):PrivateKey?=if(a==alias)identity.privateKey else null
}
class PinnedTls(val identity:LocalIdentity,val peer:ByteArray) {
    val trust=PinnedTrust(peer)
    // Fresh context per connection: no reuse of SSLSession cache across authentication attempts.
    val context:SSLContext=SSLContext.getInstance("TLSv1.3").apply{init(arrayOf(IdentityManager(identity)),arrayOf(trust),SecureRandom())}
    fun handshake(socket:SSLSocket,client:Boolean):ByteArray {
        socket.useClientMode=client
        socket.enabledProtocols=arrayOf("TLSv1.3")
        if(!client)socket.needClientAuth=true
        socket.soTimeout=10_000;socket.startHandshake()
        val session=socket.session
        checkWire(session.protocol=="TLSv1.3" && trust.verified)
        val remote=session.peerCertificates.firstOrNull() as? X509Certificate ?: throw ProtocolFailure("HF-T-PEER")
        val local=session.localCertificates?.firstOrNull() as? X509Certificate ?: throw ProtocolFailure("HF-T-LOCAL")
        checkWire(MessageDigest.isEqual(PublicPin.digest(local.publicKey),identity.pin))
        val pin=PublicPin.digest(remote.publicKey);checkWire(MessageDigest.isEqual(pin,peer))
        socket.soTimeout=1000;return pin
    }
}
