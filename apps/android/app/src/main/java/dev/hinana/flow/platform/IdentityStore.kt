package dev.hinana.flow.platform

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import dev.hinana.flow.core.*
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

object PublicPin {
    fun digest(key: PublicKey): ByteArray {
        val ec=key as? ECPublicKey ?: throw ProtocolFailure("HF-I-EC")
        val standard=AlgorithmParameters.getInstance("EC").apply{init(ECGenParameterSpec("secp256r1"))}.getParameterSpec(ECParameterSpec::class.java)
        val p=ec.params
        checkWire(p.order==standard.order && p.cofactor==standard.cofactor && p.curve==standard.curve && p.generator==standard.generator)
        fun coordinate(value:BigInteger):ByteArray {
            val b=value.toByteArray();checkWire(value.signum()>=0 && b.size<=33 && (b.size<=32 || b[0]==0.toByte()))
            return ByteArray(32).also {b.copyOfRange(maxOf(0,b.size-32),b.size).copyInto(it,32-minOf(32,b.size))}
        }
        return MessageDigest.getInstance("SHA-256").digest(byteArrayOf(4)+coordinate(ec.w.affineX)+coordinate(ec.w.affineY))
    }
    fun hex(value:ByteArray)=value.joinToString(""){"%02x".format(it.toInt() and 255)}
    fun parse(value:String):ByteArray {if(!Regex("[0-9a-fA-F]{64}").matches(value))throw ProtocolFailure("HF-S-PIN64");return value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()}
}

data class LocalIdentity(val privateKey:PrivateKey,val certificate:X509Certificate,val pin:ByteArray,val security:String)
/** All aliases belong only to this app. No enumeration, deletion or export. */
class IdentityStore(context:Context) {
    companion object {private val lock=Any()}
    fun loadOrCreate():LocalIdentity=synchronized(lock){loadOrCreateLocked()}
    fun trusted(local:ByteArray):ByteArray?=synchronized(lock){trustedLocked(local)}
    fun confirm(local:ByteArray,peer:ByteArray,oob:Boolean,mutual:Boolean)=synchronized(lock){confirmLocked(local,peer,oob,mutual)}
    private val keyAlias="dev.hinana.flow.identity.android.tls.v2"
    private val trustAlias="dev.hinana.flow.trust.aes.v1"
    private val record=AtomicFile(java.io.File(context.noBackupFilesDir,"peer-trust-v1"))
    private val aad="HinanaFlow Android peer trust v1".toByteArray(Charsets.US_ASCII)
    private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
    private fun hardware(info:KeyInfo):String {
        if(Build.VERSION.SDK_INT>=31) return when(info.securityLevel){
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT->"TEE"
            KeyProperties.SECURITY_LEVEL_STRONGBOX->"StrongBox"
            else->throw ProtocolFailure("HF-I-HARDWARE")
        }
        @Suppress("DEPRECATION")
        checkWire(info.isInsideSecureHardware)
        return "hardware (API 29/30)"
    }
    private fun loadOrCreateLocked():LocalIdentity {
        val ks=keyStore()
        if(!ks.containsAlias(keyAlias)) {
            KeyPairGenerator.getInstance("EC","AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(keyAlias,KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_NONE)
                    .setCertificateSubject(X500Principal("CN=Hinana Flow"))
                    .setCertificateSerialNumber(BigInteger(128,SecureRandom()).add(BigInteger.ONE))
                    .setCertificateNotBefore(Date(System.currentTimeMillis()-300_000))
                    .setCertificateNotAfter(Date(System.currentTimeMillis()+365L*86400_000))
                    .setUserAuthenticationRequired(false).setUnlockedDeviceRequired(true).build())
            }.generateKeyPair()
        }
        val privateKey=ks.getKey(keyAlias,null) as? PrivateKey ?: throw ProtocolFailure("HF-I-KEY")
        val info=KeyFactory.getInstance(privateKey.algorithm,"AndroidKeyStore").getKeySpec(privateKey,KeyInfo::class.java)
        val security=hardware(info);checkWire(info.keySize==256 && privateKey.encoded==null)
        if(!info.digests.toSet().containsAll(setOf(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_NONE)))throw ProtocolFailure("HF-I-TLS-DIGEST")
        val cert=ks.getCertificate(keyAlias) as? X509Certificate ?: throw ProtocolFailure("HF-I-CERT")
        cert.checkValidity();cert.verify(cert.publicKey)
        // Conscrypt delegates TLS's already-hashed ECDSA input via NONEwithECDSA.
        // This is a local provider capability check, never a pairing/authentication scheme.
        val digest=MessageDigest.getInstance("SHA-256").digest("HinanaFlow native TLS key capability".toByteArray(Charsets.US_ASCII))
        val signature=Signature.getInstance("NONEwithECDSA").apply{initSign(privateKey);update(digest)}.sign()
        checkWire(Signature.getInstance("NONEwithECDSA").apply{initVerify(cert.publicKey);update(digest)}.verify(signature))
        return LocalIdentity(privateKey,cert,PublicPin.digest(cert.publicKey),security)
    }
    private fun trustKey(create:Boolean):SecretKey {
        val ks=keyStore()
        if(!ks.containsAlias(trustAlias)) {
            checkWire(create)
            KeyGenerator.getInstance("AES","AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(trustAlias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).setUnlockedDeviceRequired(true).build())
            }.generateKey()
        }
        val key=ks.getKey(trustAlias,null) as? SecretKey ?: throw ProtocolFailure("HF-I-TRUST")
        val info=SecretKeyFactory.getInstance("AES","AndroidKeyStore").getKeySpec(key,KeyInfo::class.java) as KeyInfo
        hardware(info);checkWire(key.encoded==null);return key
    }
    private fun trustedLocked(local:ByteArray):ByteArray? {
        if(!record.baseFile.exists() && !java.io.File(record.baseFile.path+".bak").exists())return null
        val packed=record.openRead().use{it.readNBytes(129)}
        checkWire(packed.size in 29..128 && packed[0]==1.toByte())
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,trustKey(false),GCMParameterSpec(128,packed.copyOfRange(1,13)));cipher.updateAAD(aad)
        val plain=cipher.doFinal(packed.copyOfRange(13,packed.size))
        checkWire(plain.size==64 && MessageDigest.isEqual(plain.copyOfRange(0,32),local))
        return plain.copyOfRange(32,64)
    }
    private fun confirmLocked(local:ByteArray,peer:ByteArray,oob:Boolean,mutual:Boolean) {
        checkWire(local.size==32 && peer.size==32 && mutual && !local.contentEquals(peer))
        val old=trusted(local)
        if(old!=null){checkWire(MessageDigest.isEqual(old,peer));return}
        checkWire(oob)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,trustKey(true));cipher.updateAAD(aad)
        checkWire(cipher.iv.size==12)
        val packed=byteArrayOf(1)+cipher.iv+cipher.doFinal(local+peer)
        val output=record.startWrite()
        try{output.write(packed);record.finishWrite(output)}catch(e:Exception){record.failWrite(output);throw e}
    }
}
