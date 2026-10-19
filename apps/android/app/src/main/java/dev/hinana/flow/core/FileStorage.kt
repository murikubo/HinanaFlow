package dev.hinana.flow.core

import org.json.JSONObject
import java.io.InputStream
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID

fun shaHex(data:ByteArray)=MessageDigest.getInstance("SHA-256").digest(data).joinToString(""){"%02x".format(it.toInt() and 255)}
private fun hashString(data:ByteArray)=data.joinToString(""){"%02x".format(it.toInt() and 255)}
private val stagePattern=Regex("\\.hf-stage-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.part")
private val finalPattern=Regex("received-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
data class StoredFile(val internalName:String,val name:String,val size:Long,val hash:String)

/** Only constructed with OS-owned app storage or an isolated automated test directory. */
class FileStorage(val root:Path) {
    companion object {const val MAX=10_000_000L}
    init {
        if(!Files.exists(root,LinkOption.NOFOLLOW_LINKS))Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        checkWire(Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(root))
        checkWire(Files.getPosixFilePermissions(root).none{it.name.startsWith("GROUP_")||it.name.startsWith("OTHERS_")})
    }
    internal fun stage():Pair<Path,FileChannel> {
        val path=root.resolve(".hf-stage-${UUID.randomUUID()}.part")
        val fd=FileChannel.open(path,setOf(StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        return path to fd
    }
    fun snapshot(input:InputStream,name:String):FileSnapshot {
        val safe=SharedFilename.normalize(name);val (path,fd)=stage();val digest=MessageDigest.getInstance("SHA-256");var count=0L
        try {
            val bytes=ByteArray(32768)
            while(true){val n=input.read(bytes);if(n<0)break;checkWire(n>0 && count+n<=MAX);count+=n;digest.update(bytes,0,n)
                val b=ByteBuffer.wrap(bytes,0,n);while(b.hasRemaining())fd.write(b)}
            fd.force(true);fd.position(0)
            return FileSnapshot(path,fd,safe,count,hashString(digest.digest()))
        }catch(e:Exception){fd.close();Files.deleteIfExists(path);throw e}
    }
    fun receive(size:Long,hash:String,writeBudget:Long=MAX):IncomingFile {
        checkWire(size in 0..MAX && Regex("[0-9a-f]{64}").matches(hash))
        return IncomingFile(this,size,hash,writeBudget)
    }
    internal fun publish(stage:Path,size:Long,hash:String,name:String,id:String):StoredFile {
        checkWire(UUID.fromString(id).toString()==id && SharedFilename.valid(name))
        val internal="received-$id";val dest=root.resolve(internal)
        // Atomic exclusive mkdir owns the namespace: never reuse an existing transaction.
        Files.createDirectory(dest,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        var completed=false
        try {
            Files.move(stage,dest.resolve("data.bin"),StandardCopyOption.ATOMIC_MOVE)
            val json=JSONObject().put("name",name).put("size",size).put("sha256",hash).toString().toByteArray(Charsets.UTF_8)
            FileChannel.open(dest.resolve("record-stage.json"),setOf(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {fd->
                val b=ByteBuffer.wrap(json);while(b.hasRemaining())fd.write(b);fd.force(true)
            }
            // The completion marker is published last in our exclusively created directory.
            Files.move(dest.resolve("record-stage.json"),dest.resolve("complete.json"),StandardCopyOption.ATOMIC_MOVE)
            FileChannel.open(dest,StandardOpenOption.READ).use{it.force(true)}
            FileChannel.open(root,StandardOpenOption.READ).use{it.force(true)}
            completed=true;return StoredFile(internal,name,size,hash)
        }finally{
            if(!completed){
                Files.deleteIfExists(dest.resolve("complete.json"));Files.deleteIfExists(dest.resolve("record-stage.json"))
                Files.deleteIfExists(dest.resolve("data.bin"));Files.deleteIfExists(dest)
            }
        }
    }
    fun files():List<StoredFile> {
        val result=mutableListOf<StoredFile>()
        Files.newDirectoryStream(root).use {entries->for(dir in entries){
            val name=dir.fileName.toString()
            if(!finalPattern.matches(name)||!Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))continue
            val record=runCatching{
                val path=dir.resolve("data.bin");val meta=dir.resolve("complete.json")
                checkWire(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) && Files.isRegularFile(meta,LinkOption.NOFOLLOW_LINKS) && Files.size(meta) in 1..2048)
                val json=FileChannel.open(meta,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS).use{ch->
                    val b=ByteBuffer.allocate(2049);while(ch.read(b)>0){};checkWire(b.position()<=2048);JSONObject(strictUtf8(b.array().copyOf(b.position())))}
                checkWire(json.keys().asSequence().toSet()==setOf("name","size","sha256"))
                val display=json.get("name") as? String?:throw ProtocolFailure();val size=(json.get("size") as? Number)?.toLong()?:throw ProtocolFailure()
                val hash=json.get("sha256") as? String?:throw ProtocolFailure()
                checkWire(SharedFilename.valid(display) && size in 0..MAX && size==Files.size(path) && Regex("[0-9a-f]{64}").matches(hash))
                StoredFile(name,display,size,hash)
            }.getOrNull()
            if(record!=null)result+=record
        }}
        return result.sortedBy{it.internalName}
    }
    fun verifiedBytes(record:StoredFile):ByteArray {
        checkWire(finalPattern.matches(record.internalName) && record.size in 0..MAX)
        val dir=root.resolve(record.internalName)
        checkWire(Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))
        val result=ByteArray(record.size.toInt());val path=dir.resolve("data.bin")
        FileChannel.open(path,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS).use {fd->
            checkWire(fd.size()==record.size);val b=ByteBuffer.wrap(result);while(b.hasRemaining())checkWire(fd.read(b)>0)
            checkWire(fd.read(ByteBuffer.allocate(1))<0)
        }
        checkWire(shaHex(result)==record.hash);return result
    }
    fun recover() {
        Files.newDirectoryStream(root).use{entries->for(path in entries){
            val name=path.fileName.toString()
            if(stagePattern.matches(name) && Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))Files.delete(path)
            else if(finalPattern.matches(name) && Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS) &&
                !Files.exists(path.resolve("complete.json"),LinkOption.NOFOLLOW_LINKS)){
                val children=Files.newDirectoryStream(path).use{it.toList()}
                // Unexpected files or symlinks are preserved, never followed or recursively removed.
                if(children.all{it.fileName.toString() in setOf("data.bin","record-stage.json") && Files.isRegularFile(it,LinkOption.NOFOLLOW_LINKS)}){
                    children.forEach{Files.delete(it)};Files.delete(path)
                }
            }
        }}
    }
}
class FileSnapshot internal constructor(private val path:Path,private val fd:FileChannel,val name:String,val size:Long,val hash:String):Closeable {
    fun next():ByteArray? {val b=ByteBuffer.allocate(32768);val n=fd.read(b);if(n<0)return null;checkWire(n>0);return b.array().copyOf(n)}
    override fun close(){fd.close();Files.deleteIfExists(path)}
}
class IncomingFile internal constructor(private val store:FileStorage,val size:Long,private val hash:String,private val budget:Long):Closeable {
    private val stage=store.stage();private var count=0L;private val digest=MessageDigest.getInstance("SHA-256");private var done=false
    fun append(chunk:Frame.Chunk) {
        checkWire(!done && chunk.offset==count && count+chunk.data.size<=size && count+chunk.data.size<=budget)
        val b=ByteBuffer.wrap(chunk.data);while(b.hasRemaining())stage.second.write(b)
        digest.update(chunk.data);count+=chunk.data.size
    }
    fun finish(name:String,id:String):StoredFile {
        checkWire(!done && count==size && hashString(digest.digest())==hash)
        stage.second.force(true);stage.second.close()
        Files.setPosixFilePermissions(stage.first,PosixFilePermissions.fromString("r--------"))
        val result=store.publish(stage.first,size,hash,name,id);done=true;return result
    }
    override fun close(){stage.second.close();if(!done)Files.deleteIfExists(stage.first);done=true}
}
