package dev.hinana.flow.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.UUID

sealed interface Frame {
    data class Control(val data: ByteArray): Frame
    data class Chunk(val id: String, val offset: Long, val data: ByteArray): Frame {
        init { checkWire(UUID.fromString(id).toString() == id && offset in 0..10_000_000 && data.size in 1..32768) }
    }
}
/** Header kind:u8, length:u32be. Refuses allocation before validating the bounded length. */
class FrameDecoder(private val allowFiles: Boolean = true) {
    private val header = ByteArray(5); private var headerCount = 0
    private var body: ByteArray? = null; private var bodyCount = 0
    val partial: Boolean get() = headerCount != 0
    fun feed(input: ByteArray): List<Frame> {
        val result = mutableListOf<Frame>(); var at = 0
        while (at < input.size) {
            if (body == null) {
                val take = minOf(5-headerCount, input.size-at)
                input.copyInto(header,headerCount,at,at+take);headerCount+=take;at+=take
                if (headerCount < 5) continue
                val length = ByteBuffer.wrap(header,1,4).int
                checkWire((header[0].toInt()==1 && length in 1..65536) ||
                    (allowFiles && header[0].toInt()==2 && length in 25..32792))
                body=ByteArray(length);bodyCount=0
            }
            val buffer = body!!; val take=minOf(buffer.size-bodyCount,input.size-at)
            input.copyInto(buffer,bodyCount,at,at+take);bodyCount+=take;at+=take
            if (bodyCount == buffer.size) {
                result += if (header[0].toInt()==1) Frame.Control(buffer) else {
                    val b=ByteBuffer.wrap(buffer);val id=UUID(b.long,b.long).toString();val offset=b.long
                    Frame.Chunk(id,offset,buffer.copyOfRange(24,buffer.size))
                }
                body=null;headerCount=0;bodyCount=0
            }
        }
        return result
    }
    fun finish() {checkWire(!partial)}
    companion object {
        fun control(bytes: ByteArray): ByteArray {checkWire(bytes.size in 1..65536);return ByteBuffer.allocate(5+bytes.size).put(1).putInt(bytes.size).put(bytes).array()}
        fun chunk(value: Frame.Chunk): ByteArray {
            val id=UUID.fromString(value.id)
            return ByteBuffer.allocate(29+value.data.size).put(2).putInt(24+value.data.size)
                .putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).putLong(value.offset).put(value.data).array()
        }
    }
}
