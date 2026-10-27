package dz.timo.bounty
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DexReviewTest {
    private fun fixture(): ByteArray {
        val owner="Ljava/lang/Runtime;".toByteArray()
        val name="exec".toByteArray()
        val data=ByteArray(132+owner.size+2+name.size+2)
        val buffer=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        "dex\n035\u0000".toByteArray().copyInto(data)
        buffer.putInt(32,data.size); buffer.putInt(36,112); buffer.putInt(40,0x12345678)
        buffer.putInt(56,2); buffer.putInt(60,112)
        buffer.putInt(64,1); buffer.putInt(68,120)
        buffer.putInt(88,1); buffer.putInt(92,124)
        buffer.putInt(112,132); buffer.putInt(116,134+owner.size)
        buffer.putInt(120,0); buffer.putInt(128,1)
        data[132]=owner.size.toByte(); owner.copyInto(data,133)
        data[134+owner.size]=name.size.toByte(); name.copyInto(data,135+owner.size)
        return data
    }
    @Test fun detectsMethodReferenceOnly() { assertEquals(setOf("Ljava/lang/Runtime;->exec"),DexReview.methods(fixture())) }
    @Test(expected=IllegalArgumentException::class) fun rejectsTruncated() { DexReview.methods(byteArrayOf(1,2,3)) }
    @Test(expected=IllegalArgumentException::class) fun rejectsOutsideTable() { val data=fixture(); ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(92,Int.MAX_VALUE); DexReview.methods(data) }
    @Test(expected=IllegalArgumentException::class) fun rejectsWrongStringIndex() { val data=fixture(); ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(128,1000); DexReview.methods(data) }
    @Test(expected=IllegalArgumentException::class) fun rejectsOversizedTable() { val data=fixture(); ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(56,Int.MAX_VALUE); DexReview.methods(data) }
    @Test(expected=IllegalArgumentException::class) fun rejectsUnterminatedLength() { val data=fixture(); for(i in 132..136) data[i]=0x80.toByte(); DexReview.methods(data) }
    @Test fun doesNotTreatOrdinaryStringAsMethod() { val data=fixture(); "send".toByteArray().copyInto(data,data.size-5); assertTrue(DexReview.methods(data).isEmpty()) }
}
