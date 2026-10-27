package dz.timo.bounty

/** Reads DEX method references only. Never loads or executes bytecode. */
object DexReview {
    private fun uint(data: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset.toLong()+4 <= data.size) { "DEX offset out of range" }
        val value=(data[offset].toLong() and 255) or ((data[offset+1].toLong() and 255) shl 8) or ((data[offset+2].toLong() and 255) shl 16) or ((data[offset+3].toLong() and 255) shl 24)
        require(value <= Int.MAX_VALUE) { "DEX integer exceeds limit" }; return value.toInt()
    }
    private fun ushort(data: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset+2 <= data.size)
        return (data[offset].toInt() and 255) or ((data[offset+1].toInt() and 255) shl 8)
    }
    private fun table(data: ByteArray, countAt: Int, offsetAt: Int, width: Int, maximum: Int): Pair<Int,Int> {
        val count=uint(data,countAt); val offset=uint(data,offsetAt)
        require(count <= maximum && offset.toLong()+count.toLong()*width <= data.size) { "DEX table exceeds bounds" }
        return count to offset
    }
    private fun string(data: ByteArray, offset: Int): String {
        var position=offset
        var terminated=false
        for(i in 0 until 5) {
            require(position in data.indices)
            if((data[position++].toInt() and 128)==0) { terminated=true; break }
        }
        require(terminated) { "Malformed DEX string length" }
        val start=position
        while(position<data.size && position-start<512 && data[position]!=0.toByte()) position++
        // Long strings are irrelevant to short API identifiers; never include user string values.
        if(position>=data.size || position-start>=512) return ""
        return String(data,start,position-start,Charsets.UTF_8)
    }
    fun methods(data: ByteArray): Set<String> {
        require(data.size>=112 && String(data,0,4,Charsets.US_ASCII)=="dex\n" && data[7]==0.toByte()) { "Unsupported DEX format" }
        require(String(data,4,3,Charsets.US_ASCII) in listOf("035","037","038","039","040")) { "Unsupported DEX version; coverage incomplete" }
        require(uint(data,32)==data.size && uint(data,36)==112 && uint(data,40)==0x12345678) { "Malformed DEX header" }
        val (stringsCount,stringsOffset)=table(data,56,60,4,300000)
        val (typesCount,typesOffset)=table(data,64,68,4,65536)
        val (methodsCount,methodsOffset)=table(data,88,92,8,65536)
        val cache=HashMap<Int,String>()
        var decoded=0
        fun s(index: Int): String {
            require(index in 0 until stringsCount)
            return cache.getOrPut(index) {
                val text=string(data,uint(data,stringsOffset+index*4)); decoded+=text.length
                require(decoded<=2_000_000) { "DEX decoded string budget exceeded" }; text
            }
        }
        fun type(index: Int): String { require(index in 0 until typesCount); return s(uint(data,typesOffset+index*4)) }
        val watched=setOf("Landroid/webkit/WebView;->addJavascriptInterface","Landroid/webkit/SslErrorHandler;->proceed","Ldalvik/system/DexClassLoader;-><init>","Ljava/lang/Runtime;->exec","Ljava/lang/ProcessBuilder;->start","Ljavax/crypto/spec/SecretKeySpec;-><init>","Landroid/database/sqlite/SQLiteDatabase;->rawQuery","Landroid/database/sqlite/SQLiteDatabase;->execSQL")
        val found=mutableSetOf<String>()
        for(i in 0 until methodsCount) {
            val offset=methodsOffset+i*8
            val signature=type(ushort(data,offset))+"->"+s(uint(data,offset+4))
            if(signature in watched) found.add(signature)
        }
        return found
    }
}
