package dz.timo.bounty

import java.net.URI
import java.net.InetAddress

data class Asset(val scheme: String, val host: String, val port: Int, val path: String) {
    val origin: String get() = "$scheme://$host:$port"
}
object Scope {
    fun parse(raw: String): Asset {
        require(raw.length <= 2048 && raw.none { it.code <= 32 }) { "رابط غير صالح" }
        val uri = URI(raw)
        require(uri.scheme in listOf("http", "https") && uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) { "أدخل رابط HTTP(S) دقيقًا دون بيانات دخول أو معاملات" }
        val port = if (uri.port == -1) if (uri.scheme == "https") 443 else 80 else uri.port
        require(port in listOf(80, 443, 8000, 8080, 8443)) { "المنفذ خارج المجموعة المدعومة" }
        val path = uri.rawPath.ifEmpty { "/" }
        require(path == uri.normalize().rawPath.ifEmpty { "/" } && !path.contains('%') && !path.contains('\\')) { "استخدم مسارًا مباشرًا دون ترميز أو اختصارات" }
        return Asset(uri.scheme, uri.host.removeSurrounding("[", "]").lowercase(), port, path)
    }
    fun check(url: String, approved: String, excluded: List<String>): Asset {
        val asset = parse(url)
        require(asset == parse(approved)) { "الهدف ليس مطابقًا للنطاق المعتمد" }
        for (entry in excluded.filter { it.isNotBlank() }) {
            val e = parse(entry.trim())
            require(!(asset.origin == e.origin && (asset.path == e.path || e.path == "/" || asset.path.startsWith(e.path.trimEnd('/') + "/")))) { "الهدف مستثنى من النطاق" }
        }
        return asset
    }
    fun publicAddress(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress || address.isMulticastAddress) return false
        val b = address.address.map { it.toInt() and 255 }
        if (b.size == 4) {
            val a=b[0]; val c=b[1]
            return !(a==0 || a==10 || a==127 || a>=224 || (a==100 && c in 64..127) || (a==169 && c==254) || (a==172 && c in 16..31) || (a==192 && (c==168 || c==0 || (c==88 && b[2]==99))) || (a==198 && (c in 18..19 || (c==51 && b[2]==100))) || (a==203 && c==0 && b[2]==113))
        }
        // Restrict IPv6 to global-unicast 2000::/3; exclude documentation/transition prefixes.
        return b.size==16 && b[0] in 0x20..0x3f && !(b[0]==0x20 && b[1]==0x01 && (b[2]<2 || (b[2]==0x0d && b[3]==0xb8))) && !(b[0]==0x20 && b[1]==0x02) && !(b[0]==0x3f && b[1]==0xff)
    }
}
