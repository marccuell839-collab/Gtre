package dz.timo.bounty

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SNIHostName

object NativeEngine {
    init { System.loadLibrary("bounty_native") }
    external fun reviewSql(source: String): String
    external fun tcpConnect(ip: String, port: Int): String
}
data class Finding(val title: String, val status: String, val evidence: String)
object Engine {
    private fun resolve(asset: Asset): InetAddress {
        val pool = Executors.newSingleThreadExecutor()
        try {
            val task = pool.submit<Array<InetAddress>> { InetAddress.getAllByName(asset.host) }
            val addresses = task.get(5, TimeUnit.SECONDS)
            require(addresses.isNotEmpty() && addresses.all { Scope.publicAddress(it) }) { "عناوين خاصة أو محجوزة أو DNS مختلط: تم الإيقاف" }
            return addresses.first()
        } finally { pool.shutdownNow() }
    }
    fun tcp(asset: Asset): List<Finding> {
        require(asset.path == "/") { "فحص TCP يحتاج تصريح المضيف والمنفذ كاملين" }
        val ip = resolve(asset)
        val state = NativeEngine.tcpConnect(ip.hostAddress!!, asset.port)
        return listOf(Finding("TCP ${asset.port} · $state", "معلومة", "اتصال C++ واحد بالعنوان المتحقق منه. لا كشف إصدارات ولا NSE. المنفذ المفتوح وحده لا يثبت ثغرة."))
    }
    fun sql(source: String): List<Finding> {
        require(source.length <= 100000) { "حد النص 100 ألف حرف" }
        require(source.isNotBlank()) { "أدخل نص الكود أولًا" }
        val lines = NativeEngine.reviewSql(source).trim().lines().filter { it.isNotBlank() }
        return if (lines.isEmpty()) listOf(Finding("لم يظهر نمط مطابق", "معلومة", "الفحص الاستدلالي محدود ولا يثبت سلامة الكود."))
        else lines.map { Finding("بناء SQL ديناميكي · سطر $it", "مشتبه بها", "راجع تدفق المدخلات وربط المعاملات. لا تنفيذ للكود ولا إثبات للاستغلال؛ لا يُحفظ نص الكود.") }
    }
    fun headers(asset: Asset): List<Finding> {
        val ip = resolve(asset)
        val raw = Socket()
        var socket: Socket = raw
        try {
            raw.connect(InetSocketAddress(ip, asset.port), 5000)
            raw.soTimeout = 5000
            if (asset.scheme == "https") {
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, asset.host, asset.port, true) as SSLSocket
                socket = ssl
                val parameters = ssl.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                if (!asset.host.contains(':') && asset.host.any { it.isLetter() }) parameters.serverNames = listOf(SNIHostName(asset.host))
                ssl.sslParameters = parameters
                ssl.startHandshake()
            }
            val host = if (asset.host.contains(':')) "[${asset.host}]" else asset.host
            val request = "HEAD ${asset.path} HTTP/1.1\r\nHost: $host:${asset.port}\r\nUser-Agent: BountyWorkbenchAndroid/0.2\r\nConnection: close\r\n\r\n"
            socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
            val input = socket.getInputStream()
            val bytes = java.io.ByteArrayOutputStream()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
            var tail = 0
            while (bytes.size() < 32768) {
                require(System.nanoTime() < deadline) { "انتهت مهلة قراءة الرؤوس" }
                val value = input.read()
                if (value == -1) break
                bytes.write(value)
                tail = (tail shl 8) or value
                if (tail == 0x0d0a0d0a) break
            }
            val text = bytes.toString("ISO-8859-1")
            require(text.endsWith("\r\n\r\n")) { "رؤوس غير مكتملة أو أكبر من الحد" }
            val lines = text.split("\r\n")
            val code = lines.first().split(" ").getOrNull(1)?.toIntOrNull() ?: error("استجابة غير صالحة")
            if (code == 429 || code >= 500) return listOf(Finding("توقف · HTTP $code", "لم يُختبر", "لا إعادة محاولة بسبب إشارة تقييد أو خطأ خادم."))
            val names = lines.drop(1).map { it.substringBefore(':').lowercase() }.toSet()
            val results = mutableListOf(Finding("HTTP $code", "معلومة", "طلب HEAD واحد. لم يُجلب جسم الصفحة ولم تُتبع التحويلات. TLS يتحقق من شهادة المضيف."))
            for (header in listOf("content-security-policy", "x-content-type-options", "referrer-policy")) if (header !in names) results.add(Finding("رأس غائب · $header", "معلومة", "غائب في هذه الاستجابة فقط؛ لم يُثبت أثر أمني."))
            if (asset.scheme == "https" && "strict-transport-security" !in names) results.add(Finding("HSTS غير ظاهر", "معلومة", "ملاحظة إعداد فقط؛ ليست إثباتًا لثغرة."))
            if (code in 300..399) results.add(Finding("تحويل لم تتم متابعته", "لم يُختبر", "يلزم تقييم وجهته ونطاقها بصورة مستقلة."))
            return results
        } finally { socket.close(); raw.close() }
    }
}
