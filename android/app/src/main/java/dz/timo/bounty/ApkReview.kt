package dz.timo.bounty

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ComponentInfo
import android.net.Uri
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

object ApkReview {
    private const val MAX_APK=150L*1024*1024
    private const val MAX_DEX=24L*1024*1024
    private const val TOTAL_DEX=64L*1024*1024
    fun analyze(context: Context, uri: Uri): List<Finding> {
        val temporary=File.createTempFile("assessment-", ".apk",context.cacheDir)
        val result=mutableListOf<Finding>()
        val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(45)
        fun timeCheck() { require(System.nanoTime()<deadline) { "APK analysis time budget exceeded; file removed" } }
        try {
            val hash=MessageDigest.getInstance("SHA-256")
            var size=0L
            val input=context.contentResolver.openInputStream(uri) ?: error("تعذر فتح الملف")
            input.use { source -> temporary.outputStream().use { output ->
                val buffer=ByteArray(32768)
                while(true) {
                    timeCheck(); val n=source.read(buffer); if(n<0) break
                    size+=n; require(size<=MAX_APK) { "حجم APK يتجاوز 150 MiB" }
                    hash.update(buffer,0,n); output.write(buffer,0,n)
                }
            } }
            result.add(Finding("هوية الملف · SHA-256", "معلومة",hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }+"\nالحجم: $size بايت. بصمة للهوية وليست إثبات سلامة أو خلو من البرمجيات الضارة."))
            var entries=0; var dexCount=0; var reviewed=0; var total=0L; var libraries=0
            ZipFile(temporary).use { zip ->
                require((zip.getEntry("AndroidManifest.xml")?.size ?: -1L) in 1..(2L*1024*1024)) { "ليس ملف APK مستقلًا: AndroidManifest.xml غير موجود" }
                val enumeration=zip.entries()
                while(enumeration.hasMoreElements()) {
                    timeCheck(); val entry=enumeration.nextElement(); entries++
                    require(entries<=20000) { "أكثر من 20 ألف مدخل ZIP؛ توقف التحليل" }
                    if(entry.name.startsWith("lib/") && entry.name.endsWith(".so")) libraries++
                    if(!Regex("classes[0-9]*\\.dex").matches(entry.name)) continue
                    dexCount++
                    if(entry.size !in 1..MAX_DEX || total+entry.size>TOTAL_DEX || dexCount>16) {
                        result.add(Finding("DEX غير محلل · ${entry.name}","لم يُختبر","حدود الحجم: 24 MiB لكل DEX، و64 MiB إجماليًا، و16 ملفًا كحد أقصى. التغطية غير مكتملة.")); continue
                    }
                    try {
                        val bytes=java.io.ByteArrayOutputStream()
                        zip.getInputStream(entry).use { source ->
                            val buffer=ByteArray(16384)
                            while(true) {
                                timeCheck(); val n=source.read(buffer); if(n<0) break
                                total+=n
                                require(bytes.size().toLong()+n<=MAX_DEX && total<=TOTAL_DEX) { "حد فك ضغط DEX" }
                                bytes.write(buffer,0,n)
                            }
                        }
                        for(method in DexReview.methods(bytes.toByteArray())) result.add(Finding("مرجع API يحتاج مراجعة", "معلومة", "${entry.name}: $method\nمرجع داخل جدول DEX فقط؛ لا يثبت وصول التنفيذ أو مدخلات غير موثوقة أو قابلية الاستغلال. يلزم تتبع تدفق البيانات يدويًا."))
                        reviewed++
                    } catch(_: Exception) { result.add(Finding("DEX غير محلل · ${entry.name}","لم يُختبر","صيغة غير مدعومة أو حد مورد أو خطأ تحليل؛ لا يُعتبر غياب النتائج دليل سلامة.")) }
                }
            }
            timeCheck()
            result.add(Finding("تغطية الأرشيف", "معلومة","$entries مدخل ZIP؛ $reviewed من $dexCount ملفات DEX محللة؛ $libraries مكتبة أصلية. لا تفكيك للمكتبات الأصلية، ولا تحليل ديناميكي، ولا استخراج ملفات الأرشيف إلى مساراته."))
            val flags=PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or (if(Build.VERSION.SDK_INT>=28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            val info=context.packageManager.getPackageArchiveInfo(temporary.absolutePath, flags)
            if(info==null) result.add(Finding("Manifest غير محلل", "لم يُختبر","محلل Android لم يقبل الملف. قد يكون تالفًا أو split APK أو غير مدعوم؛ التغطية غير مكتملة."))
            else {
                val app=info.applicationInfo
                result.add(Finding("هوية الحزمة", "معلومة","package=${info.packageName}\nversion=${info.versionName ?: "غير معروف"}\ntargetSdk=${app?.targetSdkVersion ?: "غير معروف"}"))
                if(app!=null) {
                    if(app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) result.add(Finding("debuggable مفعّل", "مشتبه بها","Manifest يسمح بتصحيح التطبيق. يلزم تحديد هل هذه نسخة إنتاج وما سيناريو الوصول والأثر؛ لا أثر مثبت."))
                    if(app.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0) result.add(Finding("allowBackup مفعّل", "معلومة","قواعد النسخ الاحتياطي وإصدار Android ونوع البيانات غير محللة. العلم وحده لا يثبت تسريبًا."))
                    if(app.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0) result.add(Finding("سياسة cleartext تحتاج مراجعة", "معلومة","علم التطبيق يسمح مبدئيًا بـ HTTP. Network Security Config قد يغيّر السياسة؛ لم يُحلل الملف ولم يُرصد اتصال فعلي."))
                    if(app.targetSdkVersion<28) result.add(Finding("targetSdk قديم", "معلومة","targetSdk=${app.targetSdkVersion}. راجع توافق سياسات الأمان؛ ليس إثبات ثغرة مستقلة."))
                }
                val sensitive=setOf("android.permission.READ_SMS","android.permission.RECORD_AUDIO","android.permission.READ_CONTACTS","android.permission.ACCESS_FINE_LOCATION","android.permission.READ_CALL_LOG","android.permission.REQUEST_INSTALL_PACKAGES","android.permission.MANAGE_EXTERNAL_STORAGE")
                val requested=info.requestedPermissions?.filter { it in sensitive } ?: emptyList()
                if(requested.isNotEmpty()) result.add(Finding("صلاحيات حساسة مطلوبة", "معلومة",requested.joinToString("\n")+"\nوجود الصلاحية لا يعني منحها أو إساءة استخدامها."))
                var exports=0
                fun component(component: ComponentInfo, exported: Boolean, permission: String?) {
                    if(!exported) return
                    exports++
                    if(exports<=80) result.add(Finding("مكوّن مصدّر", "معلومة","${component.name}\nالحماية المعلنة: ${permission ?: "لا صلاحية على المكوّن؛ قد توجد تحققّات داخل الكود"}. التصدير قد يكون مقصودًا، ولم تُجرّب استدعاءات أو وصول لبيانات."))
                }
                info.activities?.forEach { component(it,it.exported,it.permission) }
                info.services?.forEach { component(it,it.exported,it.permission) }
                info.receivers?.forEach { component(it,it.exported,it.permission) }
                info.providers?.forEach { component(it,it.exported,listOfNotNull(it.readPermission,it.writePermission).joinToString(",").ifBlank { null }) }
                if(exports>80) result.add(Finding("قائمة المكوّنات مختصرة", "لم يُختبر","$exports مكوّنًا مصدّرًا؛ عُرض أول 80 فقط."))
                @Suppress("DEPRECATION")
                val signatures=if(Build.VERSION.SDK_INT>=28) info.signingInfo?.let { if(it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory } else info.signatures
                signatures?.take(4)?.forEach { signature ->
                    val digest=MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) }
                    result.add(Finding("بصمة شهادة مبلّغ عنها", "معلومة","SHA-256: $digest\nمصدرها PackageManager؛ ليست تحققًا مستقلًا من سلامة توقيع APK بكل مخططاته أو ثقة الناشر."))
                }
            }
            result.add(Finding("حدود التحليل المحلي", "معلومة","لا تشغيل أو تثبيت للـ APK، لا رفع للشبكة، لا فك تشفير أو إزالة تمويه، لا تأكيد لثغرات من API أو صلاحية فقط. ملفات split وAPKS/XAPK ليست مدعومة كحزمة كاملة."))
            return result
        } finally { temporary.delete() }
    }
}
