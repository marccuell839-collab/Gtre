package dz.timo.bounty

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

class Store(private val context: Context) {
    private val prefs get() = context.getSharedPreferences("workbench", Context.MODE_PRIVATE)
    fun get(key: String) = prefs.getString(key, "") ?: ""
    fun save(name: String, policy: String, rules: String, url: String, exclusions: String) {
        prefs.edit().putString("name", name).putString("policy", policy).putString("rules", rules).putString("url", url).putString("exclusions", exclusions).apply()
    }
    @Synchronized fun jobs(): JSONArray = try { JSONArray(context.openFileInput("history.json").bufferedReader().use { it.readText() }) } catch (_: Exception) { JSONArray() }
    @Synchronized fun add(mode: String, target: String, findings: List<Finding>, project: Map<String,String>): String {
        val date=Instant.now().toString()
        val output=buildString {
            append("# Bounty Workbench — مسودة\n\nالتاريخ: $date\nالبرنامج: ${project["name"]}\nمرجع التصريح: ${project["policy"]}\nالأصل: $target\nالمسار: $mode\n\n## النطاق والقواعد\n${project["rules"]}\n\n## الاستثناءات\n${project["exclusions"]}\n")
            findings.forEach { f -> append("\n## ${f.title}\nالحالة: ${f.status}\nالخطورة: غير مقيّمة؛ لم يثبت أثر أمني.\n\n### الدليل وطريقة التحقق\n${f.evidence}\n\n### الأثر\nلا أثر مثبت يتجاوز الملاحظة المسجلة.\n\n### المعالجة\nراجع الملاحظة وسياق التطبيق قبل اختيار المعالجة.\n") }
            append("\n## حدود التقييم\nفحص محدود للأصل المعتمد فقط. لا ضمان شمول التغطية. لم تُشغّل أدوات استغلال أو يُستخرج محتوى مستخدمين.\n\n## الإرسال\nمسودة للمراجعة والإرسال اليدوي فقط.\n")
        }
        val prior=jobs()
        val next=JSONArray().put(JSONObject().put("date",date).put("target",target).put("mode",mode).put("report",output).put("count",findings.size))
        for (i in 0 until minOf(prior.length(),99)) next.put(prior.getJSONObject(i))
        val atomic=android.util.AtomicFile(java.io.File(context.filesDir,"history.json"))
        val stream=atomic.startWrite()
        try { stream.write(next.toString().toByteArray()); atomic.finishWrite(stream) } catch(e:Exception) { atomic.failWrite(stream); throw e }
        return output
    }
}
