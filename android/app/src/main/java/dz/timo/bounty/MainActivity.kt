package dz.timo.bounty

import android.animation.ValueAnimator
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.*
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.*
import android.view.animation.DecelerateInterpolator
import android.widget.*
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : Activity() {
    companion object { private val busy=AtomicBoolean(false) }
    private val ink=Color.rgb(233,241,255)
    private val muted=Color.rgb(157,179,205)
    private val mint=Color.rgb(105,234,205)
    private lateinit var store: Store
    private lateinit var panel: LinearLayout
    private lateinit var body: LinearLayout
    private lateinit var nav: LinearLayout
    private var tab=0
    private var latest=""
    private val worker=Executors.newSingleThreadExecutor()
    private fun dp(n: Int) = (n*resources.displayMetrics.density).toInt()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store=Store(applicationContext)
        latest=savedInstanceState?.getString("latest") ?: ""
        val backdrop=FrameLayout(this)
        backdrop.addView(Aurora(this),FrameLayout.LayoutParams(-1,-1))
        panel=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; layoutDirection=View.LAYOUT_DIRECTION_RTL; setPadding(dp(18),dp(12),dp(18),dp(10)); fitsSystemWindows=true }
        backdrop.addView(panel,FrameLayout.LayoutParams(-1,-1))
        panel.addView(label("BOUNTY  /  WORKBENCH",13,mint).apply { letterSpacing=.15f; gravity=Gravity.START; setPadding(0,dp(8),0,dp(6)) })
        val scroll=ScrollView(this).apply { isFillViewport=true; clipToPadding=false; setPadding(0,0,0,dp(12)) }
        body=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
        scroll.addView(body)
        panel.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        nav=LinearLayout(this).apply { orientation=LinearLayout.HORIZONTAL; background=glass(25); setPadding(dp(4),dp(4),dp(4),dp(4)) }
        panel.addView(nav)
        window.decorView.systemUiVisibility=View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        panel.fitsSystemWindows=false
        panel.setOnApplyWindowInsetsListener { view,insets ->
            view.setPadding(dp(18)+insets.systemWindowInsetLeft,dp(12)+insets.systemWindowInsetTop,dp(18)+insets.systemWindowInsetRight,dp(10)+insets.systemWindowInsetBottom)
            insets
        }
        setContentView(backdrop)
        show(savedInstanceState?.getInt("tab") ?: 0)
    }
    override fun onSaveInstanceState(outState: Bundle) { outState.putInt("tab",tab); outState.putString("latest",latest); super.onSaveInstanceState(outState) }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
    private fun glass(radius: Int=22): GradientDrawable = GradientDrawable(GradientDrawable.Orientation.TL_BR,intArrayOf(0xCF223650.toInt(),0xB0122037.toInt())).apply { cornerRadius=dp(radius).toFloat(); setStroke(dp(1),0x506E97BA) }
    private fun label(value: String,size: Int=15,color: Int=ink): TextView = TextView(this).apply { text=value; textSize=size.toFloat(); setTextColor(color); setLineSpacing(dp(4).toFloat(),1f); textDirection=View.TEXT_DIRECTION_FIRST_STRONG; setPadding(0,dp(3),0,dp(3)) }
    private fun card(title: String, subtitle: String="", into: LinearLayout=body): LinearLayout {
        val box=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; background=glass(); setPadding(dp(19),dp(18),dp(19),dp(18)); elevation=dp(3).toFloat() }
        into.addView(box,LinearLayout.LayoutParams(-1,-2).apply { bottomMargin=dp(15) })
        box.addView(label(title,20))
        if(subtitle.isNotBlank()) box.addView(label(subtitle,13,muted))
        return box
    }
    private fun button(title: String, into: LinearLayout, accent: Boolean=true, action: ()->Unit): Button {
        val b=Button(this).apply { text=title; isAllCaps=false; textSize=14f; setTextColor(if(accent) Color.rgb(8,39,37) else ink); background=if(accent) GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,intArrayOf(mint,0xFF74BDFF.toInt())).apply { cornerRadius=dp(15).toFloat() } else glass(15); minHeight=dp(50); setPadding(dp(10),dp(8),dp(10),dp(8)); setOnClickListener { action() } }
        into.addView(b,LinearLayout.LayoutParams(-1,-2).apply { topMargin=dp(12) })
        return b
    }
    private fun input(title: String, value: String, into: LinearLayout, multiline: Boolean=false): EditText {
        into.addView(label(title,13,muted))
        val field=EditText(this).apply { setText(value); setTextColor(ink); setHintTextColor(muted); textSize=15f; background=glass(12); setPadding(dp(12),dp(10),dp(12),dp(10)); minHeight=dp(50); isSingleLine=!multiline; if(multiline) { minLines=3; maxLines=8; gravity=Gravity.TOP }; importantForAutofill=View.IMPORTANT_FOR_AUTOFILL_NO }
        into.addView(field,LinearLayout.LayoutParams(-1,-2).apply { topMargin=dp(6); bottomMargin=dp(13) })
        return field
    }
    private fun check(title: String, into: LinearLayout): CheckBox = CheckBox(this).apply { text=title; setTextColor(muted); textSize=14f; minHeight=dp(48); into.addView(this) }
    private fun show(index: Int) {
        tab=index; body.removeAllViews(); nav.removeAllViews()
        listOf("الرئيسية","النطاق","الفحص","السجل").forEachIndexed { i,text ->
            nav.addView(TextView(this).apply { this.text=text; textSize=13f; gravity=Gravity.CENTER; minHeight=dp(52); setTextColor(if(i==tab) mint else muted); background=if(i==tab) glass(18) else null; setOnClickListener { show(i) } },LinearLayout.LayoutParams(0,-2,1f))
        }
        when(index) { 0->home(); 1->scopePage(); 2->scanPage(); 3->historyPage() }
        if(ValueAnimator.areAnimatorsEnabled()) { body.alpha=0f; body.translationY=dp(14).toFloat(); body.animate().alpha(1f).translationY(0f).setDuration(280).setInterpolator(DecelerateInterpolator()).start() }
    }
    private fun heading(title: String, subtitle: String) { body.addView(label(title,30)); body.addView(label(subtitle,14,muted).apply { setPadding(0,0,0,dp(20)) }) }
    private fun home() {
        heading("مساحة البحث الخاصة بك", "تحليل منظم. أدلة واضحة. تحكم كامل.")
        val hero=card("جاهز لخطوتك القادمة", "KOTLIN + C++  ·  يعمل دون Root")
        hero.addView(label("ابدأ بتوثيق التصريح والنطاق، ثم وافق على خطة محدودة لكل تقييم.",16))
        button("إعداد نطاق البرنامج  ←",hero) { show(1) }
        val stats=card("${store.jobs().length()} تقييم محفوظ", if(busy.get()) "تقييم قيد التنفيذ" else "المحرك جاهز")
        stats.addView(label("HTTP HEAD  /  TLS  /  TCP  /  SQL",14,mint))
        val tools=card("الأدوات المتاحة فعلًا")
        tools.addView(label("• رؤوس HTTP مع التحقق من TLS\n• اتصال TCP أصلي عبر C++ لمنفذ واحد\n• مراجعة SQL محلية استدلالية\n• تقارير Markdown ومشاركة يدوية",15,muted))
        tools.addView(label("Nmap وsqlmap غير مدمجين في APK. فحص TCP ليس Nmap. لا يوجد استغلال أو زحف تلقائي.",13,muted))
        button("بدء تقييم جديد",tools,false) { show(2) }
    }
    private fun scopePage() {
        heading("النطاق والتصريح", "الاستثناءات تتقدم على الأهداف المسموحة.")
        val form=card("برنامجك الحالي")
        val name=input("اسم البرنامج",store.get("name"),form)
        val policy=input("رابط القواعد أو مرجع التصريح",store.get("policy"),form)
        val url=input("رابط واحد دقيق مصرح به",store.get("url"),form)
        val rules=input("القواعد والأساليب والحدود المسموحة",store.get("rules"),form,true)
        val excluded=input("روابط مستثناة · رابط كامل في كل سطر",store.get("exclusions"),form,true)
        button("حفظ النطاق",form) {
            try {
                val value=url.text.toString().trim()
                require(name.text.isNotBlank() && policy.text.isNotBlank() && rules.text.length>=30) { "أكمل اسم البرنامج والتصريح والقواعد (30 حرفًا على الأقل)" }
                Scope.parse(value)
                excluded.text.lines().filter { it.isNotBlank() }.forEach { Scope.parse(it.trim()) }
                store.save(name.text.toString(),policy.text.toString(),rules.text.toString(),value,excluded.text.toString())
                toast("تم حفظ النطاق محليًا"); show(2)
            } catch(e:Exception) { toast(e.message ?: "راجع القيم") }
        }
        card("حدود النطاق").addView(label("الرابط المسموح مطابق تمامًا للمسار والمنفذ. لا wildcards ولا توسعة تلقائية. راجع قواعد البرنامج بنفسك؛ النص لا يتحول تلقائيًا إلى تصريح. فحص TCP يحتاج إذنًا صريحًا للعنوان والمنفذ، خاصةً مع CDN.",14,muted))
    }
    private fun scanPage() {
        heading("تقييم جديد", "خطوة محدودة، ثم مراجعة الدليل.")
        val box=card("اختيار المسار")
        val group=RadioGroup(this).apply { orientation=RadioGroup.VERTICAL }
        val options=listOf("HTTP / TLS · طلب HEAD واحد","TCP / C++ · اتصال منفذ واحد","SQL / C++ · كود محلي فقط")
        options.forEachIndexed { i,s -> group.addView(RadioButton(this).apply { id=100+i; text=s; setTextColor(ink); minHeight=dp(48) }) }
        group.check(100); box.addView(group)
        val url=input("الهدف",store.get("url"),box)
        val source=input("نص الكود لمسار SQL فقط · لا تُدخل أسرارًا","",box,true)
        val authorized=check("لدي تصريح واضح لهذا الأصل والأسلوب وراجعت الاستثناءات",box)
        val hostPermission=check("لـ TCP: التصريح يشمل فحص عنوان IP والمنفذ (وليس مسار ويب فقط)",box)
        val plan=label("HTTP: طلب HEAD واحد، دون متابعة التحويلات أو جلب محتوى الصفحة. المهلات وحدود حجم الرؤوس مفعّلة.",13,mint); box.addView(plan)
        group.setOnCheckedChangeListener { _,id ->
            source.visibility=if(id==102) View.VISIBLE else View.GONE
            url.isEnabled=id!=102
            hostPermission.visibility=if(id==101) View.VISIBLE else View.GONE
            plan.text=when(id) {101->"TCP: اتصال واحد للمنفذ المحدد في الرابط، مهلة 4 ثوانٍ بعد DNS. لا تحميل بيانات أو كشف إصدارات.";102->"SQL: تحليل محلي لأنماط بناء الاستعلام. لا شبكة ولا تنفيذ للكود، والاشتباه ليس إثباتًا.";else->"HTTP: طلب HEAD واحد، دون تحويلات أو جسم الصفحة. DNS والتحقق من TLS وحدود الحجم والمهلات مفعّلة."}
        }
        source.visibility=View.GONE; hostPermission.visibility=View.GONE
        val progress=ProgressBar(this).apply { visibility=View.GONE }; box.addView(progress)
        val status=label("لم يبدأ التقييم",14,muted); box.addView(status)
        val results=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }; body.addView(results)
        lateinit var run: Button
        run=button("مراجعة الخطة وتشغيل التقييم",box) {
            try {
                require(!busy.get()) { "انتظر انتهاء التقييم الجاري" }
                require(authorized.isChecked) { "التصريح مطلوب قبل التقييم" }
                require(store.get("policy").isNotBlank() && store.get("rules").length>=30) { "أعد إعداد البرنامج والنطاق أولًا" }
                val mode=group.checkedRadioButtonId-100
                val asset=if(mode==2) null else Scope.check(url.text.toString().trim(),store.get("url"),store.get("exclusions").lines())
                if(mode==1) { require(hostPermission.isChecked) { "يلزم تصريح IP والمنفذ" }; require(asset!!.path=="/") { "TCP لا يقبل نطاق مسار فرعي" } }
                val project=listOf("name","policy","rules","exclusions").associateWith { store.get(it) }
                val code=source.text.toString()
                if(mode==2) require(code.isNotBlank() && code.length<=100000) { "أدخل مقتطفًا بين 1 و100 ألف حرف" }
                val target=if(mode==2) "نص كود محلي" else url.text.toString().trim()
                AlertDialog.Builder(this).setTitle("الموافقة على الخطة").setMessage("$target\n\n${plan.text}\n\nلن يتم إرسال بلاغ تلقائيًا.")
                    .setNegativeButton("رجوع",null).setPositiveButton("تشغيل") { _,_ ->
                        if(busy.compareAndSet(false,true)) {
                            run.isEnabled=false; progress.visibility=View.VISIBLE; status.text="جارٍ تنفيذ التقييم…"
                            worker.execute {
                                try {
                                    val findings=when(mode){0->Engine.headers(asset!!);1->Engine.tcp(asset!!);else->Engine.sql(code)}
                                    val report=store.add(options[mode],target,findings,project)
                                    runOnUiThread { if(!isDestroyed) { latest=report; results.removeAllViews(); findings.forEach { f->card(f.title,f.status,results).addView(label(f.evidence,14,muted)) }; button("عرض التقرير ومشاركته",results){ reportDialog(report) }; status.text="اكتمل التقييم · ${findings.size} ملاحظة" } }
                                } catch(e:Exception) { runOnUiThread { if(!isDestroyed) status.text="توقف التقييم: ${e.message ?: "تعذر الاتصال"}" } }
                                finally { busy.set(false); runOnUiThread { if(!isDestroyed) { run.isEnabled=true; progress.visibility=View.GONE } } }
                            }
                        }
                    }.show()
            } catch(e:Exception) { toast(e.message ?: "تعذر بدء التقييم") }
        }
    }
    private fun historyPage() {
        heading("دفتر الأدلة", "آخر 100 تقييم · محفوظة داخل التطبيق")
        val jobs=store.jobs()
        if(jobs.length()==0) card("لا توجد تقييمات بعد","ستظهر النتائج هنا بعد أول تقييم مكتمل.")
        for(i in 0 until jobs.length()) {
            val job=jobs.getJSONObject(i)
            val box=card(job.getString("mode"),job.getString("date"))
            box.addView(label(job.getString("target"),15,mint))
            box.addView(label("${job.getInt("count")} ملاحظة · دون تأكيد آلي للثغرات",13,muted))
            button("قراءة التقرير",box,false) { reportDialog(job.getString("report")) }
        }
    }
    private fun reportDialog(value: String) {
        latest=value
        val scroll=ScrollView(this)
        scroll.addView(label(value,14).apply { setPadding(dp(20),dp(14),dp(20),dp(14)); setTextIsSelectable(true) })
        AlertDialog.Builder(this).setTitle("مسودة التقرير").setView(scroll).setNegativeButton("إغلاق",null)
            .setNeutralButton("حفظ Markdown") { _,_->
                startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply { addCategory(Intent.CATEGORY_OPENABLE); type="text/markdown"; putExtra(Intent.EXTRA_TITLE,"bounty-assessment-${System.currentTimeMillis()}.md") },42)
            }.setPositiveButton("مشاركة يدوية") { _,_-> startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type="text/plain"; putExtra(Intent.EXTRA_TEXT,value) },"اختر وجهة المشاركة")) }.show()
    }
    @Deprecated("Platform document picker callback")
    override fun onActivityResult(requestCode: Int,resultCode: Int,data: Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if(requestCode==42 && resultCode==RESULT_OK) try { data?.data?.let { uri->contentResolver.openOutputStream(uri)?.use { it.write(latest.toByteArray()) }; toast("تم حفظ التقرير") } } catch(_:Exception) { toast("تعذر حفظ التقرير") }
    }
    private fun toast(message: String) { Toast.makeText(this,message,Toast.LENGTH_LONG).show() }
    private class Aurora(context: android.content.Context): View(context) {
        private val paint=Paint(Paint.ANTI_ALIAS_FLAG)
        override fun onDraw(canvas: Canvas) {
            canvas.drawColor(Color.rgb(7,14,29))
            paint.shader=RadialGradient(width*.9f,height*.12f,width*.9f,intArrayOf(0x804663CE.toInt(),0x00101C35),null,Shader.TileMode.CLAMP)
            canvas.drawRect(0f,0f,width.toFloat(),height.toFloat(),paint)
            paint.shader=RadialGradient(width*.05f,height*.68f,width*.85f,intArrayOf(0x4049CBB3,0x000B1829),null,Shader.TileMode.CLAMP)
            canvas.drawRect(0f,0f,width.toFloat(),height.toFloat(),paint)
            paint.shader=null; paint.color=0x0AFFFFFF
            for(x in 0 until width step 48) canvas.drawLine(x.toFloat(),0f,x.toFloat(),height.toFloat(),paint)
        }
    }
}
