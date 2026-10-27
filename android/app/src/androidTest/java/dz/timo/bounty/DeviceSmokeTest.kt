package dz.timo.bounty
import android.content.Intent
import android.net.Uri
import android.graphics.Bitmap
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class DeviceSmokeTest {
    @Test fun nativeLibraryLoadsWithoutNetwork() {
        assertEquals("1\n",NativeEngine.reviewSql("cursor.execute(\"SELECT \" + value)"))
        assertEquals("invalid-address",NativeEngine.tcpConnect("not-an-ip",443))
    }
    @Test fun analyzesOwnApkWithoutExecutingItsContents() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val rows=ApkReview.analyze(context,Uri.fromFile(File(context.applicationInfo.sourceDir)))
        assertTrue(rows.any { it.title.contains("SHA-256") })
        assertTrue(rows.any { it.evidence.contains("package=dz.timo.bounty") })
        assertTrue(rows.any { it.title.contains("تغطية الأرشيف") })
        assertFalse(rows.any { it.status=="مؤكدة" })
        assertTrue(context.cacheDir.listFiles()?.none { it.name.startsWith("assessment-") } ?: true)
    }
    @Test fun opensNativeScreens() {
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        val activity=instrumentation.startActivitySync(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        instrumentation.waitForIdleSync()
        fun screenshot(name:String) {
            val bitmap=instrumentation.uiAutomation.takeScreenshot() ?: error("Screenshot unavailable")
            assertNotNull(bitmap)
            File(context.getExternalFilesDir(null),name).outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }
            bitmap.recycle()
        }
        screenshot("home.png")
        fun find(root:View):View? {
            if(root is TextView && root.text.toString()=="APK") return root
            if(root is ViewGroup) for(i in 0 until root.childCount) find(root.getChildAt(i))?.let { return it }
            return null
        }
        instrumentation.runOnMainSync { val tab=find(activity.window.decorView); assertNotNull(tab); tab!!.performClick() }
        instrumentation.waitForIdleSync()
        screenshot("apk.png")
        instrumentation.runOnMainSync { activity.finish() }
    }
}
