package dz.timo.bounty
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
class ScopeTest {
    @Test fun acceptsExactScope() { assertEquals("example.com",Scope.check("https://example.com/app","https://example.com/app",emptyList()).host) }
    @Test(expected=IllegalArgumentException::class) fun rejectsOtherHost() { Scope.check("https://other.example/","https://example.com/",emptyList()) }
    @Test(expected=IllegalArgumentException::class) fun rejectsExclusion() { Scope.check("https://example.com/private/one","https://example.com/private/one",listOf("https://example.com/private")) }
    @Test(expected=IllegalArgumentException::class) fun rejectsCredentials() { Scope.parse("https://user:pass@example.com/") }
    @Test(expected=IllegalArgumentException::class) fun rejectsQuery() { Scope.parse("https://example.com/?x=1") }
    @Test(expected=IllegalArgumentException::class) fun rejectsTraversal() { Scope.parse("https://example.com/a/../b") }
    @Test(expected=IllegalArgumentException::class) fun rejectsEncoding() { Scope.parse("https://example.com/%2e%2e/") }
    @Test fun blocksPrivateAndReserved() {
        for(ip in listOf("127.0.0.1","10.0.0.1","100.64.0.1","192.168.1.1","169.254.169.254","198.18.0.1","192.0.2.1","203.0.113.1","::1","2001:db8::1","fc00::1","ff02::1")) assertFalse(ip,Scope.publicAddress(InetAddress.getByName(ip)))
    }
    @Test fun allowsPublicNumericAddress() { assertTrue(Scope.publicAddress(InetAddress.getByAddress(byteArrayOf(8,8,8,8)))) }
}
