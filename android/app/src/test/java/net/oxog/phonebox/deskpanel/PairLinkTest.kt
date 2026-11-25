package net.oxog.phonebox.deskpanel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairLinkTest {
    private val fp = "a".repeat(64)
    private val code = "ABCDEFGHijklmnop"

    @Test
    fun localAndTailscaleAddressesAreAccepted() {
        assertTrue(AgentLink.PairLink.isLocalAddress("10.0.0.1"))
        assertTrue(AgentLink.PairLink.isLocalAddress("192.168.1.10"))
        assertTrue(AgentLink.PairLink.isLocalAddress("172.16.0.2"))
        assertTrue(AgentLink.PairLink.isLocalAddress("100.64.0.7"))
        assertFalse(AgentLink.PairLink.isLocalAddress("8.8.8.8"))
        assertFalse(AgentLink.PairLink.isLocalAddress("pc.tailnet.ts.net"))
    }

    @Test
    fun allowedHostsIncludeDnsNamesButNotPublicIpv4() {
        assertTrue(AgentLink.PairLink.isAllowedHost("192.168.1.10"))
        assertTrue(AgentLink.PairLink.isAllowedHost("desk.tail1234.ts.net"))
        assertFalse(AgentLink.PairLink.isAllowedHost("8.8.8.8"))
        assertFalse(AgentLink.PairLink.isAllowedHost("localhost"))
        assertFalse(AgentLink.PairLink.isAllowedHost(""))
    }

    @Test
    fun parseQueryReadsOfficialPayload() {
        val link = AgentLink.PairLink.parseQuery("v=1&pc=Desk&fp=$fp&port=9876&h=192.168.1.10,100.64.0.7&c=$code")
        assertNotNull(link)
        assertEquals("Desk", link!!.pc)
        assertEquals(fp, link.fingerprint)
        assertEquals(9876, link.port)
        assertEquals(listOf("192.168.1.10", "100.64.0.7"), link.hosts)
        assertEquals(code, link.code)
        assertEquals("AAAA AAAA", link.check)
    }

    @Test
    fun parseQueryRejectsPublicHostsInQrPayload() {
        assertNull(AgentLink.PairLink.parseQuery("v=1&pc=Desk&fp=$fp&port=8766&h=8.8.8.8&c=$code"))
    }

    @Test
    fun fromFieldsBuildsManualPairing() {
        val link = AgentLink.PairLink.fromFields("desk.tail1234.ts.net", 9000, fp, code, "Desk")
        assertNotNull(link)
        assertEquals(listOf("desk.tail1234.ts.net"), link!!.hosts)
        assertEquals(9000, link.port)
    }

    @Test
    fun withEndpointOverridesHostAndPort() {
        val base = AgentLink.PairLink.parseQuery("v=1&pc=Desk&fp=$fp&port=8766&h=192.168.1.10&c=$code")!!
        val next = base.withEndpoint(listOf("100.64.0.7"), 9001)
        assertEquals(listOf("100.64.0.7"), next.hosts)
        assertEquals(9001, next.port)
        assertEquals(fp, next.fingerprint)
        assertEquals(code, next.code)
    }

    @Test
    fun agentHttpsPairPathIsRecognised() {
        assertTrue(AgentLink.PairLink.isPairHttpPath("/pair"))
        assertTrue(AgentLink.PairLink.isPairHttpPath("/pair/"))
        assertTrue(AgentLink.PairLink.isPairHttpHost("192.168.1.10"))
        assertTrue(AgentLink.PairLink.isPairHttpHost("g-tech-marksman.github.io"))
        assertFalse(AgentLink.PairLink.isPairHttpHost("ersinkoc.github.io"))
    }
}
