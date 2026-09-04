package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * Hits the real API, so it is opt-in: {@code VPNDETECTION_LIVE=1 mvn test}.
 *
 * <p>CI leaves it off. A test suite that spends the keyless daily allowance on every pull request
 * eventually fails for reasons that have nothing to do with the change under review.
 */
@EnabledIfEnvironmentVariable(named = "VPNDETECTION_LIVE", matches = "1")
class LiveTest {
    @Test
    void theFreeTierAnswersIsVpnAndWithholdsEverythingElse() {
        try (VPNDetection client = VPNDetection.create()) {
            Result vpn = client.lookup("45.83.91.1");
            Result notVpn = client.lookup("1.1.1.1");

            System.out.println("45.83.91.1 -> isVpn=" + vpn.isVpn()
                    + " isHosting=" + vpn.isHosting()
                    + " isBogon=" + vpn.isBogon()
                    + " raw=" + vpn.raw());
            System.out.println("1.1.1.1    -> isVpn=" + notVpn.isVpn()
                    + " isHosting=" + notVpn.isHosting()
                    + " isHosting.orElse(false)=" + notVpn.isHosting().orElse(false)
                    + " raw=" + notVpn.raw());

            assertTrue(vpn.isVpn(), "45.83.91.1 is VPN infrastructure");
            assertFalse(notVpn.isVpn(), "1.1.1.1 is not");
            // Absent, not false: the hosting flag is a paid member and this call carries no key.
            assertTrue(notVpn.isHosting().isEmpty(), "the free tier must withhold is_hosting");
            assertFalse(notVpn.isHosting().orElse(false));

            Result bogon = client.lookup("192.168.1.1");
            assertTrue(bogon.isBogon());
            assertEquals("192.168.1.1", bogon.ip());
        }
    }
}
