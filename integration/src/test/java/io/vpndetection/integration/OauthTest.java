package io.vpndetection.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vpndetection.DeviceAuthorizationOptions;
import io.vpndetection.OauthException;
import io.vpndetection.OauthExpiredTokenException;
import io.vpndetection.VPNDetection;
import io.vpndetection.model.DeviceAuthorization;
import io.vpndetection.model.OauthMetadata;

import org.junit.jupiter.api.Test;

import java.util.Optional;

/**
 * The published library's OAuth surface against staging, on a keyless client. Nothing polls, since
 * nobody approves the sign-in, and one device authorization is started a run.
 */
class OauthTest {
    // The only client the server registers, already public in the CLI's source.
    private static final String CLIENT_ID = "vpndetection-cli";

    @Test
    void metadataNamesStagingAsTheIssuer() {
        OauthMetadata metadata = keyless().oauth().metadata();

        assertEquals(Staging.STAGING, metadata.getIssuer());
        assertNotNull(metadata.getDeviceAuthorizationEndpoint(), "device_authorization_endpoint is absent");
        assertNotNull(metadata.getCodeChallengeMethodsSupported(), "code_challenge_methods_supported is absent");
        assertTrue(metadata.getCodeChallengeMethodsSupported().contains("S256"),
                "code_challenge_methods_supported lacks S256: " + metadata.getCodeChallengeMethodsSupported());
    }

    @Test
    void revokeAcceptsAnyToken() {
        keyless().oauth().revoke(CLIENT_ID, "mo_rt_sdk-ci-not-a-token");
    }

    @Test
    void anUnknownDeviceCodeHasExpired() {
        OauthExpiredTokenException e = assertThrows(OauthExpiredTokenException.class,
                () -> keyless().oauth().exchangeDeviceCode(CLIENT_ID, "mo_dc_sdk-ci-not-a-code"));
        assertEquals(Optional.of(400), e.statusCode());
    }

    // slow_down passes: the server allows 30 a minute per source address, shared by everything
    // building on this runner.
    @Test
    void aDeviceAuthorizationStartsASignIn() {
        DeviceAuthorization device;
        try {
            device = keyless().oauth().deviceAuthorization(CLIENT_ID,
                    new DeviceAuthorizationOptions().scope("account.read"));
        } catch (OauthException e) {
            assertEquals("slow_down", e.errorCode(), "refused with " + e.getMessage());
            return;
        }
        assertFalse(device.getDeviceCode().isEmpty(), "device_code is empty");
        assertFalse(device.getUserCode().isEmpty(), "user_code is empty");
        assertTrue(device.getVerificationUri().endsWith("/device"), device.getVerificationUri());
        assertTrue(device.getExpiresIn() > 0 && device.getInterval() > 0,
                "expires_in " + device.getExpiresIn() + " and interval " + device.getInterval());
    }

    private static VPNDetection keyless() {
        return VPNDetection.builder().baseUrl(Staging.STAGING).build();
    }
}
