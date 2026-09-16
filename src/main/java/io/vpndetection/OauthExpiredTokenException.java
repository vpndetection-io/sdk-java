package io.vpndetection;

/**
 * The device sign-in's code ran out before the person approved it: start a new one.
 *
 * <p>{@link #statusCode()} is absent when {@link OauthApi#pollDeviceToken} outlived the code
 * locally rather than hearing so from the server.
 */
public final class OauthExpiredTokenException extends OauthException {
    private static final long serialVersionUID = 1L;

    public OauthExpiredTokenException(String errorDescription, Integer statusCode) {
        super("expired_token", errorDescription, statusCode);
    }
}
