package io.vpndetection;

import java.util.Optional;

/**
 * The authorization server refusing an OAuth request: a 4xx whose body names an OAuth error code,
 * such as {@code authorization_pending}, {@code slow_down} or {@code invalid_grant}.
 *
 * <p>Never retryable as it stands. Its {@link #kind()} follows the status like any other answer's,
 * and a 401 here means an unregistered client ID, never the API key, which OAuth requests do not
 * carry. {@link OauthAccessDeniedException} and {@link OauthExpiredTokenException} are the two
 * refusals a device sign-in ends on.
 */
public class OauthException extends VPNDetectionException {
    private static final long serialVersionUID = 1L;

    private final String errorCode;
    private final String errorDescription;

    /**
     * @param statusCode the HTTP status, or null for a refusal reached locally, which is
     *     {@link ErrorKind#BAD_REQUEST}.
     */
    public OauthException(String errorCode, String errorDescription, Integer statusCode) {
        super(statusCode == null ? ErrorKind.BAD_REQUEST : Wire.kindOf(statusCode, null),
                errorDescription == null ? errorCode : errorCode + ": " + errorDescription,
                statusCode, null, null);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    /** The server's code, kept as sent even when this library has never seen it. */
    public String errorCode() {
        return errorCode;
    }

    /** The server's explanation, absent when it sent none. */
    public Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    @Override
    public boolean retryable() {
        return false;
    }

    // Only access_denied and expired_token have a type of their own.
    static OauthException of(String errorCode, String errorDescription, int statusCode) {
        switch (errorCode) {
            case "access_denied":
                return new OauthAccessDeniedException(errorDescription, statusCode);
            case "expired_token":
                return new OauthExpiredTokenException(errorDescription, statusCode);
            default:
                return new OauthException(errorCode, errorDescription, statusCode);
        }
    }
}
