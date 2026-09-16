package io.vpndetection;

/** The person denied the device sign-in. Its code is spent: start a new one to ask again. */
public final class OauthAccessDeniedException extends OauthException {
    private static final long serialVersionUID = 1L;

    public OauthAccessDeniedException(String errorDescription, Integer statusCode) {
        super("access_denied", errorDescription, statusCode);
    }
}
