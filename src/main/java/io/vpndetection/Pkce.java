package io.vpndetection;

/**
 * One sign-in's PKCE pair: {@code challenge} goes in the authorization URL, and {@code verifier} to
 * {@link OauthApi#exchangeAuthorizationCode}. {@code method} is always {@code S256}, the only method
 * the server accepts. {@link #toString()} leaves the verifier out, so logging the pair does not leak it.
 *
 * @param verifier 32 random bytes as 43 characters of unpadded base64url
 * @param challenge the verifier's SHA-256, as unpadded base64url
 * @param method always {@code S256}
 */
public record Pkce(String verifier, String challenge, String method) {
    @Override
    public String toString() {
        return "Pkce[challenge=" + challenge + ", method=" + method + "]";
    }
}
