package io.vpndetection;

/** What an authorization URL asks for beyond what every one carries. A value left unset, or empty, is left out. */
public final class AuthorizationUrlOptions {
    private String scope;
    private String state;
    private String resource;

    /**
     * Space-delimited scopes, sent as given, such as {@code "apikeys.use"}. The server narrows them to
     * what the client may ask for.
     */
    public AuthorizationUrlOptions scope(String scope) {
        this.scope = scope;
        return this;
    }

    /** Comes back on the redirect unchanged, so the caller can tell the answer is to its own request. */
    public AuthorizationUrlOptions state(String state) {
        this.state = state;
        return this;
    }

    /** The API the tokens are meant for. */
    public AuthorizationUrlOptions resource(String resource) {
        this.resource = resource;
        return this;
    }

    String scopeOrNull() {
        return scope;
    }

    String stateOrNull() {
        return state;
    }

    String resourceOrNull() {
        return resource;
    }
}
