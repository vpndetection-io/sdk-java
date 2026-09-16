package io.vpndetection;

import java.time.Duration;

/** What a device sign-in asks for. A value left unset, or empty, is left out of the request. */
public final class DeviceAuthorizationOptions extends OauthOptions {
    private String scope;
    private String resource;

    /**
     * Space-delimited scopes, sent as given, such as {@code "account.read apikeys.read"}. The server
     * narrows them to what the client may ask for.
     */
    public DeviceAuthorizationOptions scope(String scope) {
        this.scope = scope;
        return this;
    }

    /** The API the tokens are meant for. */
    public DeviceAuthorizationOptions resource(String resource) {
        this.resource = resource;
        return this;
    }

    @Override
    public DeviceAuthorizationOptions requestTimeout(Duration requestTimeout) {
        super.requestTimeout(requestTimeout);
        return this;
    }

    String scopeOrNull() {
        return scope;
    }

    String resourceOrNull() {
        return resource;
    }
}
