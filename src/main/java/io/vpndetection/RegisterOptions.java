package io.vpndetection;

import java.time.Duration;

/** What a registration asks for beyond its redirect URIs. A name left unset, or empty, is left out. */
public final class RegisterOptions extends OauthOptions {
    private String clientName;

    /** The name a person sees when asked to approve the client, such as {@code "Example CLI"}. */
    public RegisterOptions clientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    @Override
    public RegisterOptions requestTimeout(Duration requestTimeout) {
        super.requestTimeout(requestTimeout);
        return this;
    }

    String clientNameOrNull() {
        return clientName;
    }
}
