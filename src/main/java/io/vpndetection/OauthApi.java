package io.vpndetection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.internal.ApiException;
import io.vpndetection.model.DeviceAuthorization;
import io.vpndetection.model.OauthMetadata;
import io.vpndetection.model.TokenResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Sign a person in with OAuth, reached through {@link VPNDetection#oauth()}.
 *
 * <p>The device flow: a program running on the person's own machine has them approve it in a
 * browser and pick one of their API keys, instead of asking them to paste one. Every call takes the
 * program's client ID, issued on request through support@vpndetection.io.
 *
 * <p>No request here carries the client's API key, and none needs one, so a client built without a
 * key works the same. A refusal from the authorization server is an {@link OauthException}; every
 * other failure is the ordinary {@link VPNDetectionException}.
 */
public final class OauthApi {
    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private static final List<String> METADATA_REQUIRED =
            List.of("issuer", "authorization_endpoint", "token_endpoint");
    private static final List<String> DEVICE_REQUIRED =
            List.of("device_code", "user_code", "verification_uri", "expires_in", "interval");
    private static final List<String> TOKEN_REQUIRED = List.of("access_token", "token_type", "expires_in");

    // The generated model starts every list empty, which would read a member the server left out
    // as present.
    private static final Map<String, BiConsumer<OauthMetadata, List<String>>> METADATA_LISTS = Map.of(
            OauthMetadata.JSON_PROPERTY_SCOPES_SUPPORTED, OauthMetadata::setScopesSupported,
            OauthMetadata.JSON_PROPERTY_RESPONSE_TYPES_SUPPORTED, OauthMetadata::setResponseTypesSupported,
            OauthMetadata.JSON_PROPERTY_GRANT_TYPES_SUPPORTED, OauthMetadata::setGrantTypesSupported,
            OauthMetadata.JSON_PROPERTY_CODE_CHALLENGE_METHODS_SUPPORTED,
            OauthMetadata::setCodeChallengeMethodsSupported,
            OauthMetadata.JSON_PROPERTY_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
            OauthMetadata::setTokenEndpointAuthMethodsSupported);

    static final Ticker SYSTEM = new Ticker() {
        @Override
        public long nanoTime() {
            return System.nanoTime();
        }

        @Override
        public void sleep(Duration wait) throws InterruptedException {
            Thread.sleep(wait.toMillis());
        }
    };

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final int retries;
    private final Duration requestTimeout;
    private final Ticker ticker;

    OauthApi(HttpClient http, ObjectMapper mapper, String baseUrl, int retries, Duration requestTimeout,
            Ticker ticker) {
        this.http = http;
        this.mapper = mapper;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.retries = retries;
        this.requestTimeout = requestTimeout;
        this.ticker = ticker;
    }

    public OauthMetadata metadata() {
        return metadata(new OauthOptions());
    }

    /**
     * The authorization server's discovery document. Nothing here needs it first: every call is
     * built on the client's base URL.
     */
    public OauthMetadata metadata(OauthOptions options) {
        Objects.requireNonNull(options, "options");
        HttpRequest request = request("/.well-known/oauth-authorization-server", options).GET().build();
        return Wire.retrying(retries, () -> {
            HttpResponse<byte[]> response = send(request);
            JsonNode wire = answer(response, METADATA_REQUIRED);
            OauthMetadata metadata = read(wire, OauthMetadata.class, response.statusCode());
            METADATA_LISTS.forEach((member, set) -> {
                if (!wire.hasNonNull(member)) {
                    set.accept(metadata, null);
                }
            });
            return metadata;
        });
    }

    public DeviceAuthorization deviceAuthorization(String clientId) {
        return deviceAuthorization(clientId, new DeviceAuthorizationOptions());
    }

    /**
     * Start a device sign-in: show the person {@code user_code} and {@code verification_uri}, then
     * hand the answer to {@link #pollDeviceToken}.
     *
     * <p>It spends nothing, so it is retried like a lookup. The server allows 30 a minute per source
     * address and answers past that with an {@link OauthException} coded {@code slow_down}.
     */
    public DeviceAuthorization deviceAuthorization(String clientId, DeviceAuthorizationOptions options) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(options, "options");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", clientId);
        putIfGiven(form, "scope", options.scopeOrNull());
        putIfGiven(form, "resource", options.resourceOrNull());
        HttpRequest request = post("/oauth/device_authorization", form, options);
        return Wire.retrying(retries,
                () -> decode(send(request), DeviceAuthorization.class, DEVICE_REQUIRED));
    }

    public TokenResponse exchangeDeviceCode(String clientId, String deviceCode) {
        return exchangeDeviceCode(clientId, deviceCode, new OauthOptions());
    }

    /**
     * Ask once whether the person has approved a device sign-in. Until they do, it throws an
     * {@link OauthException} coded {@code authorization_pending}; {@link #pollDeviceToken} is the
     * loop around it.
     *
     * <p>Never retried: an approved code is spent by the answer carrying the tokens, so a retry after
     * a lost response could only lose them.
     */
    public TokenResponse exchangeDeviceCode(String clientId, String deviceCode, OauthOptions options) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(deviceCode, "deviceCode");
        Objects.requireNonNull(options, "options");
        return decode(send(post("/oauth/token", deviceCodeForm(clientId, deviceCode), options)),
                TokenResponse.class, TOKEN_REQUIRED);
    }

    public TokenResponse exchangeRefreshToken(String clientId, String refreshToken) {
        return exchangeRefreshToken(clientId, refreshToken, new OauthOptions());
    }

    /**
     * Trade a refresh token for a new pair.
     *
     * <p>The old refresh token is spent whatever happens next, so this is never retried. A refresh
     * names the key the person picked ({@link TokenResponse#getApikeyId()}) but never hands it over
     * again ({@link TokenResponse#getApikey()} is null).
     */
    public TokenResponse exchangeRefreshToken(String clientId, String refreshToken, OauthOptions options) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(refreshToken, "refreshToken");
        Objects.requireNonNull(options, "options");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        form.put("client_id", clientId);
        return decode(send(post("/oauth/token", form, options)), TokenResponse.class, TOKEN_REQUIRED);
    }

    public void revoke(String clientId, String token) {
        revoke(clientId, token, new OauthOptions());
    }

    /**
     * End a token. A refresh token ends the whole sign-in and every token it issued, which is how a
     * program signs the machine out; an access token ends only itself. The server answers the same
     * for any token, known or not.
     */
    public void revoke(String clientId, String token, OauthOptions options) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(options, "options");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        form.put("client_id", clientId);
        HttpRequest request = post("/oauth/revoke", form, options);
        Wire.retrying(retries, () -> {
            succeeded(send(request));
            return null;
        });
    }

    public TokenResponse pollDeviceToken(String clientId, DeviceAuthorization device) {
        return pollDeviceToken(clientId, device, new OauthOptions());
    }

    /**
     * Wait for the person to approve a device sign-in, and return its tokens.
     *
     * <p>Waits {@code device.interval} seconds (5 when that is below 1) before EVERY request, the
     * first included, and 5 more for the rest of the call each time the server answers
     * {@code slow_down}. Ends at the first answer that is neither that nor
     * {@code authorization_pending}: a denial throws {@link OauthAccessDeniedException}, a code that
     * ran out {@link OauthExpiredTokenException} - as does outliving {@code device.expires_in},
     * counted from this call, with no status - and any other failure throws as it came. Calling it
     * again with the same device authorization is safe until the code expires.
     *
     * <p>Interrupting the calling thread stops the wait and any request in flight, and throws a
     * {@link ErrorKind#NETWORK} failure with the thread's interrupt flag restored.
     *
     * @param options its request timeout bounds each request, never the poll as a whole.
     */
    public TokenResponse pollDeviceToken(String clientId, DeviceAuthorization device, OauthOptions options) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(options, "options");
        String deviceCode = Objects.requireNonNull(device.getDeviceCode(), "device.device_code");
        Integer expiresIn = Objects.requireNonNull(device.getExpiresIn(), "device.expires_in");
        long lifetime = TimeUnit.SECONDS.toNanos(expiresIn);
        long interval = device.getInterval() != null && device.getInterval() >= 1 ? device.getInterval() : 5;
        HttpRequest request = post("/oauth/token", deviceCodeForm(clientId, deviceCode), options);
        long started = ticker.nanoTime();
        while (true) {
            pause(interval);
            if (ticker.nanoTime() - started >= lifetime) {
                throw new OauthExpiredTokenException(null, null);
            }
            try {
                return decode(send(request), TokenResponse.class, TOKEN_REQUIRED);
            } catch (OauthException e) {
                // RFC 8628: slow_down widens the interval for every later request, not just the next.
                if ("slow_down".equals(e.errorCode())) {
                    interval += 5;
                } else if (!"authorization_pending".equals(e.errorCode())) {
                    throw e;
                }
            }
        }
    }

    /** The same calls on another clock, so a test can take both the sleep and the time. */
    OauthApi ticking(Ticker other) {
        return new OauthApi(http, mapper, baseUrl, retries, requestTimeout, other);
    }

    private static Map<String, String> deviceCodeForm(String clientId, String deviceCode) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", DEVICE_CODE_GRANT);
        form.put("device_code", deviceCode);
        form.put("client_id", clientId);
        return form;
    }

    private static void putIfGiven(Map<String, String> form, String name, String value) {
        if (value != null && !value.isEmpty()) {
            form.put(name, value);
        }
    }

    // Built by hand rather than through the generated AuthorizationWireApi, which would put the API
    // key on the request through the client's interceptor.
    private HttpRequest.Builder request(String path, OauthOptions options) {
        Duration perCall = options.requestTimeoutOrNull();
        return HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(perCall != null ? perCall : requestTimeout)
                .header("Accept", "application/json");
    }

    // URLEncoder sends a + in a value as %2B, which the server must read back as a +.
    private HttpRequest post(String path, Map<String, String> form, OauthOptions options) {
        StringJoiner body = new StringJoiner("&");
        form.forEach((name, value) -> body.add(
                name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
        return request(path, options)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build();
    }

    private HttpResponse<byte[]> send(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new VPNDetectionException(ErrorKind.NETWORK,
                    e.getMessage() != null ? e.getMessage() : "request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VPNDetectionException(ErrorKind.NETWORK, "interrupted during a request", e);
        }
    }

    private void pause(long seconds) {
        try {
            ticker.sleep(Duration.ofSeconds(seconds));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VPNDetectionException(ErrorKind.NETWORK, "interrupted while waiting to poll", e);
        }
    }

    // Only a 4xx whose body is a JSON object with a STRING error is an OAuth refusal. Every 5xx,
    // whatever it says, is the server failing, and is retried wherever the operation retries.
    private void succeeded(HttpResponse<byte[]> response) {
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }
        String body = new String(response.body(), StandardCharsets.UTF_8);
        JsonNode wire = status >= 400 && status < 500 ? parse(body) : null;
        if (wire != null && wire.isObject() && wire.path("error").isTextual()) {
            JsonNode description = wire.path("error_description");
            throw OauthException.of(wire.get("error").asText(),
                    description.isTextual() ? description.asText() : null, status);
        }
        throw Wire.translate(new ApiException(status, "request failed", response.headers(), body));
    }

    private <T> T decode(HttpResponse<byte[]> response, Class<T> type, List<String> required) {
        return read(answer(response, required), type, response.statusCode());
    }

    // A 2xx that is not the documented shape is the server failing, as an unreadable lookup is, and
    // never an OAuth refusal.
    private JsonNode answer(HttpResponse<byte[]> response, List<String> required) {
        succeeded(response);
        JsonNode wire = parse(new String(response.body(), StandardCharsets.UTF_8));
        if (wire == null || !wire.isObject()) {
            throw malformed("the answer was not a JSON object", response.statusCode(), null);
        }
        for (String member : required) {
            if (!wire.hasNonNull(member)) {
                throw malformed("the answer carried no " + member, response.statusCode(), null);
            }
        }
        return wire;
    }

    private <T> T read(JsonNode wire, Class<T> type, int status) {
        try {
            return mapper.treeToValue(wire, type);
        } catch (JsonProcessingException e) {
            throw malformed("the answer could not be read: " + e.getOriginalMessage(), status, e);
        }
    }

    private JsonNode parse(String body) {
        try {
            return mapper.readTree(body);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    private static VPNDetectionException malformed(String message, int status, Throwable cause) {
        return new VPNDetectionException(ErrorKind.SERVER_ERROR, message, status, null, cause);
    }

    /** The clock and the sleep a poll runs on. */
    interface Ticker {
        long nanoTime();

        void sleep(Duration wait) throws InterruptedException;
    }
}
