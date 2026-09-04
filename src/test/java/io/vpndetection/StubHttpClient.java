package io.vpndetection;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * An {@link HttpClient} that answers from a table and counts what it was asked for, so "never
 * touched the network" is asserted rather than assumed.
 *
 * <p>It also records the PEAK number of requests in flight, which is the only way to tell a real
 * concurrency limit from an option that was accepted and ignored.
 */
final class StubHttpClient extends HttpClient {
    static final class Route {
        final int status;
        final byte[] body;
        final Map<String, String> headers;

        Route(int status, String body, Map<String, String> headers) {
            this(status, body.getBytes(StandardCharsets.UTF_8), headers);
        }

        /** A binary answer, for the dataset transfers, whose bytes are not text at all. */
        Route(int status, byte[] body, Map<String, String> headers) {
            this.status = status;
            this.body = body;
            this.headers = headers;
        }

        static Route ok(String body) {
            return new Route(200, body, Map.of());
        }
    }

    final List<String> calls = Collections.synchronizedList(new ArrayList<>());
    /** The {@code Authorization} header of each call, or null, positionally matching {@link #calls}. */
    final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());
    final AtomicInteger inFlight = new AtomicInteger();
    final AtomicInteger peak = new AtomicInteger();

    private final Function<String, Route> responder;
    private final Duration delay;

    private StubHttpClient(Function<String, Route> responder, Duration delay) {
        this.responder = responder;
        this.delay = delay;
    }

    /** Answers the given addresses, and rejects anything else the way the API would. */
    static StubHttpClient of(Map<String, Route> routes) {
        Map<String, Route> table = new HashMap<>(routes);
        return new StubHttpClient(
                ip -> table.getOrDefault(ip,
                        new Route(400, "{\"error\": \"not a valid IP address\"}", Map.of())),
                Duration.ZERO);
    }

    /** Answers any address with a not-a-VPN verdict, slowly enough for calls to overlap. */
    static StubHttpClient echoing(Duration delay) {
        return new StubHttpClient(
                ip -> Route.ok("{\"ip\": \"" + ip + "\", \"is_vpn\": false}"), delay);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        URI uri = request.uri();
        calls.add(uri.toString());
        authorizations.add(request.headers().firstValue("Authorization").orElse(null));
        peak.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
        try {
            if (!delay.isZero()) {
                Thread.sleep(delay.toMillis());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            inFlight.decrementAndGet();
        }

        String path = uri.getPath();
        Route route = responder.apply(URLDecoder.decode(
                path.startsWith("/") ? path.substring(1) : path, StandardCharsets.UTF_8));
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("content-type", List.of("application/json"));
        route.headers.forEach((k, v) -> headers.put(k.toLowerCase(Locale.ROOT), List.of(v)));
        return (HttpResponse<T>) new StubResponse(request, route.status,
                HttpHeaders.of(headers, (a, b) -> true), new ByteArrayInputStream(route.body));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        return CompletableFuture.supplyAsync(() -> send(request, handler));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return sendAsync(request, handler);
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
        return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public SSLParameters sslParameters() {
        return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.empty();
    }

    private static final class StubResponse implements HttpResponse<InputStream> {
        private final HttpRequest request;
        private final int status;
        private final HttpHeaders headers;
        private final InputStream body;

        StubResponse(HttpRequest request, int status, HttpHeaders headers, InputStream body) {
            this.request = request;
            this.status = status;
            this.headers = headers;
            this.body = body;
        }

        @Override
        public int statusCode() {
            return status;
        }

        @Override
        public HttpRequest request() {
            return request;
        }

        @Override
        public Optional<HttpResponse<InputStream>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return headers;
        }

        @Override
        public InputStream body() {
            return body;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return request.uri();
        }

        @Override
        public Version version() {
            return Version.HTTP_1_1;
        }
    }
}
