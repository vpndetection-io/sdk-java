package io.vpndetection.integration;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * A real {@link HttpClient} that remembers what it was asked for.
 *
 * <p>The JDK has no request hook, so the recorder is the client: it delegates every call and notes
 * a few derived facts on the way past. It also keeps small JSON answers, because the tests need
 * what the WIRE carried and the library only keeps what it decoded.
 */
final class RecordingHttpClient extends HttpClient {
    /**
     * Nothing above this is ever held. A dataset transfer runs through this same client, so reading
     * a body to its end here would be the multi-gigabyte mistake the library exists to avoid.
     */
    private static final int MAX_CAPTURED_BODY = 1 << 20;

    /**
     * What a test is allowed to remember about a request.
     *
     * <p>Only derived facts leave here. A failing assertion prints its operands, so holding on to
     * the request itself is how a key ends up in a public CI log: whether the key was carried is a
     * boolean, and the caller never sees the key.
     */
    record Fact(String host, String path, boolean carriedKey) {}

    private final HttpClient delegate;
    private final String key;
    private final List<Fact> facts = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, byte[]> bodies = Collections.synchronizedMap(new HashMap<>());

    RecordingHttpClient(HttpClient delegate, String key) {
        this.delegate = delegate;
        this.key = key;
    }

    List<Fact> facts() {
        return List.copyOf(facts);
    }

    boolean carriedKey() {
        return facts().stream().anyMatch(Fact::carriedKey);
    }

    /** The JSON answer to one path, as it came off the wire. */
    Optional<byte[]> body(String path) {
        return Optional.ofNullable(bodies.get(path));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        note(request);
        HttpResponse<T> response = delegate.send(request, handler);
        if (!isJson(response) || !(response.body() instanceof InputStream body)) {
            return response;
        }
        byte[] head = body.readNBytes(MAX_CAPTURED_BODY + 1);
        if (head.length <= MAX_CAPTURED_BODY) {
            bodies.put(request.uri().getPath(), head);
        }
        // Handed back in front of the rest, so the library still sees the whole body whatever was
        // captured, and closing the replacement closes the socket underneath it.
        return (HttpResponse<T>) new ReplayedResponse(response,
                new SequenceInputStream(new ByteArrayInputStream(head), body));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        note(request);
        return delegate.sendAsync(request, handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        note(request);
        return delegate.sendAsync(request, handler, pushPromiseHandler);
    }

    private void note(HttpRequest request) {
        URI uri = request.uri();
        boolean carried = !key.isEmpty() && uri.toString().contains(key);
        if (!key.isEmpty()) {
            for (List<String> values : request.headers().map().values()) {
                carried = carried || values.stream().anyMatch(value -> value.contains(key));
            }
        }
        facts.add(new Fact(uri.getHost(), uri.getPath(), carried));
    }

    private static boolean isJson(HttpResponse<?> response) {
        return response.headers().firstValue("Content-Type")
                .filter(type -> type.startsWith("application/json")).isPresent();
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<java.time.Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    /** The delegate's response with its body replaced by one that replays the captured head. */
    private static final class ReplayedResponse implements HttpResponse<InputStream> {
        private final HttpResponse<?> original;
        private final InputStream body;

        ReplayedResponse(HttpResponse<?> original, InputStream body) {
            this.original = original;
            this.body = body;
        }

        @Override
        public int statusCode() {
            return original.statusCode();
        }

        @Override
        public HttpRequest request() {
            return original.request();
        }

        @Override
        public Optional<HttpResponse<InputStream>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return original.headers();
        }

        @Override
        public InputStream body() {
            return body;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return original.sslSession();
        }

        @Override
        public URI uri() {
            return original.uri();
        }

        @Override
        public Version version() {
            return original.version();
        }
    }
}
