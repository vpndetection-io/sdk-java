package io.vpndetection;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * An {@link HttpClient} that answers OAuth requests from a queue, in order, and records exactly what
 * left the client: method, URI, every header and the body.
 *
 * <p>It answers at most {@link #CAP} requests. Past that it hands back an answer that never arrives,
 * rather than one the code under test could catch and go round again on, so a loop fails its test
 * from outside instead of spinning.
 */
final class OauthStub extends HttpClient {
    static final int CAP = 16;

    record Answer(int status, byte[] body, Duration delay) {
        static Answer of(int status, String body) {
            return new Answer(status, body.getBytes(StandardCharsets.UTF_8), Duration.ZERO);
        }
    }

    record Sent(String method, URI uri, HttpHeaders headers, String body) {}

    final List<Sent> sent = Collections.synchronizedList(new ArrayList<>());

    private final Deque<Answer> answers;
    private final Answer whenEmpty;

    private OauthStub(List<Answer> answers, Answer whenEmpty) {
        this.answers = new ArrayDeque<>(answers);
        this.whenEmpty = whenEmpty;
    }

    /** Answers in order, then with a 500 naming the stub, so a request nobody expected fails loudly. */
    static OauthStub answering(List<Answer> answers) {
        return new OauthStub(answers, Answer.of(500, "{\"error\": \"the stub has no answer left\"}"));
    }

    static OauthStub answering(Answer... answers) {
        return answering(List.of(answers));
    }

    /**
     * Takes every request and ignores its timeout, answering only after longer than any bound a test
     * sets, and then with a failure no timeout produces.
     */
    static OauthStub hanging() {
        byte[] body = "{\"error\": \"the stub stopped waiting\"}".getBytes(StandardCharsets.UTF_8);
        return new OauthStub(List.of(), new Answer(503, body, Duration.ofSeconds(15)));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        Answer answer;
        synchronized (this) {
            sent.add(new Sent(request.method(), request.uri(), request.headers(), bodyOf(request)));
            if (sent.size() > CAP) {
                return new CompletableFuture<>();
            }
            answer = answers.isEmpty() ? whenEmpty : answers.removeFirst();
        }
        CompletableFuture<HttpResponse<T>> response = new CompletableFuture<>();
        Runnable deliver = () -> response.complete(respond(request, answer, handler));
        if (answer.delay().isZero()) {
            deliver.run();
        } else {
            CompletableFuture.delayedExecutor(answer.delay().toMillis(), TimeUnit.MILLISECONDS)
                    .execute(deliver);
        }
        return response;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return sendAsync(request, handler);
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        try {
            return sendAsync(request, handler).get();
        } catch (ExecutionException e) {
            throw new IOException(e.getCause());
        }
    }

    // The body goes through the handler the client asked for, as the JDK's own client does, so the
    // client reads it in whatever form it chose.
    private static <T> HttpResponse<T> respond(HttpRequest request, Answer answer,
            HttpResponse.BodyHandler<T> handler) {
        Map<String, List<String>> map = new HashMap<>();
        map.put("content-type", List.of("application/json"));
        HttpHeaders headers = HttpHeaders.of(map, (a, b) -> true);
        HttpResponse.ResponseInfo info = new HttpResponse.ResponseInfo() {
            @Override
            public int statusCode() {
                return answer.status();
            }

            @Override
            public HttpHeaders headers() {
                return headers;
            }

            @Override
            public Version version() {
                return Version.HTTP_1_1;
            }
        };
        HttpResponse.BodySubscriber<T> subscriber = handler.apply(info);
        AtomicBoolean delivered = new AtomicBoolean();
        subscriber.onSubscribe(new Flow.Subscription() {
            @Override
            public void request(long n) {
                if (!delivered.compareAndSet(false, true)) {
                    return;
                }
                if (answer.body().length > 0) {
                    subscriber.onNext(List.of(ByteBuffer.wrap(answer.body())));
                }
                subscriber.onComplete();
            }

            @Override
            public void cancel() {
                delivered.set(true);
            }
        });
        T body = subscriber.getBody().toCompletableFuture().join();
        return new Response<>(request, answer.status(), headers, body);
    }

    private static String bodyOf(HttpRequest request) {
        if (request.bodyPublisher().isEmpty()) {
            return null;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        CompletableFuture<Void> done = new CompletableFuture<>();
        request.bodyPublisher().get().subscribe(new Flow.Subscriber<ByteBuffer>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                bytes.writeBytes(chunk);
            }

            @Override
            public void onError(Throwable throwable) {
                done.completeExceptionally(throwable);
            }

            @Override
            public void onComplete() {
                done.complete(null);
            }
        });
        done.join();
        return bytes.toString(StandardCharsets.UTF_8);
    }

    /** Decodes a form body the way a server would: {@code +} is a space, then percent-decoding. */
    static Map<String, String> formFields(String body) {
        Map<String, String> fields = new HashMap<>();
        if (body == null || body.isEmpty()) {
            return fields;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            fields.put(URLDecoder.decode(name, StandardCharsets.UTF_8),
                    URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return fields;
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

    private record Response<T>(HttpRequest request, int statusCode, HttpHeaders headers, T body)
            implements HttpResponse<T> {
        @Override
        public Optional<HttpResponse<T>> previousResponse() {
            return Optional.empty();
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
