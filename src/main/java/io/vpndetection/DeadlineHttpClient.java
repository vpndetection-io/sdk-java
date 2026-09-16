package io.vpndetection;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * Holds a request that carries a timeout to that timeout over the WHOLE response, headers and body,
 * in a race this library owns.
 *
 * <p>{@link HttpRequest#timeout()} on its own is not that bound. The JDK stops the clock once the
 * response headers arrive, so a body that stalls after them holds the caller for as long as the
 * server likes (measured on 17, 21 and 25), and a substituted {@link HttpClient} need not honor
 * the timeout at all. A request with no timeout, which is what a dataset transfer sends, passes
 * straight through and stays streamed.
 */
final class DeadlineHttpClient extends HttpClient {
    private final HttpClient delegate;

    DeadlineHttpClient(HttpClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        Duration limit = request.timeout().orElse(null);
        if (limit == null) {
            return delegate.send(request, handler);
        }
        // Buffered, so the exchange only completes once the last byte is in. Every generated call
        // reads its whole body into a String anyway.
        CompletableFuture<HttpResponse<T>> exchange = delegate.sendAsync(request,
                info -> HttpResponse.BodySubscribers.mapping(HttpResponse.BodySubscribers.ofByteArray(),
                        bytes -> replay(bytes, handler.apply(info))));
        try {
            return exchange.get(limit.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            exchange.cancel(true);
            throw timedOut(limit);
        } catch (InterruptedException e) {
            exchange.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            throw failure(e.getCause(), limit);
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        return delegate.sendAsync(request, handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return delegate.sendAsync(request, handler, pushPromiseHandler);
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
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

    // The same words whichever side of the race gave up: the JDK's own clock also runs until the
    // headers arrive, and it can win by a hair.
    private static HttpTimeoutException timedOut(Duration limit) {
        return new HttpTimeoutException("request timed out after " + limit.toMillis() + "ms");
    }

    // A connect timeout keeps its own message: it is the connection that never opened, on the
    // client's connect bound, not this request's.
    private static IOException failure(Throwable cause, Duration limit) {
        if (cause instanceof HttpTimeoutException && !(cause instanceof HttpConnectTimeoutException)) {
            return timedOut(limit);
        }
        if (cause instanceof IOException) {
            return (IOException) cause;
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }
        if (cause instanceof Error) {
            throw (Error) cause;
        }
        return new IOException(cause);
    }

    // Hands the buffered bytes to the subscriber the caller asked for, so the body arrives as the
    // type it named.
    private static <T> T replay(byte[] bytes, HttpResponse.BodySubscriber<T> subscriber) {
        AtomicBoolean delivered = new AtomicBoolean();
        subscriber.onSubscribe(new Flow.Subscription() {
            @Override
            public void request(long n) {
                if (!delivered.compareAndSet(false, true)) {
                    return;
                }
                if (bytes.length > 0) {
                    subscriber.onNext(List.of(ByteBuffer.wrap(bytes)));
                }
                subscriber.onComplete();
            }

            @Override
            public void cancel() {
                delivered.set(true);
            }
        });
        return subscriber.getBody().toCompletableFuture().join();
    }
}
