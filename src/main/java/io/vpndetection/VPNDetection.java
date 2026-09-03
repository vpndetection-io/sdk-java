package io.vpndetection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.vpndetection.api.LookupApi;
import io.vpndetection.internal.ApiClient;

import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * A client for the VPNDetection API.
 *
 * <p>Build one with {@link #builder()} and keep it: it owns a connection pool, a cache and a
 * thread pool, all of which are wasted if it is rebuilt per request. It is thread safe.
 *
 * <p>The cache is per instance, so an answer is never shared between two clients holding different
 * API keys and therefore entitled to different fields.
 */
public final class VPNDetection implements AutoCloseable {
    public static final String DEFAULT_BASE_URL = "https://api.vpndetection.io";

    private final LookupApi lookupApi;
    private final Database database;
    private final Cache<String, Result> cache;
    private final Semaphore gate;
    private final ExecutorService ownedExecutor;
    private final Executor executor;
    private final int retries;

    private VPNDetection(Builder b) {
        HttpClient http = b.httpClient != null ? b.httpClient : defaultHttpClient();
        ApiClient api = new ApiClient(new FixedHttpClientBuilder(http),
                ApiClient.createDefaultObjectMapper(), b.baseUrl);
        api.setReadTimeout(b.requestTimeout);
        if (b.apiKey != null) {
            // The `native` generator emits no auth plumbing at all, so the key goes on by hand.
            api.setRequestInterceptor(rb -> rb.header("Authorization", "Bearer " + b.apiKey));
        }

        this.lookupApi = new LookupApi(api);
        this.retries = b.retries;
        this.database = new Database(api, b.retries);
        this.cache = b.cacheEnabled
                ? Caffeine.newBuilder().maximumSize(b.cacheSize).expireAfterWrite(b.cacheTtl).build()
                : null;
        this.gate = new Semaphore(b.concurrency);
        this.ownedExecutor = b.executor == null ? Executors.newCachedThreadPool(daemonThreads()) : null;
        this.executor = b.executor != null ? b.executor : this.ownedExecutor;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A client on the free tier, with every default. */
    public static VPNDetection create() {
        return builder().build();
    }

    /**
     * Whether an address is private, loopback, link-local, documentation, multicast or otherwise
     * not routable, including the IPv6 equivalents and the 6to4 and Teredo ranges.
     *
     * <p>These are the addresses {@link #lookup(String)} answers locally. Exposed here so the check
     * is reachable from the client you already hold; {@link Bogon#isBogon(String)} is the same
     * check without one.
     */
    public boolean isBogon(String ip) {
        return Bogon.isBogon(ip);
    }

    /** Classify one address with the client's defaults. */
    public Result lookup(String ip) {
        return lookup(ip, new LookupOptions());
    }

    /**
     * Classify one address.
     *
     * <p>A bogon is answered locally and never reaches the network. Everything else is served, then
     * cached for this instance.
     */
    public Result lookup(String ip, LookupOptions options) {
        Objects.requireNonNull(ip, "ip");
        Objects.requireNonNull(options, "options");
        if (Bogon.isBogon(ip)) {
            return Result.bogon(ip);
        }
        Result hit = cache == null ? null : cache.getIfPresent(ip);
        if (hit != null) {
            return hit;
        }
        Integer perCall = options.retriesOrNull();
        Result result = Wire.execute(perCall != null ? perCall : retries,
                () -> Result.of(lookupApi.lookupIp(ip)));
        if (cache != null) {
            cache.put(ip, result);
        }
        return result;
    }

    public CompletableFuture<Result> lookupAsync(String ip) {
        return lookupAsync(ip, new LookupOptions());
    }

    public CompletableFuture<Result> lookupAsync(String ip, LookupOptions options) {
        return CompletableFuture.supplyAsync(() -> lookup(ip, options), executor);
    }

    /** Classify many addresses concurrently, with the client's defaults. */
    public LinkedHashMap<String, BatchResult> lookupBatch(Collection<String> ips) {
        return lookupBatch(ips, new BatchOptions());
    }

    /**
     * Classify many addresses concurrently.
     *
     * <p>Keyed by address rather than positional, so duplicates in the input collapse to a single
     * request and the caller never has to line two lists up. An address that fails carries its
     * error as its value, so one bad entry cannot lose the rest of the answers. Iteration order is
     * the order the addresses were first seen in the input.
     */
    public LinkedHashMap<String, BatchResult> lookupBatch(Collection<String> ips, BatchOptions options) {
        Objects.requireNonNull(ips, "ips");
        Objects.requireNonNull(options, "options");
        Integer perCall = options.concurrencyOrNull();
        // A per-call concurrency gets its OWN semaphore. Reusing the instance's would silently cap
        // the override at the client's setting, which passes any test that does not measure peak.
        Semaphore limit = perCall == null ? gate : new Semaphore(perCall);

        LinkedHashMap<String, CompletableFuture<BatchResult>> pending = new LinkedHashMap<>();
        for (String ip : new LinkedHashSet<>(ips)) {
            pending.put(ip, submit(limit, ip, options));
        }
        LinkedHashMap<String, BatchResult> out = new LinkedHashMap<>();
        pending.forEach((ip, future) -> out.put(ip, future.join()));
        return out;
    }

    public CompletableFuture<LinkedHashMap<String, BatchResult>> lookupBatchAsync(Collection<String> ips) {
        return lookupBatchAsync(ips, new BatchOptions());
    }

    /**
     * The same batch off the calling thread.
     *
     * <p>A supplied executor must be able to grow: this coordinator occupies one of its threads
     * while the lookups occupy the rest, so a fixed pool can deadlock. The default executor and a
     * virtual-thread executor are both fine.
     */
    public CompletableFuture<LinkedHashMap<String, BatchResult>> lookupBatchAsync(
            Collection<String> ips, BatchOptions options) {
        return CompletableFuture.supplyAsync(() -> lookupBatch(ips, options), executor);
    }

    /** The licensed dataset downloads, for keys that carry the {@code db.download} scope. */
    public Database database() {
        return database;
    }

    /** Releases the thread pool this client created. A supplied executor is left alone. */
    @Override
    public void close() {
        if (ownedExecutor != null) {
            ownedExecutor.shutdown();
        }
    }

    // The permit is taken on the CALLING thread, before the task is handed to the executor, so at
    // most `concurrency` tasks ever exist. Acquiring inside the task would queue every address at
    // once and let a large batch conjure a thread per address.
    private CompletableFuture<BatchResult> submit(Semaphore limit, String ip, LookupOptions options) {
        try {
            limit.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return CompletableFuture.completedFuture(BatchResult.failed(
                    new VPNDetectionException(ErrorKind.NETWORK, "interrupted while starting a batch", e)));
        }
        return CompletableFuture.supplyAsync(() -> {
            try {
                return BatchResult.found(lookup(ip, options));
            } catch (VPNDetectionException e) {
                return BatchResult.failed(e);
            } finally {
                limit.release();
            }
        }, executor);
    }

    private static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                // Database.downloadUrl reads the Location off a 302 rather than following it.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static ThreadFactory daemonThreads() {
        AtomicLong seq = new AtomicLong();
        return runnable -> {
            Thread t = new Thread(runnable, "vpndetection-" + seq.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    /** Settings for a {@link VPNDetection} client. Every one of them has a working default. */
    public static final class Builder {
        private String apiKey;
        private String baseUrl = DEFAULT_BASE_URL;
        private boolean cacheEnabled = true;
        private long cacheSize = 10_000;
        private Duration cacheTtl = Duration.ofHours(1);
        private int concurrency = 8;
        private int retries = 2;
        private Duration requestTimeout = Duration.ofSeconds(30);
        private HttpClient httpClient;
        private Executor executor;

        private Builder() {}

        /**
         * Your API key. Leave it unset to use the free tier, which answers {@code ip} and
         * {@code is_vpn} and allows 1000 requests per day per source address.
         */
        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
            return this;
        }

        /** Pass {@code false} to disable caching. */
        public Builder cacheEnabled(boolean cacheEnabled) {
            this.cacheEnabled = cacheEnabled;
            return this;
        }

        /** Maximum number of addresses held. Default 10000. */
        public Builder cacheSize(long cacheSize) {
            this.cacheSize = cacheSize;
            return this;
        }

        /** How long an answer stays fresh. Default 1 hour. */
        public Builder cacheTtl(Duration cacheTtl) {
            this.cacheTtl = Objects.requireNonNull(cacheTtl, "cacheTtl");
            return this;
        }

        /** Concurrent in-flight requests during a batch. Default 8. */
        public Builder concurrency(int concurrency) {
            if (concurrency < 1) {
                throw new IllegalArgumentException("concurrency must be at least 1");
            }
            this.concurrency = concurrency;
            return this;
        }

        /** Retry attempts for a transient failure. Default 2. */
        public Builder retries(int retries) {
            if (retries < 0) {
                throw new IllegalArgumentException("retries cannot be negative");
            }
            this.retries = retries;
            return this;
        }

        /** How long one request may take before it is abandoned. Default 30 seconds. */
        public Builder requestTimeout(Duration requestTimeout) {
            this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
            return this;
        }

        /**
         * Use a specific {@link HttpClient}, for a proxy, a custom SSL context or a test double.
         *
         * <p>It must NOT follow redirects, or {@link Database#downloadUrl} will fetch the dataset
         * instead of returning its link.
         */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
            return this;
        }

        /**
         * Where batch and async work runs. Defaults to a cached pool of daemon threads, held to the
         * configured concurrency by the client's own limiter; on Java 21 and up,
         * {@code Executors.newVirtualThreadPerTaskExecutor()} is a good substitute. The client will
         * not shut down an executor it did not create.
         */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor");
            return this;
        }

        public VPNDetection build() {
            return new VPNDetection(this);
        }
    }

    /**
     * Hands the generated client one already-built {@link HttpClient}.
     *
     * <p>{@code ApiClient} only accepts a {@link HttpClient.Builder} and calls {@code build()} once
     * per generated API class, so a real builder would produce a second client, with its own
     * selector thread and connection pool, for every API added here.
     */
    private static final class FixedHttpClientBuilder implements HttpClient.Builder {
        private final HttpClient client;

        FixedHttpClientBuilder(HttpClient client) {
            this.client = client;
        }

        @Override
        public HttpClient build() {
            return client;
        }

        @Override
        public HttpClient.Builder cookieHandler(CookieHandler cookieHandler) {
            return this;
        }

        @Override
        public HttpClient.Builder connectTimeout(Duration duration) {
            return this;
        }

        @Override
        public HttpClient.Builder sslContext(SSLContext sslContext) {
            return this;
        }

        @Override
        public HttpClient.Builder sslParameters(SSLParameters sslParameters) {
            return this;
        }

        @Override
        public HttpClient.Builder executor(Executor executor) {
            return this;
        }

        @Override
        public HttpClient.Builder followRedirects(HttpClient.Redirect policy) {
            return this;
        }

        @Override
        public HttpClient.Builder version(HttpClient.Version version) {
            return this;
        }

        @Override
        public HttpClient.Builder priority(int priority) {
            return this;
        }

        @Override
        public HttpClient.Builder proxy(ProxySelector proxySelector) {
            return this;
        }

        @Override
        public HttpClient.Builder authenticator(Authenticator authenticator) {
            return this;
        }
    }
}
