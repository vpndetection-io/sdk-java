package io.vpndetection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.vpndetection.api.EntitlementWireApi;
import io.vpndetection.api.LookupWireApi;
import io.vpndetection.internal.ApiClient;
import io.vpndetection.model.BatchLookupError;
import io.vpndetection.model.BatchLookupRequest;
import io.vpndetection.model.BatchLookupResponse;
import io.vpndetection.model.Entitlement;
import io.vpndetection.model.LookupResponse;

import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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

    // The most addresses POST /batch takes in one call; a larger batch is sent in chunks of this
    // size.
    private static final int BATCH_MAX = 1000;

    private final ApiClient api;
    private final LookupWireApi lookupApi;
    private final EntitlementWireApi entitlementApi;
    private final DatabaseApi database;
    private final Cache<String, Result> cache;
    private final Semaphore gate;
    private final ExecutorService ownedExecutor;
    private final Executor executor;
    private final int retries;
    private final Duration requestTimeout;

    private VPNDetection(Builder b) {
        HttpClient http = new DeadlineHttpClient(b.httpClient != null ? b.httpClient : defaultHttpClient());
        this.api = new ApiClient(new FixedHttpClientBuilder(http),
                ApiClient.createDefaultObjectMapper(), b.baseUrl);
        api.setReadTimeout(b.requestTimeout);
        if (b.apiKey != null) {
            // The `native` generator emits no auth plumbing at all, so the key goes on by hand.
            api.setRequestInterceptor(rb -> rb.header("Authorization", "Bearer " + b.apiKey));
        }

        this.lookupApi = new LookupWireApi(api);
        this.entitlementApi = new EntitlementWireApi(api);
        this.retries = b.retries;
        this.requestTimeout = b.requestTimeout;
        this.database = new DatabaseApi(api, b.retries);
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
        LookupWireApi wire = lookupApi(options);
        Result result = Wire.execute(retries(options), () -> Result.of(wire.lookupIp(ip)));
        if (cache != null) {
            cache.put(ip, result);
        }
        return result;
    }

    /** Classify the address this client is calling from, with the client's defaults. */
    public Result myIp() {
        return myIp(new LookupOptions());
    }

    /**
     * Classify the address this client is calling from.
     *
     * <p>The same answer {@code lookup} would give for that address, at the same cost against your
     * allowance. The address is the one our edge observed, so a call made through a proxy or a VPN
     * reports the exit it left through - usually the point of asking.
     *
     * <p>Deliberately NOT cached. The cache is keyed by address, and which address this is IS the
     * question: a machine that moves between networks would otherwise be told where it used to be.
     */
    public Result myIp(LookupOptions options) {
        Objects.requireNonNull(options, "options");
        LookupWireApi wire = lookupApi(options);
        return Wire.execute(retries(options), () -> Result.of(wire.lookupMyIp()));
    }

    public CompletableFuture<Result> myIpAsync() {
        return myIpAsync(new LookupOptions());
    }

    public CompletableFuture<Result> myIpAsync(LookupOptions options) {
        return CompletableFuture.supplyAsync(() -> myIp(options), executor);
    }

    /** What this client's key is entitled to, with the client's defaults. */
    public Entitlement myEntitlement() {
        return myEntitlement(new LookupOptions());
    }

    /**
     * What this client's key is entitled to, and how much of it has been used.
     *
     * <p>Named for what it answers rather than {@code me}, which sits one letter from {@code myIp}
     * and means something quite different: one is which address you are calling FROM, the other is
     * what the key you are calling WITH may spend.
     *
     * <p>Unlike a lookup there is no useful unauthenticated answer, so a client built without an API
     * key gets an unauthorized error rather than a partial one.
     *
     * <p>Usage counts against the ALLOWANCE WINDOW - the anniversary of the subscription, not the
     * calendar month and not the billing period - and it is the same number a lookup is gated on. It
     * can lag by a few seconds, because requests are counted in memory and flushed in aggregate.
     *
     * <p>Deliberately NOT cached: the whole point is what has been spent, and a cached answer is a
     * wrong one within seconds of the next request.
     */
    public Entitlement myEntitlement(LookupOptions options) {
        Objects.requireNonNull(options, "options");
        ApiClient scoped = scoped(options);
        EntitlementWireApi wire = scoped == api ? entitlementApi : new EntitlementWireApi(scoped);
        return Wire.execute(retries(options), wire::myEntitlement);
    }

    public CompletableFuture<Entitlement> myEntitlementAsync() {
        return myEntitlementAsync(new LookupOptions());
    }

    public CompletableFuture<Entitlement> myEntitlementAsync(LookupOptions options) {
        return CompletableFuture.supplyAsync(() -> myEntitlement(options), executor);
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
     * Classify many addresses in as few requests as possible.
     *
     * <p>Takes any number of addresses: sending them in chunks the endpoint accepts is this
     * method's job, not the caller's.
     *
     * <p>Bogons are answered locally and cached answers are reused; everything else goes to the
     * batch endpoint in chunks of up to 1000 addresses, with at most {@code concurrency} chunks in
     * flight. Keyed by address rather than positional, so duplicates in the input collapse to a
     * single entry and the caller never has to line two lists up. An address that fails carries its
     * error as its value, so one bad entry cannot lose the rest of the answers: the API reports a
     * per-entry failure with the status the single lookup would have answered, and a chunk that
     * fails as a whole marks every address in it. Iteration order is the order the addresses were
     * first seen in the input.
     */
    public LinkedHashMap<String, BatchResult> lookupBatch(Collection<String> ips, BatchOptions options) {
        Objects.requireNonNull(ips, "ips");
        Objects.requireNonNull(options, "options");
        Integer perCall = options.concurrencyOrNull();
        // A per-call concurrency gets its OWN semaphore. Reusing the instance's would silently cap
        // the override at the client's setting, which passes any test that does not measure peak.
        Semaphore limit = perCall == null ? gate : new Semaphore(perCall);

        LinkedHashSet<String> unique = new LinkedHashSet<>(ips);
        Map<String, BatchResult> answers = new HashMap<>();
        List<String> pending = new ArrayList<>();
        for (String ip : unique) {
            if (Bogon.isBogon(ip)) {
                answers.put(ip, BatchResult.found(Result.bogon(ip)));
                continue;
            }
            Result hit = cache == null ? null : cache.getIfPresent(ip);
            if (hit != null) {
                answers.put(ip, BatchResult.found(hit));
                continue;
            }
            pending.add(ip);
        }

        LookupWireApi wire = lookupApi(options);
        int callRetries = retries(options);
        List<CompletableFuture<Map<String, BatchResult>>> chunks = new ArrayList<>();
        for (int from = 0; from < pending.size(); from += BATCH_MAX) {
            List<String> chunk = List.copyOf(pending.subList(from, Math.min(from + BATCH_MAX, pending.size())));
            chunks.add(submit(limit, chunk, wire, callRetries));
        }
        for (CompletableFuture<Map<String, BatchResult>> chunk : chunks) {
            answers.putAll(chunk.join());
        }
        LinkedHashMap<String, BatchResult> out = new LinkedHashMap<>();
        for (String ip : unique) {
            out.put(ip, answers.get(ip));
        }
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
    public DatabaseApi database() {
        return database;
    }

    /** Releases the thread pool this client created. A supplied executor is left alone. */
    @Override
    public void close() {
        if (ownedExecutor != null) {
            ownedExecutor.shutdown();
        }
    }

    static Duration positive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    private int retries(LookupOptions options) {
        Integer perCall = options.retriesOrNull();
        return perCall != null ? perCall : retries;
    }

    private LookupWireApi lookupApi(LookupOptions options) {
        ApiClient scoped = scoped(options);
        return scoped == api ? lookupApi : new LookupWireApi(scoped);
    }

    // A generated API class reads its timeout once, when it is built, so a per-call timeout needs
    // an instance of its own. That is a handful of field copies over the SAME HttpClient, not a
    // second connection pool.
    private ApiClient scoped(LookupOptions options) {
        Duration perCall = options.requestTimeoutOrNull();
        if (perCall == null || perCall.equals(requestTimeout)) {
            return api;
        }
        ApiClient scoped = new ApiClient(new FixedHttpClientBuilder(api.getHttpClient()),
                api.getObjectMapper(), api.getBaseUri());
        scoped.setReadTimeout(perCall);
        scoped.setRequestInterceptor(api.getRequestInterceptor());
        return scoped;
    }

    // The permit is taken on the CALLING thread, before the task is handed to the executor, so at
    // most `concurrency` chunks ever exist. Acquiring inside the task would queue every chunk at
    // once and let a large batch conjure a thread per chunk.
    private CompletableFuture<Map<String, BatchResult>> submit(
            Semaphore limit, List<String> chunk, LookupWireApi wire, int callRetries) {
        try {
            limit.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return CompletableFuture.completedFuture(failedChunk(chunk,
                    new VPNDetectionException(ErrorKind.NETWORK, "interrupted while starting a batch", e)));
        }
        return CompletableFuture.supplyAsync(() -> {
            try {
                return lookupChunk(chunk, wire, callRetries);
            } finally {
                limit.release();
            }
        }, executor);
    }

    // One POST /batch, mapped back onto the addresses it was asked about. A chunk-level failure -
    // the call refused, the transport failing, the retries exhausted - becomes every address's
    // error, exactly as it would have been had each been looked up alone.
    private Map<String, BatchResult> lookupChunk(List<String> chunk, LookupWireApi wire, int callRetries) {
        BatchLookupResponse body;
        try {
            body = Wire.execute(callRetries, () -> wire.lookupBatch(new BatchLookupRequest().ips(chunk)));
        } catch (VPNDetectionException e) {
            return failedChunk(chunk, e);
        }
        Map<String, LookupResponse> served = body.getResults() == null ? Map.of() : body.getResults();
        Map<String, BatchLookupError> failed = body.getErrors() == null ? Map.of() : body.getErrors();
        Map<String, BatchResult> out = new HashMap<>();
        for (String ip : chunk) {
            LookupResponse answer = served.get(ip);
            if (answer != null) {
                Result result = Result.of(answer);
                if (cache != null) {
                    cache.put(ip, result);
                }
                out.put(ip, BatchResult.found(result));
                continue;
            }
            BatchLookupError entry = failed.get(ip);
            if (entry != null) {
                int status = entry.getStatus() == null ? 500 : entry.getStatus();
                out.put(ip, BatchResult.failed(Wire.fromEntry(status, entry.getError())));
                continue;
            }
            out.put(ip, BatchResult.failed(new VPNDetectionException(
                    ErrorKind.SERVER_ERROR, "the batch answer did not include " + ip, 200, null, null)));
        }
        return out;
    }

    private static Map<String, BatchResult> failedChunk(List<String> chunk, VPNDetectionException error) {
        Map<String, BatchResult> out = new HashMap<>();
        for (String ip : chunk) {
            out.put(ip, BatchResult.failed(error));
        }
        return out;
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

        /** Concurrent batch requests - chunks of up to 1000 addresses - during a batch. Default 8. */
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

        /**
         * How long one attempt at a call may take, response body included, before it is abandoned
         * as a retryable {@link ErrorKind#NETWORK} failure. Default 30 seconds.
         *
         * <p>Per ATTEMPT, so a call that is retried can take longer in total. Overridable per call
         * with {@link LookupOptions#requestTimeout}. A dataset transfer is not bounded by it.
         */
        public Builder requestTimeout(Duration requestTimeout) {
            this.requestTimeout = positive(requestTimeout, "requestTimeout");
            return this;
        }

        /**
         * Use a specific {@link HttpClient}, for a proxy, a custom SSL context or a test double.
         *
         * <p>It must NOT follow redirects, or {@link DatabaseApi#downloadUrl} will fetch the dataset
         * instead of returning its link. API calls go through its {@code sendAsync}, which is how
         * {@link #requestTimeout} holds even where the client itself ignores a request's timeout.
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
