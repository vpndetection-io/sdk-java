package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * The client's own JDK transport against a real local server. The stubs elsewhere answer whatever
 * body type they like, so only this suite reaches the buffering behind the request timeout.
 */
class TransportTest {
    private final CountDownLatch release = new CountDownLatch(1);
    private final ExecutorService handlers = Executors.newCachedThreadPool();
    private HttpServer server;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(handlers);
        server.createContext("/", this::answer);
        server.start();
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
        handlers.shutdownNow();
    }

    @Test
    void aServedAnswerAndAnErrorBodyBothArriveWhole() {
        try (VPNDetection client = clientWithTimeout(Duration.ofSeconds(10))) {
            assertTrue(client.lookup("1.1.1.1").isVpn());

            VPNDetectionException e = assertThrows(VPNDetectionException.class,
                    () -> client.lookup("notanip"));
            assertEquals(ErrorKind.BAD_REQUEST, e.kind());
            assertEquals("not a valid IP address", e.getMessage());
        }
    }

    // The JDK stops a request's clock once the headers arrive, so this one would otherwise wait
    // for the server to give up.
    @Test
    void theTimeoutCoversABodyThatStallsAfterItsHeaders() {
        try (VPNDetection client = clientWithTimeout(Duration.ofMillis(300))) {
            assertTimesOut(() -> client.lookup("8.8.8.8"), "after 300ms");
        }
    }

    @Test
    void aPerCallTimeoutBelowTheClientsFiresOnTheRealTransport() {
        try (VPNDetection client = clientWithTimeout(Duration.ofSeconds(10))) {
            assertTimesOut(() -> client.lookup("9.9.9.9",
                    new LookupOptions().requestTimeout(Duration.ofMillis(300))), "after 300ms");
            assertTimesOut(() -> client.lookup("8.8.8.8",
                    new LookupOptions().requestTimeout(Duration.ofMillis(300))), "after 300ms");
        }
    }

    private VPNDetection clientWithTimeout(Duration timeout) {
        return VPNDetection.builder()
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .cacheEnabled(false)
                .retries(0)
                .requestTimeout(timeout)
                .build();
    }

    private static void assertTimesOut(Runnable call, String bound) {
        long started = System.nanoTime();
        VPNDetectionException e = assertThrows(VPNDetectionException.class, call::run);
        long took = Duration.ofNanos(System.nanoTime() - started).toMillis();

        assertEquals(ErrorKind.NETWORK, e.kind());
        assertTrue(e.retryable());
        assertTrue(e.getMessage().contains(bound), e.getMessage());
        assertTrue(took < 5000, "took " + took + "ms, past the bound");
    }

    // 1.1.1.1 is served, notanip is refused, 8.8.8.8 stalls half way through its body and 9.9.9.9
    // stalls before its headers, each until the test is over.
    private void answer(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        exchange.getResponseHeaders().add("content-type", "application/json");
        OutputStream out = exchange.getResponseBody();
        try {
            switch (path) {
                case "/1.1.1.1":
                    write(exchange, out, 200, "{\"ip\": \"1.1.1.1\", \"is_vpn\": true}");
                    break;
                case "/notanip":
                    write(exchange, out, 400, "{\"error\": \"not a valid IP address\"}");
                    break;
                case "/8.8.8.8":
                    exchange.sendResponseHeaders(200, 100);
                    out.write("{\"ip\": ".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    stall();
                    break;
                default:
                    stall();
                    break;
            }
        } finally {
            // Unlike the body stream's own close, this one does not throw over a short body.
            exchange.close();
        }
    }

    private static void write(HttpExchange exchange, OutputStream out, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        out.write(bytes);
    }

    private void stall() {
        try {
            release.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
