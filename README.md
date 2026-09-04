# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection Java Client Library

[![Maven Central](https://img.shields.io/maven-central/v/io.vpndetection/vpndetection.svg)](https://central.sonatype.com/artifact/io.vpndetection/vpndetection)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The official Java client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```xml
<dependency>
    <groupId>io.vpndetection</groupId>
    <artifactId>vpndetection</artifactId>
    <version>1.0.0</version>
</dependency>
```

```groovy
implementation 'io.vpndetection:vpndetection:1.0.0'
```

Requires Java 17 or newer. HTTP is the JDK's own `java.net.http.HttpClient`, so there is no third-party HTTP stack to reconcile with yours.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```java
import io.vpndetection.Result;
import io.vpndetection.VPNDetection;

VPNDetection client = VPNDetection.create();

Result result = client.lookup("45.83.91.1");
System.out.println(result.isVpn());   // true
```

Build the client once and keep it. It owns a connection pool, a cache and a thread pool, and it is thread safe.

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```java
VPNDetection client = VPNDetection.builder()
        .apiKey(System.getenv("VPNDETECTION_API_KEY"))
        .build();

Result result = client.lookup("45.83.91.1");
System.out.println(result.isVpn());                          // true
System.out.println(result.vpn().get().getProvider());        // "mullvad"
System.out.println(result.isHosting());                      // Optional[true]
System.out.println(result.hosting().get().getProvider());
```

Every member your plan does not include comes back as an empty `Optional`, which is not the same answer as `false`. Empty is "not in your plan"; `false` is "checked, and no". When you only care whether an address is flagged, each one has a companion that coalesces:

```java
result.isHosting();          // Optional<Boolean>, empty on a plan without it
result.isHosting().orElse(false);   // boolean, false on a plan without it
```

### Batch lookup

You can do batch lookups with a list, which parallelizes requests for you efficiently:

```java
var results = client.lookupBatch(List.of("45.83.91.1", "8.8.8.8", "1.1.1.1"));

for (var entry : results.entrySet()) {
    if (!entry.getValue().isSuccess()) {
        System.err.println(entry.getKey() + ": " + entry.getValue().error().get().getMessage());
        continue;
    }
    System.out.println(entry.getKey() + ": " + entry.getValue().orElseThrow().isVpn());
}
```

Results are keyed by address, so duplicates in your list collapse into a single request and one address failing never loses the rest.

Concurrency and other variables are configurable per-call:

```java
var results = client.lookupBatch(manyIps, new BatchOptions().concurrency(32).retries(4));
```

There are `CompletableFuture` variants of both, for when you would rather not block:

```java
client.lookupAsync("45.83.91.1").thenAccept(r -> System.out.println(r.isVpn()));
client.lookupBatchAsync(manyIps).thenAccept(results -> System.out.println(results.size()));
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```java
VPNDetection client = VPNDetection.create();

Result result = client.lookup("45.83.91.1");
System.out.println(result.isVpn());   // true, API request

Result result2 = client.lookup("45.83.91.1");
System.out.println(result2.isVpn());  // true, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```java
VPNDetection client = VPNDetection.builder()
        .cacheSize(50_000)
        .cacheTtl(Duration.ofHours(6))
        .build();

VPNDetection clientNoCache = VPNDetection.builder().cacheEnabled(false).build();
```

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```java
Result result = client.lookup("192.168.1.1");
result.isBogon();   // true, this answer was computed rather than served
result.isVpn();     // false
```

The check is available on the client, which is handy when your inputs are addresses anyway:

```java
client.isBogon("10.0.0.1");    // true
client.isBogon("8.8.8.8");     // false
```

It is also available on its own, if you want it without a client:

```java
import static io.vpndetection.Bogon.isBogon;

isBogon("10.0.0.1");    // true
```

### Errors

Failures throw a `VPNDetectionException` carrying a `kind()` and a `retryable()` flag. It is unchecked, so it travels through a stream or a future without being wrapped first:

```java
import io.vpndetection.VPNDetectionException;

try {
    client.lookup("1.1.1.1");
} catch (VPNDetectionException e) {
    System.err.println(e.kind() + " " + e.retryable());
}
```

`kind()` is one of `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `RATE_LIMITED`, `QUOTA_EXCEEDED`, `SERVER_ERROR` or `NETWORK`.

Note that `RATE_LIMITED` and `QUOTA_EXCEEDED` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed datasets are available through `client.database()`. A license covers a dataset family, and the ids the transfers take come from its `getVersions()`. There are three ways to take one: to a file, as a time-limited link you transfer yourself, or as bytes.

```java
var datasets = client.database().list();

// Streamed straight to disk, so nothing bigger than a chunk is ever held in memory.
long written = client.database().download(
        "vpn_ip_extended_v1", DatasetFormat.MMDB, Path.of("vpn_ip_extended_v1.mmdb"));
String url = client.database().downloadUrl("vpn_ip_extended_v1", DatasetFormat.MMDB);
byte[] raw = client.database().downloadBytes("cdn_ip_v1", DatasetFormat.CSVGZ);
```

`downloadBytes` holds the whole file in memory, and the catalog runs from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at 1.79 GB, so use `download` for anything you have not measured.

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
