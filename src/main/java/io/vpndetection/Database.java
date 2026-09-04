package io.vpndetection;

import io.vpndetection.api.DatabaseApi;
import io.vpndetection.internal.ApiClient;
import io.vpndetection.internal.ApiException;
import io.vpndetection.model.DatasetChecksums;
import io.vpndetection.model.DatasetMetadata;
import io.vpndetection.model.Download;
import io.vpndetection.model.LicensedDataset;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Objects;

/**
 * The licensed dataset downloads, reached through {@link VPNDetection#database()}.
 *
 * <p>Access is granted by contract rather than self-serve, so every method here answers
 * {@link ErrorKind#UNAUTHORIZED} for a key without the {@code db.download} scope.
 */
public final class Database {
    // A byte[] cannot be longer than this, so a dataset past it is read in growing chunks and
    // fails on its own weight rather than on a bad allocation size.
    private static final long MAX_ARRAY_LENGTH = Integer.MAX_VALUE - 8L;

    private final DatabaseApi api;
    private final HttpClient transfer;
    private final int retries;

    Database(ApiClient client, int retries) {
        this.api = new DatabaseApi(client);
        // The same HTTP client, reached WITHOUT the generated request interceptor that carries the
        // API key. See fetchDatasetFile.
        this.transfer = client.getHttpClient();
        this.retries = retries;
    }

    /**
     * The dataset families your organization is licensed to download.
     *
     * <p>A license covers a family, while a download names one of its versions, so the ids the
     * other methods here take come from {@link LicensedDataset#getVersions()} rather than from the
     * family itself.
     */
    public List<LicensedDataset> list() {
        return Wire.execute(retries, () -> api.listDatabases().getDatasets());
    }

    /**
     * What is inside one dataset: schema, samples, row count and sizes.
     *
     * <p>Carries {@code updated} and {@code entries}, so it answers whether today's build is worth
     * fetching without downloading anything.
     */
    public DatasetMetadata metadata(String id) {
        Objects.requireNonNull(id, "id");
        return Wire.execute(retries, () -> api.databaseMetadata(id));
    }

    /**
     * The digests of one published file, to verify a download.
     *
     * <p>The whole set is returned rather than one digest: which ones a dataset publishes is the
     * API's choice, not this library's.
     */
    public DatasetChecksums checksums(String id, DatasetFormat format) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(format, "format");
        return Wire.execute(retries,
                () -> api.databaseChecksum(id, format.wireValue()).getChecksums());
    }

    /** Your organization's recent download attempts, newest first. */
    public List<Download> downloads() {
        return Wire.execute(retries, () -> api.listDownloads(null).getDownloads());
    }

    public List<Download> downloads(int limit) {
        return Wire.execute(retries, () -> api.listDownloads(limit).getDownloads());
    }

    /**
     * The time-limited URL for one dataset file.
     *
     * <p>The API answers {@code 302} to object storage. The URL is returned rather than the bytes
     * so the caller decides how to transfer a file that routinely runs to gigabytes; the link
     * authorizes the START of a transfer, so one already running is not interrupted when it lapses.
     */
    public String downloadUrl(String id, DatasetFormat format) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(format, "format");
        return Wire.execute(retries, () -> {
            try {
                api.downloadDatabaseWithHttpInfo(id, format.wireValue());
            } catch (ApiException e) {
                // The generated method treats any non-2xx as a failure, so the SUCCESS case for
                // this endpoint arrives as an exception carrying the Location header.
                String location = e.getCode() != 302 || e.getResponseHeaders() == null
                        ? null
                        : e.getResponseHeaders().firstValue("Location").orElse(null);
                if (location == null) {
                    throw e;
                }
                return location;
            }
            throw new VPNDetectionException(ErrorKind.SERVER_ERROR,
                    "expected a redirect to object storage; the HttpClient must not follow redirects");
        });
    }

    /**
     * Download one dataset file to {@code destination}, and return the bytes written.
     *
     * <p>The bytes are streamed straight to disk, so nothing beyond one chunk is ever held in
     * memory whatever the dataset weighs. They land in a neighboring {@code .part} file that is
     * renamed on completion, so a transfer that dies half way leaves no truncated file that reads
     * as a whole dataset, and no leftover either.
     */
    public long download(String id, DatasetFormat format, Path destination) {
        Objects.requireNonNull(destination, "destination");
        HttpResponse<InputStream> response = fetchDatasetFile(id, format);
        Path partial = destination.resolveSibling(destination.getFileName() + ".part");
        try {
            long written;
            try (InputStream body = response.body();
                    OutputStream out = Files.newOutputStream(partial)) {
                written = body.transferTo(out);
            }
            assertWholeTransfer(response, written);
            Files.move(partial, destination,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return written;
        } catch (IOException e) {
            // A failure writing is worth telling apart from one reading: a full disk and a reset
            // socket are different problems, and only one of them is ours.
            throw new VPNDetectionException(ErrorKind.NETWORK,
                    "the dataset transfer to " + destination + " failed", e);
        } finally {
            // Reached on the way out of every path. After a successful move there is nothing left
            // under this name, so the successful case pays a stat call and nothing else.
            deleteQuietly(partial);
        }
    }

    /**
     * Download one dataset file and hand back its bytes.
     *
     * <p><b>This holds the entire file in memory</b>, and the catalog spans five orders of
     * magnitude, from {@code cdn_ip_v1} at 10 KB to {@code resproxy_ip_90d_v1} at 1.79 GB. Reach
     * for it at the small end, where the bytes go straight into a parser, and use
     * {@link #download} for anything you have not measured.
     */
    public byte[] downloadBytes(String id, DatasetFormat format) {
        HttpResponse<InputStream> response = fetchDatasetFile(id, format);
        try (InputStream body = response.body()) {
            long declared = declaredLength(response);
            // Allocated once from the declared length where there is one: readAllBytes grows by
            // doubling, so on a large dataset the final grow alone costs twice the file.
            byte[] bytes = declared >= 0 && declared <= MAX_ARRAY_LENGTH
                    ? body.readNBytes((int) declared)
                    : body.readAllBytes();
            assertWholeTransfer(response, bytes.length);
            return bytes;
        } catch (IOException e) {
            throw new VPNDetectionException(ErrorKind.NETWORK, "the dataset transfer failed", e);
        }
    }

    /**
     * Follows the {@code 302} as a SECOND, unauthenticated request.
     *
     * <p>The presigned URL carries its own authorization, so forwarding the API key would hand a
     * credential to a host that has no business holding it. The key rides a request interceptor on
     * the generated client, and this request is built by hand rather than going through it.
     *
     * <p>That is deliberate rather than a formality, because the JDK's own rule is subtler than it
     * looks: an {@link HttpClient} set to follow redirects drops {@code Authorization} when the
     * redirect crosses origins but FORWARDS it when it does not, so "the JDK strips it" is not
     * something a library can lean on.
     */
    private HttpResponse<InputStream> fetchDatasetFile(String id, DatasetFormat format) {
        URI url;
        String location = downloadUrl(id, format);
        try {
            url = new URI(location);
        } catch (URISyntaxException e) {
            throw new VPNDetectionException(ErrorKind.SERVER_ERROR, "the download link is not a URL", e);
        }
        return Wire.retrying(retries, () -> {
            HttpResponse<InputStream> response;
            try {
                // No request timeout is set. The client's is a bound on a lookup, and a dataset
                // that runs to gigabytes is a different kind of wait.
                response = transfer.send(HttpRequest.newBuilder(url).GET().build(),
                        HttpResponse.BodyHandlers.ofInputStream());
            } catch (IOException e) {
                throw new VPNDetectionException(ErrorKind.NETWORK, "the dataset transfer failed", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VPNDetectionException(ErrorKind.NETWORK, "interrupted during a transfer", e);
            }
            if (response.statusCode() != 200) {
                // Left unread: the status is what separates a lapsed link from a refused one, and
                // nothing bounds the size of an error body.
                closeQuietly(response.body());
                throw new VPNDetectionException(Wire.kindOf(response.statusCode(), null),
                        "object storage refused the download link with status " + response.statusCode(),
                        response.statusCode(), null, null);
            }
            return response;
        });
    }

    // A transfer that dies mid-body can reach a reader as a plain end of stream, so a short read is
    // silent unless what arrived is checked against what was promised.
    private static void assertWholeTransfer(HttpResponse<InputStream> response, long written) {
        long declared = declaredLength(response);
        if (declared >= 0 && declared != written) {
            throw new VPNDetectionException(ErrorKind.NETWORK,
                    "the transfer ended after " + written + " of " + declared + " bytes",
                    response.statusCode(), null, null);
        }
    }

    /** The declared body length, or -1 when the response does not carry a usable one. */
    private static long declaredLength(HttpResponse<InputStream> response) {
        try {
            return response.headers().firstValueAsLong("Content-Length").orElse(-1L);
        } catch (NumberFormatException notALength) {
            return -1L;
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Nothing useful to do: the caller is already being told what actually went wrong.
        }
    }

    private static void closeQuietly(InputStream body) {
        try {
            body.close();
        } catch (IOException ignored) {
            // Same: the status this response carried is the thing worth reporting.
        }
    }
}
