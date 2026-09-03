package io.vpndetection;

import io.vpndetection.api.DatabaseApi;
import io.vpndetection.internal.ApiClient;
import io.vpndetection.internal.ApiException;
import io.vpndetection.model.DatasetMetadata;
import io.vpndetection.model.Download;
import io.vpndetection.model.LicensedDataset;

import java.util.List;
import java.util.Objects;

/**
 * The licensed dataset downloads, reached through {@link VPNDetection#database()}.
 *
 * <p>Access is granted by contract rather than self-serve, so every method here answers
 * {@link ErrorKind#UNAUTHORIZED} for a key without the {@code db.download} scope.
 */
public final class Database {
    private final DatabaseApi api;
    private final int retries;

    Database(ApiClient client, int retries) {
        this.api = new DatabaseApi(client);
        this.retries = retries;
    }

    /** The datasets your organization is licensed to download. */
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

    /** The SHA-256 of one published file, to verify a download. */
    public String checksum(String id, DatasetFormat format) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(format, "format");
        return Wire.execute(retries,
                () -> api.databaseChecksum(id, format.wireValue()).getChecksums().getSha256());
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
}
