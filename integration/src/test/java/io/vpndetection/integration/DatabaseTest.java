package io.vpndetection.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vpndetection.DatasetFormat;
import io.vpndetection.ErrorKind;
import io.vpndetection.VPNDetectionException;
import io.vpndetection.integration.Staging.Probe;
import io.vpndetection.model.DatasetChecksums;
import io.vpndetection.model.DatasetMetadata;
import io.vpndetection.model.LicensedDataset;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * The licensed-download half, which only the max key can reach: it is the tier holding dataset
 * licenses, and {@code db.download} is a scope the other three keys do not carry.
 *
 * <p>The transfer is budgeted before it starts. {@code metadata} publishes a size per format, and
 * that size is checked against the ceiling below FIRST, so a mistaken dataset id can never quietly
 * pull one of the gigabyte datasets through CI.
 */
class DatabaseTest {
    // The max organization licenses `cdn_ip` for redistribution, and at ~10 KB it is the only
    // dataset small enough to move in CI.
    private static final String DATASET_ID = "cdn_ip_v1";
    private static final DatasetFormat FORMAT = DatasetFormat.CSVGZ;
    // 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so tripping it means
    // the suite is pointed somewhere unintended, which is exactly when a transfer must not start.
    private static final long CEILING = 8L * 1024 * 1024;
    // A real catalog id the max organization holds no license for.
    private static final String UNLICENSED_ID = "hosting_ip_v1";

    @TempDir
    static Path tmp;

    private static Probe probe;
    private static Transfer transfer;

    /** One download, shared by the tests that read it, rather than one transfer each. */
    private record Transfer(long bytes, Path path, DatasetChecksums checksums) {}

    @BeforeEach
    void requireTheMaxKey() {
        Assumptions.assumeTrue(Tiers.skipFor(Tiers.max()) == null, () -> Tiers.skipFor(Tiers.max()));
    }

    /**
     * A license covers a dataset FAMILY, and the ids a download takes hang off {@code versions}.
     * This is the endpoint that did not match its own published schema until 2026-09-04.
     */
    @Test
    void theLicensedCatalogAnswersTheFamilyShape() {
        List<LicensedDataset> datasets = client().database().list();

        assertFalse(datasets.isEmpty(), "the max organization licenses nothing");
        List<String> ids = new ArrayList<>();
        for (LicensedDataset dataset : datasets) {
            assertNotNull(dataset.getBase(), "a family arrived with no base");
            assertNotNull(dataset.getName(), dataset.getBase() + " carries no name");
            assertNotNull(dataset.getStanding(), dataset.getBase() + " carries no standing");
            assertNotNull(dataset.getRedistribution(), dataset.getBase() + " carries no right");
            assertFalse(dataset.getVersions().isEmpty(), dataset.getBase() + " carries no versions");
            dataset.getVersions().forEach(version -> {
                assertNotNull(version.getId(), dataset.getBase() + " has a version with no id");
                assertTrue(version.getVersion() > 0, version.getId() + " has no version number");
                assertFalse(version.getFormats().isEmpty(), version.getId() + " carries no formats");
                ids.add(version.getId());
            });
        }
        System.out.println("licensed: " + String.join(", ", ids));
    }

    @Test
    void aDatasetTheOrganizationDoesNotLicenseIsRefusedCleanly() {
        int before = probe().recorder().facts().size();

        VPNDetectionException err = assertThrows(VPNDetectionException.class,
                () -> client().database().downloadUrl(UNLICENSED_ID, FORMAT),
                UNLICENSED_ID + " is now licensed here, so point this at one that is not");

        assertEquals(ErrorKind.FORBIDDEN, err.kind());
        assertEquals(403, err.statusCode().orElse(0));
        assertFalse(err.retryable(), "a license refusal is not worth retrying");
        // The API says which refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back to the status
        // means the envelope went unread.
        assertFalse(err.getMessage().startsWith("request failed with status"),
                "the message is the client fallback, so the response body went unread");
        assertEquals(before + 1, probe().recorder().facts().size(), "a 4xx must not be retried");
    }

    @Test
    void downloadStreamsARealDatasetToDiskIntact() throws IOException {
        Transfer dl = downloaded();

        assertTrue(dl.bytes() > 0, "nothing was transferred");
        assertEquals(Files.size(dl.path()), dl.bytes(), "the file is not the length the method reported");
        assertFalse(Files.exists(Path.of(dl.path() + ".part")),
                "the .part file outlived a successful transfer");
        byte[] head = Files.readAllBytes(dl.path());
        assertArrayEquals(new byte[] {0x1f, (byte) 0x8b}, new byte[] {head[0], head[1]},
                "the payload is not gzip");

        // Reading a top-level `sha256` returns nothing against a healthy API, so this pins the
        // unwrap depth as well as the bytes.
        assertTrue(dl.checksums().getSha256().matches("[0-9a-f]{64}"), "no sha256 was published");
        assertEquals(dl.checksums().getSha256(), sha256(head), "the bytes are not the published file");

        // The presigned URL authorizes itself, so the second request must carry no credential.
        List<RecordingHttpClient.Fact> storage = probe().recorder().facts().stream()
                .filter(fact -> !fact.host().equals(Staging.STAGING_HOST)).toList();
        assertFalse(storage.isEmpty(), "nothing was fetched from object storage, so no 302 was followed");
        storage.forEach(fact ->
                assertFalse(fact.carriedKey(), "the API key was sent to object storage"));
    }

    @Test
    void downloadBytesAgreesWithTheStreamedCopy() throws IOException {
        Transfer dl = downloaded();

        byte[] bytes = client().database().downloadBytes(DATASET_ID, FORMAT);

        assertEquals(dl.bytes(), bytes.length, "the in-memory copy is a different length");
        assertArrayEquals(Files.readAllBytes(dl.path()), bytes, "the in-memory copy is not the file");
        assertEquals(dl.checksums().getSha256(), sha256(bytes));
    }

    private static io.vpndetection.VPNDetection client() {
        return probe().client();
    }

    private static Probe probe() {
        if (probe == null) {
            probe = Staging.clientFor(Tiers.max());
        }
        return probe;
    }

    /** Memoized, so the two transfer tests share one download rather than pulling it twice each. */
    private static Transfer downloaded() {
        if (transfer != null) {
            return transfer;
        }
        DatasetMetadata meta = client().database().metadata(DATASET_ID);
        assertEquals(DATASET_ID, meta.getId());
        Integer size = meta.getSize() == null ? null : meta.getSize().get(FORMAT.wireValue());
        assertNotNull(size, DATASET_ID + " publishes no size to check a transfer against");
        assertTrue(size > 0, DATASET_ID + " publishes a size of " + size);
        assertTrue(size <= CEILING, DATASET_ID + " is " + size + " bytes, past the ceiling");

        Path path = tmp.resolve(DATASET_ID + ".csv.gz");
        long bytes = client().database().download(DATASET_ID, FORMAT, path);
        // Read after the transfer, so a rebuild between the two calls shows up as a digest mismatch
        // rather than passing against a digest of nothing.
        DatasetChecksums checksums = client().database().checksums(DATASET_ID, FORMAT);
        System.out.println(DATASET_ID + "." + FORMAT.wireValue() + ": " + bytes
                + " bytes, metadata says " + size);
        transfer = new Transfer(bytes, path, checksums);
        return transfer;
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
