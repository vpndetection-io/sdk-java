package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vpndetection.model.DatasetChecksums;
import io.vpndetection.model.LicensedDataset;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** The licensed dataset endpoints, which no shared corpus covers. */
class DatabaseTest {
    // Every database response nests its payload one level down, so an unwrap at the wrong depth
    // returns nothing at all against a perfectly healthy API. nodejs shipped exactly that in its
    // 1.0.x checksum method; here the depth is fixed by the generated response type.
    @Test
    void databaseResponsesAreUnwrappedAtTheRightDepth() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/database/checksum", StubHttpClient.Route.ok("{\"id\": \"vpn_ip_extended_v1\","
                        + " \"format\": \"mmdb\", \"checksums\": {\"md5\": \"m\", \"sha1\": \"s1\","
                        + " \"sha256\": \"s256\", \"sha512\": \"s512\"}}"),
                // A license is held against the FAMILY, and the ids a download takes hang off
                // `versions`. Reading an id from the top level is how this endpoint came to
                // answer objects whose every field was empty.
                "api/v1/database/list", StubHttpClient.Route.ok(
                        "{\"datasets\": [{\"base\": \"vpn_ip\", \"name\": \"VPN IP\","
                                + " \"redistribution\": \"internal\", \"in_term\": true,"
                                + " \"standing\": \"licensed\", \"versions\": [{\"id\":"
                                + " \"vpn_ip_extended_v1\", \"version\": 1, \"formats\":"
                                + " [{\"format\": \"mmdb\", \"bytes\": 1234}]}]}]}"),
                "api/v1/database/downloads", StubHttpClient.Route.ok(
                        "{\"downloads\": [{\"dataset_id\": \"vpn_ip_extended_v1\"}]}"),
                "api/v1/database/metadata", StubHttpClient.Route.ok(
                        "{\"id\": \"vpn_ip_extended_v1\", \"entries\": 42}")));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            DatasetChecksums sums = client.database().checksums("vpn_ip_extended_v1", DatasetFormat.MMDB);
            assertEquals("s256", sums.getSha256(), "the digest a caller wants must not be null");
            assertEquals("m", sums.getMd5());

            LicensedDataset family = client.database().list().get(0);
            assertEquals(1, client.database().list().size());
            assertEquals("vpn_ip", family.getBase());
            assertEquals(LicensedDataset.StandingEnum.LICENSED, family.getStanding());
            assertEquals("vpn_ip_extended_v1", family.getVersions().get(0).getId());
            assertEquals(1234, family.getVersions().get(0).getFormats().get(0).getBytes());
            assertEquals(1, client.database().downloads().size());
            assertEquals("vpn_ip_extended_v1",
                    client.database().metadata("vpn_ip_extended_v1").getId());
        }
    }

    // The success case for this endpoint arrives as an ApiException, because the generated method
    // treats any non-2xx as a failure and a 302 is what a granted download looks like.
    @Test
    void aDownloadUrlIsReadOffTheRedirectRatherThanFollowed() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/database/download", new StubHttpClient.Route(302, "",
                        Map.of("Location", "https://s3.vpndetection.io/signed/vpn_ip_extended_v1.mmdb"))));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            assertEquals("https://s3.vpndetection.io/signed/vpn_ip_extended_v1.mmdb",
                    client.database().downloadUrl("vpn_ip_extended_v1", DatasetFormat.MMDB));
            assertEquals(1, http.calls.size());
        }
    }

    @Test
    void aDeniedDownloadStillReportsItsKind() {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/database/download", new StubHttpClient.Route(403,
                        "{\"rc\": \"no license for this dataset\"}", Map.of())));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class,
                    () -> client.database().downloadUrl("vpn_ip_extended_v1", DatasetFormat.MMDB));

            assertEquals(ErrorKind.FORBIDDEN, err.kind());
            // The database endpoints answer `rc` where the lookup endpoint answers `error`.
            assertEquals("no license for this dataset", err.getMessage());
        }
    }

    // A real dataset is gzip, so the payload here is bytes that are not valid text: a transfer that
    // went through a string anywhere would come out mangled rather than merely wrong.
    private static final byte[] PAYLOAD = {0x1f, (byte) 0x8b, 0x08, 0x00, (byte) 0xc3, (byte) 0x28,
            0x00, (byte) 0xff, 0x4e, 0x2d};
    private static final String SIGNED_URL = "https://s3.vpndetection.io/signed/cdn_ip_v1.csvgz";

    @Test
    void aDownloadStreamsToAFileAndAgreesWithTheInMemoryCopy(@TempDir Path dir) throws IOException {
        StubHttpClient http = transferring(PAYLOAD.length);
        Path destination = dir.resolve("cdn_ip_v1.csv.gz");

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            long written = client.database().download("cdn_ip_v1", DatasetFormat.CSVGZ, destination);

            assertEquals(PAYLOAD.length, written);
            assertArrayEquals(PAYLOAD, Files.readAllBytes(destination));
            assertFalse(Files.exists(dir.resolve("cdn_ip_v1.csv.gz.part")),
                    "the .part file outlived a successful transfer");
            assertArrayEquals(PAYLOAD, client.database().downloadBytes("cdn_ip_v1", DatasetFormat.CSVGZ),
                    "the in-memory copy is not the file");
        }
    }

    // The presigned URL authorizes itself, so handing object storage the API key would give a host
    // with no business holding it a credential. The JDK is no help here: an HttpClient that follows
    // redirects drops Authorization across origins but forwards it within one.
    @Test
    void theApiKeyNeverReachesObjectStorage(@TempDir Path dir) {
        StubHttpClient http = transferring(PAYLOAD.length);

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            client.database().download("cdn_ip_v1", DatasetFormat.CSVGZ, dir.resolve("out.gz"));
        }

        assertEquals(2, http.calls.size(), "the 302 was not followed as a second request");
        assertTrue(http.calls.get(0).contains("api/v1/database/download"));
        assertEquals("Bearer k", http.authorizations.get(0), "the API request carried no key");
        assertEquals(SIGNED_URL, http.calls.get(1));
        assertNull(http.authorizations.get(1), "the API key was sent to object storage");
    }

    // A transfer that dies mid-body can reach a reader as a plain end of stream, so a short read is
    // silent unless what arrived is checked against what was promised.
    @Test
    void aTruncatedTransferFailsLoudlyAndLeavesNoFileBehind(@TempDir Path dir) {
        StubHttpClient http = transferring(PAYLOAD.length * 4);
        Path destination = dir.resolve("cdn_ip_v1.csv.gz");

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class,
                    () -> client.database().download("cdn_ip_v1", DatasetFormat.CSVGZ, destination));

            assertEquals(ErrorKind.NETWORK, err.kind());
            assertEquals("the transfer ended after 10 of 40 bytes", err.getMessage());
            assertFalse(Files.exists(destination), "a short transfer was left under the real name");
            assertFalse(Files.exists(dir.resolve("cdn_ip_v1.csv.gz.part")), "the .part file survived");

            assertThrows(VPNDetectionException.class,
                    () -> client.database().downloadBytes("cdn_ip_v1", DatasetFormat.CSVGZ),
                    "the in-memory path accepted a short body");
        }
    }

    // The whole download path, not just downloadUrl: an unlicensed dataset must fail before any
    // transfer starts, must not be retried, and must carry what the API said rather than a status.
    @Test
    void anUnlicensedDatasetIsRefusedOnceAndNotRetried(@TempDir Path dir) {
        StubHttpClient http = StubHttpClient.of(Map.of(
                "api/v1/database/download", new StubHttpClient.Route(403,
                        "{\"rc\": \"NOT_LICENSED\"}", Map.of())));

        try (VPNDetection client = VPNDetection.builder().httpClient(http).apiKey("k").retries(3).build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class,
                    () -> client.database().download("hosting_ip_v1", DatasetFormat.CSVGZ,
                            dir.resolve("out.gz")));

            assertEquals(ErrorKind.FORBIDDEN, err.kind());
            assertEquals("NOT_LICENSED", err.getMessage());
            assertFalse(err.retryable(), "a license refusal is not worth retrying");
        }

        assertEquals(1, http.calls.size(), "a 403 was retried");
    }

    /** A granted download: the API redirects, and object storage answers the given length. */
    private static StubHttpClient transferring(int declaredLength) {
        return StubHttpClient.of(Map.of(
                "api/v1/database/download", new StubHttpClient.Route(302, "",
                        Map.of("Location", SIGNED_URL)),
                "signed/cdn_ip_v1.csvgz", new StubHttpClient.Route(200, PAYLOAD,
                        Map.of("Content-Length", String.valueOf(declaredLength)))));
    }
}
