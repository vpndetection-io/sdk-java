package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.vpndetection.model.DatasetChecksums;
import io.vpndetection.model.LicensedDataset;

import org.junit.jupiter.api.Test;

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
}
