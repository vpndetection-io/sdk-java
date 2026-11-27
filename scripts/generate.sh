#!/bin/bash

# Regenerates the wire layer from the PINNED spec in spec/openapi.yaml.
#
# The generator runs in its official container, so nothing has to be installed
# locally, and it reads the committed spec rather than a URL, so the build is
# reproducible and offline. Refresh the spec with scripts/download-spec.sh, run
# this, and commit both together so a reviewer sees which spec produced which
# client.
#
# The output is COMMITTED, unlike some of the sibling SDKs: the generator is a
# container rather than a build dependency, so leaving it out of the tree would
# mean `mvn test` on a fresh clone needed docker.

set -euo pipefail

cd "$(dirname "$0")/.."

GENERATOR_IMAGE="${GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.25.0}"

# openApiNullable=false keeps org.openapitools:jackson-databind-nullable off a
# consumer's classpath. It only affects the two `nullable: true` dataset fields,
# where null and absent mean the same thing; it does NOT touch the tier-gated
# lookup members, which are optional rather than nullable and stay boxed.
PROPS="groupId=io.vpndetection,artifactId=vpndetection"
PROPS="${PROPS},invokerPackage=io.vpndetection.internal"
PROPS="${PROPS},apiPackage=io.vpndetection.api"
PROPS="${PROPS},modelPackage=io.vpndetection.model"
PROPS="${PROPS},hideGenerationTimestamp=true,openApiNullable=false"

# The four wrapper schemas are inline in the spec, so the generator names them after
# the operation and status code (DatabaseChecksum200ResponseChecksums). One of them is
# public API here. --model-name-mappings does NOT reach an inline schema; only
# --inline-schema-name-mappings does, keyed by the generator's own placeholder name.
# The generated wire classes are named from the TAG, so the Database tag would
# take `DatabaseApi` - the name the hand-written accessor wants, since
# `client.database()` is a DatabaseApi in every brand. Suffix the generated ones
# instead; they ARE the wire layer, so the name is honest, and `Database` itself
# is the family MODEL now.
NAMES="listDatabases_200_response=DatabaseList"
NAMES="${NAMES},listDownloads_200_response=DownloadList"
NAMES="${NAMES},databaseChecksum_200_response=DatabaseChecksumsResponse"

# Without these the token response's `mslm:` members come out as getMslmApikeyId/getMslmApikey.
MEMBERS="mslm:apikey_id=apikeyId,mslm:apikey=apikey"

rm -rf .gen
mkdir -p .gen/spec

# The generator reads an edited copy, never the pin: a re-pin that would move a public type keeps
# it there until a major (scripts/keep_types.py says which members, and why).
python3 scripts/keep_types.py spec/openapi.yaml .gen/spec/openapi.yaml

docker run --rm \
    -v "$PWD/.gen/spec:/spec:ro" \
    -v "$PWD/.gen:/out" \
    "$GENERATOR_IMAGE" generate \
    -i /spec/openapi.yaml \
    -g java --library native \
    -o /out \
    --inline-schema-name-mappings "$NAMES" \
    --name-mappings "$MEMBERS" \
    --api-name-suffix WireApi \
    --additional-properties="$PROPS" \
    >/dev/null

# Only the three source packages are taken. The generator also emits its own
# pom.xml, README.md, .gitignore, gradle wrapper and CI workflow, all of which
# would overwrite ours if the output were unpacked directly over the repo.
for pkg in internal api model ; do
    rm -rf "src/main/java/io/vpndetection/${pkg}"
    cp -R ".gen/src/main/java/io/vpndetection/${pkg}" "src/main/java/io/vpndetection/${pkg}"
done

# The generated OAuth class is public by accident and nothing calls it: client.oauth() is the
# surface. Deprecated for the next major to delete.
# A generated enum fails the whole call on a value the API adds; each becomes a class that holds
# any value as served (scripts/open_enums.py says how).
python3 scripts/open_enums.py src/main/java/io/vpndetection/model

AUTHORIZATION="src/main/java/io/vpndetection/api/AuthorizationWireApi.java"
sed -i \
    -e 's|^@javax.annotation.Generated(|/** @deprecated Use {@link io.vpndetection.VPNDetection#oauth()}. */\n&|' \
    -e 's|^public class AuthorizationWireApi {$|@Deprecated(forRemoval = true)\n&|' \
    "$AUTHORIZATION"
if [ "$(grep -c -e '^/\*\* @deprecated' -e '^@Deprecated(forRemoval = true)$' "$AUTHORIZATION")" != 2 ] ; then
    echo "could not mark ${AUTHORIZATION} deprecated: its class declaration changed shape" >&2
    exit 1
fi

# The generator starts every list member at an empty list, so a lookup answer without `web` (a
# plan that leaves it out) read as `[]`, the answer under a false is_web, and absent-versus-false
# was lost. It starts null instead; a detail object's lists stay as generated, since the detail
# itself is what a plan leaves out.
LOOKUP="src/main/java/io/vpndetection/model/LookupResponse.java"
sed -i 's|^  private List<WebDetail> web = new ArrayList<>();$|  private List<WebDetail> web;|' "$LOOKUP"
if ! grep -q '^  private List<WebDetail> web;$' "$LOOKUP" ; then
    echo "could not start ${LOOKUP}'s web as null: its declaration changed shape" >&2
    exit 1
fi
rm -rf .gen
echo "regenerated src/main/java/io/vpndetection/{internal,api,model} from spec/openapi.yaml"
grep -m1 '^  version:' spec/openapi.yaml
