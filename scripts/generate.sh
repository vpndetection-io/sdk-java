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
NAMES="listDatabases_200_response=DatasetList"
NAMES="${NAMES},listDownloads_200_response=DownloadList"
NAMES="${NAMES},databaseChecksum_200_response=DatasetChecksumsResponse"
NAMES="${NAMES},databaseChecksum_200_response_checksums=DatasetChecksums"

rm -rf .gen
mkdir -p .gen

docker run --rm \
    -v "$PWD/spec:/spec:ro" \
    -v "$PWD/.gen:/out" \
    "$GENERATOR_IMAGE" generate \
    -i /spec/openapi.yaml \
    -g java --library native \
    -o /out \
    --inline-schema-name-mappings "$NAMES" \
    --additional-properties="$PROPS" \
    >/dev/null

# Only the three source packages are taken. The generator also emits its own
# pom.xml, README.md, .gitignore, gradle wrapper and CI workflow, all of which
# would overwrite ours if the output were unpacked directly over the repo.
for pkg in internal api model ; do
    rm -rf "src/main/java/io/vpndetection/${pkg}"
    cp -R ".gen/src/main/java/io/vpndetection/${pkg}" "src/main/java/io/vpndetection/${pkg}"
done

rm -rf .gen
echo "regenerated src/main/java/io/vpndetection/{internal,api,model} from spec/openapi.yaml"
grep -m1 '^  version:' spec/openapi.yaml
