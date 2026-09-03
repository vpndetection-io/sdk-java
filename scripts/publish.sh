#!/bin/bash

# Publishes to Maven Central through the Central Portal from inside the official
# Maven image, so a release needs nothing installed locally beyond docker. The
# release workflow does the same steps on a tag; this is the manual path for a
# first release or when Actions is not an option.
#
#   ./scripts/publish.sh            # build, sign, upload
#   DRY_RUN=1 ./scripts/publish.sh  # build and sign, upload nothing
#
# Required, all as environment variables so no secret is written to disk:
#   CENTRAL_TOKEN_USERNAME  user token from https://central.sonatype.com/account
#   CENTRAL_TOKEN_PASSWORD
#   GPG_PRIVATE_KEY         ASCII-armored private key (gpg --armor --export-secret-keys)
#   GPG_PASSPHRASE          passphrase for that key, empty string if there is none
#
# Central will reject the upload until the io.vpndetection namespace is verified.
# Verification is a one-off DNS TXT record on vpndetection.io, added from
# https://central.sonatype.com/publishing/namespaces; nothing can be published to
# a groupId before that lands.

set -euo pipefail

cd "$(dirname "$0")/.."

: "${CENTRAL_TOKEN_USERNAME:?set CENTRAL_TOKEN_USERNAME to a Central Portal user token}"
: "${CENTRAL_TOKEN_PASSWORD:?set CENTRAL_TOKEN_PASSWORD to a Central Portal user token}"
: "${GPG_PRIVATE_KEY:?set GPG_PRIVATE_KEY to an ASCII-armored private key}"
: "${GPG_PASSPHRASE:?set GPG_PASSPHRASE to the key passphrase, or the empty string}"

MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3-eclipse-temurin-21}"
M2_DIR="${M2_DIR:-${HOME}/.m2}"
DRY_RUN="${DRY_RUN:-}"

goal="deploy"
if [ -n "$DRY_RUN" ] ; then
    goal="verify"
fi

mkdir -p "$M2_DIR"

# settings.xml interpolates ${env.*} at read time, so the credentials stay in the
# environment and never land in the mounted cache directory.
docker run --rm \
    -v "$PWD:/w" \
    -v "$M2_DIR:/root/.m2" \
    -w /w \
    -e CENTRAL_TOKEN_USERNAME \
    -e CENTRAL_TOKEN_PASSWORD \
    -e GPG_PRIVATE_KEY \
    -e MAVEN_GPG_PASSPHRASE="$GPG_PASSPHRASE" \
    "$MAVEN_IMAGE" bash -euc "
        cat > /tmp/settings.xml <<'XML'
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>\${env.CENTRAL_TOKEN_USERNAME}</username>
      <password>\${env.CENTRAL_TOKEN_PASSWORD}</password>
    </server>
  </servers>
</settings>
XML
        printf '%s' \"\$GPG_PRIVATE_KEY\" | gpg --batch --import
        mvn -B -Duser.home=/root -s /tmp/settings.xml -Prelease ${goal}
    "
