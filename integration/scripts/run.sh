#!/bin/bash

# Runs the integration suite against the library as PUBLISHED on Maven Central,
# which is the one thing the unit suite cannot check: that suite tests this
# working tree, so it stays green through a tag that was never pushed, a jar
# that shipped without a package, or a release that never landed.
#
#   ./scripts/run.sh
#
# Maven runs from PATH when there is one and in the official image otherwise, so
# this is the same entry point on CI and on a box with no JDK.
#
# Two conditions make the run meaningless rather than failing, and each one skips
# with a reason instead:
#
#   1. Nothing published satisfies the range the pom requires. Before the first
#      release there is no artifact to test, and a Java test naming a method that
#      version does not have will not COMPILE, so this gate has to cover the whole
#      suite rather than one test.
#   2. A tier's staging key is missing. The unauthenticated tests still run, and
#      each tier without a key skips from inside the suite, so the skip and its
#      reason land in the test output rather than in this script's preamble.

set -euo pipefail

cd "$(dirname "$0")/.."

GROUP="io.vpndetection"
ARTIFACT="vpndetection"
COORDS="${GROUP}:${ARTIFACT}"

# Where the artifact is looked up AND where maven resolves it from, as one
# setting: two names for the registry could disagree, and then the suite would
# check one repository and test what came out of another.
CENTRAL_BASE_URL="${CENTRAL_BASE_URL:-https://repo1.maven.org/maven2}"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3-eclipse-temurin-21}"

# A local repository of this suite's own. The library's own build uses ~/.m2, so
# a `mvn install` next door cannot end up being what these tests resolve.
M2_DIR="${M2_INTEGRATION_DIR:-${HOME}/.m2-vpndetection-integration}"
MVN_BIN="$(command -v mvn || true)"

function main() {
    local range published latest
    range="$(requiredRange)"
    assertNoLocalSource

    published="$(publishedVersions "$range")"
    latest="${published##* }"
    if [ -z "$published" ] ; then
        skip "no published ${COORDS} satisfies ${range}, so there is no released artifact to test"
        return 0
    fi
    echo "==> ${COORDS}@${range} matches published ${published// /, }"
    echo "==> tiers with a key: $(tiersWithAKey)"

    # Purged rather than reused, so every run resolves the artifact afresh from
    # the registry and a copy somebody installed by hand cannot linger.
    rm -rf "${M2_DIR}/repository/io/vpndetection"
    mkdir -p "${M2_DIR}/repository"

    mvnRun "-Dvpndetection.version=${latest}" dependency:resolve
    assertFromTheRegistry "$latest"

    mvnRun "-Dvpndetection.version=${latest}" test
}

# The constraint the pom declares, as a Maven range. Read from the pom rather
# than duplicated here, so raising the floor is one edit in the file a human
# reads first.
function requiredRange() {
    sed -n 's|.*<vpndetection.version>\(.*\)</vpndetection.version>.*|\1|p' pom.xml | head -1
}

# Every release the registry serves that satisfies the range, ascending. A
# groupId that has never been published answers 404, and so does one whose
# metadata is not up yet; both mean the same thing here.
function publishedVersions() {
    local range="$1" metadata lower upper version out=""
    metadata="$(curl -fsS \
        "${CENTRAL_BASE_URL}/${GROUP//.//}/${ARTIFACT}/maven-metadata.xml" 2>/dev/null || true)"
    if [ -z "$metadata" ] ; then
        return 0
    fi
    lower="$(rangeBound "$range" 1)"
    upper="$(rangeBound "$range" 2)"
    while read -r version ; do
        if [ "$(newerOf "$version" "$lower")" = "$version" ] &&
            [ "$version" != "$upper" ] && [ "$(newerOf "$version" "$upper")" = "$upper" ] ; then
            out="${out}${version} "
        fi
    done < <(echo "$metadata" | sed -n 's|.*<version>\(.*\)</version>.*|\1|p' |
        grep -v -- '-SNAPSHOT' | sort -V)
    echo "${out% }"
}

# `[1.0,2.0)` is the only shape supported: lower inclusive, upper exclusive.
# Anything else is a typo rather than a constraint, and reading it as one would
# quietly test the wrong major version.
function rangeBound() {
    local range="$1" which="$2"
    if [[ ! "$range" =~ ^\[([0-9.]+),([0-9.]+)\)$ ]] ; then
        echo "==> FAILED: ${range} is not a [lower,upper) range" >&2
        exit 1
    fi
    echo "${BASH_REMATCH[$which]}"
}

function newerOf() {
    printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1
}

# The suite is worthless if maven handed it the working tree, and that failure is
# silent: every test passes, against the wrong code. The pom is checked before
# anything runs, because a path repository or a parent pointing next door would
# never even reach the registry.
function assertNoLocalSource() {
    local hits
    hits="$(grep -nE '<relativePath>|<systemPath>|<module>|file:' pom.xml || true)"
    if [ -n "$hits" ] ; then
        echo "==> FAILED: pom.xml reaches outside the registry, so this would not test a release" >&2
        echo "$hits" >&2
        exit 1
    fi
}

# What actually distinguishes a downloaded artifact from an installed one: maven
# records the repository each file came from beside it, and an artifact put there
# by `mvn install` carries an EMPTY repository id. A jar with no such record at
# all is the same problem wearing a different hat.
#
# The empty id is checked for rather than a named one being looked up, because a
# jar that was BOTH installed and downloaded carries a line of each, and "some
# line names a repository" is then true of a tree that also holds a hand-built
# copy. Any empty id at all disqualifies the artifact.
function assertFromTheRegistry() {
    local want="$1" dir jar marker origin
    dir="${M2_DIR}/repository/${GROUP//.//}/${ARTIFACT}/${want}"
    jar="${ARTIFACT}-${want}.jar"
    marker="${dir}/_remote.repositories"

    if [ ! -f "${dir}/${jar}" ] ; then
        echo "==> FAILED: ${dir}/${jar} was never resolved" >&2
        exit 1
    fi
    if [ ! -f "$marker" ] ; then
        echo "==> FAILED: ${jar} carries no repository record, so it was not downloaded" >&2
        exit 1
    fi
    if grep -q "^${jar}>=" "$marker" ; then
        echo "==> FAILED: ${jar} was installed locally, so this would not test a release" >&2
        exit 1
    fi
    origin="$(sed -n "s|^${jar}>\(.\+\)=.*|\1|p" "$marker" | head -1)"
    if [ -z "$origin" ] ; then
        echo "==> FAILED: ${jar} names no repository of origin, so it was not downloaded" >&2
        exit 1
    fi
    echo "==> testing ${COORDS}@${want} from ${origin} (${dir})"
}

# Maven runs from PATH when there is one, and in the official image otherwise:
# CI has a JDK and a maven, and the dev box has neither. Either way the four tier
# keys are passed by NAME, so no key ever reaches a command line.
function mvnRun() {
    echo "==> mvn $*"
    if [ -n "$MVN_BIN" ] ; then
        "$MVN_BIN" -B "-Dmaven.repo.local=${M2_DIR}/repository" \
            "-DcentralBaseUrl=${CENTRAL_BASE_URL}" "$@"
        return
    fi
    docker run --rm \
        -v "$PWD:/w" \
        -v "${M2_DIR}:/root/.m2" \
        -w /w \
        -e MAVEN_CONFIG=/root/.m2 \
        -e VPNDETECTION_STAGING_KEY_FREE \
        -e VPNDETECTION_STAGING_KEY_STARTER \
        -e VPNDETECTION_STAGING_KEY_SCALE \
        -e VPNDETECTION_STAGING_KEY_MAX \
        "$MAVEN_IMAGE" mvn -B -Duser.home=/root \
        "-Dmaven.repo.local=/root/.m2/repository" \
        "-DcentralBaseUrl=${CENTRAL_BASE_URL}" "$@"
}

# Empty counts as absent: Actions interpolates a secret that does not exist to an
# empty string, and an empty key is sent as no key at all.
function tiersWithAKey() {
    local named="" tier secret
    while read -r tier secret ; do
        if [ -n "${!secret:-}" ] ; then
            named="${named}${tier} "
        fi
    done <<'EOF'
free VPNDETECTION_STAGING_KEY_FREE
starter VPNDETECTION_STAGING_KEY_STARTER
scale VPNDETECTION_STAGING_KEY_SCALE
max VPNDETECTION_STAGING_KEY_MAX
EOF
    echo "${named:-none, so only the unauthenticated tests will run}"
}

function skip() {
    echo "==> SKIPPED: $1"
    notice "Integration suite skipped: $1"
}

# Surfaced on the workflow run itself, so a skip is visible without opening the
# log and reading to the end of it.
function notice() {
    if [ "${GITHUB_ACTIONS:-}" = "true" ] ; then
        echo "::notice title=Integration::$1"
    fi
}

main "$@"
