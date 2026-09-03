#!/bin/bash

# Runs Maven inside the official image, so building and testing needs nothing
# installed locally beyond docker.
#
#   ./scripts/mvn.sh test
#   ./scripts/mvn.sh -q package
#
# The dependency cache is mounted from the HOST home directory rather than the
# working tree: a container-local ~/.m2 would re-download everything on each
# run, and a repo-local one would put a few hundred megabytes of jars under
# version control.

set -euo pipefail

cd "$(dirname "$0")/.."

MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3-eclipse-temurin-21}"
M2_DIR="${M2_DIR:-${HOME}/.m2}"

mkdir -p "$M2_DIR"

docker run --rm \
    -v "$PWD:/w" \
    -v "$M2_DIR:/root/.m2" \
    -w /w \
    -e MAVEN_CONFIG=/root/.m2 \
    "$MAVEN_IMAGE" mvn -B -Duser.home=/root "$@"
