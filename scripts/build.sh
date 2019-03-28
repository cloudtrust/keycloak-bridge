#!/usr/bin/env bash

function usage()
{
	bold=$(tput bold)
	normal=$(tput sgr0)
	echo "NAME"
	echo "    build.sh - Build keycloak-bridge"
	echo "SYNOPSIS"
	echo "    ${bold}build.sh${normal} ${bold}--version${normal} version ${bold}--env${normal} environment"
}

#
# Main
#
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

while [ "$1" != "" ];
do
	case $1 in
		--env ) shift
				ENV=$1
				;;
		--version ) shift
				VERSION=$1
				;;
		* ) 	usage
				exit 1
	esac
	shift
done

if [ -z ${ENV} ] || [ -z ${VERSION} ]; then
	usage
	exit 1
fi

# Directories flatbuffer.
FB_EVENT_DIR="./api/event"

# Delete the old dirs.
echo "==> Removing old directories..."
rm -f bin/*
mkdir -p bin/
rm -f "$FB_EVENT_DIR"/fb/*

# Flatbuffers.
echo
echo "==> Flatbuffers:"
flatc --grpc --go -o "$FB_EVENT_DIR" "$FB_EVENT_DIR"/event.fbs 
ls -hl "$FB_EVENT_DIR"/fb

# Build.
echo
echo "==> Build:"

cd cmd/keycloakb

# Get the git commit.
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

# Override the variables GitCommit and Environment in the main package.
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT}${GIT_DIRTY} -X main.Environment=${ENV} -X main.Version=${VERSION}"

go build -ldflags "$LD_FLAGS" -o ../../bin/keycloak_bridge 
echo "Build commit '${GIT_COMMIT}' for '${ENV}' environment."
ls -hl ../../bin/

exit 0