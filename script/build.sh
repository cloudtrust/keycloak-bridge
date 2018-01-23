#!/usr/bin/env bash

function usage()
{
	bold=$(tput bold)
	normal=$(tput sgr0)
	echo "NAME"
	echo "    build.sh - Build flaki-service"
	echo "SYNOPSIS"
	echo "    ${bold}build.sh${normal} ${bold}--env${normal} environment"
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
		* ) 	usage
				exit 1
	esac
	shift
done

if [ -z ${ENV} ]; then
	usage
	exit 1
fi

# Directories flatbuffer.
FLATBUF_EVENT_DIR="./services/events/transport/flatbuffers"
FLATBUF_USER_DIR="./services/users/transport/flatbuffer"

# Delete the old dirs.
echo "==> Removing old directories..."
rm -f bin/*
mkdir -p bin/
rm -f "$FLATBUF_EVENT_DIR"/fb/*
rm -f "$FLATBUF_USER_DIR"/fb/*

# Get the git commit.
GIT_COMMIT="$(git rev-parse HEAD)"

# Override the variables GitCommit and Environment in the main package.
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.Environment=${ENV}"

# Flatbuffers.
echo
echo "==> Flatbuffers:"
flatc --grpc --go -o "$FLATBUF_EVENT_DIR" "$FLATBUF_EVENT_DIR"/event.fbs 
ls -hl "$FLATBUF_EVENT_DIR"/fb
flatc --grpc --go -o "$FLATBUF_USER_DIR" "$FLATBUF_USER_DIR"/users.fbs 
ls -hl "$FLATBUF_USER_DIR"/fb

# Build.
echo
echo "==> Build:"

export CGO_ENABLED="0"

go build  -ldflags "$LD_FLAGS" -o bin/keycloakBridge ./daemon/keycloakd.go
echo "Build commit '${GIT_COMMIT}' for '${ENV}' environment."
ls -hl bin/

exit 0