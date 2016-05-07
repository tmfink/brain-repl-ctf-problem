#!/bin/bash

GDB_CMD_FILE="gdb_cmds.gdb"

# Be verbose
set -e

pkill socat

function usage {
    echo "Usage: $0 (debug|d)|(run|r) BINARY"
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
fi

# Get absolute address
BINARY="$(readlink -f "$2")"
BIN_DIR="$(dirname "${BINARY}")"
BIN_NAME="$(basename "${BINARY}")"

# Change working directory to binary's dir
ORIGINAL_WD="$(pwd)"
cd "${BIN_DIR}"

CMD="socat TCP4-LISTEN:2600,bind=127.0.0.1,fork,reuseaddr EXEC:./${BIN_NAME}"
GDB_CMD_FILE=${ORIGINAL_WD}/${GDB_CMD_FILE}

case "$1" in
d|debug)
    gdb -x ${GDB_CMD_FILE} --args $CMD
    ;;
r|run)
    $CMD
    ;;
*)
    echo "Invalid command"
    usage
    ;;
esac
