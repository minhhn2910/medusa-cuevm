#!/usr/bin/env bash
# Build medusa (with the CuEVM cgo backend) using an overridable CuEVM location.
#
# The cgo directives in fuzzing/fuzzer.go already point at the default
# sibling layout (../../CuEVM-internal). This script lets you override or
# augment those paths via CUEVM_HOME so the same source tree can be built
# against:
#   - a sibling checkout of CuEVM-internal (default)
#   - a system-wide install (e.g. /opt/cuevm)
#   - a custom build directory
#
# Note: CGO_CFLAGS / CGO_LDFLAGS are APPENDED to the cgo directive flags by
# the go toolchain. The paths we export here are searched in addition to the
# in-source defaults, so an override works as long as libcuevm_go.so exists
# under $CUEVM_LIB.
#
# Usage:
#   ./scripts/build.sh                       # use defaults
#   CUEVM_HOME=/opt/cuevm ./scripts/build.sh # override install location
#   ./scripts/build.sh -tags foo -v          # extra args forwarded to go build
#
# Environment variables:
#   CUEVM_HOME      Root of the CuEVM-internal source tree.
#                   Default: <medusa>/../CuEVM-internal
#   CUEVM_LIB       Directory containing libcuevm_go.so.
#                   Default: $CUEVM_HOME/build
#   CUEVM_INCLUDE   Top-level include directory (the one that exposes
#                   "CuEVM/include/..." headers).
#                   Default: $CUEVM_HOME
#   OUT             Output binary path. Default: ./medusa
#   GO              Go binary to invoke. Default: go
#   VERBOSE         If set to 1, print the resolved flags before building.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEDUSA_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- resolve paths ---------------------------------------------------------

CUEVM_HOME_DEFAULT="$MEDUSA_ROOT/../CuEVM-internal"
CUEVM_HOME="${CUEVM_HOME:-$CUEVM_HOME_DEFAULT}"

if [[ ! -d "$CUEVM_HOME" ]]; then
  echo "error: CUEVM_HOME does not exist: $CUEVM_HOME" >&2
  echo "       set CUEVM_HOME to your CuEVM-internal checkout or install prefix" >&2
  exit 1
fi
CUEVM_HOME="$(cd "$CUEVM_HOME" && pwd)"

CUEVM_LIB="${CUEVM_LIB:-$CUEVM_HOME/build}"
CUEVM_INCLUDE="${CUEVM_INCLUDE:-$CUEVM_HOME}"

if [[ ! -d "$CUEVM_LIB" ]]; then
  echo "error: CUEVM_LIB does not exist: $CUEVM_LIB" >&2
  echo "       build CuEVM first (e.g. cmake --build $CUEVM_HOME/build)" >&2
  echo "       or set CUEVM_LIB explicitly" >&2
  exit 1
fi
CUEVM_LIB="$(cd "$CUEVM_LIB" && pwd)"

if [[ ! -f "$CUEVM_LIB/libcuevm_go.so" ]]; then
  echo "warning: libcuevm_go.so not found under $CUEVM_LIB" >&2
  echo "         the link step will likely fail" >&2
fi

# ---- compose cgo env -------------------------------------------------------

# Prepend our paths so they win over the (possibly stale) in-source defaults.
export CGO_CFLAGS="-I$CUEVM_INCLUDE -I$CUEVM_HOME/CuEVM/include ${CGO_CFLAGS:-}"
export CGO_LDFLAGS="-L$CUEVM_LIB -lcuevm_go -Wl,-rpath,$CUEVM_LIB ${CGO_LDFLAGS:-}"

# Also expose CUEVM_LIB at runtime in case the user wants to run from this
# shell without relying on rpath alone.
export LD_LIBRARY_PATH="$CUEVM_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

OUT="${OUT:-$MEDUSA_ROOT/medusa-cuevm}"
GO_BIN="${GO:-go}"

if [[ "${VERBOSE:-0}" == "1" ]]; then
  echo "Building medusa with:"
  echo "  CUEVM_HOME       = $CUEVM_HOME"
  echo "  CUEVM_LIB        = $CUEVM_LIB"
  echo "  CUEVM_INCLUDE    = $CUEVM_INCLUDE"
  echo "  CGO_CFLAGS       = $CGO_CFLAGS"
  echo "  CGO_LDFLAGS      = $CGO_LDFLAGS"
  echo "  LD_LIBRARY_PATH  = $LD_LIBRARY_PATH"
  echo "  OUT              = $OUT"
  echo "  GO               = $GO_BIN"
  echo
fi

cd "$MEDUSA_ROOT"
exec "$GO_BIN" build -o "$OUT" "$@"
