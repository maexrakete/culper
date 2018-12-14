#!/bin/bash
set -e -u -o pipefail

docker run -e LIBZ_SYS_STATIC=1 --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder:nightly cargo build --release
