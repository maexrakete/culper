#!/bin/bash
set -e -u -o pipefail

rm -rf target
if [ "$TRAVIS" = true ]; then
    chmod -R 777 .
fi

docker run -e LIBZ_SYS_STATIC=1 --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder:nightly cargo build --release
