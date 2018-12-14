#!/bin/bash
set -e -u -o pipefail

if [ "$TRAVIS" = true ]; then
    chmod -R 777 .
fi

rm -rf target

docker run -e LIBZ_SYS_STATIC=1 --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder:nightly cargo build --release
