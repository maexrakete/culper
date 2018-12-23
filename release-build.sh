#!/bin/bash
set -e -u -o pipefail

if [ "$TRAVIS" = true ]; then
    sudo chmod -R 777 .
fi

<<<<<<< HEAD
rm -rf target
=======
>>>>>>> [wip] implement sequoia
docker run -e LIBZ_SYS_STATIC=1 --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder:nightly cargo build --release
