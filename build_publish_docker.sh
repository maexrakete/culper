#!/bin/bash
set -e -u -o pipefail

tag=${cat culper-server/Cargo.toml | sed -nr 's/version = "(.*)"/\1/p'}
base_image_name=mietzekotze/culper-server
tagged_image_name=${base_image_name}:${tag}

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

docker build --build-arg CULPER_VER=${tag} -t ${tagged_image_name} .

docker push ${base_image_name}
