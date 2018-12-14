#!/bin/bash
set -e -u -o pipefail

tag=$(git describe --tags)
base_image_name=mietzekotze/culper-server
tagged_image_name=${base_image_name}:${tag}

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

docker build --build-arg CULPER_VER=${tag} -t ${tagged_image_name} .

if [ tag | rg (alpha|beta|rc) = false]; then
    docker tag ${tagged_image_name} ${base_image_name}:latest
fi

docker publish ${base_image_name}
