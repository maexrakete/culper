<<<<<<< HEAD
<<<<<<< HEAD
FROM alpine:3.8
=======
FROM ubuntu:18.04
>>>>>>> 0ca4b503ef6767717adde708b7683b2c0c165315

ARG CULPER_VER="0.3.1-alpha.1"

WORKDIR /

<<<<<<< HEAD
RUN apk update \
    && apk add gnupg \
=======
FROM ubuntu:18.04

ARG CULPER_VER="0.3.1-alpha.1"

WORKDIR /

RUN apt-get update\
    && apt-get install -y gnupg \
>>>>>>> [wip] implement sequoia
=======
RUN apt-get update\
    && apt-get install -y gnupg \
>>>>>>> 0ca4b503ef6767717adde708b7683b2c0c165315
    && rm -rf /var/cache/apk/*

RUN mkdir /config
RUN mkdir /gpg

ADD https://github.com/maexrakete/culper/releases/download/${CULPER_VER}/culper /usr/bin/culper

RUN chmod +x /usr/bin/culper

VOLUME ["/config", "/gpg"]

EXPOSE 8000
ENTRYPOINT ["culper", "--gpg_path=/gpg", "--config_file=/config/culper.toml", "server"]
