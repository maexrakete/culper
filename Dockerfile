FROM ubuntu:18.04

ARG CULPER_VER="20181228162340-b1c5540"

WORKDIR /

RUN apt-get update\
    && apt-get install -y gnupg \
    && rm -rf /var/cache/apk/*

RUN mkdir /config
RUN mkdir /gpg

ADD https://github.com/maexrakete/culper/releases/download/${CULPER_VER}/culper-server /usr/bin/culper-server

RUN chmod +x /usr/bin/culper-server

VOLUME ["/config", "/gpg"]

EXPOSE 8080
ENTRYPOINT ["culper-server"]
