FROM alpine:3.8

ARG CULPER_VER="0.3.1-alpha.1"

WORKDIR /

RUN apk update \
    && apk add gnupg \
    && rm -rf /var/cache/apk/*

RUN mkdir /config
RUN mkdir /gpg

ADD https://github.com/maexrakete/culper/releases/download/${CULPER_VER}/culper /usr/bin/culper

RUN chmod +x /usr/bin/culper

VOLUME ["/config", "/gpg"]

EXPOSE 8000
ENTRYPOINT ["culper", "--gpg_path=/gpg", "--config_file=/config/culper.toml", "server"]
