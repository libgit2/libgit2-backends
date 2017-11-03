FROM alpine

COPY CMake/         /usr/local/src/CMake
COPY elasticsearch/ /usr/local/src/elasticsearch

RUN apk add --update alpine-sdk cmake libgit2-dev
WORKDIR /usr/local/src/elasticsearch