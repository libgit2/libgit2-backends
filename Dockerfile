FROM alpine

COPY elasticsearch/ /build
WORKDIR /build

RUN apk add --update alpine-sdk cmake libgit2-dev
