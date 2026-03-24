FROM golang:1.24.13-bookworm

WORKDIR /agent

RUN apt-get update
RUN apt-get install --yes libnetfilter-queue-dev

COPY . ./

RUN go build -trimpath -ldflags=-buildid= -o agent ./cmd/agent
