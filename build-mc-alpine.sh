#!/bin/bash

# assumes that $GOPATH/src/github.com/minio/mc exists. to get it, run go get github.com/minio/mc

docker run --rm -it -e GO15VENDOREXPERIMENT=1 -v $GOPATH:/gopath -e GOPATH=/gopath -e CGO_ENABLED=0 -w /gopath/src/github.com/minio/mc golang:1.5.1 go build -o /gopath/src/github.com/minio/mc/mc
