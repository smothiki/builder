# Short name: Short name, following [a-zA-Z_], used all over the place.
# Some uses for short name:
# - Docker image name
# - Kubernetes service, rc, pod, secret, volume names
SHORT_NAME := builder

# Enable vendor/ directory support.
export GO15VENDOREXPERIMENT=1

# SemVer with build information is defined in the SemVer 2 spec, but Docker
# doesn't allow +, so we use -.
# VERSION := 0.0.1-$(shell date "+%Y%m%d%H%M%S")

VERSION := 2.0.0-$(shell date "+%Y%m%d%H%M%S")
BINARY_DEST_DIR := rootfs/usr/bin
# Common flags passed into Go's linker.
LDFLAGS := "-s -X main.version=${VERSION}"
BINARIES := extract-domain extract-types extract-version generate-buildhook get-app-config get-app-values publish-release-controller yaml2json-procfile
STANDALONE := extract-types  generate-buildhook yaml2json-procfile
# Docker Root FS
BINDIR := ./rootfs

# Legacy support for DEV_REGISTRY, plus new support for DEIS_REGISTRY.
DEV_REGISTRY ?= $$DEV_REGISTRY
DEIS_REGISTY ?= ${DEV_REGISTRY}

# Kubernetes-specific information for RC, Service, and Image.
RC := manifests/deis-${SHORT_NAME}-rc.yaml
SVC := manifests/deis-${SHORT_NAME}-service.yaml
IMAGE := arschles/${SHORT_NAME}:${VERSION}

RCDF := manifests/deis-df${SHORT_NAME}-rc.yaml
SVCDF := manifests/deis-df${SHORT_NAME}-service.yaml

all:
	@echo "Use a Makefile to control top-level building of the project."

# This illustrates a two-stage Docker build. docker-compile runs inside of
# the Docker environment. Other alternatives are cross-compiling, doing
# the build as a `docker build`.

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0  go build -a -installsuffix cgo -ldflags '-s' -o $(BINARY_DEST_DIR)/builder boot.go || exit 1
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0  go build -a -installsuffix cgo -ldflags '-s' -o $(BINARY_DEST_DIR)/fetcher fetcher/fetcher.go || exit 1
	@$(call check-static-binary,$(BINARY_DEST_DIR)/builder)
	@$(call check-static-binary,$(BINARY_DEST_DIR)/fetcher)
	for i in $(BINARIES); do \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' -o $(BINARY_DEST_DIR)/$$i pkg/src/$$i.go || exit 1; \
	done
	@echo "Past go compiling"
	@for i in $(BINARIES); do \
		$(call check-static-binary,$(BINARY_DEST_DIR)/$$i); \
	done

docker-build: build
	docker build -t $(IMAGE) rootfs
	perl -pi -e "s|image: [a-z0-9.:]+\/deis\/bp${SHORT_NAME}:[0-9a-z-.]+|image: ${IMAGE}|g" ${RC}

docker-push: docker-build
	docker push $(IMAGE)
# For cases where build is run inside of a container.

# Deploy is a Kubernetes-oriented target
deploy: kube-service kube-rc

# Some things, like services, have to be deployed before pods. This is an
# example target. Others could perhaps include kube-secret, kube-volume, etc.
kube-service:
	kubectl create -f ${SVC}

# When possible, we deploy with RCs.
kube-rc:
	kubectl create -f ${RC}

kube-clean:
	kubectl delete rc deis-builder

.PHONY: all build docker-compile kube-up kube-down deploy

define check-static-binary
	  if file $(1) | egrep -q "(statically linked|Mach-O)"; then \
	    echo ""; \
	  else \
	    echo "The binary file $(1) is not statically linked. Build canceled"; \
	    exit 1; \
	  fi
endef
