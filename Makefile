#
# Makefile for Go builds

BIN_NAME = resolv
LDFLAGS = -s -w

GO := $(shell which go)
STRIP := $(shell which strip)

tiny:
	$(GO) build -ldflags="${LDFLAGS}" -o ${BIN_NAME}
	$(STRIP) ${BIN_NAME}
