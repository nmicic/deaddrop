# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage build for deaddrop-relay. Static binary on scratch —
# minimal attack surface (no shell, no libc, no package manager).

FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /deaddrop-relay ./cmd/deaddrop-relay

FROM scratch

COPY --from=build /deaddrop-relay /deaddrop-relay

# Socket directory created at runtime via docker-compose volume.
# Secrets delivered via environment variables from .env file.

ENTRYPOINT ["/deaddrop-relay"]
