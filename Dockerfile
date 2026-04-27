# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /src

# Install certificates for module downloads.
RUN apk add --no-cache ca-certificates

# Cache dependencies before copying source code.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	set -eux; \
	export CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}"; \
	if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
	if [ "${TARGETARCH}" = "arm64" ] && [ -n "${TARGETVARIANT}" ]; then export GOARM64="${TARGETVARIANT#v}"; fi; \
	go build -trimpath -ldflags="-s -w" -o /out/distrust .

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=builder /out/distrust /distrust

USER nonroot:nonroot
EXPOSE 3000

ENTRYPOINT ["/distrust"]
