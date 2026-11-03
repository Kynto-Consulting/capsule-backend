# syntax=docker/dockerfile:1
# Image of the Capsule gateway data plane (static binary, non-root user, no shell, no package manager).
#
# Build context is backend/ :
#   docker build -f cmd/capsule-gateway/Dockerfile -t capsule-gateway:dev backend
#
# Run notes
#  - The process runs as uid 65532. Ports below 1024 need either `--cap-add NET_BIND_SERVICE` or
#    `--sysctl net.ipv4.ip_unprivileged_port_start=0` (the capability is not granted by default).
#  - For zero-downtime updates run the new container with `--network host` (or the same published ports) next to the old
#    one: both bind the same ports through SO_REUSEPORT (CAPSULE_GW_REUSEPORT=true, the default on Linux); then send
#    SIGTERM to the old container (`docker kill -s TERM`, and give it `--stop-timeout` as long as CAPSULE_GW_DRAIN_TIMEOUT).
#    Never `docker restart`: it cuts every open connection.
#  - Raise the descriptor limit (`--ulimit nofile=65536:65536`): each proxied connection uses 2 descriptors.
#  - Configuration: CAPSULE_GW_* variables (internal/gateway/data/config.go); the secret goes in CAPSULE_GW_SECRET or in a
#    mounted file referenced by CAPSULE_GW_SECRET_FILE. Certificates: CAPSULE_GW_TLS_CERT / CAPSULE_GW_TLS_KEY (SIGHUP reloads).

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/capsule-gateway ./cmd/capsule-gateway

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/capsule-gateway /capsule-gateway
USER 65532:65532
# 443 tunnel/SNI, 5432 PostgreSQL, 9102 internal admin (/metrics, /healthz, /readyz): publish it only on a private interface.
EXPOSE 443 5432 9102
ENV CAPSULE_GW_METRICS_ADDR=127.0.0.1:9102
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 CMD ["/capsule-gateway", "-healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/capsule-gateway"]
