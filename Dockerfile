# syntax=docker/dockerfile:1
# Multi-stage build mirroring gobl.dev/Dockerfile.

FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache modules separately from sources.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG DATE=
RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.date=${DATE}" \
        -o /out/gobl.lookup \
        ./cmd/gobl.lookup

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 gobl

COPY --from=builder /out/gobl.lookup /usr/local/bin/gobl.lookup

USER gobl
WORKDIR /home/gobl

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gobl.lookup"]
CMD ["serve", "--http-port", "8080"]
