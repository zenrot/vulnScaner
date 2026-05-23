FROM --platform=linux/amd64 golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN GOBIN=/out/tools go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && GOBIN=/out/tools go install golang.org/x/vuln/cmd/govulncheck@latest
RUN CGO_ENABLED=0 GOFLAGS=-mod=readonly \
    go build -trimpath -ldflags="-s -w" \
    -o /out/vulnscanner-server ./cmd/server

FROM --platform=linux/amd64 debian:bookworm-slim AS codeql-installer

ARG CODEQL_VERSION=2.19.3

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q -O /tmp/codeql.tar.gz \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
    && tar xzf /tmp/codeql.tar.gz -C /opt \
    && rm /tmp/codeql.tar.gz \
    && rm -rf \
        /opt/codeql/java \
        /opt/codeql/javascript \
        /opt/codeql/ruby \
        /opt/codeql/swift \
        /opt/codeql/kotlin

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git wget ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=codeql-installer /opt/codeql /opt/codeql
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /out/tools/gosec /usr/local/bin/gosec
COPY --from=builder /out/tools/govulncheck /usr/local/bin/govulncheck
RUN chmod -R a+rX /opt/codeql

ENV PATH="/opt/codeql:/usr/local/go/bin:${PATH}"
ENV GOPATH="/go-work/go"
ENV GOMODCACHE="/go-work/go/pkg/mod"
ENV GOCACHE="/go-work/go-build"
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

RUN adduser --disabled-password --gecos '' --uid 10001 app
WORKDIR /app
RUN mkdir -p /app/history && chown app:app /app/history
COPY --from=builder /out/vulnscanner-server /usr/local/bin/vulnscanner-server
USER app

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz | grep -q ok

ENTRYPOINT ["vulnscanner-server"]
