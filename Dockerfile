# Stage 1: Build Go binary
# TODO: Pin to digest for supply chain security:
#   docker pull golang:1.25-alpine && docker inspect --format='{{index .RepoDigests 0}}' golang:1.25-alpine
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /oqs-scanner ./cmd/oqs-scanner/

# Stage 2: Runtime with semgrep
# TODO: Pin to digest for supply chain security:
#   docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim

RUN pip install --no-cache-dir semgrep==1.113.0 && \
    rm -rf /root/.cache

# Install ast-grep from prebuilt binary (no npm/node dependency, ~7MB)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip && \
    DPKG_ARCH=$(dpkg --print-architecture) && \
    case "$DPKG_ARCH" in \
      amd64) AST_ARCH="x86_64" ;; \
      arm64) AST_ARCH="aarch64" ;; \
      *) echo "Unsupported architecture: $DPKG_ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/ast-grep/ast-grep/releases/latest/download/app-${AST_ARCH}-unknown-linux-gnu.zip" -o /tmp/ast-grep.zip && \
    unzip -o /tmp/ast-grep.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/sg /usr/local/bin/ast-grep 2>/dev/null || true && \
    rm -f /tmp/ast-grep.zip && \
    apt-get purge -y curl unzip && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN groupadd -r oqs && useradd -r -g oqs -d /home/oqs -m oqs

COPY --from=builder /oqs-scanner /usr/local/bin/oqs-scanner
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER oqs
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
