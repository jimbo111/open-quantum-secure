# Stage 1: Build Go binary
FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /oqs-scanner ./cmd/oqs-scanner/

# Stage 2: Runtime with semgrep + ast-grep
FROM python:3.12-slim

# Install semgrep (pinned version)
RUN pip install --no-cache-dir semgrep==1.113.0 && \
    rm -rf /root/.cache

# Install runtime dependencies that must persist:
#   curl — PR comments, webhooks (entrypoint.sh)
#   jq   — JSON parsing for PR comment idempotency
#   ca-certificates — HTTPS for curl and oqs-scanner API calls
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates jq unzip && \
    rm -rf /var/lib/apt/lists/*

# Install ast-grep from prebuilt binary (pinned version, not latest)
ARG AST_GREP_VERSION=0.38.0
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "$DPKG_ARCH" in \
      amd64) AST_ARCH="x86_64" ;; \
      arm64) AST_ARCH="aarch64" ;; \
      *) echo "Unsupported architecture: $DPKG_ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/ast-grep/ast-grep/releases/download/${AST_GREP_VERSION}/app-${AST_ARCH}-unknown-linux-gnu.zip" -o /tmp/ast-grep.zip && \
    unzip -o /tmp/ast-grep.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/sg /usr/local/bin/ast-grep 2>/dev/null || true && \
    rm -f /tmp/ast-grep.zip && \
    apt-get purge -y unzip && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /oqs-scanner /usr/local/bin/oqs-scanner
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# GitHub Actions Docker containers must run as root to write to
# $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY (root-owned files).
# Security is enforced by the runner's seccomp profile.
WORKDIR /github/workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
