#!/usr/bin/env bash
# OQS Scanner — Cross-platform install script
# Usage: curl -sSL https://install.oqs.dev | sh
#
# Detects OS and architecture, downloads the correct binary from GitHub Releases,
# verifies SHA-256 checksum, and installs to /usr/local/bin (or ~/bin if no root).

set -euo pipefail

REPO="jimbo111/open-quantum-secure"
BINARY="oqs-scanner"
INSTALL_DIR="/usr/local/bin"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  NC='\033[0m'
else
  GREEN='' RED='' YELLOW='' NC=''
fi

info() { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*"; }
error() { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# Detect OS
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) error "Unsupported OS: $(uname -s)" ;;
  esac
}

# Detect architecture
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# Get latest release version from GitHub API
get_latest_version() {
  if command -v curl >/dev/null 2>&1; then
    curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
  else
    error "Either curl or wget is required"
  fi
}

# Download a file
download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$dest"
  fi
}

main() {
  local os arch version binary_name download_url checksum_url

  os=$(detect_os)
  arch=$(detect_arch)
  version=${OQS_VERSION:-$(get_latest_version)}

  if [ -z "$version" ]; then
    error "Could not determine latest version. Set OQS_VERSION=v1.0.0 to specify."
  fi

  binary_name="${BINARY}-${os}-${arch}"
  if [ "$os" = "windows" ]; then
    binary_name="${binary_name}.exe"
  fi

  download_url="https://github.com/${REPO}/releases/download/${version}/${binary_name}"
  checksum_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"

  info "Installing ${BINARY} ${version} (${os}/${arch})..."

  # Create temp directory
  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  # Download binary
  info "Downloading ${download_url}..."
  download "$download_url" "${tmpdir}/${binary_name}" || error "Download failed. Check version ${version} exists at https://github.com/${REPO}/releases"

  # Download and verify checksum
  info "Verifying checksum..."
  download "$checksum_url" "${tmpdir}/checksums.txt" 2>/dev/null || warn "Checksums not available — skipping verification"

  if [ -f "${tmpdir}/checksums.txt" ]; then
    local expected_hash actual_hash
    expected_hash=$(grep -F "${binary_name}" "${tmpdir}/checksums.txt" | awk '{print $1}')
    if [ -n "$expected_hash" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        actual_hash=$(sha256sum "${tmpdir}/${binary_name}" | awk '{print $1}')
      elif command -v shasum >/dev/null 2>&1; then
        actual_hash=$(shasum -a 256 "${tmpdir}/${binary_name}" | awk '{print $1}')
      else
        warn "No sha256sum or shasum available — cannot verify checksum"
      fi
      if [ -n "$actual_hash" ]; then
        if [ "$expected_hash" != "$actual_hash" ]; then
          error "Checksum mismatch!\n  Expected: ${expected_hash}\n  Got:      ${actual_hash}"
        fi
        info "Checksum verified."
      fi
    fi
  fi

  # Install
  chmod +x "${tmpdir}/${binary_name}"

  if [ -w "$INSTALL_DIR" ]; then
    mv "${tmpdir}/${binary_name}" "${INSTALL_DIR}/${BINARY}"
  elif command -v sudo >/dev/null 2>&1; then
    info "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${tmpdir}/${binary_name}" "${INSTALL_DIR}/${BINARY}"
  else
    INSTALL_DIR="${HOME}/bin"
    mkdir -p "$INSTALL_DIR"
    mv "${tmpdir}/${binary_name}" "${INSTALL_DIR}/${BINARY}"
    warn "Installed to ${INSTALL_DIR}/${BINARY} — ensure ${INSTALL_DIR} is in your PATH"
  fi

  info "Successfully installed ${BINARY} ${version} to ${INSTALL_DIR}/${BINARY}"
  echo ""
  echo "  Get started:"
  echo "    ${BINARY} scan --path . --format table"
  echo "    ${BINARY} version"
  echo ""
}

main "$@"
