#!/bin/sh
# Auths universal installer — https://auths.dev
# Usage: curl -fsSL https://get.auths.dev | sh
set -eu

REPO="auths-dev/auths"
INSTALL_DIR="${AUTHS_INSTALL_DIR:-$HOME/.auths/bin}"

main() {
    detect_platform
    resolve_version
    download_and_install
    print_success
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  os="linux" ;;
        Darwin) os="macos" ;;
        *)      err "Unsupported OS: $OS (auths supports Linux and macOS)" ;;
    esac

    case "$ARCH" in
        x86_64 | amd64)    arch="x86_64" ;;
        aarch64 | arm64)   arch="aarch64" ;;
        *)                 err "Unsupported architecture: $ARCH" ;;
    esac

    # macOS only ships aarch64 binaries — Intel Macs can use Rosetta or Homebrew
    if [ "$os" = "macos" ] && [ "$arch" = "x86_64" ]; then
        err "Pre-built binaries for macOS x86_64 are not available yet.
  Install via Homebrew instead:
    brew tap auths-dev/auths-cli && brew install auths
  Or build from source:
    cargo install --git https://github.com/${REPO}.git auths_cli"
    fi

    ASSET="auths-${os}-${arch}.tar.gz"
}

resolve_version() {
    if [ -n "${AUTHS_VERSION:-}" ]; then
        VERSION="$AUTHS_VERSION"
        return
    fi

    say "Fetching latest release..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"([^"]+)".*/\1/')" \
        || err "Failed to fetch latest version from GitHub.
  You can set AUTHS_VERSION manually:
    AUTHS_VERSION=v0.0.1-rc.9 curl -fsSL https://get.auths.dev | sh"

    if [ -z "$VERSION" ]; then
        err "Could not determine latest version"
    fi
}

download_and_install() {
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    say "Downloading auths ${VERSION} (${os}/${arch})..."
    curl -fsSL "$URL" -o "${TMPDIR}/archive.tar.gz" \
        || err "Download failed: $URL
  Check that ${VERSION} has a release asset for your platform."

    say "Verifying checksum..."
    CHECKSUM_URL="${URL}.sha256"
    if curl -fsSL "$CHECKSUM_URL" -o "${TMPDIR}/expected.sha256" 2>/dev/null; then
        EXPECTED="$(awk '{print $1}' "${TMPDIR}/expected.sha256")"
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL="$(sha256sum "${TMPDIR}/archive.tar.gz" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL="$(shasum -a 256 "${TMPDIR}/archive.tar.gz" | awk '{print $1}')"
        else
            say "  (no sha256sum/shasum found, skipping verification)"
            ACTUAL="$EXPECTED"
        fi
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            err "Checksum mismatch!
  Expected: $EXPECTED
  Got:      $ACTUAL"
        fi
        say "  Checksum OK"
    else
        say "  (no checksum file available, skipping verification)"
    fi

    tar -xzf "${TMPDIR}/archive.tar.gz" -C "$TMPDIR"

    mkdir -p "$INSTALL_DIR"
    for bin in auths auths-sign auths-verify; do
        if [ -f "${TMPDIR}/${bin}" ]; then
            mv "${TMPDIR}/${bin}" "${INSTALL_DIR}/${bin}"
            chmod +x "${INSTALL_DIR}/${bin}"
        fi
    done
}

print_success() {
    say ""
    say "  auths ${VERSION} installed to ${INSTALL_DIR}/auths"
    say ""

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            say "  Add auths to your PATH by adding this to your shell profile:"
            say ""
            say "    export PATH=\"${INSTALL_DIR}:\$PATH\""
            say ""
            say "  Then restart your shell or run:"
            say ""
            say "    source ~/.bashrc  # or ~/.zshrc"
            say ""
            ;;
    esac

    say "  Get started:"
    say ""
    say "    auths init"
    say ""
}

say() {
    printf '%s\n' "$@"
}

err() {
    say "Error: $1" >&2
    exit 1
}

main
