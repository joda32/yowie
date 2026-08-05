#!/usr/bin/env bash
#
# Build release bundles for every supported platform.
#
#   ./scripts/release.sh            # version from `git describe`
#   ./scripts/release.sh v1.2.3     # explicit version
#
# Produces dist/ containing one archive per platform plus SHA256SUMS.
# Requires only the Go toolchain and tar/zip — no third-party release tooling.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
DIST="dist"

# Platforms worth shipping. CGO is off throughout, so every target is a static
# binary with no runtime dependencies.
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

# -trimpath keeps absolute build paths out of the binary; -s -w drop the symbol
# table and DWARF data, which halves the size and matters for a tool people
# download rather than build.
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "Building yowie ${VERSION}"
rm -rf "${DIST}"
mkdir -p "${DIST}"

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%%/*}"
  GOARCH="${platform##*/}"

  binary="yowie"
  [ "${GOOS}" = "windows" ] && binary="yowie.exe"

  stage="${DIST}/yowie_${VERSION}_${GOOS}_${GOARCH}"
  mkdir -p "${stage}"

  printf '  %-16s' "${GOOS}/${GOARCH}"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${stage}/${binary}" ./cmd/yowie

  # Ship the signature packs alongside the binary. They are embedded already,
  # but having them on disk is what makes `-signatures ./signatures` useful for
  # editing rules without rebuilding.
  cp -R signatures "${stage}/signatures"
  find "${stage}/signatures" -name '*.go' -delete
  cp README.md LICENSE NOTICE "${stage}/"

  if [ "${GOOS}" = "windows" ]; then
    (cd "${DIST}" && zip -qr "$(basename "${stage}").zip" "$(basename "${stage}")")
    archive="$(basename "${stage}").zip"
  else
    tar -czf "${stage}.tar.gz" -C "${DIST}" "$(basename "${stage}")"
    archive="$(basename "${stage}").tar.gz"
  fi

  rm -rf "${stage}"
  printf '%s (%s)\n' "${archive}" "$(du -h "${DIST}/${archive}" | cut -f1)"
done

# Checksums let anyone verify a download without trusting the transport.
(cd "${DIST}" && sha256sum ./*.tar.gz ./*.zip | sed 's|\./||' > SHA256SUMS)

echo
echo "dist/"
ls -1 "${DIST}"
echo
echo "SHA256SUMS:"
cat "${DIST}/SHA256SUMS"
