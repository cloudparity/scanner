# The scanner as a container: a static binary and a certificate bundle, nothing else.
#
# Two stages so the shipped image contains the binary and nothing else. No shell, no package manager,
# no interpreter - a compromise of the task gets a static binary and a certificate bundle.
# ARCHITECTURE IS PINNED, not inherited from the builder: an unpinned GOARCH makes the image's
# architecture depend on whoever ran the build, and an image that does not match the platform it is
# scheduled on does not start at all ("image Manifest does not contain descriptor matching platform").
# A laptop here produces arm64 and an x86 CI runner produces amd64, so one of the two silently ships
# something that cannot run. Override with --build-arg TARGETARCH=amd64.
#
# --platform on the build stage keeps the toolchain native to the builder while GOARCH decides the
# output, so cross-building from an x86 machine is not emulated.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH=arm64
WORKDIR /src

# Module files first, so a source change does not re-download the dependency graph.
COPY go.mod go.sum ./
# An OPTIONAL pre-downloaded module cache, served to `go mod download` as a file:// module proxy.
# A CI job can stage ~/go/pkg/mod/cache/download (already in proxy layout) as .gomodcache/ so a
# cache hit downloads nothing - the only way a cache reaches a download that runs INSIDE docker
# build without `docker buildx`. The single-character glob is what makes it optional: BuildKit
# copies nothing when nothing matches, so a plain `docker build .` with no .gomodcache/ has no
# /modproxy, the file:// proxy answers 404, and Go falls through to proxy.golang.org exactly as
# before.
COPY .gomodcach[e] /modproxy/
RUN GOPROXY=file:///modproxy,https://proxy.golang.org,direct go mod download

# Exactly the in-repo packages the scanner links, and nothing else. Copying `agent/` alone stopped
# compiling the day agent/internal/backup started importing chain/, and nothing noticed: the image
# is not built by any check. Keep this list equal to
# `go list -deps ./agent/cmd/scanner | grep "$(go list -m)/"`.
COPY contract/ ./contract/
COPY chain/ ./chain/
COPY agent/ ./agent/
# CGO off for a genuinely static binary: the runtime stage has no libc to link against.
# -trimpath so the image does not record the build machine's directory layout.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /scanner ./agent/cmd/scanner

# scratch, not alpine or distroless. The scanner makes HTTPS calls and does nothing else, so the only
# thing it needs from a filesystem is a root certificate bundle.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /scanner /scanner

# Runs as nobody. A container that never needs to write anywhere has no reason to run as root.
USER 65534:65534

ENTRYPOINT ["/scanner"]
