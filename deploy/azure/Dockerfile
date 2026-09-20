# The scanner as a container image, for the Container App Job a customer deploys.
#
# Alpine rather than scratch or distroless on purpose: the job needs a shell to redirect the
# estate JSON onto a mounted volume, because the scanner writes to stdout and a Container App
# Job's stdout only reaches Log Analytics, where a 100KB JSON document arrives split across
# rows and has to be reassembled. A shell and a `>` is the smaller, more honest mechanism.

# --platform=$BUILDPLATFORM pins the BUILD stage to the machine's native architecture and lets
# Go cross-compile to the target, instead of emulating the target and running the toolchain
# under QEMU. That is not a preference: building linux/amd64 on an arm64 Mac by emulation fails
# outright with "fatal error: found bad pointer in Go heap", because QEMU mis-emulates what the
# Go runtime does. Cross-compiling is also several times faster.
# The same Go minor as go.mod and the root Dockerfile, so every artifact of one commit is built
# by the same toolchain line; the release notes name the exact patch version. Not optional: the
# official golang image sets GOTOOLCHAIN=local, so a builder one minor behind go.mod does not
# download the newer toolchain, it fails `go mod download` with "go.mod requires go >= 1.26.0".
#
# PINNED BY DIGEST, tag kept for humans. The digest is the MULTI-ARCH INDEX, not the amd64
# manifest: the build stage runs on $BUILDPLATFORM, which is arm64 on a laptop and amd64 in CI,
# and only an index resolves to both. Pinning the amd64 manifest would break every local build on
# an arm64 Mac. Dependabot (docker ecosystem, .github/dependabot.yml) bumps the digest when the
# tag moves; to refresh by hand:
#   go run github.com/google/go-containerregistry/cmd/crane@latest digest golang:1.26-alpine
# or, with nothing but docker: docker pull golang:1.26-alpine && docker image inspect --format
# '{{index .RepoDigests 0}}' golang:1.26-alpine. Not `docker manifest inspect | sha256sum`: that
# re-indents the JSON and hashes something the registry never served.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
# An OPTIONAL pre-downloaded module cache, served to `go mod download` as a file:// module proxy.
# CI stages its module cache as .gomodcache/ (already in proxy layout) so a cache hit downloads
# nothing; a plain `docker build .` has no .gomodcache/, the single-character glob matches
# nothing, BuildKit copies nothing, the file:// proxy answers 404 and Go falls through to
# proxy.golang.org. Whichever proxy answers, go.sum checks every module.
COPY .gomodcach[e] /modproxy/
RUN GOPROXY=file:///modproxy,https://proxy.golang.org,direct go mod download
COPY . .
# Static, so the runtime image needs no libc and the binary is the only moving part.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/scanner ./agent/cmd/scanner

# PINNED BY DIGEST, tag kept for humans. Index digest again, not the amd64 manifest, so the same
# line serves `docker build --platform linux/amd64` in CI and a native build on any other machine;
# the index is resolved to the target platform at build time. Refresh by hand with:
#   go run github.com/google/go-containerregistry/cmd/crane@latest digest alpine:3.21
# or, with nothing but docker: docker pull alpine:3.21 && docker image inspect --format
# '{{index .RepoDigests 0}}' alpine:3.21. Not `docker manifest inspect | sha256sum`: that
# re-indents the JSON and hashes something the registry never served.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
# Non-root: the scanner only ever reads a cloud and writes one file.
RUN adduser -D -u 10001 scanner
COPY --from=build /out/scanner /usr/local/bin/scanner
USER 10001
ENTRYPOINT ["/usr/local/bin/scanner"]
