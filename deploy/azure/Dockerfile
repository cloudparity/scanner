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
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
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

FROM alpine:3.21
# Non-root: the scanner only ever reads a cloud and writes one file.
RUN adduser -D -u 10001 scanner
COPY --from=build /out/scanner /usr/local/bin/scanner
USER 10001
ENTRYPOINT ["/usr/local/bin/scanner"]
