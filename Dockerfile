####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

# Local ES 8 port of malice-plugins/pkgs. Passed as an additional build
# context: docker build --build-context pkgs=../malice-plugins
COPY --from=pkgs . /build/malice-plugins/
COPY . /build/rizin/
WORKDIR /build/rizin

# Pure Go (shells out to the rz-bin CLI) -> static binary.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan .

####################################################
# RIZIN RUNTIME
####################################################
# alpine:3.20 — minimal base. The rizin v0.9.0 rz-bin binary is a STATIC
# Linux x86-64 build (no shared-library dependencies), so it runs on musl
# without any of rizin's normal build/runtime dependencies.
FROM alpine:3.20

LABEL maintainer="https://github.com/malice-plugins"

LABEL malice.plugin.repository="https://github.com/malice-plugins/rizin.git"
LABEL malice.plugin.category="exe"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

# rizin v0.9.0 prebuilt STATIC Linux x86-64 release. The tarball ships the
# whole rizin toolset (rizin, rz-bin, rz-asm, ...); we extract ONLY bin/rz-bin
# (the headless binary-analysis CLI). The tarball is checksum-pinned for
# reproducibility.
ENV RIZIN_VERSION=0.9.0
ENV RIZIN_TARBALL=rizin-v0.9.0-static-x86_64.tar.xz
ENV RIZIN_URL=https://github.com/rizinorg/rizin/releases/download/v0.9.0/${RIZIN_TARBALL}
ENV RIZIN_SHA256=df98d39482c0844bf104acc02c633037c0ff10e3703fae92a4d9648ac73228f5

# curl (download), xz (extract .tar.xz), ca-certificates (HTTPS).
RUN apk add --no-cache curl xz ca-certificates \
  && curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o /tmp/rizin.tar.xz "${RIZIN_URL}" \
  && echo "${RIZIN_SHA256}  /tmp/rizin.tar.xz" | sha256sum -c - \
  && mkdir -p /usr/local/bin \
  && tar xJf /tmp/rizin.tar.xz -C /usr/local/bin --strip-components=1 bin/rz-bin \
  && rm -f /tmp/rizin.tar.xz \
  && test -x /usr/local/bin/rz-bin \
  && /usr/local/bin/rz-bin -v

COPY --from=go_builder /bin/scan /bin/scan

WORKDIR /malware

ENTRYPOINT ["scan"]
CMD ["--help"]
